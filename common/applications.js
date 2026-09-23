// @ts-check
'use strict';
//
// File: applications.js
//
// ===========================================================================
// EVERY APPLICATION THIS SERVICE HAS EVER BEEN ASKED ABOUT, IN ONE PLACE.
//
// A person who authenticates here has had an entry in the directory and a row
// on /admin/users since the day the user observer was written. The thing on the
// OTHER side of every one of those authentications — the OAuth client, the
// OpenID Connect relying party, the SAML service provider, the WS-Federation
// application, the Kerberos service — had nowhere at all. It was six fragments:
// a `registeredClients` Map in oauth2.js, a `client_id` that reached the
// console and was thrown away, a `wtrealm` read and forgotten, an `AppliesTo`
// echoed into an assertion, an SPN created on demand in a principal database,
// and a verifier id in a config row. Each was correct where it stood and there
// was no way to ask this service "what applications have you seen?".
//
// This is that place, and it is one store rather than a seventh fragment: the
// RFC 7591 registrations live HERE now (see `register()` below), so there is no
// second registry to disagree with it about a redirect URI. That is the same
// rule that keeps WS-Federation out of a session store of its own — two stores
// each look correct alone and never see each other.
//
// ---------------------------------------------------------------------------
// THE DIRECTORY IS THE SOURCE OF TRUTH, AND THIS MODULE HOLDS NO COPY.
//
// `ou=applications,<base>` in the embedded LDAP directory IS the registry.
// There is no Map in this file shadowing it: `seen()` reads the entry, changes
// it and writes it back, and every query below is a directory read. That is a
// deliberate choice and it has three consequences worth knowing before
// changing anything here.
//
// **An `ldapmodify` is a configuration change.** Adding a value to
// `oauthRedirectUri` on an application's entry adds a redirect URI that RFC
// 9700 mode will then accept by exact match, because the check reads the same
// attribute this registry writes. That is the point rather than a side effect —
// it is what makes the directory worth being the source of truth, and it is the
// shape the federation work needs.
//
// **The attributes win over the registration document.** RFC 7591 lets a client
// register arbitrary metadata and RFC 7592's read has to hand back what was
// registered, which no set of LDAP attributes can represent — so the whole
// registration is kept verbatim in `appRegistrationJson` beside the attributes.
// When the record is reconstructed, the JSON is the STARTING POINT and every
// member that has a schema attribute is then overwritten from that attribute.
// Otherwise an operator who edited `oauthRedirectUri` would find the edit
// ignored by the one check that matters, which is precisely the two-stores
// failure this arrangement exists to avoid.
//
// **Without the directory there is no registry.** If `ldap_server.js` was never
// required — which happens in the parent project's in-process tests, where only
// the KDC and `app.js` are loaded — `setDirectory()` was never called, every
// function here answers empty, and it says so once in the log. It does NOT fall
// back to an internal Map: a fallback store is a second store, and it would be
// the one that silently disagreed.
//
// ---------------------------------------------------------------------------
// THE SCHEMA, AND WHAT "SCHEMA" CAN HONESTLY MEAN HERE.
//
// `node-ldapjs` has NO schema subsystem. It is protocol machinery — messages,
// filters, DN parsing, a client and a server — and the only three mentions of
// objectClass in the whole of its lib/ tree are a default search filter and the
// names of result codes 65 and 69, which a server would have to raise itself.
// It is also a SUBMODULE this repository does not modify. So there was nothing
// to extend and nothing to register with: the schema below is DEFINED HERE, and
// it is a VOCABULARY rather than a constraint. Nothing rejects an entry for
// disobeying it, exactly as nothing rejects one anywhere else in this
// deliberately schemaless directory — `GET /admin/ldap/service` says so at
// length.
//
// Where a standard name exists it is used. `applicationProcess` (RFC 4519
// section 3.3) is the one registered object class that fits an application at
// all, and it brings `cn`, `description`, `seeAlso`, `ou` and `l` with it. What
// it does not bring is a `client_id`, a `redirect_uris`, an `entityID` or a
// service principal name — no registered LDAP schema has those, because every
// product that stores OAuth clients (Keycloak, AD FS, Okta) keeps them in its
// own database rather than in a directory. So `stsApplication` is invented, and
// its attributes are this service's own names in exactly the way `x509subject`,
// `didSubject` and `authnMethod` already are on the user entries next door.
//
// ---------------------------------------------------------------------------
// ONE RECORD PER IDENTIFIER, AND WHY THAT IS THE RIGHT KEY.
//
// The key is the identifier the protocol presented, verbatim. Not lower-cased:
// a `client_id` is case-sensitive and so is most of a URI. Not namespaced by
// protocol either, and that is the interesting half — an application that
// appears as an OAuth `client_id` and again as a WS-Federation `wtrealm` under
// the same string is ONE application that speaks two protocols, and this
// registry says so by accumulating `appKind` and `appProtocol` rather than
// filing it twice. That is the same reasoning that makes `alice`,
// `urn:uuid:<entryUUID>` and `alice@REALM` one person on /admin/users, and
// it is the shape the federation work will need: a relying party that federates
// over both OIDC and SAML is one relationship, not two.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3), AND ITS DIRECTORY HALF IS INVERTED (rule 6).
//
// It registers no route and requires only libraries — `helpers.js`,
// `audit.js`, `config.js`, and the leaves annotated at each require below —
// none of which requires it back, so it cannot join a cycle and its position
// in the require order does not matter. `config.js` requires nothing from this
// repository at all, which is the property that makes it safe to reach for
// here. `admin_stats.js` requires it in the ORDINARY direction
// (there is no fifth hook here; see rule 3e — a slot is what you reach for when
// a require would close a cycle or move a route, and this one would do
// neither).
//
// The DIRECTORY half has to be inverted, for the reason `vc_claims.js`'s is:
// `ldap_server.js` is required late (21 in `common/protocol_stack.ts`) because
// requiring it pulls every `/ldap` route into the router at that point, and a
// module the token
// endpoint reads cannot drag those routes to the front. So this file offers
// `setDirectory()` and `ldap_server.js` fills it at ITS require time — with
// READ as well as write functions now, since the entries are the store.
//
// The division of labour between the two files is exact and worth keeping:
// THIS module owns the SCHEMA and therefore both conversions
// (`attributesFor()`, `recordFromAttributes()`), and that module owns the
// directory mechanics — where the container is, how an entry is created, what
// the caps are. Neither knows the other's half.
//
// ---------------------------------------------------------------------------
// THE CLIENT SECRET IS STORED, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT.
//
// `oauthClientSecret` holds the secret this service minted at registration, on
// an entry that `GET /admin/ldap/directory` prints to a console administrator.
// (That page was unprotected when this was written; it is behind the console
// gate since 2026-09-06, and an LDAP search never returns the attribute —
// `ldap/ldap_server.js`'s `SECRET_ATTRIBUTES`.) The same objection applies to
// `GET /krb5/principals`, which prints Kerberos passwords, and the answer is
// the one written there: a debugger whose accounts are unusable without
// reading the source is worse than one that says what they are. The secret is
// generated per registration and lives on the entry, so it is written down
// wherever the directory is (`persistence/CLAUDE.md`).
//
// It is worth being precise about what that costs now that RFC 9700 mode
// CHECKS that secret (section 2.5): anyone who can read this directory can
// authenticate as that client. On a service that authenticates nobody and says
// so on every page, that is the honest state of affairs rather than a hole —
// but it is why `audit.js` must never be given this value. Its rule that no
// credential is ever recorded is about the audit log and stands untouched: the
// rows this module writes name the application and never its secret.
// ===========================================================================

const crypto = require('crypto');
// For TABLES only — the JWS and JWE algorithms RFC 9701's and RFC 9101's
// client metadata may name (introspectionResponseProblem(), and the
// REQUEST_OBJECT_* lists). A leaf `helpers.js` already requires, so this adds
// nothing to the load path and closes no cycle.
const stsCrypto = require('./crypto');
const config = require('./config');
// The mode. A LEAF (rule 3) requiring only `config`, which is already required
// here — so it can neither move a route nor close a cycle.
const mode = require('./mode');
const helpers = require('./helpers');
const { log, nowSec, randomId, numberWord } = helpers;
// For the ambient realm's prefix when a pinned base names the seeded callbacks.
// `helpers.js` requires it already, so this closes no cycle and moves no route.
const realms = require('./realms');
const audit = require('./audit');
// The registry of failure codes, a LEAF. A refusal this module hands back to
// the console or `/admin-api` carries its code NON-ENUMERABLY —
// `errorCodes.mark()` on the RESULT OBJECT — so a caller can read it with
// `errorCodes.codeOf(result)` and the JSON a client receives is unchanged.
const errorCodes = require('./error_codes');
const cacheRegistry = require('./cache_registry');
// THE ROLE REGISTER, for one string and one reason: `DEFAULT_REQUIRED_ROLE`.
// A plain require in the ordinary direction and it can stay one — `roles.js`
// is a leaf that requires `helpers` and `config` and nothing else here, so
// this cannot become a cycle unless somebody makes that file require back.
// Hard-coding 'EVERYBODY' here instead would put the permissive default in two
// files, and the day they disagreed every application would silently start
// requiring a role nobody holds.
const roles = require('./roles');

// THE KEY-ENCRYPTION KEY, for the one attribute in this table that is a PRIVATE
// KEY (2026-09-10). It is a LIBRARY and registers nothing, and it requires
// `config`, `crypto`, `mode`, `realms` and `secrets` — none of which requires
// this file — so this cannot close a cycle and cannot move a route. It is the
// SAME module `common/keystore.js` seals this service's own signing keys and
// `common/pki.js`'s certificate authority hierarchy with, and the same one
// `common/credentials.ts` seals an authenticator's shared secret with. See
// SEALED_FIELDS below for why an application's issued signing key joins them.
const keystore = require('./keystore');

// THE REDIRECT ALLOWLIST (2026-09-13), for the three attributes that are
// addresses a browser is sent to or a page frames. `validation.js` requires
// `config.js`, `error_codes.js` and npm packages and nothing from this file, so
// the require closes no cycle and moves no route.
const validation = require('./validation');

// RFC 8705 SECTION 2.1.2's FIVE CERTIFICATE SUBJECT PARAMETERS (2026-09-13):
// what a value of each may be, read by the schema rows, the registration door
// and the console's writes here and by the verifier in
// `oauth-oidc/client_auth.js`. A leaf over `helpers.js`, so the require closes
// no cycle and moves no route.
const certificateSubject = require('./certificate_subject');

// ---------------------------------------------------------------------------
// THE KINDS. One per way an application can present itself to this service.
//
// A record may carry SEVERAL — see the note about one identifier above — and
// the list is closed on purpose: a caller passing a kind that is not here is
// recorded with what it said and warned about, because a typo that silently
// becomes a new kind is how a page comes to list `wsfed-rp` and
// `wsfed-relying-party` as two things.
// ---------------------------------------------------------------------------
const KINDS = [
  { kind: 'oauth2-client', label: 'OAuth 2.0 client',
    what: 'A client_id presented at the authorization or token endpoint.' },
  { kind: 'oidc-relying-party', label: 'OpenID Connect relying party',
    what: 'The same client_id where the request asked for the openid scope — ' +
          'a relying party is an OAuth client that also wants an ID Token, ' +
          'so a record commonly carries both kinds.' },
  { kind: 'saml2-service-provider', label: 'SAML 2.0 service provider',
    what: 'The audience of a SAML 2.0 assertion this service issued.' },
  { kind: 'saml11-relying-party', label: 'SAML 1.1 relying party',
    what: 'The audience of a SAML 1.1 assertion — which is what a ' +
          'WS-Federation relying party is handed by default, so these two ' +
          'commonly appear together.' },
  { kind: 'wsfed-relying-party', label: 'WS-Federation application',
    what: 'A wtrealm from a wsignin1.0 request (section 13.2.1).' },
  { kind: 'wstrust-relying-party', label: 'WS-Trust relying party',
    what: 'An AppliesTo from a RequestSecurityToken — the service the token ' +
          'is for.' },
  { kind: 'oid4vp-verifier', label: 'OpenID4VP verifier',
    what: 'The client_id the mock Verifier presents in an Authorization ' +
          'Request.' },
  { kind: 'federation-identity-provider', label: 'Federated identity provider',
    what: 'A FOREIGN identity service this instance federates with as a ' +
          'service provider — it authenticates people TO this service rather ' +
          'than asking anything OF it, which makes it the one kind here that ' +
          'is not a client. It is in this registry anyway, because the ' +
          'question this container exists to answer is "what parties has ' +
          'this service dealt with?" and a federation partner is the most ' +
          'consequential of them: it is a party whose signature this service ' +
          'BELIEVES. See federation/CLAUDE.md. The relationship itself — the ' +
          'endpoints, the certificate, the attribute mapping — lives under ' +
          'ou=federations and not here; this record is the partner as a ' +
          'party, and that one is the arrangement with it.' },
  { kind: 'kerberos-service', label: 'Kerberos service principal',
    what: 'A service principal name a ticket was issued for, or that the ' +
          'acceptor was asked to be.' },
  // GNAP (RFC 9635), 2026-09-12. Two kinds because GNAP has two parties that
  // present keys to the authorization server: a CLIENT INSTANCE asks for
  // grants, and a RESOURCE SERVER (RFC 9767) introspects tokens, registers
  // resource sets and derives downstream tokens. One entry may be both — an RS
  // that calls a second RS is a client too (RFC 9767 section 4).
  { kind: 'gnap-client', label: 'GNAP client instance',
    what: 'A key (or instance identifier) that made a GNAP grant request.' },
  { kind: 'gnap-resource-server', label: 'GNAP resource server',
    what: 'A key that called the RS-facing API: introspection, resource set ' +
          'registration, or a downstream token derivation.' }
];

const KIND_IDS = KINDS.map(function (one) { return one.kind; });

// ---------------------------------------------------------------------------
// THE PROTOCOL FAMILIES AN APPLICATION MAY BE DECLARED FOR.
//
// A DIFFERENT TABLE FROM KINDS ABOVE, feeding a DIFFERENT ATTRIBUTE FROM
// `appProtocol`, and both of those distinctions are the whole reason it exists.
//
//   * `appProtocol` is DERIVED — the families this application has actually
//     appeared in, accumulated by seen() as each one happens. Nothing may edit
//     it, for the reason EDITABLE's header gives at length.
//   * `appAllowedProtocol` is DECLARED — the families somebody has said this
//     application is FOR, ticked on /admin/applications/new before it has ever
//     connected to anything. It is configuration, like the redirect URIs beside
//     it, and it is editable.
//
// A KIND is what an application IS in one protocol's own vocabulary: an
// `oauth2-client` is a client_id, a `saml2-service-provider` is an entityID.
// A FAMILY is coarser and is CHOSEN rather than observed, which is why one row
// here can cover two kinds, and why this list runs past the families that have
// a kind at all — an application may be declared for LDAP, SCIM or SPIFFE,
// where this service has no application identifier to record and therefore
// nothing to give it a kind from.
//
// **DECLARING A FAMILY GRANTS AND REFUSES NOTHING**, and this is the sentence
// to change if that ever stops being true rather than a page's. No endpoint in
// this service reads this attribute: an application declared for SAML 2.0 alone
// is still issued an access token at /oauth2/token, because that is what this
// service is for and a mock that refused would remove a test case rather than
// add one. It is a record of INTENT, which is the same claim the applications
// page already makes about the entry as a whole ("an entry here grants
// nothing") narrowed to one attribute.
//
// **FIFTEEN ATTRIBUTES DO MORE THAN DECLARE, AND ALL ARE FAMILY-SCOPED.**
// `oauthTokenExchangeRefreshToken` changes what the token endpoint issues;
// since 2026-09-12 `ssfAllowedEvents` LIMITS which Shared Signals event types a
// stream owned by the application is sent; and since 2026-09-13 RFC 9701's
// three `oauthIntrospection*` attributes decide how /oauth2/introspect signs
// and encrypts the JWT response it gives the application — joined the same day
// by RFC 9101's five request-object attributes, RFC 9126's PAR requirement,
// RFC 9396's two authorization-details attributes and RFC 9470's two step-up
// attributes. Every one carries `families:` on its SCHEMA row. The declaration
// itself is still a declaration; what changed is that each of those
// attributes may only be written onto an entry that makes it.
//
// `kinds` IS WHAT MAKES THE DECLARATION COMPARABLE WITH WHAT HAPPENED, and it
// is deliberately the kinds rather than the protocol LABELS on `appProtocol`.
// That was the first attempt and it was wrong in a way worth recording, because
// it looked right: `appProtocol` holds prose — 'OAuth 2.0 / OIDC', 'SAML 1.1',
// 'WS-Federation 1.2' — written by whichever module called seen(), and a
// FEDERATION sighting is recorded under the protocol the RELATIONSHIP speaks.
// So matching on labels made every ordinary OAuth client read as a federation
// partner, since both write 'OAuth 2.0'. The kinds do not have that problem:
// they are a closed vocabulary seen() warns about, and `federation-identity-
// provider` is a thing an application IS rather than a protocol it spoke.
//
// A row's `kind` is the ONE kind this family would be recorded as, which is
// what the pages show; `kinds` is every kind that COUNTS as a sighting of it,
// which is usually the same one list. The exception is OAuth 2.0, whose list
// carries the OpenID Connect kind as well — a relying party IS an OAuth client,
// and a request carrying the openid scope is filed under the narrower kind
// only, so an OAuth row that ignored it would report "never seen" about a
// client signing somebody in every minute.
//
// **A row may have NO kind at all**, and those rows are the reason this is
// stated rather than left to be inferred: LDAP, SCIM, SPIFFE, mutual TLS and
// OpenID4VCI record no application identifier anywhere in this service, so
// nothing will EVER mark them seen. That is a different fact from "it has not
// happened yet", and the pages say so rather than showing a bare no.
//
// ---------------------------------------------------------------------------
// `identifierAttribute` AND `redirectAttribute`: WHERE A FAMILY'S OWN NAMES GO.
//
// Added 2026-08-25, and they are the reason the create form no longer asks for
// a KIND. That select and this table were two vocabularies for one question —
// "what is this application?" — and a reader had to choose in both, from lists
// that did not line up: eight kinds against fourteen families, with five
// families having no kind at all. The families won because they are the coarser
// and the honest one, and because THEY are what an operator is actually
// declaring. The kind is still accumulated by `seen()` when a protocol
// recognises the identifier, which is where a derived attribute belongs.
//
// So a family row now carries the two attributes that family's CONFIGURATION
// lands on:
//
//   * `identifierAttribute` — the attribute holding the name this application
//     answers to in that family. A client_id, an entityID, a wtrealm, an
//     AppliesTo, an SPN, a SPIFFE ID, a bind DN.
//   * `redirectAttribute` — where a response goes back to, for the three
//     families that send one through a browser. Empty everywhere else, because
//     inventing a redirect URI for LDAP would be inventing a fact.
//
// **SEVERAL FAMILIES MAY NAME ONE ATTRIBUTE, AND THAT IS THE POINT rather than
// a shortcut.** OAuth 2.0, OpenID Connect and OpenID4VCI all name
// `oauthClientId` because a relying party IS an OAuth client and a wallet
// collecting a credential authenticates as one — the specifications share the
// identifier, so two attributes would be two spellings of one fact and would
// disagree the first time somebody edited one. SAML 2.0 and SAML 1.1 share
// `samlEntityId` and `samlAssertionConsumerService` for the same reason. The
// console walks this table, DEDUPES BY ATTRIBUTE and draws one field per
// attribute, listing the families it serves — so the form has eleven identifier
// fields for sixteen families (fourteen when this was written) and says why.
//
// **EVERY ONE OF THEM IS MULTI-VALUED BAR ONE.** An application legitimately
// answers to two client_ids, two entityIDs or two SPNs here — one per
// environment being exercised — so these accumulate like the redirect URIs
// beside them. The exception is `oauthTlsClientAuthSubjectDn`, which mutual TLS
// names: it is SINGLE-valued because RFC 8705 section 2.1 matches a certificate
// against "the single expected subject", and since 2026-09-13 a client holds at
// most one of the five subject parameters it is one of (`mtlsAttributeProblem()`
// below). It is the one attribute in this group that something ENFORCES, which
// is exactly why it is the one that cannot be widened without deciding what
// "any of these" means to a security check.
//
// **DECLARING ONE STILL GRANTS NOTHING**, the same as ticking the family does.
// The five families this service records no identifier for — LDAP, SCIM,
// SPIFFE, OpenID4VCI, mutual TLS — get a field anyway, because "what is this
// application called when it talks LDAP to us" is a fact an operator has and
// this registry had nowhere to put. Nothing will ever write those attributes on
// its own, so they read as declaration and only ever as declaration.
// ---------------------------------------------------------------------------
const PROTOCOLS = [
  { id: 'oauth2', label: 'OAuth 2.0', kind: 'oauth2-client',
    kinds: ['oauth2-client', 'oidc-relying-party'],
    identifierAttribute: 'oauthClientId', redirectAttribute: 'oauthRedirectUri',
    logoutAttribute: 'oauthPostLogoutRedirectUri',
    secretAttribute: 'oauthClientSecret',
    what: 'A client_id at the authorization and token endpoints.' },
  { id: 'oidc', label: 'OpenID Connect', kind: 'oidc-relying-party',
    kinds: ['oidc-relying-party'],
    identifierAttribute: 'oauthClientId', redirectAttribute: 'oauthRedirectUri',
    logoutAttribute: 'oauthPostLogoutRedirectUri',
    secretAttribute: 'oauthClientSecret',
    what: 'The same client_id asking for the openid scope, and therefore for ' +
          'an ID Token. A relying party IS an OAuth client, so these two are ' +
          'usually ticked together; ticking this one alone is legal and says ' +
          'the entry is for an OIDC flow.' },
  { id: 'saml2', label: 'SAML 2.0', kind: 'saml2-service-provider',
    kinds: ['saml2-service-provider'],
    identifierAttribute: 'samlEntityId',
    redirectAttribute: 'samlAssertionConsumerService',
    logoutAttribute: 'samlSingleLogoutService',
    what: 'A service provider entityID in the Web Browser SSO profile at ' +
          '/saml2, or the audience of a SAML 2.0 assertion issued anywhere ' +
          'else here.' },
  { id: 'saml11', label: 'SAML 1.1', kind: 'saml11-relying-party',
    kinds: ['saml11-relying-party'],
    identifierAttribute: 'samlEntityId',
    redirectAttribute: 'samlAssertionConsumerService',
    what: 'A relying party of the two browser profiles at /saml11 — and what ' +
          'a WS-Federation application is handed by default, which is why ' +
          'these two are commonly ticked together.' },
  { id: 'wsfed', label: 'WS-Federation', kind: 'wsfed-relying-party',
    kinds: ['wsfed-relying-party'],
    identifierAttribute: 'wsfedRealm', redirectAttribute: 'wsfedReplyUrl',
    logoutAttribute: 'wsfedSignOutUri',
    what: 'A wtrealm in a wsignin1.0 request (section 13.2.1).' },
  { id: 'wstrust', label: 'WS-Trust', kind: 'wstrust-relying-party',
    kinds: ['wstrust-relying-party'],
    identifierAttribute: 'wstrustAppliesTo', redirectAttribute: '',
    what: 'An AppliesTo in a RequestSecurityToken — the service the token is ' +
          'issued FOR.' },
  { id: 'krb5', label: 'Kerberos v5', kind: 'kerberos-service',
    kinds: ['kerberos-service'],
    identifierAttribute: 'krb5ServicePrincipalName', redirectAttribute: '',
    what: 'A service principal name a ticket may be issued for, or that the ' +
          'acceptor may be asked to be.' },
  { id: 'oid4vci', label: 'OpenID4VCI', kind: '',
    kinds: [],
    identifierAttribute: 'oauthClientId', redirectAttribute: 'oauthRedirectUri',
    what: 'A wallet collecting a verifiable credential from the issuer. The ' +
          'wallet presents no application identifier of its own on that flow ' +
          '— it authenticates as an OAuth client and is recorded as one — so ' +
          'this family has no kind and nothing will ever mark it seen.' },
  { id: 'oid4vp', label: 'OpenID4VP', kind: 'oid4vp-verifier',
    kinds: ['oid4vp-verifier'],
    identifierAttribute: 'oid4vpClientId', redirectAttribute: '',
    what: 'A verifier client_id in an Authorization Request asking for a ' +
          'presentation.' },
  { id: 'federation', label: 'Federation', kind: 'federation-identity-provider',
    kinds: ['federation-identity-provider'],
    identifierAttribute: 'federationPartnerId', redirectAttribute: '',
    what: 'A FOREIGN identity service on the other side of a federation ' +
          'relationship. It is the one thing in this registry that is not a ' +
          'client of this service — it authenticates people TO it. Its ' +
          'SIGHTING is recorded under whichever protocol the relationship ' +
          'speaks, so the protocol label on such an entry is ' +
          'indistinguishable from an ordinary client\'s and the KIND is the ' +
          'only thing that tells them apart — which is the whole reason this ' +
          'table matches on kinds. The relationship itself lives under ' +
          'ou=federations; see federation/CLAUDE.md.' },
  { id: 'ldap', label: 'LDAP', kind: '',
    kinds: [],
    identifierAttribute: 'ldapBindDn', redirectAttribute: '',
    what: 'A directory client binding on 389 or LDAPS 636. EVERY BIND HERE ' +
          'SUCCEEDS and none of them names an application, so nothing will ' +
          'ever record a sighting for this family — ticking it says what the ' +
          'entry is for and nothing more.' },
  { id: 'scim', label: 'SCIM 2.0', kind: '',
    kinds: [],
    identifierAttribute: 'scimClientId', redirectAttribute: '',
    what: 'A provisioning client at /scim/v2. That surface authenticates its ' +
          'CALLER — in any of the six schemes RFC 7644 section 2 names — ' +
          'rather than an application identifier, so, as with LDAP, nothing ' +
          'writes this family into appProtocol.' },
  { id: 'spiffe', label: 'SPIFFE', kind: '',
    kinds: [],
    identifierAttribute: 'spiffeWorkloadId', redirectAttribute: '',
    what: 'A workload on the Workload API, or an agent or admin on the SPIRE ' +
          'Server API. A SPIFFE identity gets an entry of its own under ' +
          'ou=spiffe rather than one here (see spiffe/CLAUDE.md), so this is ' +
          'a declaration and never a record.' },
  { id: 'mtls', label: 'TLS / mutual TLS', kind: '',
    kinds: [],
    identifierAttribute: 'oauthTlsClientAuthSubjectDn', redirectAttribute: '',
    what: 'A client authenticating to the token endpoint under RFC 8705. ' +
          'A TLS client certificate issued to the application from its ' +
          'Credentials section authenticates it under tls_client_auth with ' +
          'nothing registered; a certificate from another authority needs ' +
          'ONE of the five subject parameters (oauthTlsClientAuthSubjectDn ' +
          'and the four oauthTlsClientAuthSan* attributes), and ' +
          'self_signed_tls_client_auth reads the jwks x5c or ' +
          'oauthTlsClientCertificateThumbprint — so ticking this box is ' +
          'the note to self, and those are the configuration.' },
  // THE FIFTEENTH FAMILY, AND THE FIRST ONE WHOSE APPLICATION IS SOMETHING
  // THIS SERVICE CALLS RATHER THAN SOMETHING THAT CALLS IT. Every other row
  // above names a client: a client_id at the token endpoint, an entityID on
  // an AuthnRequest, a bind DN on 389. A Shared Signals RECEIVER is the other
  // way round — it agrees a stream and then this service POSTs events to it —
  // which is why it is the only family here whose `deliveryAttribute` is a
  // URL this service DIALS. See ssf/ssf_http.ts, which argues that at length.
  { id: 'ssf', label: 'Shared Signals', kind: 'ssf-receiver',
    kinds: ['ssf-receiver'],
    identifierAttribute: 'ssfReceiverId', redirectAttribute: '',
    deliveryAttribute: 'ssfDeliveryEndpoint',
    eventsAttribute: 'ssfAllowedEvents',
    what: 'A Shared Signals RECEIVER: something that agrees a stream at ' +
          '/ssf/stream and is then delivered Security Event Tokens. Its ' +
          'identifier is whatever it authenticated as when it created the ' +
          'stream, which is the `aud` those SETs carry, and its delivery ' +
          'endpoint is where a push goes. Neither is read as a permission — ' +
          'a stream carries its own delivery endpoint and this entry is ' +
          'where an operator writes down what a receiver is EXPECTED to be, ' +
          'beside everything else that application is.' },
  // GNAP (RFC 9635 + RFC 9767), 2026-09-12. The identifier is the STATIC
  // instance identifier a client may send by reference (section 2.3.1); a
  // client that sends its key by value is identified by that key's thumbprint,
  // which `gnapKeyIdentity` records. The redirect attribute is the INTERACTION
  // FINISH URI (section 2.5.2), so a finish URI gets every return-address rule
  // this registry applies — observed in development, refused until confirmed in
  // product — without GNAP writing a rule of its own.
  { id: 'gnap', label: 'GNAP', kind: 'gnap-client',
    kinds: ['gnap-client', 'gnap-resource-server'],
    identifierAttribute: 'gnapInstanceId', redirectAttribute: 'gnapFinishUri',
    secretAttribute: 'gnapSymmetricKey',
    what: 'A GNAP client instance, or a GNAP resource server, or both: a ' +
          'party that proves possession of a key to /gnap (RFC 9635) or to ' +
          'the RS-facing API (RFC 9767). Its key is gnapKey (a public key ' +
          'object) or gnapKeyReference with a sealed gnapSymmetricKey; its ' +
          'finish URIs are return addresses like any other; a resource ' +
          'server carries the locations it answers for and, once it has ' +
          'registered a resource set, the macaroon root key it verifies with.' }
];

const PROTOCOL_IDS = PROTOCOLS.map(function (one) { return one.id; });

// Every attribute a family names as its `redirectAttribute`, deduplicated —
// the return addresses product mode checks a request against, and so the ones
// `seen()` refuses to write from a sighting there. Derived from the table so a
// family added tomorrow is covered the day it is added.
const RETURN_ADDRESS_ATTRIBUTES = PROTOCOLS
  .map(function (row) { return row.redirectAttribute; })
  .filter(function (name, i, all) { return name && all.indexOf(name) === i; });

// Where the PROVENANCE of those addresses is kept — see its schema row and
// returnAddressesOf() below, which is the one place the mark is read.
const OBSERVED_ADDRESS_ATTRIBUTE = 'appReturnAddressObserved';

// THE SAML SIGNING-CERTIFICATE PAIR (2026-09-17, #37): what is registered and
// trusted, and what a request carried and nobody has vouched for. See the two
// schema rows, and `saml/request_signature.ts`.
const OBSERVED_CERTIFICATE_ATTRIBUTE = 'samlObservedSigningCertificate';

// The editable attributes that hold a certificate somebody's signature is
// checked against, normalised and checked on the way in by updateApplication().
const SAML_CERTIFICATE_ATTRIBUTES = ['samlSigningCertificate',
                                     'samlSpMetadataSigningCertificate'];

// WHAT CONSUMING A SERVICE PROVIDER'S METADATA MAY WRITE, and the only
// attributes replaceSamlMetadataFields() will touch. A closed list, because
// that function writes DERIVED attributes no door may edit, and a function
// that wrote whatever it was handed would be a door around the EDITABLE table.
const SAML_METADATA_FIELDS = [
  'samlSpMetadata', 'samlEncryptionCertificate', 'samlSigningCertificate',
  'samlAssertionConsumerService', 'samlAcsEndpoint',
  'samlSingleLogoutService', 'samlSloEndpoint', 'samlSpNameIdFormat',
  'samlSpAuthnRequestsSigned', 'samlSpWantAssertionsSigned',
  'samlSpWantAssertionsEncrypted',
  'samlSpMetadataValidUntil', 'samlSpMetadataCacheDuration',
  'samlSpMetadataConsumedAt', 'samlSpMetadataSignature'
];

const PROTOCOL_BY_ID = {};
PROTOCOLS.forEach(function (row) { PROTOCOL_BY_ID[row.id] = row; });

// Which declared families a KIND counts as a sighting of — the inverse of the
// `kinds` member, built once rather than searched per row per page. The value
// is a LIST because one kind can belong to two families: `oidc-relying-party`
// is a sighting of OpenID Connect AND of OAuth 2.0, since a relying party is an
// OAuth client. Dropping one of them would leave a page reporting that an
// application signing somebody in every minute had never been seen.
const PROTOCOLS_BY_KIND = {};
PROTOCOLS.forEach(function (row) {
  row.kinds.forEach(function (kind) {
    if (!PROTOCOLS_BY_KIND[kind]) PROTOCOLS_BY_KIND[kind] = [];
    if (PROTOCOLS_BY_KIND[kind].indexOf(row.id) < 0) PROTOCOLS_BY_KIND[kind].push(row.id);
  });
});

function protocolRow(id) {
  log.debug("Entering protocolRow().");
  log.debug("Leaving protocolRow().");
  return PROTOCOL_BY_ID[String(id || '')] || null;
}

// The declared families a record's KINDS amount to a sighting of. Used by the
// pages to mark a declared family that has actually turned up, and to notice
// one that turned up without ever being declared. A kind this table has no row
// for maps onto nothing rather than throwing: seen() warns about an unknown
// kind and records it anyway, so a record can carry one, and this function is
// not its validator.
// The kinds an entry's DECLARED families would be recorded under, in table
// order — each family's own `kind`, so ticking OAuth 2.0 alone does not make
// the entry an OpenID Connect relying party. A family with no kind (LDAP,
// SCIM and the rest) contributes nothing.
function declaredKindsOf(fields) {
  log.debug("Entering declaredKindsOf().");
  const out = [];
  valuesOf((fields || {}).appAllowedProtocol).forEach(function (id) {
    const row = protocolRow(id);
    if (row && row.kind && out.indexOf(row.kind) < 0) {
      out.push(row.kind);
    }
  });
  log.debug("Leaving declaredKindsOf(). " + out.length + " kind(s).");
  return out;
}

function protocolIdsForKinds(kinds) {
  log.debug("Entering protocolIdsForKinds().");
  const out = [];
  (kinds || []).forEach(function (kind) {
    (PROTOCOLS_BY_KIND[String(kind)] || []).forEach(function (id) {
      if (out.indexOf(id) < 0) out.push(id);
    });
  });
  log.debug("Leaving protocolIdsForKinds().");
  // Table order, for the reason normaliseProtocols() puts a declaration back
  // into it: two lists in the same order can be read against each other.
  return PROTOCOL_IDS.filter(function (id) { return out.indexOf(id) >= 0; });
}

// A declared list as it arrives from a form's checkboxes or an API body, made
// into a validated list of ids or into the one refusal this vocabulary makes.
//
// It is REFUSED rather than recorded when a value is not in the table, which is
// the same decision createApplication() makes about `kind` and for the same
// reason: a typo that silently became a new protocol family is how one
// application comes to be declared for `saml2` and `saml-2` and read as two
// different things by whatever comes to read this attribute later. Duplicates
// and blanks are dropped rather than refused — a form that posts one box twice
// is a browser doing something odd, not a caller asking for something wrong.
function normaliseProtocols(value) {
  log.debug("Entering normaliseProtocols().");
  const asked = (Array.isArray(value) ? value : [value])
    .filter(function (one) { return one !== undefined && one !== null; })
    // A single string may carry several, because a JSON caller writing this by
    // hand will send "oauth2 oidc" or "oauth2,oidc" at least as often as an
    // array, and the checkbox form sends one value per field either way.
    .reduce(function (all, one) {
      return all.concat(String(one).split(/[\s,]+/));
    },
            [])
    .map(function (one) { return one.trim(); })
    .filter(Boolean);
  const chosen = [];
  const unknown = [];
  asked.forEach(function (one) {
    if (PROTOCOL_IDS.indexOf(one) < 0) {
      if (unknown.indexOf(one) < 0) unknown.push(one);
      return;
    }
    if (chosen.indexOf(one) < 0) chosen.push(one);
  });
  if (unknown.length) {
    log.debug("Leaving normaliseProtocols(). " + unknown.length + " unknown.");
    return errorCodes.mark({ ok: false, protocols: [],
             errors: [unknown.map(function (one) { return '"' + one + '"'; })
                             .join(', ') +
                      (unknown.length > 1 ? ' are not protocol families' : ' ' +
                          'is not a protocol family') +
                      ' this registry knows. The ' + PROTOCOL_IDS.length + ' ' +
                          'are: ' +
                      PROTOCOL_IDS.join(', ') + '.'] }, 'STS-REG-0005');
  }
  // Back into TABLE ORDER rather than the order they were ticked in. The table
  // is ordered by how a reader thinks about the families, and an entry whose
  // attribute order depends on which box somebody clicked first would make two
  // identical declarations look different in an ldapsearch.
  const ordered = PROTOCOL_IDS.filter(function (id) {
    return chosen.indexOf(id) >= 0;
  });
  log.debug("Leaving normaliseProtocols(). " + ordered.length + " " +
      "family/families.");
  return { ok: true, protocols: ordered, errors: [] };
}

// ---------------------------------------------------------------------------
// THE SCHEMA.
//
// One row per attribute, and the row is the whole definition: `GET
// /admin/ldap/applications` publishes this table, `ldap_server.js` builds the
// entry from it, and there is no second list anywhere to update. An attribute
// that is not here is not written, which is what makes the published schema
// worth reading — the lesson `vc_claims.js` learned about an issuer advertising
// five claims and minting fourteen.
//
// `single` vs `multi` is load-bearing rather than descriptive, because it says
// how a repeat is treated. A multi-valued attribute ACCUMULATES — a second
// redirect URI joins the first — and a single-valued one is ASSIGNED. Getting
// that backwards on a counter is the trap `applyVcAttributes()` writes its
// second rule about: an entry that accumulated one `appAuthentications` per
// sign-in would be the visible symptom of a bug nobody could locate.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'top', where: 'RFC 4512', standard: true,
      what: 'The abstract class every entry carries.' },
    { name: 'applicationProcess', where: 'RFC 4519 section 3.3', standard: true,
      what: 'The one REGISTERED object class that fits an application. It ' +
            'brings cn, description, seeAlso, ou and l — so the NAME of an ' +
            'application here is a standard attribute even though nothing ' +
            'else about it can be.' },
    { name: 'stsApplication', where: 'this service', standard: false,
      what: 'INVENTED, because no registered LDAP schema has a client_id, a ' +
            'set of redirect URIs, an entityID or a service principal name. ' +
            'Every product that stores OAuth clients keeps them in its own ' +
            'database rather than in a directory, so there was nothing to ' +
            'borrow. These are this service\'s own names in the way ' +
            'x509subject and didSubject already are.' }
  ],
  attributes: [
    // --- identity ---------------------------------------------------------
    { name: 'appIdentifier', kind: 'single', from: 'every protocol',
      what: 'THE KEY: the identifier exactly as the protocol presented it. ' +
            'The entry\'s own cn may be a digest of it where it is too long ' +
            'to be a readable RDN, so this is the attribute to search on — ' +
            'the same arrangement didSubject has on a DID-named person.' },
    { name: 'cn', kind: 'single', from: 'this registry', standard: true,
      what: 'The RDN value: the identifier itself, or app-<12 hex> where ' +
            'that would be longer than 64 characters.' },
    { name: 'appName', kind: 'single', from: 'RFC 7591 client_name, or the ' +
                                             'identifier',
      what: 'What to call it on a page. A registration supplies one; ' +
            'otherwise the identifier is the name, because inventing a ' +
            'friendly name for an opaque id would be inventing a fact.' },
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
    // answers. It is `set` rather than `multi` for `appAuthnMechanism`'s reason
    // — an application has ONE home page, and a list would be a question no
    // page here has anywhere to ask.
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
    { name: 'appHomePageUrl', kind: 'single',
      from: 'RFC 7591 client_uri, the console, the management API, or by hand',
      what: 'THE APPLICATION\'S OWN HOME PAGE: where a person goes to reach ' +
            'it, and therefore where a sign-in to it starts. It is what ' +
            '/portal/applications links each row to, and an entry without ' +
            'one is drawn there with no link rather than with a guessed ' +
            'address. DECLARED and never derived — the redirect URIs beside ' +
            'it are callbacks and not front doors, so nothing computes this ' +
            'from them. http or https only, because it becomes an href.' },
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
    { name: 'appCorsOrigin', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'THE ORIGINS A BROWSER PAGE MAY CALL THIS SERVICE FROM FOR THIS ' +
            'APPLICATION — `https://app.example.com`, one exact origin per ' +
            'value, with no path and no wildcard. A request that names this ' +
            'application as its client (a client_id, a Basic credential, a ' +
            'client assertion, or an access token issued to it) is answered ' +
            'with Access-Control-Allow-Origin only when its Origin is listed ' +
            'here; a request that names no client at all — discovery, a ' +
            'JWKS, a DID document, a CORS preflight — is answered for an ' +
            'origin listed on ANY application in the realm. EMPTY ALLOWS NO ' +
            'THIRD-PARTY ORIGIN, in both modes. This service\'s own origins ' +
            '(its listeners, global.publicBaseUrl, the embedded debugger, ' +
            'and global.corsOrigins) never need listing. Normalised when ' +
            'written: scheme and host lower-cased, a default port dropped.' },
    { name: 'appKind', kind: 'multi', from: 'every protocol',
      what: 'What this application IS, one value per role it has been seen ' +
            'in. Several is the ordinary case and is the point: an OAuth ' +
            'client that asks for the openid scope is also a relying party.' },
    { name: 'appProtocol', kind: 'multi', from: 'every protocol',
      what: 'The protocol families it has appeared in, accumulated.' },
    { name: 'appAllowedProtocol', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'THE PROTOCOL FAMILIES THIS APPLICATION IS DECLARED FOR, one ' +
            'value per family, from the closed table PROTOCOLS publishes. It ' +
            'is the DECLARED twin of appProtocol above and the two must not ' +
            'be read as one thing: that attribute is what has happened and ' +
            'cannot be edited, this one is what somebody said the ' +
            'application is for and is ticked on /admin/applications/new ' +
            'before it has ever connected. NOTHING IN THIS SERVICE READS IT ' +
            '— an application declared for SAML 2.0 alone is still issued an ' +
            'access token, because a mock that refused would remove a test ' +
            'case rather than add one — so it grants nothing and refuses ' +
            'nothing, exactly as being in this registry at all does.' },
    { name: 'appAuthorizationServer', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'WHICH AUTHORIZATION SERVERS this client has used, by the name ' +
            'in their paths — one value per server it has been seen at. This ' +
            'process publishes several, each with its own capabilities and ' +
            'its own endpoints under /{id}/oauth2/…, and EVERY CLIENT MAY ' +
            'USE EVERY ONE of them: nothing here restricts a client to a ' +
            'server, so this records where it HAS been rather than where it ' +
            'may go. Accumulated, because a client that talks to two of them ' +
            'is one client with two values and not two clients.' },
    { name: 'description', kind: 'multi', from: 'this registry', standard: true,
      what: 'One line per protocol that first brought this application here.' },

    // --- what has happened ------------------------------------------------
    { name: 'appFirstSeen', kind: 'single', from: 'this registry',
      what: 'GeneralizedTime, when this identifier was first presented.' },
    { name: 'appLastSeen', kind: 'single', from: 'this registry',
      what: 'GeneralizedTime, the most recent time.' },
    { name: 'appAuthentications', kind: 'single', from: 'this registry',
      what: 'How many credentials this service has accepted FOR this ' +
            'application. ASSIGNED on every change — a counter that ' +
            'accumulated values would be nonsense — and it is a live number ' +
            'in a directory entry, which is unusual enough to say out loud: ' +
            'a real directory would not hold one.' },
    { name: 'appSessions', kind: 'single', from: 'this registry',
      what: 'How many DISTINCT browser sign-on sessions have involved it. ' +
            'Counted from the session id that rides on the authentication ' +
            'funnel, so a direct grant with no browser session behind it ' +
            'adds nothing.' },
    { name: 'appUsers', kind: 'single', from: 'this registry',
      what: 'How many distinct identities have authenticated for it. The ' +
            'identities themselves are NOT listed here: an application used ' +
            'by two thousand people would otherwise put two thousand values ' +
            'on one entry.' },
    { name: 'appLastSession', kind: 'single', from: 'this registry',
      what: 'The most recent sign-on session id. It is what appSessions is ' +
            'counted against — a different one increments the count — and it ' +
            'is on the entry rather than in memory because the entry is the ' +
            'store: without it a restart of nothing at all would recount the ' +
            'session already counted.' },
    { name: 'appLastUser', kind: 'single', from: 'this registry',
      what: 'The most recent identity, for the same reason and with the same ' +
            'limitation: it counts a CHANGE of user rather than a distinct ' +
            'set, which is right for the ordinary case and undercounts ' +
            'somebody alternating between two applications. Stated in seen() ' +
            'where the trade is made.' },

    // --- OAuth 2.0 / OpenID Connect ---------------------------------------
    { name: 'appRegistered', kind: 'single', from: 'POST /oauth2/register',
      what: 'TRUE when this application went through dynamic client ' +
            'registration here, FALSE when it is simply a client_id that ' +
            'turned up. It records HOW the application got here and not ' +
            'what counts: RFC 9700 mode judges a client against its own ' +
            'oauthRedirectUri whenever the entry holds one, however it got ' +
            'there, and against the oauth2.redirectUris setting only when ' +
            'it holds none — which OAuth 2.1 mode refuses instead. An ' +
            'omitted token_endpoint_auth_method means client_secret_basic ' +
            'for a registered client and nothing for one made by hand.' },
    // WHO PUT THIS APPLICATION HERE ON PURPOSE (2026-09-18). appRegistered
    // above cannot answer it: it means RFC 7591 and is what RFC 9700 mode's
    // rules and RFC 7592's endpoints turn on, so an application an operator
    // created on /admin/applications/new stays FALSE there — and the list
    // page, reading only that flag, said "Registered: no" about an entry
    // somebody had just finished registering. This is the answer the page
    // wanted, kept apart so that giving it changes no protocol's behaviour.
    { name: 'appRegisteredBy', kind: 'single', from: 'this registry',
      what: 'How this application was registered, when it was: ' +
            '"administrator" (created on /admin/applications/new or through ' +
            'the management API), "rfc7591" (POST /oauth2/register) or ' +
            '"startup" (one of this service\'s own seeded clients). Absent ' +
            'on an application that simply turned up. Written by this ' +
            'registry and not editable; it grants and refuses nothing.' },
    { name: 'oauthClientId', kind: 'multi', from: 'OAuth 2.0 / OIDC / ' +
                                                  'OpenID4VCI',
      identifier: true,
      identifierName: 'client_id',
      what: 'THE CLIENT_ID, and the identifier attribute of three families: ' +
            'an OpenID Connect relying party IS an OAuth client, and a ' +
            'wallet collecting a credential at the OpenID4VCI issuer ' +
            'authenticates as one, so all three declare their name here ' +
            'rather than in three attributes that would be three spellings ' +
            'of one fact. Usually equal to appIdentifier, which is what a ' +
            'protocol sighting writes; a SECOND value is a client_id this ' +
            'application also answers to — a per-environment id — and is why ' +
            'this accumulates rather than being assigned. Absent on an entry ' +
            'no OAuth family has been declared for.' },
    { name: 'oauthAudience', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'THE AUDIENCE THIS APPLICATION ANSWERS TO — the `aud` an access ' +
            'token addressed to it carries, and what a client puts in RFC ' +
            '8693 section 2.1\'s `audience` (or `resource`) when it ' +
            'exchanges a token to reach this application. It is the OAuth ' +
            'spelling of a fact three other families here already record ' +
            'under their own names: `wstrustAppliesTo` is the same thing in ' +
            'a RequestSecurityToken and `samlEntityId` is the same thing in ' +
            'an assertion\'s AudienceRestriction, and one attribute holding ' +
            'all three would be one string that has to mean whichever ' +
            'protocol asked last.\n\nIt is DECLARED — nobody presents an ' +
            'audience as their own name, so nothing here writes it and it ' +
            'cannot be derived — and it is a URI rather than a client_id ' +
            'because that is what an audience is: the resource, not the ' +
            'client that calls it. Several values is the ordinary case (a ' +
            'per-environment hostname), which is why it accumulates.\n\n**IT ' +
            'IS READ, WHICH MAKES IT THE EXCEPTION** among the declaration ' +
            'attributes beside it. The token exchange looks an `audience` UP ' +
            'here — forAudience() — so that a delegation recorded for ' +
            '`https://esb1.example.com` names the application `esb1` on ' +
            '/admin/delegation and in its picture, instead of drawing a box ' +
            'for a URL that nothing else in the register mentions. It is a ' +
            'LOOKUP and not a permission: an audience nobody registered is ' +
            'exchanged for exactly as before and recorded verbatim, because ' +
            'a mock that refused would remove a test case rather than add ' +
            'one.' },
    { name: 'oauthClientSecret', kind: 'single', from: 'POST /oauth2/register',
      sensitive: true,
      what: 'THE SECRET THIS SERVICE MINTED, in the clear, in a directory ' +
            'where every bind succeeds. Deliberate, and it is the same ' +
            'decision GET /krb5/principals makes about the Kerberos ' +
            'passwords: a debugger whose accounts are unusable without ' +
            'reading the source is worse than one that says what they are. ' +
            'In RFC 9700 mode this secret is CHECKED, so anyone who can read ' +
            'this directory can authenticate as this client — which is the ' +
            'honest state of a service that authenticates nobody. It is ' +
            'never written to the audit log.' },
    // CLIENT-SECRET ROTATION AND EXPIRY (2026-09-22, #49 P5, rcbj's answer).
    { name: 'oauthClientSecretPrevious', kind: 'single',
      from: 'a rotation on /admin/applications or /admin-api',
      sensitive: true,
      what: 'The secret a ROTATION replaced, still accepted at the token ' +
            'endpoint until oauthClientSecretPreviousUntil, so a client ' +
            'can move to the new one without a moment when neither works. ' +
            'In the clear for oauthClientSecret\'s reason, and cleared by ' +
            'the scheduler job oauth2.client-secret-expiry once the overlap ' +
            'has passed.' },
    { name: 'oauthClientSecretPreviousUntil', kind: 'single',
      from: 'a rotation on /admin/applications or /admin-api',
      what: 'When the previous secret stops being accepted, in ' +
            'milliseconds since the epoch: the rotation\'s instant plus ' +
            'oauth2.clientSecretOverlapS.' },
    { name: 'oauthClientSecretExpiresAt', kind: 'single',
      from: 'POST /oauth2/register, or a rotation',
      what: 'When the current secret expires, in SECONDS since the epoch — ' +
            'RFC 7591 section 3.2.1\'s client_secret_expires_at — or 0 for ' +
            'never. Refused after it in product mode ' +
            '(mode.refusesExpiredClientSecrets()); administrators are warned ' +
            'oauth2.clientSecretExpiryWarningDays ahead.' },
    { name: 'oauthRedirectUri', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'Registered redirect URIs from a registration, and any ' +
            'redirect_uri this service has ACCEPTED for the application ' +
            'beside them. The two are not the same claim and the registry ' +
            'does not merge them silently — see appRedirectUriObserved.' },
    { name: 'appRedirectUriObserved', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'A redirect_uri seen on an authorization request that this ' +
            'service answered. Kept apart from oauthRedirectUri because ' +
            '"registered" and "used" are different facts, and RFC 9700 ' +
            'section 2.1 is entirely about not confusing them: an ' +
            'exact-match check reads the registered list, and this one is ' +
            'evidence of what a client actually does.' },
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
    { name: 'appReturnAddressObserved', kind: 'multi',
      from: 'a development-mode sighting',
      what: 'WHICH RETURN ADDRESSES ON THIS ENTRY WERE NEVER REGISTERED BY ' +
            'ANYBODY. Each value is `<attribute> <address>` — for example ' +
            '`samlAssertionConsumerService https://sp.example.com/acs` — and ' +
            'marks an address a DEVELOPMENT-mode request named, which ' +
            'development writes onto the entry because it believes every ' +
            'address. PRODUCT mode treats a marked address as NOT registered ' +
            'and refuses it exactly as it refuses one that is not on the ' +
            'entry at all, so a realm switched from development to product ' +
            'does not quietly trust what development learnt. An operator ' +
            'CONFIRMS one (the mark goes, the address stays), DISCARDS one ' +
            '(both go), or writes the address explicitly, which confirms it. ' +
            'Addresses recorded BEFORE this attribute existed carry no mark ' +
            'and cannot be told apart from registered ones — review those by ' +
            'hand.' },
    { name: 'oauthPostLogoutRedirectUri', kind: 'multi', from: 'POST ' +
        '/oauth2/register',
      what: 'Registered post_logout_redirect_uris, which RP-Initiated Logout ' +
            'matches against in RFC 9700 mode.' },
    { name: 'oauthFrontchannelLogoutUri', kind: 'single',
      from: 'POST /oauth2/register, the console, or by hand',
      what: 'WHERE THIS CLIENT IS TOLD THAT THE USER SIGNED OUT — OpenID ' +
            'Connect Front-Channel Logout 1.0 section 2\'s ' +
            'frontchannel_logout_uri. The sign-out page loads it in a hidden ' +
            'iframe, with iss and sid on the query string when the client ' +
            'asked for them. It is SINGLE-valued because the specification ' +
            'defines one URI per client, unlike the redirect URIs beside it; ' +
            'a client with none registered is not notified at all and is ' +
            'listed on /logout as such rather than silently skipped.' },
    { name: 'oauthFrontchannelLogoutSessionRequired', kind: 'single',
      from: 'POST /oauth2/register, the console, or by hand',
      what: 'TRUE if this client requires `iss` and `sid` on the ' +
            'notification above — Front-Channel Logout 1.0 section 2\'s ' +
            'frontchannel_logout_session_required. It matters because an RP ' +
            'with several sessions in one browser cannot tell which one ' +
            'ended without the sid, and RFC 7591 section 2 makes an omitted ' +
            'boolean FALSE rather than unknown — so an absent value here ' +
            'means the client did not ask, which is a different fact from ' +
            'the client not having registered.' },
    { name: 'oauthBackchannelLogoutUri', kind: 'single',
      from: 'POST /oauth2/register, the console, or by hand',
      what: 'WHERE THIS SERVICE POSTS A LOGOUT TOKEN WHEN THE USER SIGNS OUT ' +
            '— OpenID Connect Back-Channel Logout 1.0 section 2.2\'s ' +
            'backchannel_logout_uri. Every sign-out of a session this client ' +
            'was issued an authorization response on sends one, ' +
            'server-to-server, after the sign-out has answered, through the ' +
            'outbound policy (https unless ' +
            'federation.outboundAllowInsecure; no internal address in ' +
            'product mode). SINGLE-valued, like the front-channel URI: the ' +
            'specification defines one per client. http or https with no ' +
            'fragment.' },
    { name: 'oauthBackchannelLogoutSessionRequired', kind: 'single',
      from: 'POST /oauth2/register, the console, or by hand',
      what: 'TRUE if this client requires `sid` in the Logout Token — ' +
            'Back-Channel Logout 1.0 section 2.2\'s ' +
            'backchannel_logout_session_required. This service puts `sid` ' +
            'AND `sub` in every Logout Token it sends, so the flag is always ' +
            'honoured; it is recorded because "false" and "not stated" are ' +
            'different facts about a client, as for the front-channel flag.' },
    { name: 'oauthGrantType', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'Grant types registered or observed at the token endpoint.' },
    { name: 'oauthResponseType', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'response_type values seen at the authorization endpoint.' },
    { name: 'oauthScope', kind: 'multi', from: 'OAuth 2.0 / OIDC',
      what: 'Scopes this application has ASKED FOR, accumulated as it asks. ' +
            'SIGHTED, never declared: nothing is allowed or refused by it. ' +
            'What the application may be issued is oauthAllowedScope.' },
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
    { name: 'oauthAllowedScope', kind: 'multi',
      from: 'POST /oauth2/register (its `scope`), the console, the ' +
            'management API, or by hand',
      what: 'THE SCOPES THIS CLIENT MAY BE ISSUED — RFC 7591 section 2\'s ' +
            '`scope`, "the list that the client can use when requesting ' +
            'access tokens". One scope token per value. Three kinds of scope ' +
            'read it differently.\n\n**This service\'s own protected ' +
            'scopes** — admin:read and admin:write (/admin-api), the SCIM ' +
            'scopes (scim.scopeRead, scim.scopeWrite), the Shared Signals ' +
            'scopes (ssf.authScopeRead, ssf.authScopeWrite) and the debugger ' +
            'permission — are issued ONLY to a client that lists them, IN ' +
            'BOTH MODES, and the resource server behind each asks again on ' +
            'every call, so removing a value here cuts off tokens already ' +
            'issued. An RFC 7591 registration may not declare them; an ' +
            'administrator does, here.\n\n**Every other scope**, in ' +
            'product mode, is issued only when listed here — or, when ' +
            'nothing is listed, when it is in the default set: openid, ' +
            'profile, email, address, phone, offline_access and this ' +
            'realm\'s OpenID4VCI credential scopes. In development any ' +
            'scope is issued.\n\n**A scope naming an application or a ' +
            'delegated permission** keeps its own rules (the audience, and ' +
            'oauthDelegatedPermission) and need not be listed.\n\nA scope ' +
            'outside the list is refused invalid_scope at the authorization ' +
            'and token endpoints (RFC 6749 section 3.3), and taken off a ' +
            'refresh or a token exchange. Distinct from oauthScope, which is ' +
            'only what the client has asked for.' },

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
    { name: 'oauthPermissionBaseUri', kind: 'single',
      from: 'the console, the management API, or by hand',
      what: 'THE BASE URI EVERY PERMISSION THIS APPLICATION DEFINES HANGS ' +
            'OFF, and the thing that makes a permission name globally unique ' +
            'here. A permission is identified by this value followed by its ' +
            'name — base `https://example.com/` and name `write` are the ' +
            'permission `https://example.com/write` — which is what a client ' +
            'puts in a `scope` and what the access token is then AUDIENCED ' +
            'to. Entra ID calls it the Application ID URI and spells it ' +
            '`api://<guid>`; the shape is the same and nothing here requires ' +
            'that scheme.\n\nIT IS NORMALISED TO END IN A SEPARATOR when it ' +
            'is written through this module — a trailing `/` is added where ' +
            'there is no `/`, `#` or `:` at the end — because base + name is ' +
            'a plain concatenation and `https://example.com` + `write` would ' +
            'otherwise produce `https://example.comwrite`. An `ldapmodify` ' +
            'reaches this attribute like every other and is not normalised, ' +
            'so a base written by hand means exactly what it ' +
            'says.\n\nSINGLE-VALUED, and it is the one attribute in this ' +
            'group that could not be widened without deciding something: two ' +
            'bases would mean every permission on the entry had two ' +
            'identifiers, and the lookup that turns a scope into an audience ' +
            'would have to pick one to put in `aud`.' },
    { name: 'oauthPermission', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'ONE PERMISSION THIS APPLICATION EXPOSES, one value each. The ' +
            'value is the permission\'s NAME — `read`, `write`, ' +
            '`Widgets.ReadWrite.All` — optionally followed by `|` and a ' +
            'description: `write|Change widgets on somebody\'s behalf`. The ' +
            'FIRST `|` is the delimiter and every later one belongs to the ' +
            'description, so a description may contain the character and a ' +
            'name may not.\n\nThe name must be a legal OAuth scope token ' +
            '(RFC 6749 section 3.3 — no space, no double quote, no ' +
            'backslash), because that is what a client will put in a `scope` ' +
            'parameter and what comes back on the token\'s `scope` claim. ' +
            'Nothing enforces that when an `ldapmodify` writes it; this ' +
            'module and both consoles do.\n\nA PERMISSION MUST EXIST BEFORE ' +
            'ANYTHING CAN BE GRANTED IT, which is the one ordering rule this ' +
            'feature has and is checked in updateApplication() so that the ' +
            'console form and the management API cannot disagree about it. ' +
            'It is checked on the GRANT and not here: this attribute is the ' +
            'definition, and a definition nobody has used yet is the ' +
            'ordinary first step rather than a mistake.' },
    // THE RFC 9728 DOCUMENT THIS APPLICATION WAS CREATED FROM (2026-09-13).
    // /admin/applications/new can be handed a protected resource's metadata
    // document and turn it into an entry; the members with an attribute of
    // their own are written to those attributes, and this keeps the whole
    // document beside them — `samlSpMetadata`'s arrangement, for its reason: a
    // setting with the document it came from missing is a value nobody can
    // check. DECLARATION ONLY: nothing in this service reads it back.
    { name: 'oauthResourceMetadata', kind: 'single',
      from: 'an RFC 9728 import, the console, the management API, or by hand',
      what: 'THE PROTECTED RESOURCE METADATA DOCUMENT (RFC 9728) THIS ' +
            'APPLICATION WAS CONFIGURED FROM, as compact JSON. Its ' +
            '`resource` is the default name, `oauthPermissionBaseUri` and ' +
            '`oauthAudience` of an entry created from it, and its ' +
            '`scopes_supported` the permissions; every other member — ' +
            '`authorization_servers`, `jwks_uri`, `bearer_methods_supported`, ' +
            'the DPoP members — is recorded here and nowhere else.\n\nIt is ' +
            'DECLARATION ONLY: nothing reads it back, nothing re-fetches it, ' +
            'and changing it changes none of the attributes it filled in. A ' +
            'value written through this module must be a JSON object with a ' +
            '`resource`; an `ldapmodify` is not checked.' },
    { name: 'oauthResourceMetadataUrl', kind: 'single',
      from: 'an RFC 9728 import, the console, the management API, or by hand',
      what: 'WHERE THE PROTECTED RESOURCE METADATA DOCUMENT WAS FETCHED FROM, ' +
            'when it was fetched rather than pasted or uploaded. Recorded and ' +
            'never dialled again: the fetch is an administrator\'s act on ' +
            '/admin/applications/new or POST ' +
            '/admin-api/applications/load-resource-metadata, and nothing ' +
            'refreshes it.' },
    { name: 'oauthDelegatedPermission', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'A PERMISSION THIS APPLICATION HAS BEEN GRANTED ON ANOTHER ONE — ' +
            'the whole permission identifier, base URI and name together: ' +
            '`https://example.com/write`. It is the DELEGATION RELATIONSHIP, ' +
            'and it is held on the CLIENT rather than on the resource for ' +
            'Entra\'s reason and one more: the client is the party that will ' +
            'name it in a `scope`, so the entry that answers "may this ' +
            'request be honoured" is the entry the request ' +
            'identifies.\n\n**IT IS READ, and it is read in the one place ' +
            'that decides what a token says.** A `scope` value matching a ' +
            'defined permission becomes the access token\'s `aud` (the base ' +
            'URI) and its `scope` (the name) — see oauth2.js\'s ' +
            'audienceScopes(). In PRODUCT MODE an ungranted permission is ' +
            'refused `invalid_scope` at the authorization and token ' +
            'endpoints, always. In development it is reported and REFUSES ' +
            'nothing unless `oauth2.delegatedPermissionsEnforced` is on, ' +
            'which is off by default: a client under test is exercised by ' +
            'both answers.\n\nA VALUE THAT RESOLVES TO NO DEFINED ' +
            'PERMISSION IS NOT AN ERROR AND IS NOT HIDDEN. The resource\'s ' +
            'entry may have been deleted, or the permission removed from ' +
            'under it; `/admin/delegation` shows such a grant as DANGLING, ' +
            'which is the same three-state honesty the rest of this console ' +
            'applies to a name it cannot resolve.' },

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
    { name: 'oauthGlobalConsent', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'A SCOPE NOBODY IS ASKED ABOUT WHEN THEY SIGN IN TO THIS ' +
            'APPLICATION. One value per scope, written exactly as a client ' +
            'puts it in a `scope` parameter — `openid`, `profile`, or a ' +
            'whole delegated permission identifier such as ' +
            '`https://example.com/write`.\n\n**It is an OVERRIDE and not a ' +
            'record.** With `oauth2.consentRequired` on (which is the ' +
            'default), the authorization endpoint draws /oauth2/consent for ' +
            'any scope this person has not agreed to for this application; a ' +
            'scope named here is skipped for EVERYBODY, and nothing is ' +
            'written to anybody\'s entry. So removing a value asks everybody ' +
            'again — including the people who would have said yes — where ' +
            'removing a person\'s own `oauthConsent` asks only them.\n\n**It ' +
            'is keyed on the pair and not on the scope alone.** Consenting ' +
            '`read` here consents it for THIS application; an application ' +
            'registered five minutes later that spells the same word is ' +
            'still asked.\n\nA value that names no permission any ' +
            'application defines is not an error and is not hidden — most ' +
            'scopes are not permissions. It must be a legal RFC 6749 section ' +
            '3.3 scope token, because a value with a space in it could never ' +
            'match one scope; an `ldapmodify` reaches this attribute like ' +
            'every other and is not checked, and /admin/consent shows what ' +
            'it put there.' },
    { name: 'oauthTokenEndpointAuthMethod', kind: 'single', from: 'POST ' +
        '/oauth2/register',
      what: 'How it authenticates. RFC 7591 section 2 makes ' +
            'client_secret_basic the default when a registration omits it, ' +
            'which is why an omission means CONFIDENTIAL rather than ' +
            'unknown.' },
    // OPENID CONNECT CORE SECTION 8 AND SECTION 9 (#118, 2026-09-22).
    { name: 'oauthSubjectType', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oidc'],
      familyWhy: 'It decides which `sub` an ID Token and a UserInfo response ' +
        'name this person by, which only an OpenID Connect client is given.',
      what: 'OIDC Core section 8 `subject_type`: `public` (the default, and ' +
            'what an empty value means) gives every client the same `sub`; ' +
            '`pairwise` gives this client one of its own, derived from the ' +
            'person, the sector and a secret every node shares, so two ' +
            'clients of different sectors cannot correlate one person.' },
    { name: 'oauthSectorIdentifierUri', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oidc'],
      familyWhy: 'It is the sector a pairwise `sub` is computed for.',
      what: 'OIDC Core section 8.1 `sector_identifier_uri`: an https URL ' +
            'whose HOST is the sector a pairwise `sub` is derived for, so ' +
            'several redirect hosts of one organisation see one subject. A ' +
            'REGISTRATION that names one has it FETCHED and must be listed ' +
            'in the JSON array it serves, every redirect URI of it; one ' +
            'written here by an administrator is the administrator\'s ' +
            'statement and is not fetched. Empty: the sector is the host of ' +
            'the redirect URIs, which must then all share one.' },
    { name: 'oauthTokenEndpointAuthSigningAlg', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides which signature a private_key_jwt or ' +
        'client_secret_jwt assertion at the token endpoint must carry.',
      what: 'OIDC Core section 9 / RFC 7591 ' +
            '`token_endpoint_auth_signing_alg`: the ONE JWS algorithm this ' +
            'client\'s authentication assertion must be signed with. An ' +
            'assertion signed with any other is refused, in every mode. ' +
            'Empty: any algorithm the method allows.' },
    { name: 'oauthJwks', kind: 'single', from: 'POST /oauth2/register, or by ' +
                                               'hand',
      what: 'THE CLIENT\'S PUBLIC KEYS, as a JWKS document — what ' +
            'private_key_jwt is verified against (RFC 7591 `jwks`). This is ' +
            'the asymmetric credential RFC 9700 section 2.5 RECOMMENDS, and ' +
            'it is the one credential attribute here that is NOT a secret: ' +
            'it is public key material, worth nothing to anybody who reads ' +
            'it, which is the whole point of preferring it to a shared ' +
            'secret.' },
    { name: 'oauthJwksUri', kind: 'single', from: 'POST /oauth2/register',
      what: 'RFC 7591 `jwks_uri`. RECORDED AND NEVER FETCHED: following it ' +
            'would mean this service making an outbound request to a URL ' +
            'somebody registered in order to verify a credential, which is a ' +
            'server-side request forgery with a specification citation ' +
            'attached — the same refusal WS-Federation\'s wreqptr gets. A ' +
            'client that registers only this is told to register `jwks` ' +
            'instead, by name, when it tries to authenticate.' },
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
    { name: 'oauthIntrospectionSignedResponseAlg', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides how /oauth2/introspect signs the JWT response ' +
        'it gives this client, so on an entry declared for neither OAuth ' +
        'family it would sit there reading like a registration in force.',
      what: 'RFC 9701 section 6 `introspection_signed_response_alg`: the JWS ' +
            'algorithm of the JWT introspection response this application ' +
            'receives when it asks /oauth2/introspect with `Accept: ' +
            'application/token-introspection+jwt`. EMPTY MEANS RS256, the ' +
            'section\'s default. Any algorithm in ' +
            '`introspection_signing_alg_values_supported` — every asymmetric ' +
            'one this service holds a key for, and HS256/384/512 keyed with ' +
            'this application\'s own client_secret. `none` is refused: ' +
            'section 5 says the response MUST be cryptographically secured.' },
    { name: 'oauthIntrospectionEncryptedResponseAlg', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides whether /oauth2/introspect encrypts the JWT ' +
        'response it gives this client, so on an entry declared for neither ' +
        'OAuth family it would sit there reading like a registration in ' +
        'force.',
      what: 'RFC 9701 section 6 `introspection_encrypted_response_alg`: the ' +
            'JWE key management algorithm the signed introspection response ' +
            'is ENCRYPTED to this application with, making it a Nested JWT. ' +
            'EMPTY MEANS NOT ENCRYPTED. One of the asymmetric algorithms ' +
            '(RSA-OAEP, RSA-OAEP-256, ECDH-ES and its key-wrap variants), ' +
            'and ' +
            'the key is taken from this entry\'s `oauthJwks` — a `jwks_uri` ' +
            'is never fetched. The symmetric families are refused: they are ' +
            'for a document encrypted TO this service.' },
    { name: 'oauthIntrospectionEncryptedResponseEnc', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides how /oauth2/introspect encrypts the JWT ' +
        'response it gives this client, so on an entry declared for neither ' +
        'OAuth family it would sit there reading like a registration in ' +
        'force.',
      what: 'RFC 9701 section 6 `introspection_encrypted_response_enc`: the ' +
            'JWE content encryption algorithm. EMPTY MEANS A128CBC-HS256 ' +
            'once ' +
            '`oauthIntrospectionEncryptedResponseAlg` is set. It MUST NOT be ' +
            'set without that attribute, and a write that tries is refused; ' +
            'an entry left holding one alone (by `ldapmodify`, or by ' +
            'clearing ' +
            'the algorithm) makes the JWT introspection response fail with ' +
            'the reason rather than go out unencrypted.' },
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
    { name: 'oauthRequestUri', kind: 'multi',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It is the list of request_uri values /oauth2/authorize ' +
        'will fetch for this client, so on an entry declared for neither ' +
        'OAuth family it would sit there reading like a permission to dial ' +
        'those URLs.',
      what: 'OpenID Connect Registration `request_uris`: the request_uri ' +
            'values (RFC 9101 section 5.2) this client may send, one per ' +
            'line. THE AUTHORIZATION ENDPOINT FETCHES A request_uri ONLY ' +
            'WHEN IT IS ONE OF THESE, compared exactly once any #fragment is ' +
            'removed — a request_uri nobody registered is refused ' +
            'invalid_request_uri and never dialled, which is what keeps the ' +
            'fetch from being a server-side request forgery. https, or http ' +
            'in development mode only.' },
    { name: 'oauthRequestObjectSigningAlg', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides which request objects /oauth2/authorize accepts ' +
        'from this client, so on an entry declared for neither OAuth family ' +
        'it would read like a restriction in force.',
      what: 'OpenID Connect Registration `request_object_signing_alg`: the ' +
            'ONLY JWS algorithm a request object from this client is ' +
            'accepted in. EMPTY MEANS ANY algorithm in ' +
            'request_object_signing_alg_values_supported. `none` may be ' +
            'registered only where an unsigned request object is accepted at ' +
            'all — development mode, with no signed one required.' },
    { name: 'oauthRequestObjectEncryptionAlg', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides which request objects /oauth2/authorize accepts ' +
        'from this client, so on an entry declared for neither OAuth family ' +
        'it would read like a restriction in force.',
      what: 'OpenID Connect Registration `request_object_encryption_alg`: ' +
            'when set, a request object from this client MUST be encrypted ' +
            '(RFC 9101 section 6.1) with this JWE key management algorithm — ' +
            'to this realm\'s request object key published in /oauth2/jwks ' +
            '(use: enc) for RSA-OAEP and ECDH-ES, or to this client\'s own ' +
            'client_secret for the symmetric families. EMPTY MEANS ' +
            'encryption is optional.' },
    { name: 'oauthRequestObjectEncryptionEnc', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides which request objects /oauth2/authorize accepts ' +
        'from this client, so on an entry declared for neither OAuth family ' +
        'it would read like a restriction in force.',
      what: 'OpenID Connect Registration `request_object_encryption_enc`: ' +
            'the JWE content encryption a request object from this client ' +
            'must use. EMPTY MEANS A128CBC-HS256 once ' +
            '`oauthRequestObjectEncryptionAlg` is set; it may not be set ' +
            'without that attribute.' },
    { name: 'oauthRequireSignedRequestObject', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides whether /oauth2/authorize refuses a plain ' +
        'request from this client, so on an entry declared for neither OAuth ' +
        'family it would read like a requirement in force.',
      what: 'RFC 9101 section 10.5 `require_signed_request_object`, for ' +
            'this client alone: TRUE refuses an authorization request from ' +
            'it that carries no `request` or `request_uri`, and a request ' +
            'object signed with `none`, with invalid_request. FALSE or ' +
            'empty defers to oauth2.requireSignedRequestObject.' },
    // RFC 9126 SECTION 6 (2026-09-13). ONE MEMBER a client registers about
    // HOW it sends an authorization request: pushed, or not at all. READ by
    // `oauth-oidc/oauth2.ts`'s `pushedRequestPolicyRefusal()`. Family-scoped for
    // the introspection attributes' reason.
    { name: 'oauthRequirePushedAuthorizationRequests', kind: 'single',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It decides whether /oauth2/authorize refuses a request ' +
        'from this client that was not pushed, so on an entry declared for ' +
        'neither OAuth family it would read like a requirement in force.',
      what: 'RFC 9126 section 6 `require_pushed_authorization_requests`, ' +
            'for this client alone: TRUE refuses an authorization request ' +
            'from it that does not carry a request_uri issued at ' +
            '/oauth2/par, with invalid_request. FALSE or empty defers to ' +
            'oauth2.requirePushedAuthorizationRequests.' },
    // -------------------------------------------------------------------
    // RFC 9396, RICH AUTHORIZATION REQUESTS (2026-09-13). TWO ATTRIBUTES, and
    // they sit on DIFFERENT KINDS OF ENTRY, which is the design rcbj chose:
    // a RESOURCE declares the authorization_details types it understands (a
    // type selects its resource server the way a delegated permission does),
    // and a CLIENT may register the types it will use (RFC 9396 section 10's
    // `authorization_details_types`). READ by
    // `oauth-oidc/authorization_details.ts`. Family-scoped for the
    // introspection attributes' reason.
    { name: 'oauthAuthorizationDetailsType', kind: 'multi',
      from: 'the console, the management API, the RFC 9728 import, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It is a type /oauth2/authorize and /oauth2/token accept ' +
        'and address tokens to this application for, so on an entry ' +
        'declared for neither OAuth family it would read like an API in ' +
        'service.',
      what: 'An RFC 9396 authorization_details TYPE this application, as a ' +
            'resource server, understands — one per value. A bare type ' +
            'name, or a JSON object {"type", "description", "locations", ' +
            '"schema"}: `locations` are the addresses a detail of this type ' +
            'may name (the permission base URI and oauthAudience always ' +
            'count), and `schema` is a JSON Schema every detail of this type ' +
            'must satisfy. A detail whose type no application declares is ' +
            'refused invalid_authorization_details, and a token carrying one ' +
            'is addressed to the application that declares it.' },
    { name: 'oauthAuthorizationDetailsTypes', kind: 'multi',
      from: 'POST /oauth2/register, the console, the management API, or by ' +
            'hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It narrows what /oauth2/authorize and /oauth2/token accept ' +
        'from this client, so on an entry declared for neither OAuth family ' +
        'it would read like a restriction in force.',
      what: 'RFC 9396 section 10 `authorization_details_types`: the ONLY ' +
            'authorization_details types this client may use, one per ' +
            'value. EMPTY MEANS any type this authorization server ' +
            'supports.' },
    // -------------------------------------------------------------------
    // RFC 9470, STEP-UP AUTHENTICATION (2026-09-13). TWO ATTRIBUTES ON A
    // RESOURCE: what it requires of the authentication behind an access token
    // addressed to it. RFC 9470 defines no registration or metadata member for
    // either — section 3 is a challenge a resource server sends — so they are
    // written by an operator, never by a registration. ENFORCED by the stand-in
    // resource `/oauth2/step-up/resource/{identifier}`, which answers for this
    // application; READ through `stepUpRequirementOf()` below, whose grammar is
    // `oauth-oidc/step_up.ts`'s header's. Family-scoped for the introspection
    // attributes' reason.
    { name: 'oauthStepUpAcrValues', kind: 'single',
      from: 'the console, the management API, or by hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It is a requirement on OAuth access tokens addressed to ' +
        'this application, so on an entry declared for neither OAuth family ' +
        'it would read like a requirement in force.',
      what: 'RFC 9470 section 3: the acr values this application, as a ' +
            'resource server, requires of the authentication behind an ' +
            'access token — space-separated, most preferred first. A token ' +
            'whose acr meets none is challenged 401 ' +
            'insufficient_user_authentication with these as acr_values. The ' +
            'levels 0 < 1 < mfa are ordered; hwk, phr and phrh are met by a ' +
            'password with a security key; any other value only by that ' +
            'exact acr. EMPTY requires nothing.' },
    { name: 'oauthStepUpMaxAge', kind: 'single',
      from: 'the console, the management API, or by hand',
      families: ['oauth2', 'oidc'],
      familyWhy: 'It is a requirement on OAuth access tokens addressed to ' +
        'this application, so on an entry declared for neither OAuth family ' +
        'it would read like a requirement in force.',
      what: 'RFC 9470 section 3\'s max_age: the oldest authentication, in ' +
            'whole seconds, this application accepts behind an access token. ' +
            'A token whose auth_time is older, or absent, is challenged 401 ' +
            'insufficient_user_authentication with max_age. 0 means an ' +
            'authentication this second. EMPTY requires nothing.' },
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
    { name: 'oauthAssertionIssuer', kind: 'multi', from: 'by hand',
      identifier: true,
      identifierName: 'assertion iss',
      what: 'THE `iss` VALUES THIS APPLICATION MAY PRESENT IN AN RFC 7523 ' +
            'SECTION 2.1 AUTHORIZATION GRANT, and it is one of the few ' +
            'DECLARED attributes here that is READ. A JWT bearer assertion ' +
            'IS the whole authorization — there is no browser, no password ' +
            'and no consent step in that grant — so accepting one from ' +
            'anybody would mean anybody who can reach this port getting an ' +
            'access token as anybody. This is therefore the second feature ' +
            'in this service with no permissive answer available, beside ' +
            'federation, and `oauth2.jwtBearerRequireRegisteredIssuer` is on ' +
            'by default.\n\nAn assertion a client issues ABOUT ITSELF names ' +
            'its own client_id as `iss` and needs no value here: that lookup ' +
            'already succeeds through oauthClientId, and asking an operator ' +
            'to write the client_id down twice would be a configuration step ' +
            'with no decision in it. It accumulates, because one application ' +
            'legitimately asserts under a per-environment issuer name.' },
    { name: 'oauthAssertionJwks', kind: 'single', from: '/admin/pki',
      what: 'THE PUBLIC KEYS THIS SERVICE ISSUED THIS APPLICATION, as a JWKS ' +
            'document, each key carrying `x5c` (its certificate chain) and ' +
            '`x5t#S256`. Written by the Issue control on /admin/pki and by ' +
            'POST /admin-api/pki/issue.\n\nIt is a SECOND attribute beside ' +
            '`oauthJwks` and never overwrites it. A client that registered ' +
            'its own keys and was later issued a pair by an operator has two ' +
            'ways to sign, both of which somebody deliberately arranged — ' +
            'and writing over the first would silently end it the moment ' +
            'somebody pressed a button about the second. Both are read, ' +
            'ORed, by client_auth.js and by assertion_grant.js. Public key ' +
            'material, so like oauthJwks it is worth nothing to whoever ' +
            'reads this directory.' },
    { name: 'oauthAssertionCertificate', kind: 'single', from: '/admin/pki',
      what: 'The leaf certificate, PEM, whose subject is this application ' +
            'and whose issuer is the realm\'s Issuing CA. The same bytes as ' +
            'the first `x5c` member above, in the form a person can paste ' +
            'into `openssl x509 -text`.' },
    { name: 'oauthAssertionCertificateChain', kind: 'single',
      from: '/admin/pki',
      what: 'The Issuing CA and the Intermediate CA, PEM, in that order — ' +
            'what a leaf travels with. The ROOT is deliberately not in it: a ' +
            'root is a trust anchor, and a relying party that accepted one ' +
            'because it arrived in the chain would be accepting a ' +
            'certificate that vouched for itself.' },
    { name: 'oauthAssertionPrivateKey', kind: 'single', from: '/admin/pki',
      sensitive: true,
      what: 'THE PRIVATE KEY, PEM. **SEALED AT REST WHEREVER THE ' +
            'KEY-ENCRYPTION KEY OUTLIVES THE PROCESS** — AES-256-GCM through ' +
            'common/keystore.js, the same mechanism and the same key that ' +
            'seal this service\'s own signing keys, common/pki.js\'s three ' +
            'CA key pairs and an authenticator\'s shared secret. So an ' +
            'ldapsearch on TCP 389 where every bind succeeds, an ldif file, ' +
            'a database row and a backup of either hold `$aesgcm$…` and not ' +
            'a usable key. The surfaces that come through this module — ' +
            '/admin/applications and GET /admin-api/applications, both ' +
            'behind a credential — are handed the PEM, because the seal ' +
            'protects the STORE rather than the console an operator collects ' +
            'an issued credential from; SEALED_FIELDS argues the split. In ' +
            'DEVELOPMENT mode it is written in the clear, which is the rule ' +
            'the authenticator secret beside it follows and for its reason: ' +
            'the key-encryption key there is ephemeral, so sealing an entry ' +
            'that survives a restart under a key that does not would make ' +
            'the private half permanent garbage while the certificate came ' +
            'back. It is never written to the audit log, and this service ' +
            'keeps NO SECOND COPY of it — common/pki.js hands it over once, ' +
            'at issuance, and forgets it.' },
    { name: 'oauthAssertionKid', kind: 'single', from: '/admin/pki',
      what: 'The `kid` of the issued key, derived from the key material as ' +
            'every kid in this service is (RFC 7638). An assertion naming it ' +
            'in its JWS header narrows the verification to that key; one ' +
            'naming nothing is tried against every key registered for this ' +
            'application, which is correct rather than lax.' },
    { name: 'oauthAssertionExpiresAt', kind: 'single', from: '/admin/pki',
      what: 'When the issued certificate expires, as a GeneralizedTime. It ' +
            'is a fact about the CERTIFICATE and not a policy: nothing here ' +
            'refuses an assertion because this date has passed — what ' +
            'refuses one is the certificate failing to build a path, which ' +
            'is checked where the chain is checked. Drawn on /admin/pki so ' +
            'that an operator can see what is about to stop working.' },
    { name: 'oauthAssertionKeySource', kind: 'single',
      from: '/admin/pki, or the application\'s own page',
      what: 'WHERE THE RFC 7523 KEY PAIR ABOVE CAME FROM, and therefore who ' +
            'holds its private half. `issued` — generated here and signed by ' +
            'this realm\'s Issuing CA, the private key on ' +
            '`oauthAssertionPrivateKey`. `uploaded-realm-ca` — a certificate ' +
            'this realm\'s own certificate authority issued, uploaded in ' +
            'place of a generated pair. `uploaded-external-ca` — a ' +
            'certificate from another authority, uploaded with its whole ' +
            'chain up to a self-signed root, every link verified. For both ' +
            'uploaded values the APPLICATION holds the private key and this ' +
            'service never has.\n\nA fact about what was done and not a ' +
            'policy: no verifier reads it, and an entry written before it ' +
            'existed carries none — the console reads a sealed private key ' +
            'as `issued` there, which is the only thing that could have put ' +
            'one on the entry.' },
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
    { name: 'oauthSamlAssertionIssuer', kind: 'multi', from: 'by hand',
      identifier: true,
      identifierName: 'SAML assertion Issuer',
      what: 'THE `<Issuer>` VALUES THIS APPLICATION MAY PRESENT IN AN RFC ' +
            '7522 SECTION 2.1 AUTHORIZATION GRANT. It is ' +
            '`oauthAssertionIssuer`\'s sibling for the SAML 2.0 profile and ' +
            'it is READ for the same reason: a bearer assertion IS the whole ' +
            'authorization — no browser, no password, no consent step — so ' +
            'accepting one from anybody would mean anybody who can reach ' +
            'this port getting an access token as anybody. ' +
            '`oauth2.saml2BearerRequireRegisteredIssuer` is on by ' +
            'default.\n\nIt is a SEPARATE attribute from the JWT one and not ' +
            'a shared list: a party trusted to assert in one format has not ' +
            'thereby been trusted to assert in the other, and an operator ' +
            'who declared an issuer for RFC 7523 must not silently have ' +
            'declared it for RFC 7522. Compared by Simple String Comparison ' +
            '(RFC 3986 section 6.2.1), which RFC 7522 section 3 item 1 asks ' +
            'for — no case folding and no trailing-slash tolerance. It ' +
            'accumulates, for the reason the JWT one does.' },
    { name: 'oauthSamlAssertionSigningCertificate', kind: 'single',
      from: 'by ' +
        'hand',
      what: 'THE CERTIFICATE THIS PARTY SIGNS ITS RFC 7522 ASSERTIONS WITH, ' +
            'PEM, registered by value. The analogue of `oauthJwks` for a ' +
            'profile whose signatures are XML Signature rather than JWS — ' +
            'there is no JWKS in SAML, the thing a party registers IS a ' +
            'certificate.\n\nSeveral PEM blocks may be in one value, because ' +
            'a party rotating a certificate holds two for as long as ' +
            'assertions signed by the old one are still in flight. Public ' +
            'key material, so like `oauthJwks` it is worth nothing to ' +
            'whoever reads this directory.\n\n**A CERTIFICATE ARRIVING IN ' +
            'THE ASSERTION\'S OWN `<ds:KeyInfo>` IS NOT A SUBSTITUTE FOR ' +
            'THIS.** It is used to choose among what is registered here and ' +
            'never as a key in its own right, which is where this profile is ' +
            'stricter than RFC 7523: a chain to this realm\'s Root proves ' +
            'the REALM issued a key and says nothing about WHICH application ' +
            'holds it, so accepting one would let an application\'s RFC 7523 ' +
            'leaf sign a SAML assertion.' },
    { name: 'oauthSamlAssertionCertificate', kind: 'single', from: '/admin/pki',
      what: 'The leaf certificate this service ISSUED this application for ' +
            'RFC 7522, PEM, whose subject is the application and whose ' +
            'issuer is the realm\'s Issuing CA. Written by the Issue control ' +
            'on /admin/pki with the SAML 2.0 purpose chosen, and by POST ' +
            '/admin-api/pki/issue with `purpose: "saml"`. It is a DIFFERENT ' +
            'certificate over a DIFFERENT key pair from ' +
            '`oauthAssertionCertificate` beside it, and its subjectAltName ' +
            'carries the RFC 7522 profile URI so that a certificate read out ' +
            'of context says which profile it was issued for.' },
    { name: 'oauthSamlAssertionCertificateChain', kind: 'single',
      from: '/admin/pki',
      what: 'The Issuing CA and the Intermediate CA, PEM, in that order — ' +
            'what the leaf above travels with. The ROOT is deliberately not ' +
            'in it, for the reason the JWT chain row gives: a relying party ' +
            'that accepted one because it arrived in the chain would be ' +
            'accepting a certificate that vouched for itself.' },
    { name: 'oauthSamlAssertionPrivateKey', kind: 'single', from: '/admin/pki',
      sensitive: true,
      what: 'THE PRIVATE KEY of the RFC 7522 pair, PEM. **SEALED AT REST ' +
            'WHEREVER THE KEY-ENCRYPTION KEY OUTLIVES THE PROCESS**, by the ' +
            'same mechanism and under the same key as ' +
            '`oauthAssertionPrivateKey` beside it — see that row, which ' +
            'argues the whole of it. This service keeps NO SECOND COPY: ' +
            'common/pki.js hands it over once, at issuance, and forgets it.' },
    { name: 'oauthSamlAssertionThumbprint', kind: 'single', from: '/admin/pki',
      what: 'The SHA-256 thumbprint of the issued certificate, base64url. It ' +
            'is what `oauthAssertionKid` is for the JWT profile and it is ' +
            'spelt differently because the two formats carry different ' +
            'handles: a JWS header names a `kid` and an XML Signature ' +
            'carries the certificate itself, so what matches a presented ' +
            '<ds:KeyInfo> against what is registered is a thumbprint.' },
    { name: 'oauthSamlAssertionExpiresAt', kind: 'single', from: '/admin/pki',
      what: 'When the issued RFC 7522 certificate expires, as a ' +
            'GeneralizedTime. A fact about the CERTIFICATE and not a policy, ' +
            'exactly as `oauthAssertionExpiresAt` is: nothing here refuses ' +
            'an assertion because this date has passed. Drawn on /admin/pki ' +
            'so that an operator can see what is about to stop working.' },
    { name: 'oauthSamlAssertionKeySource', kind: 'single',
      from: '/admin/pki, or the application\'s own page',
      what: 'Where the RFC 7522 key pair above came from, in the vocabulary ' +
            '`oauthAssertionKeySource` uses and for its reason: `issued`, ' +
            '`uploaded-realm-ca` or `uploaded-external-ca`. It is a SEPARATE ' +
            'attribute from the JWT one because the two key pairs are ' +
            'separate — one may be issued here while the other is somebody ' +
            'else\'s certificate.' },
    // -------------------------------------------------------------------
    // RFC 7591 SECTION 2.3 — SOFTWARE STATEMENTS (2026-09-13). Two kinds of
    // row, and `oauth-oidc/software_statement.ts` argues both: on a PUBLISHER,
    // the declaration and the statement this realm issued it; on a client that
    // REGISTERED with a statement, three facts about how it got in. The keys a
    // declared publisher signs with are the ones above — `oauthJwks` and the
    // RFC 7523 key pair — because a key is the party's and the declaration is
    // the decision.
    // -------------------------------------------------------------------
    { name: 'oauthSoftwareStatementIssuer', kind: 'multi', from: 'by hand',
      identifier: true,
      identifierName: 'software statement iss',
      what: 'THE `iss` VALUES WHOSE SOFTWARE STATEMENTS THIS APPLICATION ' +
            'VOUCHES FOR at POST /oauth2/register (RFC 7591 section 2.3) — ' +
            'the application is the software PUBLISHER, and a statement ' +
            'naming one of these issuers is verified against its `jwks` or ' +
            'its RFC 7523 key pair from /admin/pki, or an x5c this realm ' +
            'issued to it. It is READ: a statement from an issuer nobody ' +
            'declares is refused unapproved_software_statement while ' +
            '`oauth2.softwareStatementRequireTrustedIssuer` is on, and a ' +
            'trusted one fixes the registered metadata and may open a ' +
            'closed registration endpoint.\n\nA SEPARATE attribute from ' +
            '`oauthAssertionIssuer`: a party trusted to say who a person is ' +
            'has not thereby been trusted to say what software may register ' +
            'as. A statement this realm issued itself needs no declaration. ' +
            'It accumulates, for the reason the assertion issuers do.' },
    { name: 'oauthIssuedSoftwareStatement', kind: 'single',
      from: 'the application\'s own page, or POST ' +
            '/admin-api/applications/issue-software-statement',
      what: 'THE SOFTWARE STATEMENT THIS REALM LAST ISSUED FOR THIS ' +
            'APPLICATION, as the compact JWS, typed ' +
            '`software-statement+jwt`, with `sub` naming this application. ' +
            'A client presenting it at POST /oauth2/register is registered ' +
            'with the members it fixes. NOT A SECRET — RFC 7591 section 2.3 ' +
            'expects a statement to ship with every copy of the software — ' +
            'and not a record of every statement issued: issuing again ' +
            'replaces this value, and the earlier statement still verifies ' +
            'until it expires or the realm\'s signing key changes.' },
    { name: 'appSoftwareStatementIssuer', kind: 'single',
      from: 'POST /oauth2/register',
      what: 'The `iss` of the software statement this client REGISTERED ' +
            'with, or absent when it presented none. Cleared by an RFC 7592 ' +
            'update that carries none, and by the registration being ' +
            'deleted.' },
    { name: 'appSoftwareStatementTrusted', kind: 'single',
      from: 'POST /oauth2/register',
      what: 'TRUE when that statement was verified against an issuer this ' +
            'realm trusts, FALSE when it was accepted unverified because ' +
            '`oauth2.softwareStatementRequireTrustedIssuer` was off. A ' +
            'client registered on a TRUE statement at an endpoint otherwise ' +
            'closed must present a trusted statement from the same issuer ' +
            'with every update.' },
    { name: 'appSoftwareStatementPublisher', kind: 'single',
      from: 'POST /oauth2/register',
      what: 'The application the trust came through: the one declaring the ' +
            'issuer, or — for a statement this realm issued — the ' +
            'application it was issued for.' },
    { name: 'oauthTlsClientAuthSubjectDn', kind: 'single', from: 'by hand',
      identifier: true,
      identifierName: 'subject DN',
      what: 'RFC 8705 section 2.1.2 `tls_client_auth_subject_dn`: the ' +
            'subject DN of the PKI certificate this client authenticates ' +
            'with, in RFC 4514 form. Compared as a NAME since 2026-09-13 ' +
            '(common/certificate_subject.js: attribute types folded, values ' +
            'caseIgnoreMatch, the AVAs of a multi-valued RDN in any order) ' +
            'and only against a certificate whose chain VERIFIED. One of the ' +
            'FIVE subject parameters, and a client registers at most one — ' +
            'a second is refused (STS-REG-0131, STS-REG-0135). With none, ' +
            'tls_client_auth still authenticates a certificate this realm ' +
            'issued to THIS application. IT IS ALSO THE IDENTIFIER ATTRIBUTE ' +
            'OF THE `mtls` FAMILY, and it is SINGLE-VALUED while every other ' +
            'identifier here accumulates, because RFC 8705 says the ' +
            'certificate matches "the single expected subject".' },
    { name: 'oauthTlsClientAuthSanDns', kind: 'single',
      from: 'by hand / POST /oauth2/register',
      what: 'RFC 8705 section 2.1.2 `tls_client_auth_san_dns`: a dNSName ' +
            'the certificate this client authenticates with must carry, ' +
            'compared without regard to case or a trailing dot, never as a ' +
            'wildcard. One of the five subject parameters; see ' +
            'oauthTlsClientAuthSubjectDn.' },
    { name: 'oauthTlsClientAuthSanUri', kind: 'single',
      from: 'by hand / POST /oauth2/register',
      what: 'RFC 8705 section 2.1.2 `tls_client_auth_san_uri`: a ' +
            'uniformResourceIdentifier the certificate must carry, compared ' +
            'exactly. One of the five subject parameters.' },
    { name: 'oauthTlsClientAuthSanIp', kind: 'single',
      from: 'by hand / POST /oauth2/register',
      what: 'RFC 8705 section 2.1.2 `tls_client_auth_san_ip`: an iPAddress ' +
            'the certificate must carry, IPv4 or IPv6, compared as the ' +
            'address rather than its spelling. One of the five subject ' +
            'parameters.' },
    { name: 'oauthTlsClientAuthSanEmail', kind: 'single',
      from: 'by hand / POST /oauth2/register',
      what: 'RFC 8705 section 2.1.2 `tls_client_auth_san_email`: an ' +
            'rfc822Name the certificate must carry, the domain compared ' +
            'without regard to case and the local part exactly (RFC 5280 ' +
            'section 7.5). One of the five subject parameters.' },
    { name: 'oauthTlsClientCertificateBoundAccessTokens', kind: 'single',
      from: 'by hand / POST /oauth2/register',
      what: 'RFC 8705 section 3.4 ' +
            '`tls_client_certificate_bound_access_tokens`, TRUE or FALSE. ' +
            'TRUE is this client DECLARING that its tokens are ' +
            'certificate-bound, and it is held to that in EVERY mode: a ' +
            'token request from it over a connection with no client ' +
            'certificate is refused (STS-OAUTH-0487) rather than answered ' +
            'with an unbound token, which section 3.4 leaves to the ' +
            'authorization server. FALSE or absent changes nothing — a ' +
            'client presenting a certificate still gets a bound token.' },
    { name: 'oauthTlsClientCertificateThumbprint', kind: 'single', from: 'by ' +
        'hand',
      what: 'For RFC 8705 section 2.2 self_signed_tls_client_auth: the ' +
            'base64url SHA-256 of the DER of the certificate this client ' +
            'authenticates with. THIS SERVICE\'S OWN NAME, kept beside ' +
            'what the RFC names: since 2026-09-13 a certificate also ' +
            'authenticates the client when it is the x5c[0] of a key in the ' +
            'jwks it registered (section 2.2.2). Fetch a certificate\'s ' +
            'thumbprint with GET /tls/sign-in, or compute it: openssl x509 ' +
            '-outform DER | openssl dgst -sha256 -binary | base64url.' },
    { name: 'oauthConfidential', kind: 'single', from: 'this registry',
      what: 'TRUE/FALSE, the determination RFC 9700 mode makes about it — ' +
            'and therefore whether PKCE is required of it and whether its ' +
            'secret is checked. Written here so the answer can be read ' +
            'rather than inferred.' },

    // --- SAML, WS-Federation, WS-Trust ------------------------------------
    { name: 'samlEntityId', kind: 'multi', from: 'SAML 2.0 / SAML 1.1',
      identifier: true,
      identifierName: 'entityID',
      what: 'THE SERVICE PROVIDER\'S ENTITYID — the assertion audience, and ' +
            'the identifier attribute of BOTH SAML families. SAML 1.1 has no ' +
            'entityID of its own in the protocol (there is no request ' +
            'message for one to travel in) and what stands in for it — ' +
            'Shibboleth\'s providerId, the path segment, or the TARGET\'s ' +
            'origin — names the same party, so one attribute holds it rather ' +
            'than two that would disagree the first time an application was ' +
            'declared for both. Accumulates: an application answering to two ' +
            'entityIDs is one application.\n\nIT IS READ, as the SECOND half ' +
            'of forAppliesTo(): a WS-Trust AppliesTo and the ' +
            'AudienceRestriction of the assertion issued for it are one ' +
            'string, so an application that registered it here rather than ' +
            'on `wstrustAppliesTo` still gets its own box on the delegation ' +
            'map. The same lookup and the same non-permission — nothing here ' +
            'is ever refused for being unregistered.' },
    { name: 'samlAssertionConsumerService', kind: 'multi', from: 'SAML 2.0 / ' +
        'SAML 1.1',
      what: 'THE ASSERTION CONSUMER SERVICE URL — where a SAML response is ' +
            'posted back to, and the redirect URI of both SAML families. It ' +
            'held WS-Federation\'s `wreply` as well until 2026-08-25; that ' +
            'moved to wsfedReplyUrl, because the SAML pages read this ' +
            'attribute for the Single Logout fallback and a wreply arriving ' +
            'in it made a WS-Federation application look as though it had ' +
            'named a SAML ACS. CHECKED IN PRODUCT MODE ONLY: development ' +
            'sends a response wherever the request asked and records the ' +
            'address here; product delivers only to an address already on ' +
            'this list, and a sighting there never adds one. What ' +
            'development RECORDS here is marked on appReturnAddressObserved, ' +
            'and product refuses a marked address until an operator confirms ' +
            'it — so a realm switched from development to product does not ' +
            'trust what development learnt. Values recorded before that mark ' +
            'existed carry none and still need reviewing.' },
    { name: 'samlSingleLogoutService', kind: 'multi',
      from: 'consumed metadata, or by hand',
      what: 'WHERE A <samlp:LogoutResponse> IS SENT for this service ' +
            'provider, and where a LogoutRequest goes when this identity ' +
            'provider starts the logout. DECLARED, not observed: a ' +
            'LogoutRequest carries no return address, so only SP METADATA ' +
            'or an operator can say. Consuming the metadata writes its ' +
            'SingleLogoutService locations here (and each endpoint\'s ' +
            'binding and ResponseLocation on samlSloEndpoint, which is read ' +
            'first). With none recorded the fallback is ' +
            'saml2.defaultSingleLogoutService and then the assertion ' +
            'consumer service URL above, which is a guess this service makes ' +
            'out loud rather than quietly.' },
    { name: 'samlNameIdFormat', kind: 'multi', from: 'SAML 2.0',
      what: 'Every NameID Format this service provider has asked for in a ' +
            'NameIDPolicy, accumulated. It is evidence rather than ' +
            'configuration: this identity provider answers with whatever was ' +
            'asked for, including a format nobody has ever heard of, so a ' +
            'value here does not restrict the next request.' },
    { name: 'samlResponseBinding', kind: 'multi', from: 'SAML 2.0',
      what: 'The ProtocolBinding values it has asked its responses back on — ' +
            'HTTP-POST, HTTP-Redirect or HTTP-Artifact. Several is the ' +
            'ordinary case for a service provider being exercised, which is ' +
            'what makes this a list.' },
    // THE TRUST ANCHOR FOR A SERVICE PROVIDER'S SIGNATURES (2026-09-17,
    // #37). It was single-valued and written straight off the ds:KeyInfo of
    // every signed AuthnRequest while nothing verified a request signature;
    // now that something does, a certificate a REQUEST carries cannot be
    // what the request is checked against, so a sighting writes
    // `samlObservedSigningCertificate` below instead and this attribute holds
    // only what an operator or consumed metadata registered. MULTI, because
    // metadata publishes the old and new key side by side during a rollover
    // and both must verify. `saml/request_signature.ts` argues the rest.
    { name: 'samlSigningCertificate', kind: 'multi',
      from: 'consumed metadata, the SAML 2.0 page, or by hand',
      what: 'THE SERVICE PROVIDER\'S REGISTERED SIGNING CERTIFICATES, base64 ' +
            'DER, one per value. A signed AuthnRequest, LogoutRequest or ' +
            'LogoutResponse from this service provider is VERIFIED against ' +
            'these — in every mode — and refused when it verifies against ' +
            'none. Written by consuming its metadata (every KeyDescriptor ' +
            'use="signing" or with no use), by the SAML 2.0 console page, by ' +
            'POST /admin-api/saml2/set-signing-certificate, by confirming ' +
            'the observed certificate below, or by hand; an RSA certificate ' +
            'is required, because the verifier here is RSA. It is NEVER ' +
            'written from a request: the certificate a request carries in ' +
            'its ds:KeyInfo goes on samlObservedSigningCertificate. Values ' +
            'written before 2026-09-17 were captured off requests and carry ' +
            'no provenance — review them before trusting them. Public key ' +
            'material, so unlike oauthClientSecret it is worth nothing to ' +
            'whoever reads this directory.' },
    { name: 'samlObservedSigningCertificate', kind: 'single',
      from: 'a signed SAML 2.0 request',
      what: 'THE CERTIFICATE THE LAST SIGNED REQUEST CARRIED IN ITS ' +
            'ds:KeyInfo, base64 DER, when it is not one of the registered ' +
            'samlSigningCertificate values. OBSERVED, NOT TRUSTED: a key a ' +
            'request brings with it proves nothing about who sent the ' +
            'request, so it verifies nothing in either mode. Development ' +
            'still encrypts an assertion to it when the entry holds no other ' +
            'certificate; product does not. An operator CONFIRMS it (it ' +
            'moves onto samlSigningCertificate) or DISCARDS it, on the SAML ' +
            '2.0 page or with POST /admin-api/saml2/confirm-signing-' +
            'certificate and /discard-signing-certificate. ONE value — the ' +
            'last — so a stream of requests carrying made-up keys cannot ' +
            'grow the entry.' },
    { name: 'samlAuthnRequestVerification', kind: 'single',
      from: 'SAML 2.0',
      what: 'WHAT CHECKING THE LAST REQUEST\'S SIGNATURE FOUND: `verified`, ' +
            '`failed`, `unsigned` or `no-certificate` (signed, and nothing ' +
            'registered to check it against), then the binding and the ' +
            'algorithm. Assigned, like samlAuthnRequestSigned beside it.' },
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
    { name: 'samlSpMetadataUrl', kind: 'single', from: 'by hand',
      what: 'WHERE THIS SERVICE PROVIDER\'S METADATA IS PUBLISHED. It is ' +
            'fetched by the "refresh metadata" action on the application ' +
            'page and by POST /admin-api/applications/refresh-metadata, and ' +
            'NEVER while a flow is running — an assertion that had to wait ' +
            'on somebody else\'s web server to be issued would make every ' +
            'sign-in as reliable as that server. What the fetch writes is ' +
            'everything consuming the document writes — see ' +
            'samlSpMetadata below.\n\nThis is ' +
            'the SECOND outbound-request surface in this service; federation ' +
            'was the first and is the only other. It follows the same ' +
            'refusals — the URL must be one this entry carries, the scheme ' +
            'must be http or https, and the request times out.' },
    { name: 'samlSpMetadata', kind: 'single', from: 'a metadata fetch, or by ' +
                                                    'hand',
      what: 'THE SERVICE PROVIDER\'S METADATA DOCUMENT, cached verbatim. It ' +
            'is what the refresh action stores, and what uploading one on ' +
            'the SAML 2.0 page (or POST /admin-api/saml2/upload-metadata) ' +
            'stores for a service provider whose metadata this service ' +
            'cannot reach. CONSUMING it (2026-09-17) writes its ' +
            'AssertionConsumerService and SingleLogoutService endpoints as ' +
            'REGISTERED return addresses (samlAssertionConsumerService, ' +
            'samlAcsEndpoint, samlSingleLogoutService, samlSloEndpoint), its ' +
            'signing certificates (samlSigningCertificate), its encryption ' +
            'certificate (samlEncryptionCertificate), its NameIDFormats, ' +
            'AuthnRequestsSigned and WantAssertionsSigned, and its ' +
            'validUntil and cacheDuration. Setting this attribute by hand ' +
            'stores the document and consumes NOTHING — use the upload.' +
            '\n\nIT IS KEPT AS WELL AS THE EXTRACT so that a reader can see ' +
            'what was actually consumed. A certificate with no document ' +
            'behind it is a value nobody can check.' },
    { name: 'samlEncryptionCertificate', kind: 'single',
      from: 'metadata, or by hand',
      what: 'THE CERTIFICATE AN ASSERTION IS ENCRYPTED TO, base64 DER or ' +
            'PEM. Written by the metadata fetch from the <md:KeyDescriptor ' +
            'use="encryption"> — falling back to an unqualified ' +
            'KeyDescriptor, which the specification says serves both uses — ' +
            'and settable by hand for a service provider with no metadata at ' +
            'all.\n\nIt decides what goes out. With none here a registered ' +
            'samlSigningCertificate is used, then — in development only — ' +
            'the observed one, and with none of them the assertion is sent ' +
            'in clear (development) or refused (product), and the page says ' +
            'so.' },
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
    { name: 'samlAcsEndpoint', kind: 'multi', from: 'consumed metadata',
      what: 'An <md:AssertionConsumerService> from the consumed metadata, as ' +
            '`<index> <isDefault> <binding> <location>` — isDefault is ' +
            '`true`, `false` or `-` for unstated. An AuthnRequest naming an ' +
            'AssertionConsumerServiceIndex is answered at that endpoint and ' +
            'on its binding; one naming an AssertionConsumerServiceURL must ' +
            'name one of these (in EVERY mode, once metadata has been ' +
            'consumed); one naming neither goes to the default endpoint ' +
            '(saml-metadata-2.0-os section 2.2.3).' },
    { name: 'samlSloEndpoint', kind: 'multi', from: 'consumed metadata',
      what: 'An <md:SingleLogoutService> from the consumed metadata, as ' +
            '`<binding> <location>` or `<binding> <location> ' +
            '<responseLocation>`. A LogoutResponse goes to the ' +
            'ResponseLocation where there is one, on the binding the ' +
            'LogoutRequest arrived on where the service provider publishes ' +
            'it.' },
    { name: 'samlSpNameIdFormat', kind: 'multi', from: 'consumed metadata',
      what: 'The <md:NameIDFormat> values the service provider\'s metadata ' +
            'declares. Unlike samlNameIdFormat (what it has ASKED for), ' +
            'these RESTRICT: a NameIDPolicy naming another format is ' +
            'answered InvalidNameIDPolicy (saml-core-2.0-os section ' +
            '3.4.1.1), and the default format is chosen from them.' },
    { name: 'samlSpAuthnRequestsSigned', kind: 'single',
      from: 'consumed metadata',
      what: 'TRUE when the metadata says AuthnRequestsSigned="true": an ' +
            'unsigned request from this service provider is then refused ' +
            'whatever saml2.requireSignedAuthnRequests says, and the ' +
            'metadata this identity provider serves it says ' +
            'WantAuthnRequestsSigned="true".' },
    { name: 'samlSpWantAssertionsSigned', kind: 'single',
      from: 'consumed metadata',
      what: 'TRUE when the metadata says WantAssertionsSigned="true": the ' +
            'assertion is signed even where saml2.signAssertion (or ' +
            'saml2SignAssertion) is off — in product mode; development ' +
            'honours the setting, which is a test case, and logs that the ' +
            'service provider asked otherwise.' },
    { name: 'samlSpWantAssertionsEncrypted', kind: 'single',
      from: 'consumed metadata',
      what: 'TRUE when the consumed metadata publishes a KeyDescriptor ' +
            'marked use="encryption" — the service provider saying it has a ' +
            'key for encrypted assertions, which SAML 2.0 metadata has no ' +
            'attribute of its own for (the interoperability profiles read ' +
            'the key as the request). The assertion is then ENCRYPTED to ' +
            'that key in every mode, whatever saml2.encryptAssertion says.' },
    { name: 'samlSpMetadataValidUntil', kind: 'single',
      from: 'consumed metadata',
      what: 'The EFFECTIVE validUntil of the consumed document — the ' +
            'earliest on any enclosing EntitiesDescriptor, the ' +
            'EntityDescriptor and its SPSSODescriptor. A document already ' +
            'expired is refused when consumed; once this passes, every ' +
            'request from the service provider is REFUSED (STS-SAML-0074) ' +
            'until a newer document is consumed.' },
    { name: 'samlSpMetadataCacheDuration', kind: 'single',
      from: 'consumed metadata',
      what: 'The EFFECTIVE cacheDuration of the consumed document (the ' +
            'shortest in its chain), as the xs:duration it carried. Once it ' +
            'has elapsed since the document was consumed, the document is ' +
            'STALE: the background refresher fetches it again where it can ' +
            '(saml2.spMetadataRefresh), and it keeps working until its ' +
            'validUntil.' },
    { name: 'samlSpMetadataConsumedAt', kind: 'single',
      from: 'consumed metadata',
      what: 'When the document was last consumed, and how: `<ISO instant> ' +
            '<refresh|upload|mdq>` — `mdq` for one fetched from the Metadata ' +
            'Query responder, which the background refresher can fetch ' +
            'again.' },
    { name: 'samlSpMetadataSignature', kind: 'single',
      from: 'consumed metadata',
      what: 'What checking the consumed document\'s own signature found: ' +
            '`verified`, `unsigned`, or `signed-not-verified` (signed, and ' +
            'no samlSpMetadataSigningCertificate to check it against).' },
    { name: 'samlSpMetadataSigningCertificate', kind: 'single',
      from: 'by hand',
      what: 'THE CERTIFICATE THIS SERVICE PROVIDER\'S METADATA MUST BE ' +
            'SIGNED WITH, base64 DER. With it set, a document that is ' +
            'unsigned, or whose signature does not verify against it, is ' +
            'REFUSED and nothing on the entry changes. Without it a signed ' +
            'document is consumed and recorded as signed-not-verified: the ' +
            'trust act is then the operator\'s choice of URL (or document), ' +
            'which is what an explicit refresh or upload is.' },
    { name: 'saml2EncryptAssertion', kind: 'single', from: 'by hand',
      overrides: 'saml2.encryptAssertion',
      what: 'TRUE or FALSE: encrypt the assertion issued to THIS service ' +
            'provider, overriding saml2.encryptAssertion. This is the one of ' +
            'the four most worth having per application — an estate where ' +
            'one service provider requires encryption and the others cannot ' +
            'read it is the ordinary case, and a service-wide switch could ' +
            'not express it.' },
    { name: 'saml2EncryptionAlgorithm', kind: 'single', from: 'by hand',
      overrides: 'saml2.encryptionAlgorithm',
      what: 'The block cipher used for this service provider — aes256-gcm, ' +
            'aes128-gcm, aes256-cbc or aes128-cbc — overriding ' +
            'saml2.encryptionAlgorithm. A value that is not one of those ' +
            'four is IGNORED with a warning and the service-wide choice is ' +
            'used, exactly as an unparseable number would be.' },
    { name: 'saml2KeyTransportAlgorithm', kind: 'single', from: 'by hand',
      overrides: 'saml2.keyTransportAlgorithm',
      what: 'How the content key is wrapped for this service provider — ' +
            'rsa-oaep-mgf1p or rsa-1_5 — overriding ' +
            'saml2.keyTransportAlgorithm. An appliance that accepts only ' +
            'rsa-1_5 is the reason this is per application rather than a ' +
            'decision made once for the whole service.' },
    { name: 'saml2EncryptLogoutNameId', kind: 'single', from: 'by hand',
      overrides: 'saml2.encryptLogoutNameId',
      what: 'TRUE or FALSE: send <saml:EncryptedID> rather than ' +
            '<saml:NameID> in the LogoutRequest sent to this service ' +
            'provider, overriding saml2.encryptLogoutNameId. Separate from ' +
            'the assertion switch above because they are separate ' +
            'capabilities in every service provider library that has them: ' +
            'one that decrypts assertions may still expect a plain NameID in ' +
            'a logout message.' },

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
    { name: 'oauthAccessTokenTtlS', kind: 'single', from: 'by hand',
      overrides: 'oauth2.accessTokenTtlS',
      what: 'HOW LONG AN ACCESS TOKEN ISSUED TO THIS CLIENT LIVES, in ' +
            'seconds, overriding oauth2.accessTokenTtlS for it alone. It ' +
            'becomes the token\'s `exp`, so it is stamped in at signing time ' +
            'and nothing here can shorten a token already issued. Set it to ' +
            '30 on one client to watch that client refresh while every other ' +
            'client carries on.' },
    { name: 'oauthIdTokenTtlS', kind: 'single', from: 'by hand',
      overrides: 'oauth2.idTokenTtlS',
      what: 'The same for the OIDC ID Token, overriding oauth2.idTokenTtlS. ' +
            'Separate from the access token\'s because the two go to ' +
            'different readers: an ID Token is consumed once at sign-in and ' +
            'an access token is presented for as long as it lasts.' },
    { name: 'oauthRefreshTokenTtlS', kind: 'single', from: 'by hand',
      overrides: 'oauth2.refreshTokenTtlS',
      what: 'The same for the refresh token, overriding ' +
            'oauth2.refreshTokenTtlS. A value at or below ' +
            'oauthAccessTokenTtlS is legal and is a grant that can never ' +
            'usefully be renewed — /admin/token-lifetimes reports that ' +
            'combination for the service-wide pair, and it is just as ' +
            'reachable here.' },
    { name: 'oauthRefreshIdleSeconds', kind: 'single', from: 'by hand',
      overrides: 'oauth2.refreshIdleSeconds',
      what: 'RFC 9700 MODE ONLY: how long a refresh chain may sit unused ' +
            'before it is cut off, overriding oauth2.refreshIdleSeconds for ' +
            'this client. It is measured from the last time any token in the ' +
            'CHAIN was redeemed rather than from issuance, so a busy client ' +
            'keeps its grant and a quiet one does not. Outside RFC 9700 mode ' +
            'nothing reads it, which is a property of the setting rather ' +
            'than of this attribute.' },
    { name: 'oauthRevokeRefreshOnLogout', kind: 'single', from: 'by hand',
      overrides: 'oauth2.revokeRefreshOnLogout',
      what: 'TRUE or FALSE: does signing out revoke this client\'s refresh ' +
            'tokens, overriding oauth2.revokeRefreshOnLogout. FALSE is the ' +
            'interesting case and it is why this is worth having per client ' +
            '— a client that can refresh its way back after a sign-out is a ' +
            'real defect in real deployments, and this makes it reproducible ' +
            'for ONE client while the rest behave.' },

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
    { name: 'oauthTokenExchangeRefreshToken', kind: 'single',
      from: 'the console, the management API, or by hand',
      overrides: 'oauth2.tokenExchangeRefreshToken',
      families: ['oauth2', 'oidc'],
      what: 'WHETHER AN RFC 8693 TOKEN EXCHANGE PERFORMED BY THIS CLIENT ' +
            'GETS A `refresh_token` BESIDE THE EXCHANGED ACCESS TOKEN, ' +
            'overriding oauth2.tokenExchangeRefreshToken for it alone. One ' +
            'of three words: `never`, `when-requested` (the service-wide ' +
            'default — the client asks with RFC 8693 section 2.1\'s ' +
            '`requested_token_type` and gets one only if it did) or ' +
            '`always`.\n\nIT IS READ ON THE CLIENT PERFORMING THE EXCHANGE ' +
            'and not on the audience, because the refresh token is handed to ' +
            'the client: it is that party\'s credential to hold, revoke and ' +
            'eventually redeem. The subject the exchange is ABOUT has no ' +
            'entry in this registry at all in the interesting case, since ' +
            'the whole point of an exchange is a subject_token from ' +
            'somewhere else.\n\n**IT APPLIES TO THE OAUTH 2.0 AND OPENID ' +
            'CONNECT FAMILIES AND TO NO OTHER, and unlike every other ' +
            'attribute here that is ENFORCED.** An entry declared for ' +
            'neither is turned away by both console doors and by the ' +
            'management API, naming the family to tick first — because a ' +
            'value here is a policy about the token endpoint, and an entry ' +
            'no token request can ever name would carry it looking as though ' +
            'it were in force. The block above this row argues it. ' +
            '`ldapmodify` reaches this attribute like every other and is not ' +
            'checked.\n\nA VALUE THAT IS NOT ONE OF THE THREE WORDS IS NOT ' +
            'AN ERROR AT WRITE TIME AND IS NOT SILENT: settingFor() warns ' +
            'naming the entry, the attribute and what it holds, and the ' +
            'service-wide setting decides — the same three-state honesty ' +
            'every other override on this entry gets.' },

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
    { name: 'appRequiredRole', kind: 'multi', from: 'by hand',
      what: 'A role somebody must hold before this application is issued ' +
            'anything — a token, an assertion, a WS-Federation response, a ' +
            'session. Multi-valued and ANY of them is enough. ABSENT MEANS ' +
            'EVERYBODY, the built-in role everybody holds, which is why an ' +
            'unconfigured application refuses nobody. The decision is made ' +
            'by the XACML PDP against the policy named by ' +
            'xacml.issuancePolicy, not by an if in an issuance site, so the ' +
            'reason for a refusal is a policy somebody can read.' },

    { name: 'appGroupsClaim', kind: 'single', from: 'by hand',
      overrides: 'groups.claim',
      what: 'TRUE or FALSE: does anything issued to this application carry a ' +
            'groups claim at all, overriding groups.claim. FALSE on one ' +
            'application is how a client that breaks on an unexpected claim ' +
            'is exercised without taking the claim away from everything ' +
            'else.' },
    { name: 'appGroupsClaimName', kind: 'single', from: 'by hand',
      overrides: 'groups.claimName',
      what: 'What the groups claim is CALLED for this application, ' +
            'overriding groups.claimName. This is the attribute that earns ' +
            'the group its place here: `groups`, `roles`, `memberOf` and a ' +
            'URI-shaped claim name are all ordinary, they differ per relying ' +
            'party in every real deployment, and a single service-wide name ' +
            'meant only one of them could be tested at a time.' },
    { name: 'appGroupsClaimValue', kind: 'single', from: 'by hand',
      overrides: 'groups.claimValue',
      what: 'Whether the claim carries each group\'s name or its whole DN, ' +
            'overriding groups.claimValue. Relying parties genuinely differ: ' +
            'one matches on `cn` and the next was written against an LDAP ' +
            'DN.' },
    { name: 'appGroupsClaimFromMemberOf', kind: 'single', from: 'by hand',
      overrides: 'groups.claimFromMemberOf',
      what: 'Where the groups are read from for this application, overriding ' +
            'groups.claimFromMemberOf — the person\'s memberOf attribute, or ' +
            'a search of the groups container. The two agree in this ' +
            'directory; they are worth telling apart because a real ' +
            'directory\'s memberOf can lag.' },

    // ---------------------------------------------------------------------
    // THE WS-FEDERATION ASSERTION LIFETIME, added 2026-08-27 together with the
    // setting it overrides — which did not exist either, because wsfed.js
    // carried a module-level `const lifetimeMin = 60`. A group of one, for the
    // reason config.js's row gives.
    { name: 'wsfedAssertionLifetimeMin', kind: 'single', from: 'by hand',
      overrides: 'wsfed.assertionLifetimeMin',
      what: 'How long the SAML 1.1 assertion inside a WS-Federation sign-in ' +
            'response for THIS relying party is valid, in minutes, ' +
            'overriding wsfed.assertionLifetimeMin. It sets the assertion\'s ' +
            'Conditions and the wsu:Lifetime of the ' +
            'RequestSecurityTokenResponse around it, so the envelope and the ' +
            'document inside it cannot disagree. It is separate from ' +
            'saml11AssertionLifetimeMin: one application may speak both, and ' +
            'a WS-Federation session and a Browser/POST assertion are not ' +
            'consumed the same way.' },

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
    // "yes" instead of "true" would be a mock that stopped answering.
    { name: 'saml2AssertionLifetimeMin', kind: 'single', from: 'by hand',
      overrides: 'saml2.assertionLifetimeMin',
      what: 'HOW LONG THIS SERVICE PROVIDER\'S ASSERTIONS ARE VALID, in ' +
            'minutes, overriding saml2.assertionLifetimeMin for it alone. ' +
            'What it becomes is Conditions/NotOnOrAfter and the bearer ' +
            'SubjectConfirmationData/NotOnOrAfter alike, widened at both ' +
            'ends by saml.clockSkewS — which is NOT per application, because ' +
            'it is a fact about the clocks in this estate rather than about ' +
            'one relying party.' },
    { name: 'saml2SignAssertion', kind: 'single', from: 'by hand',
      overrides: 'saml2.signAssertion',
      what: 'TRUE or FALSE: sign the <saml:Assertion> issued to this service ' +
            'provider, overriding saml2.signAssertion for it alone. FALSE is ' +
            'a test case rather than a mistake — a service provider that ' +
            'accepts an unsigned assertion has a hole in it, and this is how ' +
            'one is found without turning signing off for every other ' +
            'application at the same time. That is the whole reason this is ' +
            'per application.' },
    { name: 'saml2SignResponse', kind: 'single', from: 'by hand',
      overrides: 'saml2.signResponse',
      what: 'TRUE or FALSE: sign the <samlp:Response> around the assertion ' +
            'for this service provider, overriding saml2.signResponse. On ' +
            'the HTTP Redirect binding it also controls the query-string ' +
            'signature of section 3.4.4.1, which is the one a redirect ' +
            'response is really verified by.' },
    { name: 'saml2NameIdFormat', kind: 'single', from: 'by hand',
      overrides: 'saml2.nameIdFormat',
      what: 'The NameID Format used for this service provider when its ' +
            'AuthnRequest\'s NameIDPolicy asks for none, overriding ' +
            'saml2.nameIdFormat. A request that DOES name a format is still ' +
            'answered with the one it named — this is the default, not a ' +
            'restriction, and it is deliberately NOT checked against ' +
            'samlNameIdFormat beside it, which is the list of formats this ' +
            'service provider has ASKED for.' },
    { name: 'saml2ArtifactTtlS', kind: 'single', from: 'by hand',
      overrides: 'saml2.artifactTtlS',
      what: 'How long an artifact minted for this service provider can be ' +
            'resolved for, in seconds, overriding saml2.artifactTtlS. An ' +
            'artifact is ALSO one-shot however long this is — resolving it ' +
            'destroys it, which section 3.6.4.1 requires and no lifetime can ' +
            'express.' },
    { name: 'saml11AssertionLifetimeMin', kind: 'single', from: 'by hand',
      overrides: 'saml11.assertionLifetimeMin',
      what: 'The SAML 1.1 equivalent of saml2AssertionLifetimeMin, ' +
            'overriding saml11.assertionLifetimeMin for this relying party. ' +
            'Separate from the 2.0 attribute for the reason the two SETTINGS ' +
            'are separate: the profiles are separate implementations ' +
            'consumed differently, and an application declared for both ' +
            'legitimately wants two answers.' },
    { name: 'saml11SignAssertion', kind: 'single', from: 'by hand',
      overrides: 'saml11.signAssertion',
      what: 'TRUE or FALSE: sign the SAML 1.1 <saml:Assertion> for this ' +
            'relying party, overriding saml11.signAssertion. The ' +
            'Browser/POST profile REQUIRES a signed assertion ' +
            '(saml-profile-1.1 section 4.2.1.4), so FALSE here is exactly ' +
            'the test case: a relying party that accepts it anyway has a ' +
            'hole.' },
    { name: 'saml11SignResponse', kind: 'single', from: 'by hand',
      overrides: 'saml11.signResponse',
      what: 'TRUE or FALSE: sign the SAML 1.1 <samlp:Response> for this ' +
            'relying party, overriding saml11.signResponse, with the ' +
            'reference naming ResponseID.' },
    { name: 'saml11NameIdFormat', kind: 'single', from: 'by hand',
      overrides: 'saml11.nameIdFormat',
      what: 'The NameIdentifier Format used for this relying party, ' +
            'overriding saml11.nameIdFormat. SAML 1.1 has no request ' +
            'message, so nothing can ask for a format and this is the only ' +
            'thing that decides it — which makes it the more useful of the ' +
            'two per-application format attributes.' },
    { name: 'saml11ArtifactTtlS', kind: 'single', from: 'by hand',
      overrides: 'saml11.artifactTtlS',
      what: 'How long a SAML 1.1 artifact minted for this relying party can ' +
            'be resolved for, in seconds, overriding saml11.artifactTtlS. ' +
            'The Browser/Artifact profile\'s SOAP responder is what redeems ' +
            'it, once.' },
    { name: 'samlAuthnRequestSigned', kind: 'single', from: 'SAML 2.0',
      what: 'TRUE when the last AuthnRequest from this service provider ' +
            'carried a signature — an enveloped ds:Signature on the POST ' +
            'binding, or the Signature parameter of section 3.4.4.1 on the ' +
            'Redirect binding. ASSIGNED rather than accumulated, because it ' +
            'is a fact about the last request and a history of booleans ' +
            'would say nothing.' },
    { name: 'wsfedRealm', kind: 'multi', from: 'WS-Federation',
      identifier: true,
      identifierName: 'wtrealm',
      what: 'THE WTREALM from a wsignin1.0 request (section 13.2.1) — ' +
            'WS-Federation\'s identifier attribute. Accumulates, for the ' +
            'reason every identifier here does.' },
    { name: 'wsfedReplyUrl', kind: 'multi',
      from: 'WS-Federation, the console, or by hand',
      what: 'WHERE A SIGN-IN RESPONSE IS POSTED BACK TO for this ' +
            'application: the `wreply` of section 13.2.1, WS-Federation\'s ' +
            'redirect URI. It was written into samlAssertionConsumerService ' +
            'until 2026-08-25, which put a wreply in the attribute the SAML ' +
            'pages read for an assertion consumer service and for the Single ' +
            'Logout fallback — one attribute holding two protocols\' return ' +
            'addresses, so a WS-Federation application appeared to have a ' +
            'SAML ACS it had never named. Two facts, two attributes. Like ' +
            'the SAML one beside it this is CHECKED IN PRODUCT MODE ONLY: ' +
            'development refuses no wreply, because a mock that refused ' +
            'would remove a test case rather than add one; product posts ' +
            'only to an address on this list and a sighting never adds one. ' +
            'A wreply development recorded is marked on ' +
            'appReturnAddressObserved and product refuses it until it is ' +
            'confirmed; values recorded before that mark existed carry none ' +
            'and still need reviewing before a realm is switched to product.' },
    { name: 'wsfedSignOutUri', kind: 'multi', from: 'by hand',
      what: 'WHERE A wsignoutcleanup1.0 PING IS SENT for this application — ' +
            'WS-Federation\'s logout URI, and the one this table did not ' +
            'have until 2026-08-30. DECLARED, not observed, which makes it ' +
            'the sibling of samlSingleLogoutService rather than of ' +
            'wsfedReplyUrl: a cleanup is sent when a SESSION ends, and by ' +
            'then the request that would have carried a wreply is long ' +
            'over.\n\n**IT IS NOT READ BY THE SIGN-OUT YET**, and that is ' +
            'stated rather than implied. `cleanupTargetsFor()` builds its ' +
            'list from `session.wsfedRealms`, which records the wreply each ' +
            'sign-in response actually went to — so what this service pings ' +
            'today is what it OBSERVED, and this attribute is what an ' +
            'operator DECLARED. They are two different facts and the second ' +
            'is the one a person setting an application up can state in ' +
            'advance. Wiring it in as the fallback for a realm signed into ' +
            'with no wreply is the obvious next step and is deliberately not ' +
            'taken here: this change adds the field and the storage, and ' +
            'changing where a cleanup goes is a change to what the protocol ' +
            'does.' },
    { name: 'wstrustAppliesTo', kind: 'multi', from: 'WS-Trust',
      identifier: true,
      identifierName: 'AppliesTo',
      what: 'THE APPLIESTO ADDRESS from a RequestSecurityToken — the service ' +
            'the token is issued FOR, and WS-Trust\'s identifier attribute. ' +
            'Accumulates.\n\n**IT IS READ**, which it was not before ' +
            '2026-08-27, and it is `oauthAudience`\'s exception arriving ' +
            'through a second protocol: an OnBehalfOf or ActAs asking for a ' +
            'token to reach `https://esb.example.com` is recorded on ' +
            '/admin/delegation against the APPLICATION that registered that ' +
            'address, so a chain of delegated hops draws as one picture ' +
            'rather than as boxes named after URLs that nothing else in it ' +
            'mentions. A LOOKUP and not a permission — an AppliesTo nobody ' +
            'registered is issued for exactly as before and recorded ' +
            'verbatim. See forAppliesTo(), which asks this attribute first ' +
            'and `samlEntityId` behind it.' },

    // --- Kerberos and OID4VP ----------------------------------------------
    { name: 'krb5ServicePrincipalName', kind: 'multi', from: 'Kerberos v5',
      identifier: true,
      identifierName: 'SPN',
      what: 'THE SPN, e.g. HTTP/sts@EXAMPLE.COM — Kerberos v5\'s identifier ' +
            'attribute. A Kerberos service is an application like the others ' +
            'here, and it is the one whose identifier this service may have ' +
            'created on demand (KRB5_SERVICE_DOMAINS). It accumulates, and ' +
            'here that is the ordinary case rather than the unusual one: one ' +
            'service commonly answers to several SPNs — HTTP/host and ' +
            'HTTP/host.example.com — and a real KDC holds them all against ' +
            'one account.' },
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
    { name: 'krb5ServiceKeys', kind: 'single',
      from: '/admin/kerberos/principals',
      secret: true,
      what: 'A SERVICE PRINCIPAL\'S RANDOM LONG-TERM KEYS, one per enctype, ' +
            'in ONE value: a JSON document naming the SPN, the realm and the ' +
            'kvno beside the keys, SEALED under the key-encryption key ' +
            'wherever that key outlives the process. One value rather than ' +
            'one per enctype so that a key cannot be moved onto another ' +
            'entry or another kvno without the seal failing. ' +
            'Password-equivalent: it is WITHHELD from every page and every ' +
            '/admin-api reply, and the one time it leaves this service is as ' +
            'the keytab a create or a rotate hands over.' },
    { name: 'krb5ServiceKeyInfo', kind: 'single',
      from: '/admin/kerberos/principals',
      what: 'What `krb5ServiceKeys` holds, without the keys: the kvno, the ' +
            'enctypes, when the keys were made and whether they are sealed. ' +
            'Written in the same act as the keys, so the two cannot describe ' +
            'different generations.' },
    // CERTIFICATE ENROLLMENT (2026-09-13): what ACME, EST and SCEP issued to
    // this application, the credentials that let it ask, and the host names
    // an administrator registered for it. `common/cert_enrollment.ts` is the
    // one reader and writer; the attributes are schema rows so that a sighting
    // rewriting this entry from its record does not erase them.
    { name: 'appEnrolledCertificate', kind: 'multi',
      from: '/enroll/acme, /.well-known/est, /enroll/scep',
      what: 'One JSON record per certificate issued to this application over ' +
            'an enrollment protocol: serial, protocol, profile, subject, ' +
            'names, validity, who asked, whether the key was generated here, ' +
            'the certificate and its issuing chain, and a revocation mark. ' +
            'Public material. Written by common/cert_enrollment.ts only.' },
    { name: 'appEnrolledPrivateKey', kind: 'multi',
      from: '/.well-known/est/serverkeygen',
      secret: true,
      what: 'A private key THIS SERVICE generated for one of the certificates ' +
            'above (EST server-side key generation, or the console\'s ' +
            'server-generated key pair), as `<serial>:<PEM>`, sealed wherever ' +
            'the key-encryption key outlives the process. WITHHELD from every ' +
            'page and /admin-api reply; it is handed over once, at issuance.' },
    { name: 'appAcmeEabKey', kind: 'multi',
      from: '/admin/acme',
      secret: true,
      what: 'ACME External Account Binding keys issued for this application, ' +
            'one JSON record each: the key id, the sealed HMAC key, its ' +
            'expiry and the account it bound. A working credential, WITHHELD ' +
            'from every page and /admin-api reply.' },
    { name: 'appScepChallenge', kind: 'multi',
      from: '/admin/scep',
      secret: true,
      what: 'SCEP challenge passwords issued for this application, one JSON ' +
            'record each: the id, a SHA-256 digest of the secret, the profile, ' +
            'the expiry and when it was redeemed. WITHHELD from every page and ' +
            '/admin-api reply.' },
    { name: 'appCertificateHostName', kind: 'multi',
      from: '/admin/acme, /admin/est, /admin/scep',
      what: 'A DNS name or IP address this application may be issued a ' +
            'certificate for over ACME, EST or SCEP. Registering one is the ' +
            'whole proof of control: this service never dials a name to ' +
            'validate it. Set by an administrator; read by ' +
            'common/cert_enrollment.ts.' },
    { name: 'appRegistrationJson', kind: 'single',
      from: 'POST /oauth2/register',
      what: 'THE RFC 7591 REGISTRATION VERBATIM, as JSON on one attribute. ' +
            'It is here because RFC 7591 lets a client register arbitrary ' +
            'metadata and RFC 7592\'s read has to hand back what was ' +
            'registered — which no fixed set of LDAP attributes can ' +
            'represent. It is the STARTING POINT when the record is ' +
            'reconstructed and not the last word: every member that also has ' +
            'an attribute above is then overwritten FROM that attribute, so ' +
            'an ldapmodify of oauthRedirectUri is what RFC 9700 mode ' +
            'enforces. Edit this only to change a member that has no ' +
            'attribute of its own.' },
    { name: 'appRegistrationAccessToken', kind: 'single', from: 'POST ' +
        '/oauth2/register',
      sensitive: true,
      what: 'The RFC 7592 registration access token, which is what guards ' +
            'the read, update and delete operations on this client. In the ' +
            'clear for the same stated reason oauthClientSecret is, and ' +
            'never written to the audit log.' },
    { name: 'oid4vpClientId', kind: 'multi', from: 'OpenID4VP',
      identifier: true,
      identifierName: 'client_id',
      what: 'THE VERIFIER\'S CLIENT_ID in an Authorization Request asking ' +
            'for a presentation — OpenID4VP\'s identifier attribute. This ' +
            'service\'s own mock Verifier takes its from configuration ' +
            '(oid4vp.clientId) rather than from a caller, so that record ' +
            'appears the first time a presentation is verified; a value ' +
            'declared here is a FOREIGN verifier somebody is configuring.' },

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
    { name: 'federationPartnerId', kind: 'multi', from: 'the console, or by ' +
                                                        'hand',
      identifier: true,
      identifierName: 'partner id',
      what: 'WHAT A FEDERATION PARTNER CALLS ITSELF — a foreign identity ' +
            'provider\'s entityID, or its issuer identifier where the ' +
            'relationship speaks OpenID Connect. THE RELATIONSHIP IS NOT ' +
            'HERE: the endpoints, the certificate and the attribute mapping ' +
            'live under ou=federations and are what /federation/acs/{id} ' +
            'actually verifies against (see federation/CLAUDE.md). This ' +
            'entry is the partner as a PARTY, and this attribute is the name ' +
            'it goes by — so a value here federates with nobody, which is ' +
            'the one place in this service where that sentence has teeth.' },
    { name: 'ldapBindDn', kind: 'multi', from: 'the console, or by hand',
      identifier: true,
      identifierName: 'bind DN',
      what: 'THE DN A DIRECTORY CLIENT BINDS AS on 389 or LDAPS 636. EVERY ' +
            'BIND HERE SUCCEEDS — any DN, any password, anonymous — so ' +
            'nothing will ever write this and nothing will ever read it; it ' +
            'is where an operator records which credential an application is ' +
            'expected to use, beside the rest of what that application is.' },
    { name: 'scimClientId', kind: 'multi', from: 'the console, or by hand',
      identifier: true,
      identifierName: 'client_id',
      what: 'WHAT A PROVISIONING CLIENT AT /scim/v2 IS CALLED — the OAuth ' +
            'client_id it presents a token from, or the username it sends in ' +
            'Basic. That surface authenticates its CALLER in any of the six ' +
            'schemes RFC 7644 section 2 names rather than an application ' +
            'identifier, so it writes nothing here; the value is a ' +
            'declaration, and the SCIM gate is what decides whether a ' +
            'credential is demanded at all.' },
    { name: 'ssfReceiverId', kind: 'multi',
      from: 'SSF, the console, or by hand',
      identifier: true,
      identifierName: 'receiver id',
      what: 'WHAT A SHARED SIGNALS RECEIVER IS CALLED — whatever it ' +
            'authenticated as when it created a stream at /ssf/stream, which ' +
            'is also the `aud` of every Security Event Token that stream ' +
            'carries. Unlike the four declaration-only identifiers above it, ' +
            'this one IS written by the protocol: creating a stream records ' +
            'a sighting, because a receiver authenticating and being agreed ' +
            'a stream is exactly the kind of event this registry exists to ' +
            'hold. It still grants nothing — a stream is what decides what a ' +
            'receiver gets, and it carries its own audience.' },
    { name: 'ssfDeliveryEndpoint', kind: 'multi', from: 'the console, or by ' +
                                                        'hand',
      what: 'WHERE THIS RECEIVER EXPECTS ITS EVENTS PUSHED — an RFC 8935 ' +
            'delivery endpoint. It is a DECLARATION and nothing reads it: a ' +
            'push goes to the endpoint on the STREAM, which the receiver ' +
            'named when it created one, and this service will not take a URL ' +
            'to dial from an application entry. That is the same position ' +
            'federation/federation_http.ts takes about oauthJwksUri, one ' +
            'family along: a URL recorded here is a note about what a ' +
            'receiver is, and a URL on a stream is a URL this service opens ' +
            'a connection to. The two are deliberately not the same store.' },
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
    { name: 'ssfAllowedEvents', kind: 'multi',
      from: 'the console, the management API, or by hand',
      families: ['ssf'],
      familyWhy: 'It limits which Security Event Tokens a stream owned by ' +
        'this application is sent, so on an entry declared for no Shared ' +
        'Signals family it would sit there reading like a limit that was in ' +
        'force.',
      what: 'WHICH SHARED SIGNALS EVENT TYPES A STREAM OWNED BY THIS ' +
            'APPLICATION MAY BE SENT. One value per line, each either a ' +
            'whole profile — `caep` (the eight session events) or `risc` ' +
            '(the fourteen account events) — or one event type URI, such as ' +
            'https://schemas.openid.net/secevent/caep/event-type/session-revoked. ' +
            'EMPTY MEANS UNRESTRICTED. SSF\'s own verification and ' +
            'stream-updated events are always allowed. It is ENFORCED twice: ' +
            'a stream this application creates or updates is agreed only the ' +
            'types allowed here (anything else it asked for is absent from ' +
            '`events_delivered`, and the stream\'s log says why), and every ' +
            'delivery checks it again, so removing a value stops existing ' +
            'streams receiving that type. The owner is whoever authenticated ' +
            'to /ssf/stream, matched against this entry\'s identifier or its ' +
            'ssfReceiverId values.' },
    // ---------------------------------------------------------------------
    // GNAP (RFC 9635 + RFC 9767), 2026-09-12. See gnap/CLAUDE.md.
    // ---------------------------------------------------------------------
    { name: 'gnapInstanceId', kind: 'single', from: 'the console, or by hand',
      identifier: true,
      identifierName: 'GNAP instance identifier',
      what: 'A STATIC instance identifier (RFC 9635 section 2.3.1): the ' +
            'string a client sends as `client` in place of its key. The key ' +
            'it must then prove is gnapKey or gnapKeyReference on this ' +
            'entry. Dynamic identifiers the authorization server hands out ' +
            '(section 3.5) are not written here.' },
    { name: 'gnapKey', kind: 'single', from: 'GNAP (on first sight, ' +
                                             'development), the console, or ' +
                                             'by hand',
      what: 'The client instance\'s or resource server\'s PUBLIC key, as the ' +
            'JSON key object of RFC 9635 section 7.1: a proof method and ' +
            'exactly one of jwk, cert or cert#S256. It is how a request by ' +
            'value is matched to this entry, by the key\'s thumbprint.' },
    { name: 'gnapKeyIdentity', kind: 'single', from: 'GNAP',
      what: 'The thumbprint identity of gnapKey (jkt:... for a JWK, x5t:... ' +
            'for a certificate), written when GNAP creates the entry so the ' +
            'key can be found without re-reading it.' },
    { name: 'gnapKeyReference', kind: 'single', from: 'the console, or by hand',
      what: 'A KEY REFERENCE (RFC 9635 section 7.1.1): the opaque string a ' +
            'client sends as `key`. It resolves to gnapSymmetricKey when ' +
            'that is set, and to gnapKey otherwise.' },
    { name: 'gnapKeyProof', kind: 'single', from: 'the console, or by hand',
      what: 'The proofing method a key reference is bound to (section 7.1.1: ' +
            '"MUST be bound to a single proofing mechanism"): httpsig, jwsd ' +
            'or jws. Default httpsig.' },
    { name: 'gnapSymmetricKey', kind: 'single', from: 'the console, or by hand',
      sensitive: true,
      what: 'A SHARED SECRET for a key reference, base64url, at least 32 ' +
            'bytes — the one case GNAP allows a symmetric key, because it ' +
            'never crosses the wire (section 7.1.2). Sealed with the ' +
            'key-encryption key when keys persist, withheld from LDAP ' +
            'readers in product mode.' },
    { name: 'gnapSymmetricAlg', kind: 'single', from: 'the console, or by hand',
      what: 'The algorithm a shared secret signs with: HS256 (default), ' +
            'HS384 or HS512 for jwsd and jws; hmac-sha256 for httpsig.' },
    { name: 'gnapClassId', kind: 'single',
      from: 'GNAP, the console, or by hand',
      what: 'The client software\'s class_id (section 2.3). A registered ' +
            'value takes precedence over the one a request carries.' },
    { name: 'gnapDisplayUri', kind: 'single', from: 'GNAP, the console, or ' +
                                                    'by hand',
      what: 'The client\'s display.uri, shown on the approval page (section ' +
            '2.3.2).' },
    { name: 'gnapLogoUri', kind: 'single',
      from: 'GNAP, the console, or by hand',
      what: 'The client\'s display.logo_uri. Only a data: image is drawn; ' +
            'any other URI is shown as a link (section 11.16).' },
    { name: 'gnapFinishUri', kind: 'multi', from: 'GNAP (observed, ' +
                                                  'development), the ' +
                                                  'console, or by hand',
      what: 'An INTERACTION FINISH URI (section 2.5.2) this client may be ' +
            'sent back to or pushed to. A return address: in product mode a ' +
            'finish URI not listed here is refused.' },
    { name: 'gnapInteractionStartModes', kind: 'multi', from: 'the console, ' +
        'or by hand',
      what: 'The interaction start modes this client may use (redirect, app, ' +
            'user_code, user_code_uri). Empty means every mode the ' +
            'authorization server offers.' },
    { name: 'gnapAllowedAccess', kind: 'multi', from: 'the console, or by hand',
      what: 'The access types and reference strings this client may request, ' +
            'or this resource server may register. Empty means any.' },
    { name: 'gnapBearerTokens', kind: 'single', from: 'the console, or by hand',
      what:
        'FALSE refuses the bearer flag for this client with invalid_flag.' },
    { name: 'gnapSkipInteraction', kind: 'single', from: 'the console, or by ' +
        'hand',
      what: 'TRUE makes this a TRUSTED client instance (section 2.3.3): a ' +
            'grant that asks for no subject information is approved with no ' +
            'resource owner and no interaction, and one carrying a verified ' +
            'user assertion is approved for that person. Honoured only for a ' +
            'registered entry, never one GNAP created on sight.' },
    { name: 'gnapAccessTokenFormat', kind: 'single', from: 'the console, or ' +
        'by hand',
      what: 'The RFC 9767 token format for tokens issued to this client, or ' +
            'for this resource server: jwt-signed, jwt-encrypted, macaroon, ' +
            'biscuit or zcap.' },
    { name: 'gnapAccessTokenLifetimeS', kind: 'single', from: 'the console, ' +
        'or by hand',
      overrides: 'gnap.accessTokenLifetimeS',
      what: 'The lifetime in seconds of access tokens issued to this client.' },
    { name: 'gnapResourceServerUri', kind: 'multi', from: 'the console, or ' +
        'by hand',
      what: 'The locations this resource server answers for. An access right ' +
            'whose locations start with one of these is audienced to this ' +
            'entry, and a token for it is minted with this resource ' +
            'server\'s format, JWE key and macaroon key.' },
    { name: 'gnapJweKey', kind: 'single', from: 'the console, or by hand',
      what: 'This resource server\'s PUBLIC encryption key (a JWK) for ' +
            'jwt-encrypted tokens, so only this resource server can read ' +
            'them.' },
    { name: 'gnapMacaroonKey', kind: 'single', from: 'GNAP',
      sensitive: true,
      what: 'The macaroon ROOT KEY this resource server verifies its ' +
            'macaroon tokens with, base64url. Written by the authorization ' +
            'server when the resource server first registers a resource set; ' +
            'sealed with the key-encryption key when keys persist.' },
    { name: 'gnapScopedSignals', kind: 'single',
      from: 'the console, or by hand',
      what: 'FALSE opts this web application out of Shared Signals scoping: ' +
            'a stream it owns then carries events about everybody, like any ' +
            'other receiver\'s.' },
    { name: 'spiffeWorkloadId', kind: 'multi', from: 'the console, or by hand',
      identifier: true,
      identifierName: 'SPIFFE ID',
      what: 'A SPIFFE ID this application is expected to hold — ' +
            'spiffe://<trust domain>/<path>. A SPIFFE identity gets an entry ' +
            'of its OWN under ou=spiffe (see spiffe/CLAUDE.md) and the ' +
            'registry there is what an SVID is actually issued against, so ' +
            'this writes nothing and reads nothing: it is the link between ' +
            'an application in this registry and an identity in that one, ' +
            'said by hand because no protocol says it.' },

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
    { name: 'appFederationRelationship', kind: 'multi',
      from: 'the console, the management API, or by hand',
      what: 'THE FEDERATION RELATIONSHIPS THIS APPLICATION\'S USERS ARE ' +
            'AUTHENTICATED THROUGH — each value the `fedId` of an entry ' +
            'under ou=federations, in THIS trust realm, whose `fedRole` is ' +
            'service-provider. Both halves of that are checked when it is ' +
            'read rather than when it is written: an identity-provider-side ' +
            'relationship goes the other way (this service asserts to that ' +
            'partner, so there is nothing to sign in to), and the register ' +
            'is per realm, so an id that names a relationship in another ' +
            'realm names nothing here.\n\nIT HOLDS A LIST, and that is what ' +
            'makes an application able to offer more than one identity ' +
            'provider. ONE usable value with the auto-redirect on is the ' +
            'case this attribute was added for and it is unchanged: the ' +
            'browser goes straight to that partner. SEVERAL usable values ' +
            'draw /authn/select-idp, where the person chooses which one — ' +
            'home realm discovery narrowed to this application\'s partners ' +
            'rather than performed against every relationship this service ' +
            'has. They need not share a protocol: a SAML 2.0 partner and an ' +
            'OpenID Connect one are two values here and two buttons there, ' +
            'because what the list names is where a person can be ' +
            'authenticated and not how.\n\nA value that names a relationship ' +
            'this service cannot use is REPORTED on the screen rather than ' +
            'dropped, one line per value: a list of three whose middle entry ' +
            'is disabled must not look like a list of two.\n\nIt is WRITTEN ' +
            'BY NOBODY. No protocol presents it and no sighting derives it — ' +
            'an application\'s home identity provider is an arrangement ' +
            'somebody made, not something this service can observe — so it ' +
            'is editable and it starts empty.' },
    { name: 'appFederationAutoRedirect', kind: 'single',
      from: 'the console, the management API, or by hand',
      what: 'TRUE if a person signing in to this application should be sent ' +
            'STRAIGHT to the partner named above, without the sign-in screen ' +
            'in between. This is home realm discovery done by configuration ' +
            'instead of by asking, which is what a deployment with one ' +
            'federated identity provider actually does.\n\nIt is TRUE BY ' +
            'DEFAULT once a relationship is named, because naming one and ' +
            'then having to click a button is the state nobody wants; set it ' +
            'FALSE to keep the screen, where the partners are then the only ' +
            'buttons offered. An absent value therefore means "yes" here and ' +
            'not "unknown", which is the opposite of what RFC 7591 section 2 ' +
            'makes an omitted boolean mean — said out loud because the two ' +
            'rules meet on one entry.\n\nWITH SEVERAL RELATIONSHIPS NAMED IT ' +
            'MEANS EXACTLY WHAT IT ALWAYS MEANT — "without the sign-in ' +
            'screen" — and what changes is what that leaves. With one it is ' +
            'a redirect straight to the partner. With several it is the ' +
            'chooser at /authn/select-idp: one button per partner and no ' +
            'password field, which is the sign-in screen\'s job done without ' +
            'the sign-in screen. What it never means is "pick one for them"; ' +
            'there is no value of a boolean that can say which identity ' +
            'provider somebody\'s employer is.\n\nFALSE with several named ' +
            'is therefore the SCREEN, with one button per partner under the ' +
            'password box — the same thing FALSE has always done, with the ' +
            'partners plural.\n\nWith no relationship named it does nothing ' +
            'at all, rather than being an error: the two are edited ' +
            'separately and a value left behind by a relationship that was ' +
            'cleared should not refuse the next write.' },

    // ---------------------------------------------------------------------
    // AND THE THIRD, WHICH GENERALISES THE PAIR ABOVE IT.
    //
    // The two attributes above can say "send my people to a federated
    // identity provider" and cannot say anything else, because until
    // 2026-08-26 there was nothing else to say: every way of authenticating
    // somebody here was either this service's own screen or somebody else's
    // service. The SPNEGO sign-in is neither — it is a credential the
    // browser already holds — so an application had no way to ask for the
    // commonest integrated-authentication deployment there is.
    //
    // ITS VOCABULARY IS THE FEDERATION REGISTER'S, and deliberately the same
    // one: `password`, `password-mfa`, `webauthn`, `spnego`, `federation`,
    // which is `fedAuthnMechanism`'s list exactly. Two tables would have
    // drifted the first time either grew a value, and the two attributes
    // answer the same question from two sides — this one says where THIS
    // APPLICATION's people sign in, and that one says what to do when THAT
    // PARTNER asks. **The list is not imported here**, which is worth saying
    // rather than looking like an oversight: `federation.js` requires this
    // file, so a require back would close a cycle. It is checked where it is
    // READ instead — `authn.js`'s declaredMechanismFor() — which is where
    // `appFederationRelationship`'s four checks are made too, and for the same
    // reason: this is a string on a directory entry that `ldapmodify` can
    // reach, so a check made at the write would be a check about the past.
    //
    // AN EMPTY VALUE IS NOT `password`. It means this entry says nothing, and
    // that is the whole compatibility argument: every entry in existence holds
    // an empty one, and reading it as an explicit "use the password screen"
    // would have switched off every appFederationRelationship in the field in
    // one commit.
    //
    // LIKE THE PAIR ABOVE IT, IT IS NOT A PERMISSION. Nothing refuses a person
    // who reaches the sign-in screen by another route, nothing refuses the
    // Kerberos door to an application that has not declared it — the button is
    // on the screen for everybody — and clearing this takes the shortcut away
    // rather than locking anybody out. What it changes is the DEFAULT ROUTE.
    // ---------------------------------------------------------------------
    { name: 'appAuthnMechanism', kind: 'single',
      from: 'the console, the management API, or by hand',
      what: 'HOW THIS APPLICATION\'S USERS AUTHENTICATE, one value from the ' +
            'same closed list fedAuthnMechanism uses: password, ' +
            'password-mfa, webauthn, spnego, wallet, federation.\n\nIt is ' +
            'the ' +
            'generalisation of appFederationRelationship beside it, and the ' +
            'value that could not be said before it existed is `spnego` — ' +
            'INTEGRATED AUTHENTICATION, where this application\'s people are ' +
            'sent to /authn/spnego and signed in on the Kerberos ticket ' +
            'their machine already holds, with no screen drawn and nothing ' +
            'typed. That is the one mechanism here resting on a credential ' +
            'this service genuinely verifies.\n\n`wallet` (2026-09-17) ' +
            'sends them to /authn/wallet instead, where their wallet ' +
            'presents a credential this realm issued them and they are ' +
            'signed in as the entry it was issued for — asked for a second ' +
            'factor afterwards where the request demands two.\n\n' +
            '`federation` means the ' +
            'relationships named in appFederationRelationship, which is what ' +
            'naming one already implied, said out loud — so it changes ' +
            'nothing, and declaring it while naming NO usable relationship ' +
            'is reported on the sign-in screen rather than falling quietly ' +
            'back to a password box. `password`, `password-mfa` and ' +
            '`webauthn` are the sign-in screen, in the three shapes it ' +
            'has.\n\nEMPTY MEANS THIS ENTRY SAYS NOTHING, which is not the ' +
            'same as password: it falls through to appFederationRelationship ' +
            'and then to the screen, which is exactly what every application ' +
            'did before this attribute existed.\n\nA value this service ' +
            'cannot honour — a mechanism it does not have, `spnego` while ' +
            'krb5.spnegoAuthentication is off, or `wallet` while ' +
            'oid4vp.signIn is off — is REPORTED on the screen, ' +
            'one line, rather than dropped. A configured mechanism that ' +
            'silently is not happening looks exactly like one that is.\n\nIt ' +
            'is WRITTEN BY NOBODY. No protocol presents it and no sighting ' +
            'derives it, so it is editable and it starts empty.' }
  ]
};

// ---------------------------------------------------------------------------
// WHAT A CONSOLE MAY CHANGE, which is a different question from what an entry
// carries and is therefore a table of its own rather than a field on the rows
// above.
//
// The distinction is DERIVED versus DECLARED. An application entry holds both
// kinds and they must not be edited alike:
//
//   * DECLARED — what this application IS allowed to do. Its redirect URIs, its
//     grant types, its secret, whether it is confidential. Nothing about them
//     is a fact about the past; they are configuration, they are what RFC 9700
//     mode READS, and being able to change them is the point of having a
//     registry at all. These are editable.
//
//   * DERIVED — what HAPPENED. The counters, the first and last sighting, the
//     kinds and protocols it has been seen in, the redirect URIs it has
//     actually used. A form that could rewrite those would make this page lie
//     about the service's own behaviour, and the lie would be indistinguishable
//     from a bug in the recording. These are not editable here.
//
// LDAP can still change every one of them — this directory enforces nothing and
// `ldapmodify` reaches any attribute on any entry. That is not an inconsistency
// to fix: an operator with an LDAP client is doing something deliberate, and
// the console is a set of controls somebody clicks. Refusing the derived ones
// HERE is the difference between offering an operation and merely not
// preventing it.
//
// `set` replaces (single-valued), `multi` adds and removes values. The mode has
// to match the attribute's own `kind` or the entry ends up with a list where
// the schema promises one value, so both are read from these two tables and
// never from a caller.
// ---------------------------------------------------------------------------
const EDITABLE = {
  appName: 'set',
  // DECLARED, which is the whole of why it is here and `appProtocol` is not.
  // See the PROTOCOLS table above: one of those two attributes is what somebody
  // said this application is for and the other is what happened to it.
  appAllowedProtocol: 'multi',
  // `multi` for `oauthClientId`'s reason read the other way: an application
  // that will admit either of two roles is one application, and a `set` here
  // would replace the list with one value and read afterwards as the others
  // having been deliberately withdrawn — which, on the one attribute here
  // that REFUSES people, is the failure worth designing against.
  appRequiredRole: 'multi',
  // THE IDENTIFIER ATTRIBUTES, one per protocol family (see the PROTOCOLS
  // table). Every one of them is `multi` bar oauthTlsClientAuthSubjectDn below,
  // whose own row says why — an application answering to two client_ids or two
  // SPNs is one application, and a `set` here would replace the list with one
  // value and read afterwards as the others having been forgotten.
  oauthClientId: 'multi',
  // THE AUDIENCE, which is the identifier from the OTHER side: what a token
  // addressed to this application says in `aud`, rather than what the
  // application calls itself at the token endpoint. `multi` because a per-
  // environment hostname is the ordinary case, and because it is the one
  // attribute here something LOOKS UP — see forAudience(), and the row in
  // SCHEMA, where the difference between a lookup and a permission is spelled
  // out.
  oauthAudience: 'multi',
  oauthClientSecret: 'set',
  oauthClientSecretPrevious: 'set',
  oauthClientSecretPreviousUntil: 'set',
  oauthClientSecretExpiresAt: 'set',
  oauthTokenEndpointAuthMethod: 'set',
  // OIDC Core sections 8 and 9 (#118). One answer each.
  oauthSubjectType: 'set',
  oauthSectorIdentifierUri: 'set',
  oauthTokenEndpointAuthSigningAlg: 'set',
  oauthJwks: 'set',
  oauthJwksUri: 'set',
  // RFC 9701's three. `set`, because each holds one algorithm.
  oauthIntrospectionSignedResponseAlg: 'set',
  oauthIntrospectionEncryptedResponseAlg: 'set',
  oauthIntrospectionEncryptedResponseEnc: 'set',
  // RFC 9101's five. The request URIs accumulate, like redirect URIs; the
  // other four hold one answer each.
  oauthRequestUri: 'multi',
  oauthRequestObjectSigningAlg: 'set',
  oauthRequestObjectEncryptionAlg: 'set',
  oauthRequestObjectEncryptionEnc: 'set',
  oauthRequireSignedRequestObject: 'set',
  // RFC 9126's one. It holds one answer.
  oauthRequirePushedAuthorizationRequests: 'set',
  // RFC 9396's two. Both accumulate: a resource understands several types, and
  // a client uses several.
  oauthAuthorizationDetailsType: 'multi',
  oauthAuthorizationDetailsTypes: 'multi',
  // RFC 9470's two. Each holds one answer: the acr values are one ordered
  // list in one value, because a directory's multi-valued attribute has no
  // order and the order is the preference.
  oauthStepUpAcrValues: 'set',
  oauthStepUpMaxAge: 'set',
  // RFC 7521 / RFC 7523. The declaration is `multi` like every other
  // identifier attribute here — one application legitimately asserts under a
  // per-environment issuer name, and a `set` would replace the list with one
  // value and read afterwards as the others having been forgotten. The six the
  // PKI page writes are `set`, because each holds ONE answer and a list of two
  // private keys has no rule for which signs.
  oauthAssertionIssuer: 'multi',
  oauthAssertionJwks: 'set',
  oauthAssertionCertificate: 'set',
  oauthAssertionCertificateChain: 'set',
  oauthAssertionPrivateKey: 'set',
  oauthAssertionKid: 'set',
  oauthAssertionExpiresAt: 'set',
  // WHERE THE KEY PAIR CAME FROM (2026-09-13) — issued here, or a certificate
  // uploaded in its place. `set` for the six's reason, and in this table at
  // all because `admin-ui/pki_admin.ts` writes it through updateApplication()
  // beside them; KEY_SOURCES below is the closed vocabulary it is checked
  // against.
  oauthAssertionKeySource: 'set',
  // RFC 7522's seven, the same two kinds for the same two reasons: the
  // declaration accumulates and the five the PKI page writes each hold ONE
  // answer. The REGISTERED certificate is `set` and not `multi` because
  // several PEM blocks go in ONE value — a certificate rotation is two blocks
  // in one attribute, not two attribute values, so that the whole of what a
  // party may sign with is replaced in one write.
  oauthSamlAssertionIssuer: 'multi',
  oauthSamlAssertionSigningCertificate: 'set',
  oauthSamlAssertionCertificate: 'set',
  oauthSamlAssertionCertificateChain: 'set',
  oauthSamlAssertionPrivateKey: 'set',
  oauthSamlAssertionThumbprint: 'set',
  oauthSamlAssertionExpiresAt: 'set',
  oauthSamlAssertionKeySource: 'set',
  // RFC 7591 section 2.3 (2026-09-13). The declaration accumulates like every
  // issuer declaration here; the issued statement is ONE value, replaced by
  // the next issue. The three `appSoftwareStatement*` facts are what a
  // registration recorded and are not here.
  oauthSoftwareStatementIssuer: 'multi',
  oauthIssuedSoftwareStatement: 'set',
  oauthTlsClientAuthSubjectDn: 'set',
  // RFC 8705's other four subject parameters and the section 3.4 flag
  // (2026-09-13). Checked on the way in by mtlsAttributeProblem().
  oauthTlsClientAuthSanDns: 'set',
  oauthTlsClientAuthSanUri: 'set',
  oauthTlsClientAuthSanIp: 'set',
  oauthTlsClientAuthSanEmail: 'set',
  oauthTlsClientCertificateBoundAccessTokens: 'set',
  oauthTlsClientCertificateThumbprint: 'set',
  oauthConfidential: 'set',
  appRegistrationAccessToken: 'set',
  samlEntityId: 'multi',
  // DECLARED, both of them, which is why they are here and the four SAML
  // attributes beside them are not: where a LogoutResponse goes and which
  // certificate the service provider signs with are configuration, and the
  // NameID formats it has asked for and whether its last request was signed
  // are what HAPPENED.
  // `multi` since 2026-09-17 (#37): a rollover publishes two keys.
  samlSigningCertificate: 'multi',
  samlSingleLogoutService: 'multi',
  samlSpMetadataSigningCertificate: 'set',
  // THE TEN PER-APPLICATION SETTING OVERRIDES. Every one is `set`, for the
  // reason their SCHEMA rows give: a setting has one answer, and `multi` would
  // accumulate two values with no rule for which won. They are editable
  // because nothing observes them — like samlSingleLogoutService above, if
  // they cannot be written here they cannot be written at all.
  saml2AssertionLifetimeMin: 'set',
  saml2SignAssertion: 'set',
  saml2SignResponse: 'set',
  saml2NameIdFormat: 'set',
  saml2ArtifactTtlS: 'set',
  saml11AssertionLifetimeMin: 'set',
  saml11SignAssertion: 'set',
  saml11SignResponse: 'set',
  saml11NameIdFormat: 'set',
  saml11ArtifactTtlS: 'set',
  // The OAuth 2.0 / OIDC per-client five, the group claim's four and
  // WS-Federation's one. Same rule as the SAML ten above: `set`, because a
  // setting has one answer.
  oauthAccessTokenTtlS: 'set',
  oauthIdTokenTtlS: 'set',
  oauthRefreshTokenTtlS: 'set',
  oauthRefreshIdleSeconds: 'set',
  oauthRevokeRefreshOnLogout: 'set',
  // The sixth, and the first whose row carried `families`. Editable like the
  // five above it and refused on an entry declared for neither OAuth 2.0 nor
  // OpenID Connect — see familyRefusal(), and the block above the row itself.
  oauthTokenExchangeRefreshToken: 'set',
  appGroupsClaim: 'set',
  appGroupsClaimName: 'set',
  appGroupsClaimValue: 'set',
  appGroupsClaimFromMemberOf: 'set',
  wsfedAssertionLifetimeMin: 'set',
  // SAML 2.0 encryption: three that say where the recipient's key comes from,
  // and four setting overrides. All `set` — one answer each.
  samlSpMetadataUrl: 'set',
  samlSpMetadata: 'set',
  samlEncryptionCertificate: 'set',
  saml2EncryptAssertion: 'set',
  saml2EncryptionAlgorithm: 'set',
  saml2KeyTransportAlgorithm: 'set',
  saml2EncryptLogoutNameId: 'set',
  wsfedRealm: 'multi',
  wstrustAppliesTo: 'multi',
  krb5ServicePrincipalName: 'multi',
  oid4vpClientId: 'multi',
  // The four that are ONLY ever declared — nothing in this service writes them.
  federationPartnerId: 'multi',
  // And the pair that IS read, by authn.js, on the way to the sign-in screen.
  // Editable for the reason the rest of the declared half is: nothing observes
  // an application's home identity provider, so if this cannot be written here
  // it cannot be written at all. `multi` since 2026-08-26, and it used to be
  // `set`. An application may name SEVERAL service-provider-side relationships
  // — a SAML 2.0 partner and an OpenID Connect one are an ordinary pair — and
  // the person picks between them at /authn/select-idp. A `set` here would
  // replace the list with one value and read afterwards as the others having
  // been forgotten, which is the same argument every other identifier attribute
  // above makes.
  appFederationRelationship: 'multi',
  appFederationAutoRedirect: 'set',
  // And the THIRD of that group, added 2026-08-26. Editable for the same
  // reason the other two are: nothing in this service can OBSERVE how an
  // application's people are supposed to authenticate, so if it cannot be
  // written here it cannot be written at all. `set` and not `multi` — an
  // application has one answer to "how do my people sign in", and a list would
  // be a question this attribute has no page to ask.
  appAuthnMechanism: 'set',
  // The home page, `set` for its row's reason: an application has one. It is
  // editable AND written by register() from RFC 7591 `client_uri`, which is the
  // same arrangement oauthRedirectUri has — a registration states it, and an
  // entry nobody registered has no other way to acquire one.
  appHomePageUrl: 'set',
  // The CORS allowlist, `multi` because an application is served from several
  // origins as an ordinary matter — a per-environment host, a local
  // development server beside the deployed one.
  appCorsOrigin: 'multi',
  ldapBindDn: 'multi',
  scimClientId: 'multi',
  spiffeWorkloadId: 'multi',
  // The Shared Signals pair. `ssfReceiverId` is the one identifier here that a
  // PROTOCOL also writes — creating a stream records a sighting — so it is
  // `multi` like every other accumulating identifier; the delivery endpoint is
  // declaration only, and `multi` because a receiver legitimately runs one per
  // environment.
  ssfReceiverId: 'multi',
  ssfDeliveryEndpoint: 'multi',
  ssfAllowedEvents: 'multi',
  // GNAP. `gnapKeyIdentity` and `gnapMacaroonKey` are the authorization
  // server's to write and are deliberately absent: an identity that disagreed
  // with gnapKey, or a macaroon key that was not the derived one, would be an
  // entry that verified nothing.
  gnapInstanceId: 'set',
  gnapKey: 'set',
  gnapKeyReference: 'set',
  gnapKeyProof: 'set',
  gnapSymmetricKey: 'set',
  gnapSymmetricAlg: 'set',
  gnapClassId: 'set',
  gnapDisplayUri: 'set',
  gnapLogoUri: 'set',
  gnapFinishUri: 'multi',
  gnapInteractionStartModes: 'multi',
  gnapAllowedAccess: 'multi',
  gnapBearerTokens: 'set',
  gnapSkipInteraction: 'set',
  gnapAccessTokenFormat: 'set',
  gnapAccessTokenLifetimeS: 'set',
  gnapResourceServerUri: 'multi',
  gnapJweKey: 'set',
  gnapScopedSignals: 'set',
  oauthRedirectUri: 'multi',
  oauthPostLogoutRedirectUri: 'multi',
  oauthFrontchannelLogoutUri: 'set',
  oauthFrontchannelLogoutSessionRequired: 'set',
  oauthBackchannelLogoutUri: 'set',
  oauthBackchannelLogoutSessionRequired: 'set',
  oauthGrantType: 'multi',
  oauthResponseType: 'multi',
  oauthScope: 'multi',
  // DECLARED (#110): what the client may be issued. See its SCHEMA row.
  oauthAllowedScope: 'multi',
  // THE THREE THAT MAKE A DELEGATED PERMISSION. Two `multi` and one `set`, and
  // each mode is the attribute's own kind read back: a base URI is one answer
  // per application (its own row says why widening it would mean deciding
  // which of two identifiers a token is audienced to), and both lists
  // accumulate because an application legitimately exposes six permissions and
  // holds four.
  //
  // THEY ARE THE ONLY EDITABLE ATTRIBUTES HERE WITH A CROSS-ENTRY RULE, and it
  // is checked in updateApplication() rather than in the console: a permission
  // must be DEFINED before it can be GRANTED, and the check has to sit where
  // both doors go through it or the form and `POST
  // /admin-api/applications/update` would hold two opinions about the same
  // relationship. Same argument as `appAllowedProtocol`'s closed vocabulary two
  // hundred lines up, and the same asymmetry: only an ADD is checked, because a
  // REMOVE has to name a value the entry already carries and refusing to remove
  // what LDAP put there would shut the one door that could tidy it up.
  oauthPermissionBaseUri: 'set',
  oauthPermission: 'multi',
  oauthDelegatedPermission: 'multi',
  oauthGlobalConsent: 'multi',
  // The RFC 9728 document an entry was created from, and where it came from.
  // Declared and not read; see the two SCHEMA rows.
  oauthResourceMetadata: 'set',
  oauthResourceMetadataUrl: 'set',
  samlAssertionConsumerService: 'multi',
  // WS-Federation's return address, which used to be recorded in the attribute
  // above. Its own row says why the two were split.
  wsfedReplyUrl: 'multi',
  wsfedSignOutUri: 'multi',
  description: 'multi'
};

// Merged onto the rows so that one table answers "what is this attribute?" and
// "may I change it?" — the console builds its two selects from it and the
// action validates against the same thing, which is what stops a form offering
// a field the action would refuse.
SCHEMA.attributes.forEach(function (row) {
  row.editable = EDITABLE[row.name] || false;
});

const ATTRIBUTE_BY_NAME = {};
SCHEMA.attributes.forEach(function (row) {
  ATTRIBUTE_BY_NAME[row.name] = row;
});

function editableAttributes(mode) {
  log.debug("Entering editableAttributes().");
  log.debug("Leaving editableAttributes().");
  return SCHEMA.attributes.filter(function (row) {
    return mode ? row.editable === mode : !!row.editable;
  });
}

// ---------------------------------------------------------------------------
// AN ATTRIBUTE THAT ONLY MEANS SOMETHING TO SOME FAMILIES, AND THE TWO
// FUNCTIONS THAT ARE THE WHOLE MECHANISM.
//
// A SCHEMA row may carry `families: ['oauth2', 'oidc']`. Fifteen do today —
// `oauthTokenExchangeRefreshToken`, whose own block argues why it is the first,
// `ssfAllowedEvents` (2026-09-12), which carries its own `familyWhy` so the
// refusal names what IT does rather than the token endpoint, RFC 9701's three
// `oauthIntrospection*` attributes (2026-09-13), each with its own, and the
// RFC 9101, RFC 9126, RFC 9396 and RFC 9470 attributes of the same day — and
// the rule it declares is that the attribute may be WRITTEN only onto an entry
// declared for at least one of those families.
//
// IT IS A TABLE AND NOT A SPECIAL CASE, deliberately, and for the reason
// OVERRIDE_ATTRIBUTES is built from the rows rather than written out: a second
// family-scoped attribute must cost a member on its row and nothing else. The
// alternative — an `if (attribute === ...)` in updateApplication() beside the
// permission rules — would have been shorter today and would be the place the
// console's idea of what it may offer eventually disagrees with the action's.
//
// THE TEST IS `appAllowedProtocol` AND NOT `appProtocol`, which is the
// declared-versus-derived line EDITABLE's header draws, applied to a refusal.
// What somebody DECLARED the application is for is a statement they made and
// can change; what this service has SEEN it do is a fact about the past, and an
// application that has been ticked for OAuth 2.0 and has never yet made a
// request is exactly the entry somebody is configuring when they reach for
// this. Testing the derived attribute would refuse every write until after the
// first token request, which is the wrong way round.
// ---------------------------------------------------------------------------
function declaredFamiliesOf(record) {
  log.debug("Entering declaredFamiliesOf().");
  log.debug("Leaving declaredFamiliesOf().");
  return valuesOf((record && record.fields || {}).appAllowedProtocol)
    .map(function (one) { return String(one).trim().toLowerCase(); })
    .filter(function (one) { return !!one; });
}

// '' when the write is allowed, and the sentence to refuse it with otherwise.
// `declared` is a list of family ids — from the entry for an update, and from
// what the create is about to write for a create, which is why it is a
// parameter rather than being read in here.
function familyRefusal(attributeName, declared, identifier) {
  log.debug("Entering familyRefusal(). attribute=" + attributeName);
  const row = ATTRIBUTE_BY_NAME[attributeName];
  if (!row || !row.families || !row.families.length) {
    log.debug("Leaving familyRefusal(). Not family-scoped.");
    return '';
  }
  const held = (declared || []).map(function (one) {
    return String(one).trim().toLowerCase();
  });
  const matched = row.families.filter(function (id) {
    return held.indexOf(id) >= 0;
  });
  if (matched.length) {
    log.debug("Leaving familyRefusal(). Declared for " + matched.join(', ') +
              ".");
    return '';
  }
  const labels = row.families.map(function (id) {
    const family = PROTOCOL_BY_ID[id];
    return family ? family.label : id;
  });
  log.debug("Leaving familyRefusal(). Refused.");
  return '"' + attributeName + '" applies to the ' + labels.join(' and ') +
         ' ' + (labels.length === 1 ? 'family' : 'families') + ', and "' +
         String(identifier) + '" is declared for ' +
         (held.length ? held.join(', ') : 'no family at all') + '. ' +
         (row.familyWhy || 'It decides what the TOKEN ENDPOINT does for one ' +
          'client_id, so on an entry no token request can ever name it would ' +
          'sit there looking like a policy that was in force.') + ' Add ' +
         labels.join(' or ') + ' to `appAllowedProtocol` first — that is the ' +
         'tick box on /admin/applications/new and the `protocols` member of ' +
         'the create — and then set this. An `ldapmodify` reaches the ' +
         'attribute like every other and is not checked.';
}

// ---------------------------------------------------------------------------
// THE ATTRIBUTES A DECLARATION IS MADE OF, ONE ROW PER ATTRIBUTE AND NOT ONE
// PER FAMILY.
//
// `/admin/applications/new` draws a field for each of these and `GET
// /admin-api/applications/new` publishes them, so the form and the document a
// caller reads to learn what it may send come off ONE walk of the PROTOCOLS
// table. Building the list in the console instead was the obvious thing and it
// is exactly the drift this module exists to prevent: the page would have had
// its own idea of which attribute a family's identifier goes in, and
// `createApplication()` would have had another.
//
// **IT IS DEDUPED BY ATTRIBUTE**, which is why there are fewer identifier
// rows than families (eleven for sixteen today). Three
// families name `oauthClientId` and two name `samlEntityId`, because the
// specifications genuinely share those identifiers — see the PROTOCOLS header —
// so a row carries the LIST of families it serves and the form says so under
// the field. Two inputs writing one attribute would be a form that silently
// dropped whichever the reader filled in second.
//
// The order is first appearance in the PROTOCOLS table, with a family's
// identifier ahead of its redirect URI, so the fields read in the order the
// checkboxes above them do.
// ---------------------------------------------------------------------------
function declarationAttributes() {
  log.debug("Entering declarationAttributes().");
  const rows = [];
  const byAttribute = {};
  function note(attribute, role, family) {
    log.debug("Entering note().");
    if (!attribute) {
      log.debug("Leaving note().");
      return;
    }
    const schemaRow = ATTRIBUTE_BY_NAME[attribute];
    if (!schemaRow) {
      // A family naming an attribute the schema does not have. It cannot be
      // written — setField() refuses it — so drawing a field for it would be
      // offering a control whose only outcome is a silent no. Warned rather
      // than thrown for the reason setField() warns: this is a table somebody
      // edited, and the service starting is more useful than it not.
      log.warn('applications: the protocol table names "' + attribute + '" ' +
               'as an attribute and SCHEMA.attributes has no such row. No ' +
               'field is offered for it. Add the row rather than removing ' +
               'the reference.');
      log.debug("Leaving note().");
      return;
    }
    if (!byAttribute[attribute]) {
      byAttribute[attribute] = {
        attribute: attribute,
        role: role,
        kind: schemaRow.kind,
        editable: schemaRow.editable,
        sensitive: !!schemaRow.sensitive,
        what: schemaRow.what,
        families: []
      };
      rows.push(byAttribute[attribute]);
    }
    byAttribute[attribute].families.push({ id: family.id,
                                           label: family.label });
    log.debug("Leaving note().");
  }
  PROTOCOLS.forEach(function (family) {
    note(family.identifierAttribute, 'identifier', family);
    note(family.redirectAttribute, 'redirect', family);
    // WHERE A SIGN-OUT GOES, for the four families that have one. SAML 1.1 is
    // the interesting absence and it is not an oversight: 1.1 has no Single
    // Logout at all — that arrived with SAML 2.0 — so a field for it would be
    // a control whose value nothing could ever read. The same is true of
    // WS-Trust, Kerberos, LDAP, SCIM, SPIFFE, mTLS and the two OID4VC
    // families, and of federation, which does not consume a federated
    // sign-out either.
    note(family.logoutAttribute, 'logout', family);
    // WHERE AN EVENT GOES, for the one family that has one. It is a fourth
    // ROLE rather than being folded into `redirectAttribute` above, and the
    // distinction is not pedantry: a redirect is where a BROWSER is sent back
    // to after a protocol hop, and this is a URL THIS SERVICE OPENS A
    // CONNECTION TO. Calling it a redirect would make a table this repository
    // reads literally say something false about the one attribute here with
    // an outbound request behind it.
    note(family.deliveryAttribute, 'delivery', family);
    // WHICH EVENTS A RECEIVER MAY BE SENT, for the same one family
    // (2026-09-12). A role of its own because it is the only attribute on this
    // walk that LIMITS a protocol rather than describing an application — see
    // the `ssfAllowedEvents` schema row.
    note(family.eventsAttribute, 'events', family);
    // The client secret, which only the two OAuth families have. It is on this
    // walk rather than being special-cased on the form for the reason the
    // redirect URI is: the form, `GET /admin-api/applications/new` and
    // `createApplication()`'s accepted set all read this one list, so a field
    // that exists on one of them exists on all three.
    note(family.secretAttribute, 'secret', family);
  });
  // THE CORS ORIGINS (2026-09-18) — the one declaration that belongs to NO
  // family, and so the one row this walk cannot reach through PROTOCOLS.
  //
  // `appCorsOrigin` configures CORS on EVERY endpoint this service publishes:
  // `common/cors.js` asks it for a request that names this application as its
  // client, whatever the family, and asks every application's list for one
  // that names nobody (discovery, a JWKS, a DID document, every preflight).
  // The schema row says so by carrying no `families`, and familyRefusal() lets
  // it through on an entry declared for nothing at all.
  //
  // IT WAS ON NO FORM UNTIL THIS ROW. `createApplication()` accepted it and
  // the management API took it — both read `fields` whole — but the create
  // form draws a section PER ROLE out of this list, and an attribute that was
  // not in the list was a field nobody could type into from the console. A
  // row here puts it in all three readers at once, which is the reason this
  // is a table rather than a form.
  //
  // `families: []` and `everyFamily: true`, rather than every family listed:
  // an empty list is what makes the form's section UNCONDITIONAL (a section
  // carries the union of its rows' families, and none means no `pf` class, so
  // it is shown whatever is ticked), and `everyFamily` is what lets a reader
  // tell "applies to all" from "applies to none" without inferring it.
  const cors = ATTRIBUTE_BY_NAME.appCorsOrigin;
  if (cors) {
    rows.push({ attribute: 'appCorsOrigin', role: 'cors', kind: cors.kind,
                editable: cors.editable, sensitive: !!cors.sensitive,
                what: cors.what, families: [], everyFamily: true });
  }
  log.debug("Leaving declarationAttributes(). " + rows.length + " " +
      "attribute(s) for " +
            PROTOCOLS.length + " family/families.");
  return rows;
}

const DECLARATION_ATTRIBUTE_NAMES = declarationAttributes().map(function (row) {
  return row.attribute;
});

// The identifier half of that table, computed ONCE rather than per call. Every
// caller of identifiersOf() below asks the same question of the same closed
// table, and declarationAttributes() walks PROTOCOLS and can WARN while it does
// — a page that asked it per box would print that warning once per box.
const IDENTIFIER_ATTRIBUTES = declarationAttributes().filter(function (row) {
  return row.role === 'identifier';
});

// ---------------------------------------------------------------------------
// WHAT THIS APPLICATION ANSWERS TO, AND WHAT EACH PROTOCOL CALLS THAT NAME.
//
// Added 2026-08-27 for the delegation pictures, which draw an application by
// the name somebody GAVE it — a `cn`, an `appName` — and until now said nowhere
// on the diagram what a protocol would have to present to reach that box. A
// rectangle labelled `Acme Web` is unusable in a request you are about to
// build; `client_id: acme-web` under it is the whole point of looking.
//
// **IT IS HERE RATHER THAN IN THE RENDERER**, and that is the rule this module
// already lives by: which attribute holds a family's identifier is the
// PROTOCOLS table's statement, and `identifierName` — what the specification
// spells it — is the SCHEMA row's. A picture that built either list for itself
// would be a second opinion about the store, and the first time a family was
// added it would be a second opinion that disagreed.
//
// Rows come back in table order and only where the entry actually carries a
// value, so an application that has only ever been an OAuth client gets ONE
// row rather than eleven, ten of them empty. The FAMILIES are labels rather
// than ids because the only caller prints them, and because several families
// share one attribute (see the PROTOCOLS header) — `oauthClientId` is the
// identifier of OAuth 2.0, OpenID Connect and OpenID4VCI at once, so naming
// only the first would be picking one of three true answers.
//
// It takes a `view()`, a record, or a bare fields object, because those are the
// three shapes a caller has in hand and making them convert first would put
// this module's own layout in the caller.
// ---------------------------------------------------------------------------
function identifiersOf(source) {
  log.debug("Entering identifiersOf().");
  const holder = source || {};
  const fields = holder.fields || holder;
  const rows = [];
  IDENTIFIER_ATTRIBUTES.forEach(function (row) {
    const values = valuesOf(fields[row.attribute]);
    if (!values.length) {
      return;
    }
    const schemaRow = ATTRIBUTE_BY_NAME[row.attribute];
    rows.push({
      attribute: row.attribute,
      // The protocol's own word for it. Falling back to the ATTRIBUTE rather
      // than to nothing: a row added to PROTOCOLS whose schema row forgot
      // `identifierName` should read as `oauthClientId: acme-web`, which is
      // ugly and correct, rather than as a bare value that says nothing about
      // what kind of name it is.
      name: (schemaRow && schemaRow.identifierName) || row.attribute,
      families: row.families.map(function (one) { return one.label; }),
      values: values
    });
  });
  log.debug("Leaving identifiersOf(). " + rows.length + " identifier " +
                                                        "attribute(s).");
  return rows;
}

// ---------------------------------------------------------------------------
// THE APPLICATION'S OWN HOME PAGE, AND THE ONE THING THAT MAY BE DONE WITH IT.
//
// Added 2026-09-10 with `appHomePageUrl`, whose schema row above argues why the
// fact is DECLARED rather than computed from the redirect URIs beside it.
// These two functions are the whole of the rule that value obeys.
//
// **`homePageProblem()` IS THE WRITE-TIME REFUSAL AND `homePageOf()` IS THE
// READ-TIME ONE, AND BOTH ARE NEEDED.** The doors that go through
// normaliseFields() and updateApplication() are checked, and `ldapmodify` on
// TCP 389 is not — it reaches this attribute exactly as it reaches every other
// one here, which is a property this directory has on purpose and which
// `ldap/CLAUDE.md` argues. So the reader checks again rather than trusting the
// store, because the one thing this service does with the value is put it in
// an `href` on a page somebody is signed in to.
//
// **http AND https AND NOTHING ELSE.** That refuses three real cases and one
// dangerous one. A native client's private-use scheme
// (`com.example.app:/oauth2redirect`) is not somewhere a browser can be sent
// from a page; a `urn:` is a NAME rather than an address; a `mailto:` is not a
// home page. And `javascript:` is the reason the check is a scheme allowlist
// rather than a blocklist — a registry this service will accept a registration
// into must not be a way to get a scheme of somebody's choosing into an
// attribute a page renders as a link.
//
// A loopback address is allowed and is the ordinary case here rather than an
// oversight: this is a mock, and the application being exercised is usually on
// the same machine as the browser reading the page.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AN `ssfAllowedEvents` VALUE: `caep`, `risc`, or an event type URI this
// transmitter knows. '' when it is one of those, the sentence to refuse it with
// otherwise. A value nothing could ever match would be a limit that silently
// allows nothing of what its author meant, which is the failure a refusal here
// exists to turn into a message. `ssf/ssf_events.js` is required lazily: it is
// a library, and this module is loaded long before any SSF code is.
// ---------------------------------------------------------------------------
function ssfAllowedEventProblem(value) {
  log.debug("Entering ssfAllowedEventProblem().");
  const word = String(value == null ? '' : value).trim();
  if (!word) {
    log.debug("Leaving ssfAllowedEventProblem().");
    return '"ssfAllowedEvents" was given an empty value.';
  }
  if (word.toLowerCase() === 'caep' || word.toLowerCase() === 'risc') {
    log.debug("Leaving ssfAllowedEventProblem().");
    return '';
  }
  let events;
  try {
    events = require('../ssf/ssf_events');
  } catch (e) {
    // No SSF vocabulary in this process; nothing can say the URI is wrong.
    log.debug("ssfAllowedEventProblem(): the SSF vocabulary is not loadable: " +
              e.message);
    log.debug("Leaving ssfAllowedEventProblem().");
    return '';
  }
  if (events.EVENT_BY_URI[word]) {
    log.debug("Leaving ssfAllowedEventProblem().");
    return '';
  }
  log.debug("Leaving ssfAllowedEventProblem().");
  return '"' + word + '" is not an event type this transmitter knows. An ' +
         'ssfAllowedEvents value is `caep`, `risc`, or one event type URI ' +
         '— ' + events.CAEP_PREFIX +
         '<name> for a session event, ' + events.RISC_PREFIX + '<name> for ' +
             'an account event.';
}

// ---------------------------------------------------------------------------
// THE TWO RFC 9728 ATTRIBUTES, CHECKED WHERE THEY ARE WRITTEN (2026-09-13).
//
// The document is held to the one thing that makes it the document it claims
// to be — a JSON object carrying a `resource` string — and no further: the
// member-by-member reading is `oauth-oidc/protected_resource_metadata.ts`'s,
// which this module cannot require (it requires this one), and a declaration
// nothing reads is not the place for a second opinion about RFC 9728.
// ---------------------------------------------------------------------------
function resourceMetadataProblem(value) {
  log.debug("Entering resourceMetadataProblem().");
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    log.debug("Leaving resourceMetadataProblem().");
    return '';
  }
  let document = null;
  try {
    document = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in resourceMetadataProblem(): " +
              ((e && e.message) || e));
    log.debug("Leaving resourceMetadataProblem().");
    return '`oauthResourceMetadata` is not JSON (' + e.message + '). It ' +
           'holds an RFC 9728 protected resource metadata document, which ' +
           'is a JSON object.';
  }
  if (!document || typeof document !== 'object' || Array.isArray(document) ||
      typeof document.resource !== 'string' || !document.resource.trim()) {
    log.debug("Leaving resourceMetadataProblem().");
    return '`oauthResourceMetadata` must be a JSON object carrying a ' +
           '`resource` string — the one member RFC 9728 section 2 makes ' +
           'REQUIRED.';
  }
  log.debug("Leaving resourceMetadataProblem().");
  return '';
}

function resourceMetadataUrlProblem(value) {
  log.debug("Entering resourceMetadataUrlProblem().");
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    log.debug("Leaving resourceMetadataUrlProblem().");
    return '';
  }
  try {
    const parsed = new URL(text);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      log.debug("Leaving resourceMetadataUrlProblem().");
      return '';
    }
  } catch (e) {
    log.debug("Caught in resourceMetadataUrlProblem(): " +
              ((e && e.message) || e));
  }
  log.debug("Leaving resourceMetadataUrlProblem().");
  return '"' + text + '" is not an http or https URL, and ' +
         '`oauthResourceMetadataUrl` records where an RFC 9728 document was ' +
         'fetched from.';
}

function homePageProblem(value) {
  log.debug("Entering homePageProblem().");
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    log.debug("Leaving homePageProblem().");
    return '';
  }
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (e) {
    log.debug("Caught in homePageProblem(): " + ((e && e.message) || e));
    log.debug("Leaving homePageProblem().");
    // Not an absolute URI at all. The message names what was sent rather than
    // the exception, which says only "Invalid URL" and would send somebody
    // looking at their own client.
    return '"' + text + '" is not an absolute URL. A home page is what ' +
           '/portal/applications links this application to, so it has to be ' +
           'somewhere a browser can be sent — ' +
           '`https://expenses.example.com/` is the shape. A path on its own ' +
           'is relative to whichever page it is drawn on, which would be ' +
           'this service.';
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    log.debug("Leaving homePageProblem().");
    return '"' + text + '" has the scheme `' + parsed.protocol + '` and a ' +
           'home page must be http or https. This value becomes a link on a ' +
           'page somebody is signed in to, so the schemes are an allowlist ' +
           'rather than a list of the ones to avoid: a private-use scheme ' +
           'like `com.example.app:/callback` is a native client\'s redirect ' +
           'URI and not a web page, and a `urn:` is a name rather than an ' +
           'address.';
  }
  log.debug("Leaving homePageProblem().");
  return '';
}

// The home page this entry carries, or '' — which is a state every caller has
// to DRAW rather than hide, because an entry without one is the ordinary shape
// of an application nobody has told this registry where to find.
//
// It takes a `view()`, a record, or a bare fields object, the three shapes
// identifiersOf() takes and for its reason.
function homePageOf(source) {
  log.debug("Entering homePageOf().");
  const holder = source || {};
  const fields = holder.fields || holder;
  const text = String(fields.appHomePageUrl == null
    ? '' : fields.appHomePageUrl).trim();
  if (!text || homePageProblem(text)) {
    log.debug("Leaving homePageOf().");
    return '';
  }
  log.debug("Leaving homePageOf().");
  return text;
}

// ---------------------------------------------------------------------------
// THE CORS ORIGINS, WRITTEN AND READ (2026-09-13).
//
// The grammar is `common/validation.js`'s — `originProblem()` and
// `normaliseOrigin()` from one parse — and this is the registry's half: the
// sentence a write door refuses with, and the two readers `common/cors.js`
// asks. See the `appCorsOrigin` row for what the attribute means.
//
// **THE READERS WALK THE DIRECTORY'S ENTRIES AND NOT `list()`**, and that is
// the point of them rather than a shortcut. They run for every browser request
// whose Origin is not this service's own, and `list()` builds a `view()` of
// every entry — which OPENS the sealed signing key on each one that holds one.
// A CORS decision that decrypted every application's private key per request
// would be the most expensive header this service sends. So they read the one
// or two attributes they need off `allApplications()`, whose listing the
// directory keeps until something under ou=applications is written.
//
// **A VALUE THAT IS NOT AN ORIGIN IS DROPPED ON THE WAY OUT**, and normalised
// otherwise: `ldapmodify` reaches this attribute unchecked, and a stored
// `https://App.Example.com` should match the header a browser sends for it
// rather than silently never matching.
// ---------------------------------------------------------------------------
function corsOriginWriteProblem(value) {
  log.debug("Entering corsOriginWriteProblem().");
  const problem = validation.originProblem(String(value == null ? ''
                                                                : value));
  log.debug("Leaving corsOriginWriteProblem().");
  return problem ? '"' + value + '" cannot be appCorsOrigin: it ' + problem +
                   '.' : null;
}

function readableOrigins(values) {
  log.debug("Entering readableOrigins().");
  const out = [];
  valuesOf(values).forEach(function (one) {
    const origin = validation.normaliseOrigin(String(one));
    if (origin && out.indexOf(origin) < 0) {
      out.push(origin);
    }
  });
  log.debug("Leaving readableOrigins().");
  return out;
}

// The origins one application lists, from a view(), a record or its fields.
function corsOriginsOf(source) {
  log.debug("Entering corsOriginsOf().");
  const holder = source || {};
  const fields = holder.fields || holder;
  log.debug("Leaving corsOriginsOf().");
  return readableOrigins(fields.appCorsOrigin);
}

// THE APPLICATION A REQUEST NAMED, and the origins it lists.
//
// `name` is the string the request presented and `attributes` the identifier
// attributes that kind of name is looked for in — `common/cors.js` decides
// which, because it is the module that knows whether the name came out of a
// `client_id` or a GNAP instance reference. The match is exact and not
// case-folded, `forClientId()`'s rule for its reason: a client_id is
// case-sensitive. Answers `{ known: false }` when no entry carries the name,
// which the caller reads as a request naming a client this realm does not
// have. Two entries claiming one name are forClientId()'s configuration
// mistake; the first is taken, as it is there.
function corsOriginsForClient(name, attributes) {
  log.debug("Entering corsOriginsForClient(). name=" + name);
  const wanted = String(name == null ? '' : name).trim();
  const backing = wanted ? store() : null;
  if (!backing) {
    log.debug("Leaving corsOriginsForClient(). Nothing to look in.");
    return { known: false, identifier: '', origins: [] };
  }
  const names = (attributes && attributes.length ? attributes
                                                 : ['oauthClientId'])
    .map(function (one) { return String(one).toLowerCase(); });
  const entries = backing.allApplications();
  for (let i = 0; i < entries.length; i++) {
    const indexed = byLowerName(entries[i].attributes);
    const matched = names.some(function (attribute) {
      return valuesOf(indexed[attribute]).indexOf(wanted) >= 0;
    });
    if (matched) {
      const identifier = firstValue(indexed, 'appIdentifier') ||
                         firstValue(indexed, 'cn');
      log.debug("Leaving corsOriginsForClient(). " + identifier + ".");
      return { known: true, identifier: identifier,
               origins: readableOrigins(indexed.appcorsorigin) };
    }
  }
  log.debug("Leaving corsOriginsForClient(). No application carries it.");
  return { known: false, identifier: '', origins: [] };
}

// ---------------------------------------------------------------------------
// WHAT A SHARED SIGNALS STREAM'S OWNER IS ALLOWED, WITHOUT BUILDING A VIEW
// (2026-09-14). `ssf/ssf_streams.ts` asks this for every event on every stream,
// and it used `get()` and then `list()` — a whole `view()` of EVERY application
// in the realm, sealed signing keys opened, to read one attribute. A session
// sweep that expired 2,412 sessions sent a session-revoked for each, and on a
// realm holding a suite's worth of applications that was 58 seconds with the
// event loop blocked: an LDAP modify sent in that minute timed out.
//
// The same two matches in the same order: the owner's application identifier
// (what `readApplication()` resolves), then an entry listing the name among its
// `ssfReceiverId` values. Raw attributes, as the CORS readers above read them.
// ---------------------------------------------------------------------------
// **AND THE ANSWER IS KEPT UNTIL ou=applications CHANGES.** The owner of this
// service's own console and portal streams is `internal`, which names no
// application, so every lookup fell through to reading every entry — 4ms a
// session with 300 applications registered. Per realm, keyed on the store's
// `applicationsVersion()`; a store without that hook is asked every time.
const ssfAllowedCache = realms.keyed(function () {
  return { version: -1, answers: new Map() };
});
// The answers kept per realm (2026-09-18). One per principal a Shared Signals
// event has been about, so it grew with the people; at the bound the oldest
// answer goes and is looked up again when next needed.
const MAX_SSF_ALLOWED_ANSWERS = 4096;

// Described to `/admin/caches` (#74, rule 3ap). A realm's answers are current
// while its ou=applications has not changed since they were kept; the
// version is AMBIENT, so each realm's is read inside that realm.
const ssfAllowedCount = cacheRegistry.register({
  name: 'applications.ssf-allowed-events',
  title: 'Shared Signals receiver permissions',
  description: 'Which application owns a Shared Signals stream and which ' +
    'events it may receive, per principal, so a session event does not ' +
    'walk every registered application.',
  owner: 'common/applications.js',
  scope: 'realm',
  maxEntries: function () {
    return MAX_SSF_ALLOWED_ANSWERS;
  },
  bound: 'Enforced: ' + MAX_SSF_ALLOWED_ANSWERS + ' answers per realm, the ' +
    'oldest dropped and looked up again when next needed.',
  lifetime: function () {
    return 'Until anything under the realm\'s ou=applications changes; ' +
      'the next lookup then empties that realm\'s answers.';
  },
  entries: function () {
    const out = [];
    ssfAllowedCache.existing().forEach(function (held, id) {
      let current = false;
      try {
        current = realms.run(realms.get(id), function () {
          const backing = store();
          return !!backing &&
            typeof backing.applicationsVersion === 'function' &&
            backing.applicationsVersion() === held.version;
        });
      } catch (e) {
        log.debug("Caught in the ssf-allowed-events entries(): " +
                  ((e && e.message) || e));
        current = false;
      }
      held.answers.forEach(function (found, principal) {
        out.push({ realm: id, key: principal + ' → ' +
                     (found ? 'an application' : 'nobody'),
                   validUntil: null, valid: current,
                   basis: 'ou=applications version' });
      });
    });
    return out;
  }
});

function ssfAllowedEventsFor(principal) {
  log.debug("Entering ssfAllowedEventsFor().");
  const wanted = String(principal == null ? '' : principal);
  const backing = wanted ? store() : null;
  if (!backing) {
    log.debug("Leaving ssfAllowedEventsFor(). Nothing to look in.");
    return null;
  }
  const version = typeof backing.applicationsVersion === 'function'
    ? backing.applicationsVersion() : null;
  const cache = version === null ? null : ssfAllowedCache();
  if (cache) {
    if (cache.version !== version) {
      cache.version = version;
      cache.answers.clear();
    }
    if (cache.answers.has(wanted)) {
      ssfAllowedCount.hit();
      log.debug("Leaving ssfAllowedEventsFor(). Cached.");
      return cache.answers.get(wanted);
    }
    ssfAllowedCount.miss();
  }
  const found = findSsfOwner(backing, wanted);
  if (cache) {
    cacheRegistry.makeRoom(cache.answers, MAX_SSF_ALLOWED_ANSWERS,
                           { counter: ssfAllowedCount });
    cache.answers.set(wanted, found);
  }
  log.debug("Leaving ssfAllowedEventsFor().");
  return found;
}

function findSsfOwner(backing, wanted) {
  log.debug("Entering findSsfOwner().");
  const answer = function (entry) {
    const indexed = byLowerName(entry.attributes);
    // `receiverIds` (#144): the other names the receiver is associated
    // with, which `ssf_streams.ts` offers as a stream's `aud`.
    return { identifier: firstValue(indexed, 'appIdentifier') ||
                         firstValue(indexed, 'cn') || wanted,
             values: valuesOf(indexed.ssfallowedevents),
             receiverIds: valuesOf(indexed.ssfreceiverid) };
  };
  const direct = backing.readApplication(wanted);
  if (direct) {
    log.debug("Leaving findSsfOwner(). By identifier.");
    return answer(direct);
  }
  const entries = backing.allApplications();
  for (let i = 0; i < entries.length; i++) {
    const indexed = byLowerName(entries[i].attributes);
    if (valuesOf(indexed.ssfreceiverid).indexOf(wanted) >= 0) {
      log.debug("Leaving findSsfOwner(). By ssfReceiverId.");
      return answer(entries[i]);
    }
  }
  log.debug("Leaving findSsfOwner(). No application.");
  return null;
}

// Every origin any application in the ambient realm lists — what a request
// that names no client is judged against.
function corsOriginsOfRealm() {
  log.debug("Entering corsOriginsOfRealm().");
  const backing = store();
  if (!backing) {
    log.debug("Leaving corsOriginsOfRealm(). No directory.");
    return [];
  }
  const out = [];
  backing.allApplications().forEach(function (entry) {
    readableOrigins(byLowerName(entry.attributes).appcorsorigin)
      .forEach(function (origin) {
        if (out.indexOf(origin) < 0) {
          out.push(origin);
        }
      });
  });
  log.debug("Leaving corsOriginsOfRealm(). " + out.length + " origin(s).");
  return out;
}

// ===========================================================================
// THE ONE ATTRIBUTE IN THIS TABLE THAT IS A PRIVATE KEY, AND WHAT IS DONE
// WITH IT (2026-09-10).
//
// `/admin/pki` issues an application a signing key pair for RFC 7521 / RFC
// 7523 and writes it onto that application's own entry, because
// `common/pki.js` hands one over ONCE and keeps no copy — `ou=applications` is
// the only place the answer exists. Five of the six attributes it wrote then
// are public by construction (the seventh, the key source of 2026-09-13, is
// public too): a certificate, a chain, a JWKS, a kid and an expiry
// are all things a relying party is MEANT to be given, and `client_auth.js`
// and `assertion_grant.js` read the JWKS to verify what the key signs. **The
// sixth is the private half**, and it is sealed at rest under the same
// key-encryption key as everything else private this service holds.
//
// **IT IS THE SAME MECHANISM AND DELIBERATELY NOT A NEW ONE.**
// `keystore.seal()` and `keystore.open()` — AES-256-GCM under a key this
// service never generates and never stores, read from a mounted file or one of
// four secret managers (`common/secrets.js`). That is what seals this
// service's own signing keys, what seals `common/pki.js`'s three CA key pairs
// in the `sts_keys` row family, what seals every minted row in product mode,
// and what `common/credentials.ts` seals an authenticator's shared secret
// with. A key pair issued FROM that hierarchy being the one piece of private
// key material left in the clear was the gap this closes.
//
// **`keystore.persists()` AND NOT `keystore.sealed()`**, which is
// `writeTotpRecord()`'s rule word for word and for its reason: the question is
// whether the KEY outlives the process, not whether there is one. Development
// mode has a key-encryption key — an ephemeral one, so that the request-worker
// pool can share minted rows — and sealing a DIRECTORY attribute under it
// would be worse than leaving it clear: the entry survives a restart in the
// `ldif` and `postgres` stores and the key does not, so the certificate and
// the chain would come back and the private half would be permanent garbage.
// So development writes the PEM as it always did, which is also the mode whose
// whole promise is that nothing it minted survives a restart.
//
// **THE VALUE SAYS WHICH IT IS AND NOTHING HAS TO REMEMBER.** A sealed value
// is `crypto.encryptWithKek()`'s own envelope, which begins `$aesgcm$`; a PEM
// begins `-----BEGIN`. So `isSealed()` is a prefix test rather than a marker
// attribute beside it — a second attribute would be a second fact to keep in
// step, and an entry carried between two modes would be read wrongly the first
// time the two disagreed.
//
// ---------------------------------------------------------------------------
// SEALED AT REST, OPENED FOR A READER THAT ASKED THIS MODULE.
//
// The split is `view()`'s existing one and needed no new shape: `fields` is
// what THIS MODULE has recorded about the application, and `attributes` is
// what the ENTRY carries. So `/admin/applications` and
// `GET /admin-api/applications` — both of which read `fields`, both behind a
// credential — hand over the PEM exactly as they did, and a dump of the store
// hands over the ciphertext, because ciphertext is what the store holds. That
// is every surface that was giving the key away without asking this module:
// `/admin/ldap/directory`, an `ldapsearch` on TCP 389 where every bind
// succeeds (a search no longer returns the attribute at all —
// `ldap/ldap_server.js`'s `SECRET_ATTRIBUTES`), an `ldif` file on disk, a
// `postgres` row, a backup of either.
//
// **A VALUE THAT WILL NOT OPEN IS LEFT AS IT IS AND REPORTED.** Rotating the
// key-encryption key is what produces one, the key pair is unusable either
// way, and a reader seeing `$aesgcm$…` where a PEM belongs plus a line in the
// log naming the application is a truer answer than an empty attribute —
// which would read as *no key pair was ever issued* and is the same
// distinction `totpOf()` draws about an enrolment.
// ===========================================================================

// One member. It is a LIST rather than an `if` because the question "is this
// attribute private key material" is one somebody adding a row to SCHEMA has
// to answer, and a list is where they will look for it.
const SEALED_FIELDS = ['oauthAssertionPrivateKey',
                       'oauthSamlAssertionPrivateKey',
                       // GNAP's two credentials (2026-09-12): a client's shared
                       // secret for a key reference, and a resource server's
                       // macaroon root key. Sealed under the PROCESS
                       // key-encryption key — the user's decision, over a
                       // per-realm derivation that does not exist yet.
                       'gnapSymmetricKey',
                       'gnapMacaroonKey'];

// The label each sealed field is sealed under, which is what
// /admin/encryption counts by (admin-ui/encryption_admin.ts DATA_CLASSES). One
// label per KIND of secret, so the page can say what it is looking at.
const SEAL_LABELS = {
  oauthAssertionPrivateKey: 'application-private-key',
  oauthSamlAssertionPrivateKey: 'application-private-key',
  gnapSymmetricKey: 'gnap-shared-key',
  gnapMacaroonKey: 'gnap-macaroon-key'
};

function sealLabelOf(name) {
  log.debug("Entering sealLabelOf().");
  log.debug("Leaving sealLabelOf().");
  return SEAL_LABELS[name] || 'application-private-key';
}

// ---------------------------------------------------------------------------
// WITHHELD, WHICH IS A STRONGER CLAIM THAN SEALED (2026-09-12).
//
// A SEALED_FIELDS value is OPENED for a reader that came through this module,
// because an application's signing key is something an operator collects from
// `/admin/applications`. A Kerberos service key is not: it leaves this service
// exactly once, as the keytab `/admin/kerberos/principals` hands over when it
// is made, and after that no page and no `/admin-api` reply may carry it in any
// form — ciphertext included, because a sealed value copied onto another entry
// is how a key would be planted. So `view()` replaces the value, in `fields`
// and in `attributes` alike, with a sentence saying how many bytes were kept
// back. The ENTRY still holds it; that is what the KDC reads, through the
// directory and not through here.
// ---------------------------------------------------------------------------
const WITHHELD_FIELDS = ['krb5ServiceKeys',
                         // Certificate enrollment (2026-09-13): a private key
                         // this service generated, and two working credentials.
                         'appEnrolledPrivateKey', 'appAcmeEabKey',
                         'appScepChallenge'];

// ---------------------------------------------------------------------------
// WHERE A MANAGED KEY PAIR CAME FROM (2026-09-13) — the closed vocabulary of
// `oauthAssertionKeySource` and `oauthSamlAssertionKeySource`. A table rather
// than a check at the one writer, because `updateApplication()` is the door
// the console's generic Set and `POST /admin-api/applications/set` go through
// too, and a value this table does not hold would be a page drawing a
// provenance nothing in this service produces.
// ---------------------------------------------------------------------------
const KEY_SOURCES = ['issued', 'uploaded-realm-ca', 'uploaded-external-ca'];

// ---------------------------------------------------------------------------
// WHICH ATTRIBUTE HOLDS WHICH HALF OF A MANAGED KEY PAIR, PER PROFILE
// (2026-09-13). The two sets share no name — the RFC 7522 block in SCHEMA
// argues why — and three modules have to agree on them: `admin-ui/pki_admin.ts`
// writes them, the application page and `GET /admin-api/applications` read
// them, and `/admin/pki` lists them. This module owns the schema, so it owns
// the answer; a second copy in any of the three is the one that would go
// stale when an attribute is added.
// ---------------------------------------------------------------------------
const KEY_PAIR_ATTRIBUTES = {
  jwt: { issuer: 'oauthAssertionIssuer',
         certificate: 'oauthAssertionCertificate',
         chain: 'oauthAssertionCertificateChain',
         privateKey: 'oauthAssertionPrivateKey',
         handle: 'oauthAssertionKid', handleLabel: 'kid',
         expires: 'oauthAssertionExpiresAt',
         source: 'oauthAssertionKeySource',
         jwks: 'oauthAssertionJwks',
         // What the party registered ITSELF, by value, beside the managed pair.
         registered: 'oauthJwks' },
  saml: { issuer: 'oauthSamlAssertionIssuer',
          certificate: 'oauthSamlAssertionCertificate',
          chain: 'oauthSamlAssertionCertificateChain',
          privateKey: 'oauthSamlAssertionPrivateKey',
          handle: 'oauthSamlAssertionThumbprint', handleLabel: 'thumbprint',
          expires: 'oauthSamlAssertionExpiresAt',
          source: 'oauthSamlAssertionKeySource',
          jwks: '',
          registered: 'oauthSamlAssertionSigningCertificate' }
};
// Derived rather than written out, from the table above.
const KEY_SOURCE_ATTRIBUTES = Object.keys(KEY_PAIR_ATTRIBUTES).map(
    function (id) {
  return KEY_PAIR_ATTRIBUTES[id].source;
});


function withheldSentence(value) {
  log.debug("Entering withheldSentence().");
  log.debug("Leaving withheldSentence().");
  return '(withheld: Kerberos key material, ' + String(value || '').length +
         ' characters, never shown)';
}

function withholdFields(fields) {
  log.debug("Entering withholdFields().");
  let out = fields;
  WITHHELD_FIELDS.forEach(function (name) {
    if (!out || out[name] === undefined) {
      return;
    }
    if (out === fields) {
      out = Object.assign({}, fields);
    }
    out[name] = Array.isArray(out[name]) ? out[name].map(withheldSentence)
                                         : withheldSentence(out[name]);
  });
  log.debug("Leaving withholdFields().");
  return out;
}

function isSealed(value) {
  log.debug("Entering isSealed().");
  log.debug("Leaving isSealed().");
  return String(value == null ? '' : value).indexOf('$aesgcm$') === 0;
}

// Seal on the way in, where this process holds a key-encryption key that will
// still be there after a restart. Returns the value to store, or null when
// sealing was required and failed — which the callers turn into a refusal
// rather than a write, for `writeTotpRecord()`'s reason: storing a private key
// in the clear in product mode would put a working signing credential in every
// directory dump, and doing it silently after being asked not to is worse than
// refusing.
function sealFieldValue(name, value) {
  log.debug("Entering sealFieldValue().");
  if (SEALED_FIELDS.indexOf(name) < 0 || !value) {
    log.debug("Leaving sealFieldValue().");
    return String(value == null ? '' : value);
  }
  if (isSealed(value)) {
    log.debug("Leaving sealFieldValue().");
    // ALREADY SEALED. A value copied off one entry onto another through the
    // console's `set` or `POST /admin-api/applications/set` arrives like this,
    // and sealing it twice would produce something that opens to ciphertext.
    return String(value);
  }
  if (!keystore.persists()) {
    log.debug("Leaving sealFieldValue().");
    return String(value);
  }
  const out = keystore.seal(String(value), sealLabelOf(name));
  if (!out) {
    log.debug("Leaving sealFieldValue().");
    return null;
  }
  log.debug("Leaving sealFieldValue().");
  return out;
}

// And open on the way out, for `view()`. Takes the whole fields object and
// returns it unchanged where there is nothing sealed in it, so that the
// ordinary entry — which carries none of these attributes at all — pays a
// property lookup and not a copy.
function openSealedFields(fields, identifier) {
  log.debug("Entering openSealedFields().");
  let out = fields;
  SEALED_FIELDS.forEach(function (name) {
    const value = out[name];
    if (!value || !isSealed(value)) {
      return;
    }
    const opened = keystore.open(String(value), sealLabelOf(name));
    if (!opened) {
      log.warn(errorCodes.tag('STS-REG-0023') +
               'applications: the private key on "' + identifier + '" is ' +
               'sealed and will not open under this process\'s ' +
               'key-encryption key — it was written under a different one. ' +
               'It is reported as it is stored rather than as absent, ' +
               'because absent would read as no key pair having been issued. ' +
               'Issue again on /admin/pki.');
      return;
    }
    if (out === fields) {
      out = Object.assign({}, fields);
    }
    out[name] = opened;
  });
  log.debug("Leaving openSealedFields().");
  return out;
}

// ---------------------------------------------------------------------------
// THE VALUES A CREATE MAY CARRY, validated whole before anything is written.
//
// Same rule the protocol families go through one function above and for the
// same reason: a create that half-succeeded — the entry there, one field
// silently dropped — is worse than a refusal, because what is left reads as a
// complete declaration of what somebody typed.
//
// **THE GATE IS `EDITABLE`, NOT THE SCHEMA.** An attribute has to be in the
// table AND declared rather than derived: a create that could set
// `appAuthentications` or `appProtocol` would let a form assert that things had
// happened, which is the line this module's EDITABLE header draws and the one
// `updateApplication()` already refuses at. So this refuses the derived ones by
// name and says which they are, rather than writing them and leaving the page
// to lie.
//
// A `single` attribute given several values is REFUSED rather than truncated.
// Taking the first would be a form quietly keeping one of two things a person
// typed, and the only single-valued identifier here is the one an RFC 8705
// check compares by exact string — where quietly keeping one is precisely the
// wrong answer.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// WHICH ADDRESSES AN OAUTH ENTRY MAY HOLD (2026-09-13).
//
// `oauthRedirectUri` and `oauthPostLogoutRedirectUri` are addresses a browser
// is SENT to, and `oauthFrontchannelLogoutUri` is one a sign-out page FRAMES.
// `oauthBackchannelLogoutUri` (2026-09-17, #36) is one this service POSTs a
// Logout Token to, and takes the same http(s)-only rule.
// Until this date none of the three was checked on the way in — at
// registration, at a console `add` or at `/admin-api` — so `javascript:` could
// be stored in all of them. The two redirect attributes were caught again at
// the endpoints, which type what a request presents; the front-channel one was
// not, and is drawn as an iframe and a link.
//
// One function, so the create walk, the update door and both RFC 7591 routes
// ask the same question: `validation.redirectUriProblem()` for the redirect
// pair (http or https with a host, or a private-use scheme named for a domain
// in reverse), and `frontchannelUriProblem()` — http or https only — for the
// framed one. A private-use post-logout address may be held; the logout
// endpoint decides when one is followed.
//
// `ldapmodify` still reaches all three, which is why the endpoints keep their
// own checks and `frontchannel_logout.js` checks again when it reads.
// ---------------------------------------------------------------------------
const ADDRESS_ATTRIBUTES = {
  oauthRedirectUri: 'redirect',
  oauthPostLogoutRedirectUri: 'redirect',
  oauthFrontchannelLogoutUri: 'frontchannel',
  oauthBackchannelLogoutUri: 'backchannel'
};

function addressProblem(attribute, value) {
  log.debug("Entering addressProblem(). attribute=" + attribute);
  const kind = ADDRESS_ATTRIBUTES[attribute];
  if (!kind) {
    log.debug("Leaving addressProblem(). Not an address attribute.");
    return null;
  }
  const problem = kind === 'frontchannel'
    ? validation.frontchannelUriProblem(String(value))
    : kind === 'backchannel'
      ? validation.backchannelUriProblem(String(value))
      : validation.redirectUriProblem(String(value));
  log.debug("Leaving addressProblem().");
  return problem ? '"' + value + '" cannot be ' + attribute + ': it ' +
                   problem + '.' : null;
}

// ---------------------------------------------------------------------------
// FRONT-CHANNEL LOGOUT 1.0 SECTION 2's ORIGIN RULE (#122, 2026-09-22): "The
// domain, port, and scheme of this URL MUST be the same as that of a
// registered Redirection URI value." The scheme rule above is about what a
// sign-out page may frame; this one is about WHOSE page it frames — without
// it a client could have a sign-out load an address on a host that is not
// its own, in the person's browser, with the session's `sid` on it.
//
// Asked at every door, in every mode: RFC 7591 registration and update
// (STS-REG-0170, through registrationUriProblem()), a console or /admin-api
// write of the attribute (STS-REG-0171), and when a sign-out reads the stored
// value (`frontchannel_logout.ts`, STS-OAUTH-0572), because `ldapmodify`
// passes neither of the first two. Returns the sentence, or null.
// ---------------------------------------------------------------------------
function frontchannelOriginProblem(uri, redirectUris) {
  log.debug("Entering frontchannelOriginProblem().");
  let origin = '';
  try {
    origin = new URL(String(uri)).origin;
  } catch (e) {
    log.debug("Caught in frontchannelOriginProblem(): " +
              ((e && e.message) || e));
    // Not a URL: the scheme rule refuses it with a better sentence.
    origin = '';
  }
  if (!origin || origin === 'null') {
    log.debug("Leaving frontchannelOriginProblem(). Not a URL.");
    return '"' + uri + '" is not a URL with a scheme, host and port.';
  }
  const origins = valuesOf(redirectUris).map(function (one) {
    try {
      return new URL(String(one)).origin;
    } catch (e) {
      log.debug("Caught in frontchannelOriginProblem(): " +
                ((e && e.message) || e));
      // A redirect URI that is not a URL has no origin to match.
      return '';
    }
  });
  if (origins.indexOf(origin) >= 0) {
    log.debug("Leaving frontchannelOriginProblem(). Matched.");
    return null;
  }
  log.debug("Leaving frontchannelOriginProblem(). No redirect URI there.");
  return '"' + uri + '" is at ' + origin + ', and ' +
    (origins.filter(function (one) { return !!one; }).length
      ? 'no registered redirect URI is (the scheme, host and port must be ' +
        'the same as one of them)'
      : 'the client registers no redirect URI for it to match') +
    ' — Front-Channel Logout 1.0 section 2.';
}

// The same question about an RFC 7591 document, before any of it is written.
// Answers null or `{ errorCode, error, description }` in RFC 7591 section
// 3.2.2's vocabulary — `invalid_redirect_uri` for a redirect URI, and
// `invalid_client_metadata` for the other two.
function registrationUriProblem(metadata) {
  log.debug("Entering registrationUriProblem().");
  const meta = metadata || {};
  const members = [
    ['redirect_uris', 'oauthRedirectUri', 'invalid_redirect_uri'],
    ['post_logout_redirect_uris', 'oauthPostLogoutRedirectUri',
     'invalid_client_metadata'],
    ['frontchannel_logout_uri', 'oauthFrontchannelLogoutUri',
     'invalid_client_metadata'],
    ['backchannel_logout_uri', 'oauthBackchannelLogoutUri',
     'invalid_client_metadata']
  ];
  for (let i = 0; i < members.length; i++) {
    const values = valuesOf(meta[members[i][0]]);
    for (let j = 0; j < values.length; j++) {
      const problem = addressProblem(members[i][1], values[j]);
      if (problem) {
        log.debug("Leaving registrationUriProblem(). " + members[i][0] + ".");
        return { errorCode: 'STS-REG-0070', error: members[i][2],
                 description: members[i][0] + ': ' + problem };
      }
    }
  }
  const frontchannel = valuesOf(meta.frontchannel_logout_uri)[0];
  if (frontchannel) {
    const originProblem = frontchannelOriginProblem(frontchannel,
                                                    meta.redirect_uris);
    if (originProblem) {
      log.debug("Leaving registrationUriProblem(). The front-channel " +
                "origin.");
      return { errorCode: 'STS-REG-0170', error: 'invalid_client_metadata',
               description: 'frontchannel_logout_uri: ' + originProblem };
    }
  }
  log.debug("Leaving registrationUriProblem(). Nothing refused.");
  return null;
}

// ---------------------------------------------------------------------------
// RFC 9701 SECTION 6: WHAT THE THREE INTROSPECTION RESPONSE MEMBERS MAY HOLD.
//
// Here, because this module owns what a value of one of its attributes may be
// — `consent.js` delegates the scope grammar here for the same reason — and
// because every write door comes through here: RFC 7591 registration and RFC
// 7592 update (`register()`, `updateRegistration()`, and the endpoint's own 400
// in front of them), the console's create and set, and `/admin-api`.
// `oauth-oidc/introspection_jwt.ts` asks the same function when it answers, for
// a value an `ldapmodify` put on the entry.
//
// **THE LISTS ARE `common/crypto.js`'s**, so a value this service cannot sign
// or encrypt with cannot be stored and the metadata cannot advertise one it
// would refuse. Signing is every algorithm in the JWS table — which has no `none`,
// and section 5 says the response MUST be cryptographically secured. Encryption
// is the ASYMMETRIC list only, for the UserInfo response's reason: the key is
// the one the client registered, and a symmetric family there would be a key
// derived from the JSON of a public key.
//
// Answers null, or `{ errorCode, error, description }` in RFC 7591 section
// 3.2.2's vocabulary. `values` holds any of the three members by their
// REGISTRATION names; an absent or empty member is "not registered".
// ---------------------------------------------------------------------------
const INTROSPECTION_DEFAULT_SIGNING_ALG = 'RS256';

const INTROSPECTION_DEFAULT_ENC = 'A128CBC-HS256';

const INTROSPECTION_SIGNING_ALGS = stsCrypto.JWS_SIGNING_ALGS.slice(0);

const INTROSPECTION_ENCRYPTION_ALGS = stsCrypto.JWE_ASYMMETRIC_ALGS.slice(0);

const INTROSPECTION_ENCRYPTION_ENCS = Object.keys(stsCrypto.JWE_ENCS);

// The attribute each member is stored in, in section 6's order.
const INTROSPECTION_ATTRIBUTES = {
  introspection_signed_response_alg: 'oauthIntrospectionSignedResponseAlg',
  introspection_encrypted_response_alg:
    'oauthIntrospectionEncryptedResponseAlg',
  introspection_encrypted_response_enc:
    'oauthIntrospectionEncryptedResponseEnc'
};

function introspectionResponseProblem(values) {
  log.debug("Entering introspectionResponseProblem().");
  const asked = values || {};
  const refusal = function (member, description) {
    log.debug("Entering refusal(). member=" + member);
    log.debug("Leaving refusal().");
    return { errorCode: 'STS-REG-0072', error: 'invalid_client_metadata',
             member: member, description: member + ': ' + description };
  };
  const text = {};
  const names = Object.keys(INTROSPECTION_ATTRIBUTES);
  for (let i = 0; i < names.length; i++) {
    const value = asked[names[i]];
    if (value !== undefined && value !== null && typeof value !== 'string') {
      log.debug("Leaving introspectionResponseProblem(). Not a string.");
      return refusal(names[i], 'must be a string naming one algorithm.');
    }
    text[names[i]] = String(value || '').trim();
  }
  const sign = text.introspection_signed_response_alg;
  const alg = text.introspection_encrypted_response_alg;
  const enc = text.introspection_encrypted_response_enc;
  if (sign && INTROSPECTION_SIGNING_ALGS.indexOf(sign) < 0) {
    log.debug("Leaving introspectionResponseProblem(). Signing alg.");
    return refusal('introspection_signed_response_alg', '"' + sign + '" ' +
      (sign.toLowerCase() === 'none'
        ? 'is refused: RFC 9701 section 5 says an introspection response ' +
          'MUST be cryptographically secured, so there is no unsigned one.'
        : 'is not an algorithm this service signs with. It signs with ' +
          INTROSPECTION_SIGNING_ALGS.join(', ') + ' (see ' +
          'introspection_signing_alg_values_supported).'));
  }
  if (alg && INTROSPECTION_ENCRYPTION_ALGS.indexOf(alg) < 0) {
    log.debug("Leaving introspectionResponseProblem(). Encryption alg.");
    return refusal('introspection_encrypted_response_alg', '"' + alg + '" is ' +
      'not an algorithm this service encrypts a response with. It encrypts ' +
      'with ' + INTROSPECTION_ENCRYPTION_ALGS.join(', ') + ' (see ' +
      'introspection_encryption_alg_values_supported). The symmetric ' +
      'families are for a document encrypted TO this service; a response is ' +
      'encrypted to the key you registered.');
  }
  if (enc && !alg) {
    log.debug("Leaving introspectionResponseProblem(). enc without alg.");
    return refusal('introspection_encrypted_response_enc', 'RFC 9701 section ' +
      '6 says it MUST NOT be specified without ' +
      'introspection_encrypted_response_alg, and none is registered.');
  }
  if (enc && INTROSPECTION_ENCRYPTION_ENCS.indexOf(enc) < 0) {
    log.debug("Leaving introspectionResponseProblem(). Content encryption.");
    return refusal('introspection_encrypted_response_enc', '"' + enc + '" is ' +
      'not a content encryption algorithm this service has. It has ' +
      INTROSPECTION_ENCRYPTION_ENCS.join(', ') + ' (see ' +
      'introspection_encryption_enc_values_supported).');
  }
  log.debug("Leaving introspectionResponseProblem(). Nothing refused.");
  return null;
}

// The same question about ONE attribute written through the console or
// `/admin-api`, with the entry's (or the create's) other two attributes read
// beside it — the enc-without-alg rule is about the pair. A CLEAR is never
// refused, which is every check in updateApplication()'s rule: an entry left
// holding an `enc` alone is refused where it is read, by name.
function introspectionAttributeProblem(attribute, value, fields) {
  log.debug("Entering introspectionAttributeProblem(). attribute=" +
            attribute);
  const members = Object.keys(INTROSPECTION_ATTRIBUTES);
  const member = members.filter(function (name) {
    return INTROSPECTION_ATTRIBUTES[name] === attribute;
  })[0];
  if (!member || !String(value || '').trim()) {
    log.debug("Leaving introspectionAttributeProblem(). Not asked.");
    return '';
  }
  const beside = fields || {};
  const values = {};
  members.forEach(function (name) {
    const held = valuesOf(beside[INTROSPECTION_ATTRIBUTES[name]])[0];
    values[name] = held === undefined ? '' : String(held);
  });
  values[member] = String(value);
  const problem = introspectionResponseProblem(values);
  log.debug("Leaving introspectionAttributeProblem().");
  return problem
    ? problem.description.replace(problem.member,
                                  INTROSPECTION_ATTRIBUTES[problem.member])
    : '';
}

// ---------------------------------------------------------------------------
// OPENID CONNECT REGISTRATION SECTION 2: WHAT A CLIENT MAY REGISTER ABOUT THE
// ENCRYPTION OF ITS ID TOKENS (2026-09-17, #36 follow-up).
//
// `id_token_encrypted_response_alg` and `_enc`, which OpenID Connect Core
// section 10.2 turns into a Nested JWT and Back-Channel Logout section 2.4
// applies to a Logout Token too. The grammar is here for the introspection
// members' reason — this module owns what a registration may say, and every
// write door (`register()`, `updateRegistration()`, the registration endpoint's
// own 400) asks it. Unlike those three members these two have NO ATTRIBUTE:
// they live in `appRegistrationJson` beside `id_token_signed_response_alg`,
// the member they qualify, which has none either. Whether the client's `jwks`
// holds a key to encrypt to is asked by `oauth-oidc/id_token_encryption.ts`,
// which owns the key selection and cannot be required from here.
//
// The lists are the introspection response's: the ASYMMETRIC families only,
// every content encryption `common/crypto.js` has, A128CBC-HS256 by default,
// and an `enc` with no `alg` refused (Registration section 2: "If
// id_token_encrypted_response_enc is included,
// id_token_encrypted_response_alg MUST also be provided").
// ---------------------------------------------------------------------------
const ID_TOKEN_DEFAULT_ENC = 'A128CBC-HS256';

const ID_TOKEN_ENCRYPTION_ALGS = stsCrypto.JWE_ASYMMETRIC_ALGS.slice(0);

const ID_TOKEN_ENCRYPTION_ENCS = Object.keys(stsCrypto.JWE_ENCS);

function idTokenEncryptionMetadataProblem(values) {
  log.debug("Entering idTokenEncryptionMetadataProblem().");
  const asked = values || {};
  const refusal = function (member, description) {
    log.debug("Entering refusal(). member=" + member);
    log.debug("Leaving refusal().");
    return { errorCode: 'STS-REG-0164', error: 'invalid_client_metadata',
             member: member, description: member + ': ' + description };
  };
  const names = ['id_token_encrypted_response_alg',
                 'id_token_encrypted_response_enc'];
  for (let i = 0; i < names.length; i++) {
    const value = asked[names[i]];
    if (value !== undefined && value !== null && typeof value !== 'string') {
      log.debug("Leaving idTokenEncryptionMetadataProblem(). Not a string.");
      return refusal(names[i], 'must be a string naming one algorithm.');
    }
  }
  const alg = String(asked.id_token_encrypted_response_alg || '').trim();
  const enc = String(asked.id_token_encrypted_response_enc || '').trim();
  if (alg && ID_TOKEN_ENCRYPTION_ALGS.indexOf(alg) < 0) {
    log.debug("Leaving idTokenEncryptionMetadataProblem(). Encryption alg.");
    return refusal(names[0], '"' + alg + '" is not an algorithm this ' +
      'service encrypts an ID Token with. It encrypts with ' +
      ID_TOKEN_ENCRYPTION_ALGS.join(', ') + ' (see ' +
      'id_token_encryption_alg_values_supported). The symmetric families ' +
      'are for a document encrypted TO this service; an ID Token is ' +
      'encrypted to the key you registered in "jwks".');
  }
  if (enc && !alg) {
    log.debug("Leaving idTokenEncryptionMetadataProblem(). enc without alg.");
    return refusal(names[1], 'OpenID Connect Dynamic Client Registration ' +
      'section 2 says id_token_encrypted_response_alg MUST also be provided, ' +
      'and none is.');
  }
  if (enc && ID_TOKEN_ENCRYPTION_ENCS.indexOf(enc) < 0) {
    log.debug("Leaving idTokenEncryptionMetadataProblem(). Content " +
              "encryption.");
    return refusal(names[1], '"' + enc + '" is not a content encryption ' +
      'algorithm this service has. It has ' +
      ID_TOKEN_ENCRYPTION_ENCS.join(', ') + ' (see ' +
      'id_token_encryption_enc_values_supported).');
  }
  log.debug("Leaving idTokenEncryptionMetadataProblem(). Nothing refused.");
  return null;
}

// ---------------------------------------------------------------------------
// RFC 9101 AND OPENID CONNECT REGISTRATION: WHAT A CLIENT MAY REGISTER ABOUT
// ITS REQUEST OBJECTS (2026-09-13).
//
// The introspection check's shape, for its reason — this module owns what a
// value of one of its attributes may be, and every write door comes through
// here. `oauth-oidc/request_object.ts` reads the same tables when it verifies.
//
//   request_uris                   absolute URLs, https — or http where
//                                  `mode.acceptsLooseRequestUris()` — with no
//                                  credentials in them, at most 2048 characters
//   request_object_signing_alg     a JWS algorithm this service verifies, or
//                                  `none` where an unsigned object is accepted
//   request_object_encryption_alg  a JWE algorithm this service DECRYPTS: the
//                                  asymmetric ones to this realm's published
//                                  key, the symmetric ones to the client secret
//   request_object_encryption_enc  a content encryption; not without an alg
//   require_signed_request_object  a boolean
// ---------------------------------------------------------------------------
const REQUEST_OBJECT_DEFAULT_ENC = 'A128CBC-HS256';

const REQUEST_OBJECT_SIGNING_ALGS = stsCrypto.JWS_SIGNING_ALGS.slice(0);

const REQUEST_OBJECT_ENCRYPTION_ALGS = stsCrypto.JWE_DECRYPT_ALGS.slice(0);

const REQUEST_OBJECT_ENCRYPTION_ENCS = Object.keys(stsCrypto.JWE_ENCS);

const REQUEST_OBJECT_ATTRIBUTES = {
  request_uris: 'oauthRequestUri',
  request_object_signing_alg: 'oauthRequestObjectSigningAlg',
  request_object_encryption_alg: 'oauthRequestObjectEncryptionAlg',
  request_object_encryption_enc: 'oauthRequestObjectEncryptionEnc',
  require_signed_request_object: 'oauthRequireSignedRequestObject'
};

// One registered request_uri, as a sentence naming what is wrong, or ''.
function requestUriProblem(value) {
  log.debug("Entering requestUriProblem().");
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  if (!text) {
    log.debug("Leaving requestUriProblem(). Empty.");
    return 'a request_uri is empty';
  }
  if (text.length > 2048) {
    log.debug("Leaving requestUriProblem(). Too long.");
    return 'a request_uri is ' + text.length + ' characters, and RFC 9101 ' +
           'section 5.2 says one SHOULD NOT exceed 512 (2048 is the most this ' +
           'service stores)';
  }
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (e) {
    log.debug("Caught in requestUriProblem(): " + ((e && e.message) || e));
    log.debug("Leaving requestUriProblem(). Not a URL.");
    return '"' + text + '" is not an absolute URL';
  }
  if (parsed.username || parsed.password) {
    log.debug("Leaving requestUriProblem(). Credentials in it.");
    return '"' + text + '" carries a user name or password, which this ' +
           'service will not send anywhere';
  }
  if (parsed.protocol === 'https:') {
    log.debug("Leaving requestUriProblem(). https.");
    return '';
  }
  if (parsed.protocol === 'http:' && mode.acceptsLooseRequestUris()) {
    log.debug("Leaving requestUriProblem(). http, development.");
    return '';
  }
  log.debug("Leaving requestUriProblem(). Wrong scheme.");
  return '"' + text + '" is ' + parsed.protocol.replace(':', '') + ', and ' +
         'RFC 9101 section 5.2 makes a request_uri https' +
         (parsed.protocol === 'http:'
           ? ' — plain http is accepted in development mode only' : '');
}

function requestObjectMetadataProblem(values) {
  log.debug("Entering requestObjectMetadataProblem().");
  const asked = values || {};
  const refusal = function (member, description) {
    log.debug("Entering refusal(). member=" + member);
    log.debug("Leaving refusal().");
    return { errorCode: 'STS-REG-0100', error: 'invalid_client_metadata',
             member: member, description: member + ': ' + description };
  };
  if (asked.request_uris !== undefined && asked.request_uris !== null) {
    if (!Array.isArray(asked.request_uris)) {
      log.debug("Leaving requestObjectMetadataProblem(). Not an array.");
      return refusal('request_uris', 'must be an array of URLs.');
    }
    for (let i = 0; i < asked.request_uris.length; i++) {
      if (typeof asked.request_uris[i] !== 'string') {
        log.debug("Leaving requestObjectMetadataProblem(). Not a string.");
        return refusal('request_uris', 'every member must be a string.');
      }
      const problem = requestUriProblem(asked.request_uris[i]);
      if (problem) {
        log.debug("Leaving requestObjectMetadataProblem(). A request_uri.");
        return refusal('request_uris', problem + '.');
      }
    }
  }
  const text = {};
  const strings = ['request_object_signing_alg',
                   'request_object_encryption_alg',
                   'request_object_encryption_enc'];
  for (let i = 0; i < strings.length; i++) {
    const value = asked[strings[i]];
    if (value !== undefined && value !== null && typeof value !== 'string') {
      log.debug("Leaving requestObjectMetadataProblem(). Not a string.");
      return refusal(strings[i], 'must be a string naming one algorithm.');
    }
    text[strings[i]] = String(value || '').trim();
  }
  const required = asked.require_signed_request_object;
  if (required !== undefined && required !== null &&
      typeof required !== 'boolean') {
    log.debug("Leaving requestObjectMetadataProblem(). Not a boolean.");
    return refusal('require_signed_request_object', 'must be true or false.');
  }
  const sign = text.request_object_signing_alg;
  if (sign === 'none') {
    if (!mode.acceptsUnsignedRequestObjects() || required === true) {
      log.debug("Leaving requestObjectMetadataProblem(). none refused.");
      return refusal('request_object_signing_alg', '`none` is refused: ' +
        (required === true
          ? 'this registration also sets require_signed_request_object'
          : 'this realm is in product mode, where RFC 9101 section 4\'s ' +
            'signed request object is required') + '.');
    }
  } else if (sign && REQUEST_OBJECT_SIGNING_ALGS.indexOf(sign) < 0) {
    log.debug("Leaving requestObjectMetadataProblem(). Signing alg.");
    return refusal('request_object_signing_alg', '"' + sign + '" is not an ' +
      'algorithm this service verifies. It verifies ' +
      REQUEST_OBJECT_SIGNING_ALGS.join(', ') + ' (see ' +
      'request_object_signing_alg_values_supported).');
  }
  const alg = text.request_object_encryption_alg;
  const enc = text.request_object_encryption_enc;
  if (alg && REQUEST_OBJECT_ENCRYPTION_ALGS.indexOf(alg) < 0) {
    log.debug("Leaving requestObjectMetadataProblem(). Encryption alg.");
    return refusal('request_object_encryption_alg', '"' + alg + '" is not an ' +
      'algorithm this service decrypts a request object with. It decrypts ' +
      REQUEST_OBJECT_ENCRYPTION_ALGS.join(', ') + ' (see ' +
      'request_object_encryption_alg_values_supported).');
  }
  if (enc && !alg) {
    log.debug("Leaving requestObjectMetadataProblem(). enc without alg.");
    return refusal('request_object_encryption_enc', 'it may not be ' +
      'registered without request_object_encryption_alg, and none is.');
  }
  if (enc && REQUEST_OBJECT_ENCRYPTION_ENCS.indexOf(enc) < 0) {
    log.debug("Leaving requestObjectMetadataProblem(). Content encryption.");
    return refusal('request_object_encryption_enc', '"' + enc + '" is not a ' +
      'content encryption algorithm this service has. It has ' +
      REQUEST_OBJECT_ENCRYPTION_ENCS.join(', ') + '.');
  }
  log.debug("Leaving requestObjectMetadataProblem(). Nothing refused.");
  return null;
}

// The same question about ONE attribute written through the console or
// `/admin-api`, with the entry's other attributes beside it. A request URI is
// checked alone (an `add` or a create's value); the boolean holds TRUE or
// FALSE, the directory's spelling; the algorithms are read as the registration
// members they are. A CLEAR is never refused.
function requestObjectAttributeProblem(attribute, value, fields) {
  log.debug("Entering requestObjectAttributeProblem(). attribute=" +
            attribute);
  const member = Object.keys(REQUEST_OBJECT_ATTRIBUTES).filter(function (name) {
    return REQUEST_OBJECT_ATTRIBUTES[name] === attribute;
  })[0];
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  if (!member || !text) {
    log.debug("Leaving requestObjectAttributeProblem(). Not asked.");
    return '';
  }
  if (member === 'request_uris') {
    const uri = requestUriProblem(text);
    log.debug("Leaving requestObjectAttributeProblem(). A request URI.");
    return uri ? attribute + ': ' + uri + '.' : '';
  }
  const beside = fields || {};
  const heldOf = function (name) {
    log.debug("Entering heldOf().");
    const held = valuesOf(beside[REQUEST_OBJECT_ATTRIBUTES[name]])[0];
    log.debug("Leaving heldOf().");
    return held === undefined ? '' : String(held);
  };
  if (member === 'require_signed_request_object' &&
      ['TRUE', 'FALSE'].indexOf(text.toUpperCase()) < 0) {
    log.debug("Leaving requestObjectAttributeProblem(). Not a boolean.");
    return attribute + ': "' + text + '" is not TRUE or FALSE.';
  }
  const values = {
    request_object_signing_alg: heldOf('request_object_signing_alg'),
    request_object_encryption_alg: heldOf('request_object_encryption_alg'),
    request_object_encryption_enc: heldOf('request_object_encryption_enc'),
    require_signed_request_object: heldOf('require_signed_request_object')
      .toUpperCase() === 'TRUE'
  };
  values[member] = member === 'require_signed_request_object'
    ? text.toUpperCase() === 'TRUE' : text;
  const problem = requestObjectMetadataProblem(values);
  log.debug("Leaving requestObjectAttributeProblem().");
  return problem
    ? problem.description.replace(problem.member,
                                  REQUEST_OBJECT_ATTRIBUTES[problem.member])
    : '';
}

// ---------------------------------------------------------------------------
// OPENID CONNECT CORE SECTIONS 8 AND 9: WHAT A CLIENT MAY REGISTER ABOUT ITS
// SUBJECT AND ITS ASSERTION ALGORITHM (#118, 2026-09-22).
//
// The SHAPE of three members, checked without a network — `subject_type` is
// `public` or `pairwise`, `sector_identifier_uri` is an https URL, and
// `token_endpoint_auth_signing_alg` is a JWS algorithm this service verifies
// that the registered authentication method can use (never `none`, an HMAC
// only for client_secret_jwt). And one rule about the set: a pairwise client
// with no sector_identifier_uri must have every redirect URI on ONE host,
// because that host IS its sector (section 8.1). What the sector URI SERVES
// is `oauth-oidc/pairwise_subjects.ts`'s, asynchronously, at the registration
// endpoint. Registration answers STS-REG-0167; a console or API write
// STS-REG-0168.
// ---------------------------------------------------------------------------
const OIDC_SUBJECT_ATTRIBUTES = {
  subject_type: 'oauthSubjectType',
  sector_identifier_uri: 'oauthSectorIdentifierUri',
  token_endpoint_auth_signing_alg: 'oauthTokenEndpointAuthSigningAlg'
};

function oidcSubjectMetadataProblem(values) {
  log.debug("Entering oidcSubjectMetadataProblem().");
  const asked = values || {};
  const refusal = function (member, description) {
    log.debug("Entering refusal(). member=" + member);
    log.debug("Leaving refusal().");
    return { errorCode: 'STS-REG-0167', error: 'invalid_client_metadata',
             member: member, description: member + ': ' + description };
  };
  const text = {};
  const members = Object.keys(OIDC_SUBJECT_ATTRIBUTES);
  for (let i = 0; i < members.length; i++) {
    const value = asked[members[i]];
    if (value !== undefined && value !== null && typeof value !== 'string') {
      log.debug("Leaving oidcSubjectMetadataProblem(). Not a string.");
      return refusal(members[i], 'must be a string.');
    }
    text[members[i]] = String(value || '').trim();
  }
  if (text.subject_type &&
      ['public', 'pairwise'].indexOf(text.subject_type) < 0) {
    log.debug("Leaving oidcSubjectMetadataProblem(). An unknown type.");
    return refusal('subject_type', '"' + text.subject_type + '" is not ' +
                   'one this service supports; subject_types_supported is ' +
                   '["public", "pairwise"] (OIDC Core section 8).');
  }
  if (text.sector_identifier_uri) {
    let parsed = null;
    try {
      parsed = new URL(text.sector_identifier_uri);
    } catch (e) {
      log.debug("Caught in oidcSubjectMetadataProblem(): " +
                ((e && e.message) || e));
      // Not a URL; refused just below.
      parsed = null;
    }
    if (!parsed || parsed.protocol !== 'https:' || parsed.hash) {
      log.debug("Leaving oidcSubjectMetadataProblem(). Not an https URL.");
      return refusal('sector_identifier_uri', '"' +
                     text.sector_identifier_uri + '" is not an https URL ' +
                     'with no fragment (OIDC Core section 8.1 and Dynamic ' +
                     'Client Registration section 5).');
    }
  }
  if (text.subject_type === 'pairwise' && !text.sector_identifier_uri) {
    const hosts = {};
    valuesOf(asked.redirect_uris).forEach(function (uri) {
      try {
        hosts[new URL(String(uri)).host] = true;
      } catch (e) {
        log.debug("Caught in oidcSubjectMetadataProblem(): " +
                  ((e && e.message) || e));
        // Refused elsewhere for its shape; it names no host here.
      }
    });
    if (Object.keys(hosts).length > 1) {
      log.debug("Leaving oidcSubjectMetadataProblem(). Several hosts.");
      return refusal('sector_identifier_uri', 'a pairwise client whose ' +
                     'redirect_uris are on ' + Object.keys(hosts).length +
                     ' hosts (' + Object.keys(hosts).join(', ') + ') must ' +
                     'register a sector_identifier_uri: with none, the ' +
                     'sector is the one host they share (OIDC Core ' +
                     'section 8.1).');
    }
  }
  if (text.token_endpoint_auth_signing_alg) {
    const alg = text.token_endpoint_auth_signing_alg;
    const method = String(asked.token_endpoint_auth_method || '').trim();
    if (stsCrypto.JWS_SIGNING_ALGS.indexOf(alg) < 0) {
      log.debug("Leaving oidcSubjectMetadataProblem(). Unknown algorithm.");
      return refusal('token_endpoint_auth_signing_alg', '"' + alg + '" is ' +
                     'not a JWS algorithm this service verifies (' +
                     stsCrypto.JWS_SIGNING_ALGS.join(', ') + '); `none` is ' +
                     'never one (OIDC Core section 9).');
    }
    const hmac = /^HS/.test(alg);
    if ((method === 'client_secret_jwt' && !hmac) ||
        (method === 'private_key_jwt' && hmac)) {
      log.debug("Leaving oidcSubjectMetadataProblem(). The wrong family.");
      return refusal('token_endpoint_auth_signing_alg', '"' + alg + '" ' +
                     'cannot sign a ' + method + ' assertion: ' +
                     (hmac ? 'private_key_jwt is asymmetric'
                           : 'client_secret_jwt is an HMAC (HS256, HS384 ' +
                             'or HS512)') + '.');
    }
  }
  log.debug("Leaving oidcSubjectMetadataProblem(). Nothing refused.");
  return null;
}

// The same question about ONE attribute written through the console or
// `/admin-api`, with the entry's other attributes beside it. A CLEAR is never
// refused.
function oidcSubjectAttributeProblem(attribute, value, fields) {
  log.debug("Entering oidcSubjectAttributeProblem(). attribute=" + attribute);
  const member = Object.keys(OIDC_SUBJECT_ATTRIBUTES).filter(function (name) {
    return OIDC_SUBJECT_ATTRIBUTES[name] === attribute;
  })[0];
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  if (!member || !text) {
    log.debug("Leaving oidcSubjectAttributeProblem(). Not asked.");
    return '';
  }
  const beside = fields || {};
  const values = {
    token_endpoint_auth_method:
      String(valuesOf(beside.oauthTokenEndpointAuthMethod)[0] || ''),
    redirect_uris: valuesOf(beside.oauthRedirectUri)
  };
  Object.keys(OIDC_SUBJECT_ATTRIBUTES).forEach(function (name) {
    const held = valuesOf(beside[OIDC_SUBJECT_ATTRIBUTES[name]])[0];
    values[name] = held === undefined ? '' : String(held);
  });
  values[member] = text;
  const problem = oidcSubjectMetadataProblem(values);
  log.debug("Leaving oidcSubjectAttributeProblem().");
  return problem
    ? problem.description.replace(problem.member,
                                  OIDC_SUBJECT_ATTRIBUTES[problem.member])
    : '';
}

// ---------------------------------------------------------------------------
// RFC 9126 SECTION 6: WHAT A CLIENT MAY REGISTER ABOUT PUSHING (2026-09-13).
//
// One member, a boolean, and the one check is that it IS one — a string
// "true" in a registration document is refused rather than read, because a
// client that thinks it registered a requirement and did not is a client whose
// authorization requests are quietly not held to it. Asked by the registration
// endpoint (`STS-REG-0120`, RFC 7591's invalid_client_metadata) and, for a
// console or `/admin-api` write, by `pushedAuthorizationAttributeProblem()`
// (`STS-REG-0121`).
// ---------------------------------------------------------------------------
function pushedAuthorizationMetadataProblem(values) {
  log.debug("Entering pushedAuthorizationMetadataProblem().");
  const asked = values || {};
  const value = asked.require_pushed_authorization_requests;
  if (value !== undefined && value !== null && typeof value !== 'boolean') {
    log.debug("Leaving pushedAuthorizationMetadataProblem(). Not a boolean.");
    return { errorCode: 'STS-REG-0120', error: 'invalid_client_metadata',
             member: 'require_pushed_authorization_requests',
             description: 'require_pushed_authorization_requests must be ' +
               'true or false (RFC 9126 section 6), and this registration ' +
               'gives ' + JSON.stringify(value) + '.' };
  }
  log.debug("Leaving pushedAuthorizationMetadataProblem(). Nothing refused.");
  return null;
}

// The same question about the attribute, written through the console or
// `/admin-api`: TRUE or FALSE, the directory's spelling. A CLEAR is never
// refused.
function pushedAuthorizationAttributeProblem(attribute, value) {
  log.debug("Entering pushedAuthorizationAttributeProblem().");
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  if (attribute !== 'oauthRequirePushedAuthorizationRequests' || !text) {
    log.debug("Leaving pushedAuthorizationAttributeProblem(). Not asked.");
    return '';
  }
  if (['TRUE', 'FALSE'].indexOf(text.toUpperCase()) < 0) {
    log.debug("Leaving pushedAuthorizationAttributeProblem(). Not a boolean.");
    return attribute + ': "' + text + '" is not TRUE or FALSE.';
  }
  log.debug("Leaving pushedAuthorizationAttributeProblem(). Nothing refused.");
  return '';
}

// ---------------------------------------------------------------------------
// RFC 8705: WHAT A CLIENT MAY REGISTER ABOUT ITS CERTIFICATE (2026-09-13).
//
// Section 2.1.2's five subject parameters, of which a `tls_client_auth` client
// uses "exactly one", and section 3.4's
// `tls_client_certificate_bound_access_tokens`. **AT MOST ONE, NOT EXACTLY
// ONE**, and that is a decision rather than a leniency: a client with none is
// authenticated here by a certificate this realm issued to THIS application
// (the implicit mapping `client_auth.js` argues), so none is a registration
// with a meaning. Two is a client that does not know which subject it will
// present, and the check it would get is "any of these", which the RFC does
// not describe — so it is refused rather than chosen between.
//
// The grammar of each value is `certificate_subject.js`'s, so a spelling the
// verifier cannot match is refused where it is written.
//
//   STS-REG-0130  a value is not what its member says it is
//   STS-REG-0131  more than one subject parameter
//   STS-REG-0132  the section 3.4 flag is not a boolean
//
// and the console's and `/admin-api`'s writes of the attributes, through
// `mtlsAttributeProblem()`: 0134 for a value, 0135 for a second parameter and
// 0136 for a flag that is not TRUE or FALSE. 0133 is the registration
// endpoint's — a client asking for bound tokens from a service whose main port
// is not TLS — and is decided in `oauth-oidc/oauth2.ts`, which knows the port.
// ---------------------------------------------------------------------------
const TLS_SUBJECT_ATTRIBUTES = certificateSubject.MEMBER_NAMES.map(
  function (member) {
    return certificateSubject.MEMBERS[member].attribute;
  });
const TLS_BOUND_TOKENS_ATTRIBUTE =
  'oauthTlsClientCertificateBoundAccessTokens';

function mtlsMetadataProblem(values) {
  log.debug("Entering mtlsMetadataProblem().");
  const asked = values || {};
  const present = certificateSubject.MEMBER_NAMES.filter(function (member) {
    return asked[member] !== undefined && asked[member] !== null;
  });
  for (let i = 0; i < present.length; i++) {
    const said = certificateSubject.valueProblem(present[i], asked[present[i]]);
    if (said) {
      log.debug("Leaving mtlsMetadataProblem(). A value.");
      return { errorCode: 'STS-REG-0130', error: 'invalid_client_metadata',
               member: present[i], description: 'RFC 8705 section 2.1.2: ' +
                 said };
    }
  }
  if (present.length > 1) {
    log.debug("Leaving mtlsMetadataProblem(). More than one.");
    return { errorCode: 'STS-REG-0131', error: 'invalid_client_metadata',
             member: present[1],
             description: 'RFC 8705 section 2.1.2: a client uses exactly ' +
               'one certificate subject parameter, and this registration ' +
               'gives ' + present.length + ' (' + present.join(', ') + '). ' +
               'Register the one subject the certificate will carry.' };
  }
  const flag = asked.tls_client_certificate_bound_access_tokens;
  if (flag !== undefined && flag !== null && typeof flag !== 'boolean') {
    log.debug("Leaving mtlsMetadataProblem(). Not a boolean.");
    return { errorCode: 'STS-REG-0132', error: 'invalid_client_metadata',
             member: 'tls_client_certificate_bound_access_tokens',
             description: 'tls_client_certificate_bound_access_tokens must ' +
               'be true or false (RFC 8705 section 3.4), and this ' +
               'registration gives ' + JSON.stringify(flag) + '.' };
  }
  log.debug("Leaving mtlsMetadataProblem(). Nothing refused.");
  return null;
}

// The same questions about an attribute written through the console or
// `/admin-api`, read against what the entry already holds. A CLEAR is never
// refused, and a SET of the parameter already held replaces it — only a
// DIFFERENT second parameter is refused, with the one to take off named.
// Answers `{ code, message }` or null.
function mtlsAttributeProblem(attribute, value, fields) {
  log.debug("Entering mtlsAttributeProblem(). attribute=" + attribute);
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  if (!text) {
    log.debug("Leaving mtlsAttributeProblem(). Not asked.");
    return null;
  }
  if (attribute === TLS_BOUND_TOKENS_ATTRIBUTE) {
    if (['TRUE', 'FALSE'].indexOf(text.toUpperCase()) < 0) {
      log.debug("Leaving mtlsAttributeProblem(). Not a boolean.");
      return { code: 'STS-REG-0136',
               message: attribute + ': "' + text + '" is not TRUE or FALSE.' };
    }
    log.debug("Leaving mtlsAttributeProblem(). A usable flag.");
    return null;
  }
  const index = TLS_SUBJECT_ATTRIBUTES.indexOf(attribute);
  if (index < 0) {
    log.debug("Leaving mtlsAttributeProblem(). Not an RFC 8705 attribute.");
    return null;
  }
  const member = certificateSubject.MEMBER_NAMES[index];
  const said = certificateSubject.valueProblem(member, text);
  if (said) {
    log.debug("Leaving mtlsAttributeProblem(). A value.");
    return { code: 'STS-REG-0134',
             message: attribute + ': ' + said.replace(member + ' ', '') };
  }
  const beside = fields || {};
  const other = TLS_SUBJECT_ATTRIBUTES.filter(function (name) {
    return name !== attribute && valuesOf(beside[name]).some(function (one) {
      return String(one).trim() !== '';
    });
  })[0];
  if (other) {
    log.debug("Leaving mtlsAttributeProblem(). A second parameter.");
    return { code: 'STS-REG-0135',
             message: attribute + ': this application already registers ' +
               other + ', and RFC 8705 section 2.1.2 gives a client exactly ' +
               'one certificate subject parameter. Clear ' + other +
               ' first.' };
  }
  log.debug("Leaving mtlsAttributeProblem(). Nothing refused.");
  return null;
}

// ---------------------------------------------------------------------------
// RFC 9396: WHAT AN ENTRY MAY SAY ABOUT authorization_details (2026-09-13).
//
// This module owns what a value of its attributes may be, for the introspection
// check's reason, so the TYPE DEFINITION a resource writes is read here — and
// `oauth-oidc/authorization_details.ts` reads it back through
// `authorizationDetailsTypeOf()` rather than parsing it a second way.
//
//   a type name                    1 to 512 printable characters with no
//                                  space; `openid_credential` is OpenID4VCI's
//                                  and is built in, so no entry may declare it
//   a definition                   the name alone, or a JSON object of `type`
//                                  (required), `description` (a string),
//                                  `locations` (absolute URIs, no fragment)
//                                  and `schema` (a JSON Schema that COMPILES) —
//                                  nothing else, so a misspelt member is
//                                  refused rather than ignored
//   authorization_details_types    a client's registration member: an array of
//                                  type names
// ---------------------------------------------------------------------------
const AUTHORIZATION_DETAILS_BUILT_IN = ['openid_credential'];

const AUTHORIZATION_DETAILS_DEFINITION_MEMBERS = ['type', 'description',
                                                  'locations', 'schema'];

// The largest definition an entry may hold: a schema is data a person wrote,
// and every authorization request carrying the type compiles it once.
const AUTHORIZATION_DETAILS_DEFINITION_MAX = 65536;

let authorizationDetailsAjv = null;

// One Ajv for every definition this process reads, made on first use so that a
// process that never meets a rich authorization request never loads it. Not
// strict, because a schema is somebody else's document and Ajv's strict mode
// refuses keywords that are merely unusual; the draft is 2020-12.
function authorizationDetailsSchemaCompiler() {
  log.debug("Entering authorizationDetailsSchemaCompiler().");
  if (!authorizationDetailsAjv) {
    // `any`: both are CommonJS modules whose declared types are ES defaults.
    const Ajv2020 = /** @type {any} */ (require('ajv/dist/2020'));
    authorizationDetailsAjv = new Ajv2020({ strict: false, allErrors: false,
                                            coerceTypes: false });
    /** @type {any} */ (require('ajv-formats'))(authorizationDetailsAjv);
  }
  log.debug("Leaving authorizationDetailsSchemaCompiler().");
  return authorizationDetailsAjv;
}

// A type NAME, as a sentence naming what is wrong, or ''.
function authorizationDetailsTypeNameProblem(value) {
  log.debug("Entering authorizationDetailsTypeNameProblem().");
  const text = typeof value === 'string' ? value : '';
  if (!text) {
    log.debug("Leaving authorizationDetailsTypeNameProblem(). Empty.");
    return 'a type is not a non-empty string';
  }
  if (text.length > 512 || !/^[\x21-\x7e]+$/.test(text)) {
    log.debug("Leaving authorizationDetailsTypeNameProblem(). Shape.");
    return '"' + text.slice(0, 80) + '" is not a type name: 1 to 512 ' +
           'printable ASCII characters with no space';
  }
  log.debug("Leaving authorizationDetailsTypeNameProblem().");
  return '';
}

// One `oauthAuthorizationDetailsType` value read as a definition:
// `{ type, description, locations, schema, validate, problem }`. `problem` is ''
// for a usable one; `validate` is the compiled schema, or null where there is
// none. NEVER throws.
function authorizationDetailsTypeOf(value) {
  log.debug("Entering authorizationDetailsTypeOf().");
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  const out = { type: '', description: '', locations: [], schema: null,
                validate: null, problem: '' };
  if (!text) {
    out.problem = 'the definition is empty';
    log.debug("Leaving authorizationDetailsTypeOf(). Empty.");
    return out;
  }
  if (text.length > AUTHORIZATION_DETAILS_DEFINITION_MAX) {
    out.problem = 'the definition is ' + text.length + ' characters, and at ' +
      'most ' + AUTHORIZATION_DETAILS_DEFINITION_MAX + ' are stored';
    log.debug("Leaving authorizationDetailsTypeOf(). Too long.");
    return out;
  }
  let definition = null;
  if (text.charAt(0) === '{') {
    try {
      definition = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in authorizationDetailsTypeOf(): " +
                ((e && e.message) || e));
      out.problem = 'the definition starts with "{" and is not readable ' +
                    'JSON: ' + e.message;
      log.debug("Leaving authorizationDetailsTypeOf(). Not JSON.");
      return out;
    }
  } else {
    definition = { type: text };
  }
  if (!definition || typeof definition !== 'object' ||
      Array.isArray(definition)) {
    out.problem = 'the definition is not a JSON object';
    log.debug("Leaving authorizationDetailsTypeOf(). Not an object.");
    return out;
  }
  const stray = Object.keys(definition).filter(function (name) {
    return AUTHORIZATION_DETAILS_DEFINITION_MEMBERS.indexOf(name) < 0;
  });
  if (stray.length) {
    out.problem = 'the definition carries ' + stray.join(', ') + ', and a ' +
      'definition holds only ' +
      AUTHORIZATION_DETAILS_DEFINITION_MEMBERS.join(', ');
    log.debug("Leaving authorizationDetailsTypeOf(). A stray member.");
    return out;
  }
  const nameProblem = authorizationDetailsTypeNameProblem(definition.type);
  if (nameProblem) {
    out.problem = nameProblem;
    log.debug("Leaving authorizationDetailsTypeOf(). The type name.");
    return out;
  }
  out.type = definition.type;
  if (AUTHORIZATION_DETAILS_BUILT_IN.indexOf(out.type) >= 0) {
    out.problem = '"' + out.type + '" is OpenID4VCI\'s type, which this ' +
      'service understands itself and no application may declare';
    log.debug("Leaving authorizationDetailsTypeOf(). Built in.");
    return out;
  }
  if (definition.description !== undefined &&
      typeof definition.description !== 'string') {
    out.problem = 'description must be a string';
    log.debug("Leaving authorizationDetailsTypeOf(). description.");
    return out;
  }
  out.description = definition.description || '';
  if (definition.locations !== undefined) {
    if (!Array.isArray(definition.locations)) {
      out.problem = 'locations must be an array of absolute URIs';
      log.debug("Leaving authorizationDetailsTypeOf(). locations.");
      return out;
    }
    for (let i = 0; i < definition.locations.length; i++) {
      const location = authorizationDetailsLocationProblem(
        definition.locations[i]);
      if (location) {
        out.problem = 'locations: ' + location;
        log.debug("Leaving authorizationDetailsTypeOf(). A location.");
        return out;
      }
    }
    out.locations = definition.locations.slice(0);
  }
  if (definition.schema !== undefined) {
    if (!definition.schema || typeof definition.schema !== 'object' ||
        Array.isArray(definition.schema)) {
      out.problem = 'schema must be a JSON Schema object';
      log.debug("Leaving authorizationDetailsTypeOf(). schema shape.");
      return out;
    }
    try {
      out.validate = authorizationDetailsSchemaCompiler()
        .compile(definition.schema);
    } catch (e) {
      log.debug("Caught in authorizationDetailsTypeOf(): " +
                ((e && e.message) || e));
      out.problem = 'schema does not compile as a JSON Schema: ' + e.message;
      log.debug("Leaving authorizationDetailsTypeOf(). schema compile.");
      return out;
    }
    out.schema = definition.schema;
  }
  log.debug("Leaving authorizationDetailsTypeOf(). " + out.type + ".");
  return out;
}

// One location, as RFC 9396 section 2.2 describes one: an absolute URI with no
// fragment. As a sentence, or ''.
function authorizationDetailsLocationProblem(value) {
  log.debug("Entering authorizationDetailsLocationProblem().");
  if (typeof value !== 'string' || !value) {
    log.debug("Leaving authorizationDetailsLocationProblem(). Not a string.");
    return 'a location is not a non-empty string';
  }
  let parsed = null;
  try {
    parsed = new URL(value);
  } catch (e) {
    log.debug("Caught in authorizationDetailsLocationProblem(): " +
              ((e && e.message) || e));
    log.debug("Leaving authorizationDetailsLocationProblem(). Not a URI.");
    return '"' + value.slice(0, 200) + '" is not an absolute URI';
  }
  if (parsed.hash || value.indexOf('#') >= 0) {
    log.debug("Leaving authorizationDetailsLocationProblem(). A fragment.");
    return '"' + value.slice(0, 200) + '" carries a fragment';
  }
  log.debug("Leaving authorizationDetailsLocationProblem().");
  return '';
}

// A registration's `authorization_details_types`, as an RFC 7591 refusal or
// null (`STS-REG-0110`).
function authorizationDetailsMetadataProblem(values) {
  log.debug("Entering authorizationDetailsMetadataProblem().");
  const asked = values || {};
  const types = asked.authorization_details_types;
  if (types === undefined || types === null) {
    log.debug("Leaving authorizationDetailsMetadataProblem(). Not asked.");
    return null;
  }
  const refusal = function (description) {
    log.debug("Entering refusal().");
    log.debug("Leaving refusal().");
    return { errorCode: 'STS-REG-0110', error: 'invalid_client_metadata',
             member: 'authorization_details_types',
             description: 'authorization_details_types: ' + description };
  };
  if (!Array.isArray(types)) {
    log.debug("Leaving authorizationDetailsMetadataProblem(). Not an array.");
    return refusal('must be an array of type names (RFC 9396 section 10).');
  }
  for (let i = 0; i < types.length; i++) {
    const problem = authorizationDetailsTypeNameProblem(types[i]);
    if (problem) {
      log.debug("Leaving authorizationDetailsMetadataProblem(). A name.");
      return refusal(problem + '.');
    }
  }
  log.debug("Leaving authorizationDetailsMetadataProblem(). Nothing refused.");
  return null;
}

// The same questions about ONE attribute value written through the console or
// `/admin-api`: a type name for a client's list (`STS-REG-0111`), a definition
// for a resource's (`STS-REG-0112`). As `{ code, message }`, or null. A CLEAR
// is never refused.
function authorizationDetailsAttributeProblem(attribute, value) {
  log.debug("Entering authorizationDetailsAttributeProblem(). attribute=" +
            attribute);
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  if (!text) {
    log.debug("Leaving authorizationDetailsAttributeProblem(). A clear.");
    return null;
  }
  if (attribute === 'oauthAuthorizationDetailsTypes') {
    const problem = authorizationDetailsTypeNameProblem(text);
    log.debug("Leaving authorizationDetailsAttributeProblem(). A name.");
    return problem ? { code: 'STS-REG-0111',
                       message: attribute + ': ' + problem + '.' } : null;
  }
  if (attribute === 'oauthAuthorizationDetailsType') {
    const definition = authorizationDetailsTypeOf(text);
    log.debug("Leaving authorizationDetailsAttributeProblem(). A definition.");
    return definition.problem
      ? { code: 'STS-REG-0112',
          message: attribute + ': ' + definition.problem + '.' }
      : null;
  }
  log.debug("Leaving authorizationDetailsAttributeProblem(). Not asked.");
  return null;
}

// ---------------------------------------------------------------------------
// RFC 9470: WHAT A RESOURCE MAY REQUIRE (2026-09-13).
//
// The grammar of the two attributes, here because this module owns them (the
// rule `authorizationDetailsTypeOf()` keeps). `oauth-oidc/step_up.ts` holds
// the same acr pattern for what arrives in a request, and cannot be required
// from here without `common/` reaching into a protocol directory, so the
// pattern is repeated and `tests/rfc9470_step_up.js` holds the two equal.
// ---------------------------------------------------------------------------
const STEP_UP_ACR_VALUE = /^[\x21\x23-\x5B\x5D-\x7E]{1,256}$/;

const STEP_UP_MAX_AGE_LIMIT = 315360000;

// One attribute value written through the console or `/admin-api`, as
// `{ code, message }` or null. A CLEAR is never refused.
function stepUpAttributeProblem(attribute, value) {
  log.debug("Entering stepUpAttributeProblem(). attribute=" + attribute);
  const text = String(value === undefined || value === null ? '' : value)
    .trim();
  if (!text) {
    log.debug("Leaving stepUpAttributeProblem(). A clear.");
    return null;
  }
  if (attribute === 'oauthStepUpAcrValues') {
    const bad = text.split(/\s+/).filter(function (one) {
      return !STEP_UP_ACR_VALUE.test(one);
    });
    log.debug("Leaving stepUpAttributeProblem(). acr values.");
    return bad.length
      ? { code: 'STS-REG-0140',
          message: attribute + ': ' + bad.map(function (one) {
            return JSON.stringify(one.slice(0, 60));
          }).join(', ') + ' cannot be an acr value. A value is printable ' +
          'ASCII with no double quote or backslash, because it is repeated ' +
          'in a WWW-Authenticate challenge (RFC 9470 section 3).' }
      : null;
  }
  if (attribute === 'oauthStepUpMaxAge') {
    const ok = /^\d{1,9}$/.test(text) && Number(text) <= STEP_UP_MAX_AGE_LIMIT;
    log.debug("Leaving stepUpAttributeProblem(). max age.");
    return ok ? null
      : { code: 'STS-REG-0141',
          message: attribute + ': "' + text.slice(0, 60) + '" is not a ' +
          'whole number of seconds between 0 and ' + STEP_UP_MAX_AGE_LIMIT +
          '.' };
  }
  log.debug("Leaving stepUpAttributeProblem(). Not asked.");
  return null;
}

// What an entry requires, in `step_up.js`'s shape. A value an `ldapmodify`
// left that the grammar refuses is dropped with a warning rather than
// enforced: a requirement no token could meet would lock the resource with
// nothing on its page to say why.
function stepUpRequirementOf(entry) {
  log.debug("Entering stepUpRequirementOf().");
  const fields = (entry && entry.fields) || {};
  const acrText = String(valuesOf(fields.oauthStepUpAcrValues)[0] || '');
  const acrValues = [];
  acrText.split(/\s+/).forEach(function (one) {
    if (!one) {
      return;
    }
    if (!STEP_UP_ACR_VALUE.test(one)) {
      log.warn(errorCodes.tag('STS-OAUTH-0508') + 'applications: "' +
               (entry && entry.identifier) + '" holds ' +
               JSON.stringify(one.slice(0, 60)) + ' in oauthStepUpAcrValues, ' +
               'which cannot be an acr value; it is ignored.');
      return;
    }
    if (acrValues.indexOf(one) < 0) {
      acrValues.push(one);
    }
  });
  const ageText = String(valuesOf(fields.oauthStepUpMaxAge)[0] || '').trim();
  let maxAge = null;
  if (ageText) {
    if (/^\d{1,9}$/.test(ageText) &&
        Number(ageText) <= STEP_UP_MAX_AGE_LIMIT) {
      maxAge = Number(ageText);
    } else {
      log.warn(errorCodes.tag('STS-OAUTH-0508') + 'applications: "' +
               (entry && entry.identifier) + '" holds "' +
               ageText.slice(0, 60) + '" in oauthStepUpMaxAge, which is not ' +
               'a whole number of seconds; it is ignored.');
    }
  }
  log.debug("Leaving stepUpRequirementOf().");
  return { acrValues: acrValues, maxAge: maxAge,
           present: acrValues.length > 0 || maxAge !== null };
}

// WHETHER AN ACCESS TOKEN'S `aud` NAMES THIS ENTRY AS A RESOURCE: its
// identifier, an `oauthClientId`, an `oauthAudience`, or its permission base
// URI normalised on both sides — the four spellings `accessTokenPlan()`
// addresses a token to an application by, and the ones RFC 9701's
// "intended for" check in `introspection_jwt.js` reads.
function audienceNamesEntry(entry, aud) {
  log.debug("Entering audienceNamesEntry().");
  if (!entry) {
    log.debug("Leaving audienceNamesEntry(). No entry.");
    return false;
  }
  const fields = entry.fields || {};
  const audiences = (Array.isArray(aud) ? aud : [aud])
    .filter(function (one) {
      return one !== undefined && one !== null && String(one) !== '';
    }).map(String);
  const names = [String(entry.identifier)]
    .concat(valuesOf(fields.oauthClientId).map(String))
    .concat(valuesOf(fields.oauthAudience).map(String));
  const base = permissionBaseOf(valuesOf(fields.oauthPermissionBaseUri)[0] ||
                                '');
  const named = audiences.some(function (one) {
    return names.indexOf(one) >= 0 ||
           (!!base && permissionBaseOf(one) === base);
  });
  log.debug("Leaving audienceNamesEntry(). " + named);
  return named;
}

function normaliseFields(value) {
  log.debug("Entering normaliseFields().");
  const asked = (value && typeof value === 'object') ? value : {};
  const errors = [];
  const fields = {};
  // The condition the FIRST refusal was for, which is the one a caller shows
  // first — see errorCodes.mark() on the result at the foot.
  let code = '';
  Object.keys(asked).forEach(function (name) {
    const values = valuesOf(asked[name]);
    if (!values.length) {
      // An empty box is not a value and is not an error either. Every field on
      // the create form is optional, so most of them arrive empty on every
      // post.
      return;
    }
    const row = ATTRIBUTE_BY_NAME[name];
    if (!row) {
      errors.push('"' + name + '" is not in the published schema. GET ' +
                  '/admin/ldap/applications lists every attribute an entry ' +
                  'may carry; adding one that is not there means adding a ' +
                  'row to SCHEMA.attributes, not writing it through this.');
      code = code || 'STS-REG-0006';
      return;
    }
    if (!row.editable) {
      errors.push('"' + name + '" cannot be given here. It is DERIVED — what ' +
                  'has happened to this application rather than what it may ' +
                  'do — and an entry created with one would be asserting a ' +
                  'past it does not have. It is accumulated by the protocol ' +
                  'endpoints as they accept this identifier.');
      code = code || 'STS-REG-0007';
      return;
    }
    if (row.kind !== 'multi' && values.length > 1) {
      errors.push('"' + name + '" holds ONE value and ' + values.length + ' ' +
                  'were given. It is single-valued in the published schema, ' +
                  'so the alternative to refusing this is keeping one of ' +
                  'them and discarding the rest silently.');
      code = code || 'STS-REG-0008';
      return;
    }
    // THE ONE VALUE CHECK ON THIS WALK, and it is here rather than left to
    // updateApplication() because a create goes through this function and not
    // through that one. An entry created with a home page nothing may link to
    // would sit there looking configured while /portal/applications drew it
    // greyed out, which is the silent half-success this whole function exists
    // to refuse.
    //
    // THE PERMISSION ATTRIBUTES, CHECKED HERE AS WELL AS IN
    // updateApplication() (2026-09-13). A create never reached that function,
    // so a create carrying `oauthPermission` wrote names no `scope` could carry
    // and duplicates `permissionsOf()` lists twice — which an RFC 9728 import,
    // which creates an entry WITH its permissions, would have done for any
    // document naming an unusable scope. The same rules and the same codes as
    // the update: the base absolute, each name a scope token, no name twice,
    // and no permission on an entry with no base to identify it by.
    if (name === 'oauthPermissionBaseUri') {
      const problem = permissionBaseProblem(values[0]);
      if (problem) {
        errors.push(problem);
        code = code || 'STS-REG-0012';
        return;
      }
    }
    if (name === 'oauthPermission') {
      const names = {};
      const permissionProblems = [];
      values.forEach(function (one) {
        const parsed = parsePermissionValue(one);
        const problem = permissionNameProblem(parsed.name);
        if (problem) {
          permissionProblems.push(problem);
          code = code || 'STS-REG-0013';
        } else if (names[parsed.name]) {
          permissionProblems.push('The permission "' + parsed.name + '" is ' +
                                  'given twice. A permission has one ' +
                                  'description, so give it once.');
          code = code || 'STS-REG-0014';
        }
        names[parsed.name] = true;
      });
      if (!permissionProblems.length &&
          !permissionBaseOf(valuesOf(asked.oauthPermissionBaseUri)[0])) {
        permissionProblems.push('A permission is named by the base URI ' +
                                'followed by its name, and this create ' +
                                'carries no `oauthPermissionBaseUri` — give ' +
                                'one with the permissions.');
        code = code || 'STS-REG-0015';
      }
      if (permissionProblems.length) {
        permissionProblems.forEach(function (one) { errors.push(one); });
        return;
      }
    }
    if (name === 'oauthResourceMetadata' ||
        name === 'oauthResourceMetadataUrl') {
      const problem = name === 'oauthResourceMetadata'
        ? resourceMetadataProblem(values[0])
        : resourceMetadataUrlProblem(values[0]);
      if (problem) {
        errors.push(problem);
        code = code || 'STS-REG-0089';
        return;
      }
    }
    if (name === 'appHomePageUrl') {
      const problem = homePageProblem(values[0]);
      if (problem) {
        errors.push(problem);
        code = code || 'STS-REG-0011';
        return;
      }
    }
    // The addresses, every value, because a create adds every one of them.
    if (ADDRESS_ATTRIBUTES[name]) {
      const addressProblems = values.map(function (one) {
        return addressProblem(name, one);
      }).filter(function (one) {
        return !!one;
      });
      if (addressProblems.length) {
        addressProblems.forEach(function (one) { errors.push(one); });
        code = code || 'STS-REG-0071';
        return;
      }
      // Front-Channel Logout section 2, against the create's redirect URIs.
      if (name === 'oauthFrontchannelLogoutUri') {
        const originProblem = frontchannelOriginProblem(values[0],
                                                        asked.oauthRedirectUri);
        if (originProblem) {
          errors.push(originProblem);
          code = code || 'STS-REG-0171';
          return;
        }
      }
    }
    // The CORS origins, every value, and STORED NORMALISED — see
    // corsOriginWriteProblem(). A create with one value that is not an origin
    // is refused whole rather than written with the rest.
    if (name === 'appCorsOrigin') {
      const originProblems = values.map(corsOriginWriteProblem)
                                   .filter(function (one) {
        return !!one;
      });
      if (originProblems.length) {
        originProblems.forEach(function (one) { errors.push(one); });
        code = code || 'STS-REG-0150';
        return;
      }
      fields[name] = values.map(validation.normaliseOrigin)
                           .filter(function (one, index, all) {
        return all.indexOf(one) === index;
      });
      return;
    }
    // #110: a declared scope is a scope token, the rule oauthGlobalConsent
    // has, for its reason — a value that is not one can never be asked for.
    if (name === 'oauthAllowedScope') {
      const scopeProblems = values.map(scopeTokenProblem)
                                  .filter(function (one) {
        return !!one;
      });
      if (scopeProblems.length) {
        scopeProblems.forEach(function (one) { errors.push(one); });
        code = code || 'STS-REG-0172';
        return;
      }
    }
    if (name === 'ssfAllowedEvents') {
      const problems = values.map(ssfAllowedEventProblem)
                             .filter(function (one) {
        return !!one;
      });
      if (problems.length) {
        problems.forEach(function (one) { errors.push(one); });
        code = code || 'STS-REG-0053';
        return;
      }
    }
    // RFC 9701's three, read against the create's OTHER two, because a create
    // may carry the `enc` and the `alg` together and the rule is about the
    // pair.
    const introspectionProblem = introspectionAttributeProblem(name,
                                                               values[0],
                                                               asked);
    if (introspectionProblem) {
      errors.push(introspectionProblem);
      code = code || 'STS-REG-0073';
      return;
    }
    // RFC 9101's five, every value — a create may carry several request URIs.
    const requestObjectProblems = values.map(function (one) {
      return requestObjectAttributeProblem(name, one, asked);
    }).filter(function (one) {
      return !!one;
    });
    if (requestObjectProblems.length) {
      requestObjectProblems.forEach(function (one) { errors.push(one); });
      code = code || 'STS-REG-0101';
      return;
    }
    // RFC 9126's one.
    const pushedProblem = pushedAuthorizationAttributeProblem(name, values[0]);
    if (pushedProblem) {
      errors.push(pushedProblem);
      code = code || 'STS-REG-0121';
      return;
    }
    // OIDC Core sections 8 and 9 (#118), read against the create's others.
    const subjectProblem = oidcSubjectAttributeProblem(name, values[0], asked);
    if (subjectProblem) {
      errors.push(subjectProblem);
      code = code || 'STS-REG-0168';
      return;
    }
    // RFC 8705's six, read against the create's OTHER subject parameters,
    // because a create may carry two at once and the rule is about the set.
    const mtlsProblem = mtlsAttributeProblem(name, values[0], asked);
    if (mtlsProblem) {
      errors.push(mtlsProblem.message);
      code = code || mtlsProblem.code;
      return;
    }
    // RFC 9470's two.
    const stepUpProblem = stepUpAttributeProblem(name, values[0]);
    if (stepUpProblem) {
      errors.push(stepUpProblem.message);
      code = code || stepUpProblem.code;
      return;
    }
    // RFC 9396's two, every value.
    const detailsProblems = values.map(function (one) {
      return authorizationDetailsAttributeProblem(name, one);
    }).filter(function (one) {
      return !!one;
    });
    if (detailsProblems.length) {
      detailsProblems.forEach(function (one) { errors.push(one.message); });
      code = code || detailsProblems[0].code;
      return;
    }
    if (row.kind !== 'multi' && SEALED_FIELDS.indexOf(name) >= 0) {
      // PRIVATE KEY MATERIAL. Sealed here as well as in updateApplication()
      // because a create goes through this function and not through that one —
      // the same reason the home page is checked here.
      const sealedValue = sealFieldValue(name, values[0]);
      if (sealedValue === null) {
        errors.push('"' + name + '" is private key material and this service ' +
                    'could not encrypt it, so it was not stored. Storing a ' +
                    'signing key in the clear in product mode would put a ' +
                    'working credential in every directory dump. The ' +
                    'key-encryption key is the one /admin/persistence ' +
                    'reports on.');
        code = code || 'STS-REG-0019';
        return;
      }
      fields[name] = sealedValue;
      return;
    }
    fields[name] = row.kind === 'multi' ? values : values[0];
  });
  log.debug("Leaving normaliseFields(). " + Object.keys(fields).length + " " +
      "field(s), " +
            errors.length + " error(s).");
  const normalised = { ok: !errors.length, fields: fields, errors: errors };
  log.debug("Leaving normaliseFields().");
  return code ? errorCodes.mark(normalised, code) : normalised;
}

// ---------------------------------------------------------------------------
// THE STORE IS THE DIRECTORY. These are the only ways in and out of it.
//
// `ldap_server.js` fills this at its require time. The four the store is
// made of:
//
//   readApplication(identifier)   the entry, or null
//   writeApplication(identifier, attributes)  create or update it
//   allApplications()             every entry, in tree order
//   countApplications()           how many there are, for the cap message
//
// and, beside them, `deleteApplication`, `containerDn`, `maxApplications` and
// `applicationsVersion` (when anything under ou=applications last changed).
//
// The two directions are DELIBERATELY NOT SYMMETRICAL, which is worth saying
// because it looks like an oversight. A WRITE speaks in ATTRIBUTE OBJECTS
// ({name: [values]}) — that is all a record has to say, and the conversion is
// this module's because this module owns the schema. A READ hands back the
// whole ENTRY:
//
//   { dn, origin, createdAt, modifiedAt, operational: [...], attributes: {...} }
//
// the same shape ldap_server.js's objectFor() gives the console for a person.
// It has to be the entry rather than the attributes, because THE DN IS NOT AN
// ATTRIBUTE — it is the key the entry is stored under — so a caller handed only
// `attributes` had no way to learn where in the tree the application lives, and
// every applications page could show the `cn` and nothing else. That was the
// bug. `attributes` now also arrives CANONICALLY SPELLED and with the
// operational attributes included, `entryDN` among them, which is why every
// lookup below goes through byLowerName() rather than indexing the map.
// ---------------------------------------------------------------------------
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(fns) {
  log.debug("Entering setDirectory().");
  directory = fns || null;
  log.debug("Leaving setDirectory(). The registry " +
            (directory ? "is now backed by the directory." : "has no store."));
}

// WHAT IS INSTALLED, so that something which replaces it can put it back.
//
// It exists for the in-process tests and says so rather than pretending to be
// general: several of them stub this slot to answer without a directory, a
// socket or a realm, and the slot is ONE REFERENCE FOR THE WHOLE PROCESS —
// `tests/run.js` runs every file in one — so a stub left installed answers
// every later question about the registry with that file's fixtures. Two of
// them "restored" it by setting `null`, which is only right in a process where
// `ldap_server.js` was never required, and node's module cache means whether
// that is true depends on which test file happened to require it first. A test
// cannot re-run the fill (a cached module does not re-execute), so the only
// honest restore is putting back what was there.
//
// Nothing in the SERVICE calls this: `ldap_server.js` fills the slot once at
// its require time and no code path replaces it.
function directoryInstalled() {
  log.debug("Entering directoryInstalled().");
  log.debug("Leaving directoryInstalled().");
  return directory;
}

// Every read and every write goes through here, so the "there is no store"
// case is answered in one place and complained about once rather than per call.
function store() {
  log.debug("Entering store().");
  if (directory) {
    log.debug("Leaving store().");
    return directory;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn(errorCodes.tag('STS-REG-0002') +
             'applications: ldap_server.js was never required, so there is ' +
             'no ou=applications container and therefore no application ' +
             'registry. This module keeps no store of its own on purpose — a ' +
             'fallback Map would be a second source of truth, and it would ' +
             'be the one that silently disagreed. Every query answers empty ' +
             'until that module is loaded.');
  }
  log.debug("Leaving store().");
  return null;
}

function generalizedTime(when) {
  log.debug("Entering generalizedTime().");
  const d = when ? new Date(when) : new Date();
  const pad = function (n) {
    log.debug("Entering pad().");
    log.debug("Leaving pad().");
    return String(n).padStart(2, '0');
  };
  log.debug("Leaving generalizedTime().");
  return d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate()) +
         pad(d.getUTCHours()) + pad(d.getUTCMinutes()) +
         pad(d.getUTCSeconds()) + 'Z';
}

// ---------------------------------------------------------------------------
// AN ISSUED RFC 7523 KEY PAIR, ONTO ITS APPLICATION'S ENTRY (#138): the seven
// attributes `/admin/pki` writes, in the order it writes them, as one list so
// the console and this service's own surfaces (`oidc_rp.ts`, which issues its
// console, portal and debugger their private_key_jwt keys) cannot disagree
// about what an issued key pair is. `record` is `pki.issueSigningKeyPair()`'s
// `issued`.
// ---------------------------------------------------------------------------
function issuedJwtKeyPairValues(record) {
  log.debug("Entering issuedJwtKeyPairValues().");
  log.debug("Leaving issuedJwtKeyPairValues().");
  return [
    ['oauthAssertionJwks', JSON.stringify(record.jwks)],
    ['oauthAssertionCertificate', record.certificatePem],
    ['oauthAssertionCertificateChain', (record.chainPem || []).join('')],
    ['oauthAssertionPrivateKey', record.privateKeyPem],
    ['oauthAssertionKid', record.kid],
    ['oauthAssertionExpiresAt', generalizedTime(new Date(record.notAfter))],
    // `issued` for a key pair generated here; an upload's record says which
    // kind of upload it was. See KEY_SOURCES.
    ['oauthAssertionKeySource', record.source || 'issued']
  ];
}

// Writes them, all or a report of which failed. A failure loses the private
// key — common/pki.js keeps no copy — so the caller must issue again.
function storeIssuedJwtKeyPair(identifier, record) {
  log.debug("Entering storeIssuedJwtKeyPair(). " + identifier);
  const writes = issuedJwtKeyPairValues(record);
  for (let i = 0; i < writes.length; i++) {
    const done = updateApplication(identifier, {
      attribute: writes[i][0], mode: 'set', value: writes[i][1] });
    if (!done || done.ok === false) {
      log.debug("Leaving storeIssuedJwtKeyPair(). " + writes[i][0] +
                " failed.");
      return { ok: false, failed: writes[i][0],
               errors: (done && done.errors) || [] };
    }
  }
  log.debug("Leaving storeIssuedJwtKeyPair(). Stored.");
  return { ok: true };
}

function fromGeneralizedTime(value) {
  log.debug("Entering fromGeneralizedTime().");
  const text = String(value || '');
  const m = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) {
    log.debug("Leaving fromGeneralizedTime().");
    return 0;
  }
  log.debug("Leaving fromGeneralizedTime().");
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

// A short, stable name for an identifier too long to be a readable RDN. The
// same device didUid() uses on a DID, for the same reason and with the same
// consequence: the cn is then NOT the identity — `appIdentifier` is, and that
// is the attribute every lookup here searches on.
function shortName(identifier) {
  log.debug("Entering shortName().");
  log.debug("Leaving shortName().");
  return 'app-' + crypto.createHash('sha256').update(String(identifier), 'utf8')
    .digest('hex').slice(0, 12);
}

const MAX_RDN_LENGTH = 64;

function labelFor(identifier) {
  log.debug("Entering labelFor().");
  const text = String(identifier);
  log.debug("Leaving labelFor().");
  return text.length <= MAX_RDN_LENGTH ? text : shortName(text);
}

// ---------------------------------------------------------------------------
// THE TWO CONVERSIONS, which are the whole of what "a schema" means here.
//
// A record is the convenient shape; the attributes are what is stored. Both are
// built by WALKING `SCHEMA.attributes` rather than by naming each one, so a row
// added to that table reaches the directory, the page and the JSON view with no
// second edit. That property is the reason to have a table at all — it is the
// lesson vc_claims.js writes down about an issuer advertising five claims and
// minting fourteen.
// ---------------------------------------------------------------------------
function valuesOf(value) {
  log.debug("Entering valuesOf().");
  if (value === undefined || value === null || value === '') {
    log.debug("Leaving valuesOf().");
    return [];
  }
  log.debug("Leaving valuesOf().");
  return (Array.isArray(value) ? value : [value])
    .map(function (one) { return String(one); })
    .filter(function (one) { return one !== ''; });
}

function attributesFor(record) {
  log.debug("Entering attributesFor(). identifier=" + record.identifier);
  const attributes = {
    objectClass: SCHEMA.objectClasses.map(function (one) { return one.name; }),
    cn: [labelFor(record.identifier)],
    appIdentifier: [record.identifier],
    appName: [record.name || record.identifier],
    appKind: record.kinds.slice(0),
    appProtocol: record.protocols.slice(0),
    appFirstSeen: [generalizedTime(record.firstAt)],
    appLastSeen: [generalizedTime(record.lastAt)],
    appAuthentications: [String(record.authentications)],
    appSessions: [String(record.sessions.length)],
    appUsers: [String(record.users.length)],
    appRegistered: [record.registered ? 'TRUE' : 'FALSE'],
    description: record.descriptions.slice(0)
  };
  // The protocol-specific half, from the table. Anything not in the table was
  // refused at setField() and cannot get here.
  Object.keys(record.fields).forEach(function (name) {
    if (attributes[name] === undefined) {
      attributes[name] = valuesOf(record.fields[name]);
    }
  });
  // Two operational counts that are NOT attributes and must not become them:
  // the distinct session and user ids themselves. An application used by two
  // thousand people would otherwise put two thousand values on one entry, and
  // the count is the fact anybody wanted. An attribute with NO VALUES is not an
  // attribute. LDAP has no such thing — the last value takes the attribute with
  // it, which is what the modify handler in ldap_server.js does for every other
  // entry — so an empty list is dropped here rather than stored. Without this a
  // hand-created application carries an `appProtocol` with nothing in it, which
  // reads on every page and in every ldapsearch as a protocol whose name went
  // missing.
  Object.keys(attributes).forEach(function (name) {
    const values = attributes[name];
    if (Array.isArray(values) && !values.length) {
      delete attributes[name];
    }
  });
  log.debug("Leaving attributesFor(). " + Object.keys(attributes).length + " " +
      "attribute(s).");
  return attributes;
}

// Attribute names arrive from the directory in one of TWO spellings and every
// lookup here has to survive both. The store lower-cases them, because
// @ldapjs/attribute lower-cases a type on the way in; readApplication() then
// puts the CANONICAL spelling back so that a page does not show `oauthclientid`
// beside a published schema that says `oauthClientId`. So an index that assumed
// either one would silently find nothing — and finding nothing here does not
// throw, it produces a record with an empty identifier and no fields, which
// reads as an application that lost its attributes rather than as a lookup that
// missed. LDAP attribute descriptions are case-insensitive anyway (RFC 4512
// section 2.5), so folding is the correct answer and not merely the defensive
// one.
function byLowerName(attributes) {
  log.debug("Entering byLowerName().");
  const index = {};
  Object.keys(attributes || {}).forEach(function (name) {
    index[String(name).toLowerCase()] = attributes[name];
  });
  log.debug("Leaving byLowerName().");
  return index;
}

function firstValue(attributes, name) {
  log.debug("Entering firstValue().");
  const values = attributes[String(name).toLowerCase()];
  log.debug("Leaving firstValue().");
  return (values && values.length) ? String(values[0]) : '';
}

function allValues(attributes, name) {
  log.debug("Entering allValues().");
  const values = attributes[String(name).toLowerCase()];
  log.debug("Leaving allValues().");
  return (values || []).map(function (one) { return String(one); });
}

function recordFromAttributes(attributes) {
  log.debug("Entering recordFromAttributes().");
  const attrs = byLowerName(attributes);
  const record = {
    identifier: firstValue(attrs, 'appIdentifier'),
    label: firstValue(attrs, 'cn'),
    name: firstValue(attrs, 'appName'),
    kinds: allValues(attrs, 'appKind'),
    protocols: allValues(attrs, 'appProtocol'),
    descriptions: allValues(attrs, 'description'),
    firstAt: fromGeneralizedTime(firstValue(attrs, 'appFirstSeen')),
    lastAt: fromGeneralizedTime(firstValue(attrs, 'appLastSeen')),
    authentications: parseInt(firstValue(attrs, 'appAuthentications') || '0',
                              10) || 0,
    // Read back as COUNTS. The identities behind them are not on the entry (see
    // attributesFor()), so a record reconstructed from the directory can add to
    // these numbers but cannot tell whether a session it is now seeing was
    // already counted — which is stated in seen() where it matters.
    sessions: [],
    users: [],
    sessionCount: parseInt(firstValue(attrs, 'appSessions') || '0', 10) || 0,
    userCount: parseInt(firstValue(attrs, 'appUsers') || '0', 10) || 0,
    registered: firstValue(attrs, 'appRegistered') === 'TRUE',
    fields: {}
  };
  SCHEMA.attributes.forEach(function (row) {
    // The computed ones above are not fields; reading them back as fields would
    // put two copies of appKind on the next write.
    if (['appIdentifier', 'cn', 'appName', 'appKind', 'appProtocol',
         'description',
         'appFirstSeen', 'appLastSeen', 'appAuthentications', 'appSessions',
         'appUsers', 'appRegistered'].indexOf(row.name) >= 0) {
      return;
    }
    const values = allValues(attrs, row.name);
    if (!values.length) {
      return;
    }
    record.fields[row.name] = row.kind === 'multi' ? values : values[0];
  });
  log.debug("Leaving recordFromAttributes(). identifier=" + record.identifier);
  return record;
}

function blankRecord(identifier) {
  log.debug("Entering blankRecord().");
  log.debug("Leaving blankRecord().");
  return {
    identifier: String(identifier),
    label: labelFor(identifier),
    name: String(identifier),
    kinds: [],
    protocols: [],
    descriptions: [],
    firstAt: 0,
    lastAt: 0,
    authentications: 0,
    sessions: [],
    users: [],
    sessionCount: 0,
    userCount: 0,
    registered: false,
    fields: {}
  };
}

// Read one application out of the directory, or a blank record if it is not
// there yet. `known` says which, because the caller has to tell a first sight
// from a repeat and cannot infer it from an empty record.
//
// `entry` is the third thing it returns and it is NOT derivable from the other
// two: it carries the DN, the origin and the timestamps, none of which is an
// attribute of the record. Callers that only want to write ignore it — a write
// is built from the record — and the two callers that render an application
// read it, because "where does this entry live" is the question the pages could
// not answer. It is null when there is no directory, which is a different state
// from an entry with nothing on it and the pages say so.
function load(identifier) {
  log.debug("Entering load().");
  const backing = store();
  if (!backing) {
    log.debug("Leaving load().");
    return { record: blankRecord(identifier), known: false, entry: null };
  }
  const entry = backing.readApplication(String(identifier));
  if (!entry) {
    log.debug("Leaving load().");
    return { record: blankRecord(identifier), known: false, entry: null };
  }
  log.debug("Leaving load().");
  return { record: recordFromAttributes(entry.attributes), known: true,
           entry: entry };
}

function save(record) {
  log.debug("Entering save().");
  const backing = store();
  if (!backing) {
    log.debug("Leaving save().");
    return false;
  }
  log.debug("Leaving save().");
  return !!backing.writeApplication(record.identifier, attributesFor(record));
}

function addTo(list, value) {
  log.debug("Entering addTo().");
  const text = String(value == null ? '' : value).trim();
  if (!text || list.indexOf(text) >= 0) {
    log.debug("Leaving addTo().");
    return false;
  }
  list.push(text);
  log.debug("Leaving addTo().");
  return true;
}

// Set a schema field, honouring the row's `kind`: multi accumulates, single is
// assigned. The one place that distinction is applied, so a caller cannot get
// it wrong per attribute — and an attribute that is not in the table is REFUSED
// rather than written, which is what keeps the published schema true.
function setField(record, name, value) {
  log.debug("Entering setField().");
  const row = ATTRIBUTE_BY_NAME[name];
  if (!row) {
    log.warn(errorCodes.tag('STS-REG-0006') +
             'applications: "' + name + '" is not in the schema and was not ' +
             'recorded. Add a row to SCHEMA.attributes rather than writing ' +
             'an attribute nothing publishes.');
    log.debug("Leaving setField().");
    return false;
  }
  if (value === undefined || value === null || value === '') {
    log.debug("Leaving setField().");
    return false;
  }
  if (row.kind === 'multi') {
    if (!record.fields[name]) record.fields[name] = [];
    let changed = false;
    (Array.isArray(value) ? value : [value]).forEach(function (one) {
      if (addTo(record.fields[name], one)) changed = true;
    });
    log.debug("Leaving setField().");
    return changed;
  }
  const text = String(value);
  if (record.fields[name] === text) {
    log.debug("Leaving setField().");
    return false;
  }
  record.fields[name] = text;
  log.debug("Leaving setField().");
  return true;
}

// ---------------------------------------------------------------------------
// WHO PUT A RETURN ADDRESS ON THE ENTRY, AND THE ONE FUNCTION THAT DECIDES
// WHETHER IT COUNTS AS REGISTERED (2026-09-12).
//
// Development mode writes the return address a request NAMED — a SAML ACS URL,
// a SAML 1.1 `shire`, a WS-Federation `wreply`, the callback the console and
// portal learn from a Host header — onto the very attribute product mode
// checks a request against. That is fine while nothing trusts it. It stopped
// being fine the moment a realm could be switched to product: every address
// development had learnt came across as though an operator had registered it,
// and the root CLAUDE.md's answer was a sentence — "review them before the
// switch" — which is documentation and not enforcement.
//
// **SO THE ENTRY RECORDS PROVENANCE**, on `appReturnAddressObserved`, one
// value per marked address, `<attribute> <address>`. A development sighting
// that ADDS an address marks it; an operator who confirms it, discards it or
// writes it explicitly removes the mark.
//
// **`returnAddressesOf()` IS THE WHOLE RULE AND EVERY CHECK ASKS IT.** Four
// places decide whether a return address is registered — both SAML profiles,
// WS-Federation, and the console's and portal's own OIDC client through
// `clientConfigOf()` — and teaching four call sites to read a mark would be
// four places for one of them to forget. They ask for an attribute's addresses
// and get two lists back: `registered`, what the check may believe in the mode
// this realm is in, and `unconfirmed`, what it refused to believe because the
// mark is still there, so that a refusal can say how to confirm it rather than
// reading as though the address were not on the entry at all.
//
// **DEVELOPMENT BELIEVES EVERYTHING, MARKED OR NOT**, which is the
// development behaviour this change is not allowed to move: `unconfirmed` is
// always empty there. **PRODUCT BELIEVES ONLY THE UNMARKED.**
//
// **WHAT IT CANNOT DO IS TELL AN ADDRESS RECORDED BEFORE THE MARK EXISTED
// FROM A REGISTERED ONE.** Neither carries a mark, and guessing — "anything a
// sighting could have written" — would refuse addresses operators really did
// register. That half stays a review, and every surface that describes this
// says so.
// ---------------------------------------------------------------------------
function observedMarkFor(attribute, value) {
  log.debug("Entering observedMarkFor().");
  log.debug("Leaving observedMarkFor().");
  return String(attribute) + ' ' + String(value);
}

// One stored mark back into its two halves, or null for a value this service
// did not write — an `ldapmodify` reaches this attribute like every other, and
// a mark naming an attribute that is not a return address, or naming nothing,
// is not a mark on anything. It is skipped rather than refused because a
// READ must not fail over something only a write could have prevented.
function parseObservedMark(text) {
  log.debug("Entering parseObservedMark().");
  const raw = String(text == null ? '' : text);
  const at = raw.indexOf(' ');
  if (at <= 0) {
    log.debug("Leaving parseObservedMark().");
    return null;
  }
  const attribute = raw.slice(0, at);
  const value = raw.slice(at + 1).trim();
  if (RETURN_ADDRESS_ATTRIBUTES.indexOf(attribute) < 0 || !value) {
    log.debug("Leaving parseObservedMark().");
    return null;
  }
  log.debug("Leaving parseObservedMark().");
  return { attribute: attribute, value: value };
}

// A `view()`, a record or a bare fields object — the three shapes a caller has
// in hand, which is identifiersOf()'s reason for taking all three.
function fieldsOfSource(source) {
  log.debug("Entering fieldsOfSource().");
  const holder = source || {};
  log.debug("Leaving fieldsOfSource().");
  return holder.fields || holder;
}

// Every readable mark on an entry, with whether the address it marks is still
// ON the attribute. A mark whose address is gone (an `ldapmodify` removed the
// value and left the mark) is `held: false`: it decides nothing, because there
// is no address for it to withhold, and it is listed so that it can be tidied.
function observedReturnAddresses(source) {
  log.debug("Entering observedReturnAddresses().");
  const fields = fieldsOfSource(source);
  const rows = [];
  valuesOf(fields[OBSERVED_ADDRESS_ATTRIBUTE]).forEach(function (mark) {
    const parsed = parseObservedMark(mark);
    if (!parsed) {
      return;
    }
    rows.push({ attribute: parsed.attribute, value: parsed.value,
                held: valuesOf(fields[parsed.attribute]).indexOf(
                    parsed.value) >= 0 });
  });
  log.debug("Leaving observedReturnAddresses(). " + rows.length + " mark(s).");
  return rows;
}

function returnAddressesOf(source, attribute) {
  log.debug("Entering returnAddressesOf(). attribute=" + attribute);
  const fields = fieldsOfSource(source);
  const values = valuesOf(fields[attribute]);
  const marked = observedReturnAddresses(fields)
    .filter(function (row) { return row.attribute === attribute; })
    .map(function (row) { return row.value; });
  if (mode.acceptsUnregisteredAddresses()) {
    log.debug("Leaving returnAddressesOf(). Development believes all " +
              values.length + ".");
    return { attribute: attribute, registered: values, unconfirmed: [] };
  }
  const registered = values.filter(function (one) {
    return marked.indexOf(one) < 0;
  });
  const unconfirmed = values.filter(function (one) {
    return marked.indexOf(one) >= 0;
  });
  log.debug("Leaving returnAddressesOf(). Product: " + registered.length +
            " registered, " + unconfirmed.length + " still marked observed.");
  return { attribute: attribute, registered: registered,
           unconfirmed: unconfirmed };
}

// Mark what a sighting ADDED. `before` is the attribute's values before the
// write, so an address that was already on the entry — registered by hand, or
// recorded before the mark existed — is never marked by being seen again: a
// sighting may not demote a registration.
function markObservedAddresses(record, attribute, before) {
  log.debug("Entering markObservedAddresses().");
  let changed = false;
  valuesOf(record.fields[attribute]).forEach(function (one) {
    if (before.indexOf(one) >= 0) {
      return;
    }
    if (setField(record, OBSERVED_ADDRESS_ATTRIBUTE,
                 observedMarkFor(attribute, one))) {
      changed = true;
    }
  });
  log.debug("Leaving markObservedAddresses().");
  return changed;
}

// Take one mark off, whatever it holds. Answers whether anything was there.
// The last mark takes the attribute with it, which is what the remove branch
// of updateApplication() does for every other multi-valued attribute.
function clearObservedMark(record, attribute, value) {
  log.debug("Entering clearObservedMark().");
  const have = valuesOf(record.fields[OBSERVED_ADDRESS_ATTRIBUTE]);
  const left = have.filter(function (mark) {
    const parsed = parseObservedMark(mark);
    return !(parsed && parsed.attribute === attribute &&
             parsed.value === String(value));
  });
  if (left.length === have.length) {
    log.debug("Leaving clearObservedMark().");
    return false;
  }
  if (left.length) {
    record.fields[OBSERVED_ADDRESS_ATTRIBUTE] = left;
  } else {
    delete record.fields[OBSERVED_ADDRESS_ATTRIBUTE];
  }
  log.debug("Leaving clearObservedMark().");
  return true;
}

// The mode question, under a name of its own for the one function that needs
// it: updateApplication() has a local called `mode` (the change's verb) that
// shadows this module's `mode`, and reaching through the shadow is a bug that
// reads correctly.
function acceptsSightedAddresses() {
  log.debug("Entering acceptsSightedAddresses().");
  log.debug("Leaving acceptsSightedAddresses().");
  return mode.acceptsUnregisteredAddresses();
}

// ---------------------------------------------------------------------------
// SEEN — the one way an application gets into this registry.
//
// Called wherever a protocol ACCEPTS an application identifier, which is not
// the same moment as accepting a credential and therefore not the same funnel.
// That is worth stating because the user side has exactly one funnel and this
// side cannot: `admin_stats.recordAuthentication()` is reached when a PERSON is
// authenticated, and in the authorization code flow that happens in `authn.js`,
// which knows nothing about OAuth by design — the sign-in screen never reads a
// client_id. So the application is recorded where its own protocol decides it
// is real, and each of those points is named in the module that owns it.
//
// `detail` carries whatever that protocol knows:
//
//   identifier  REQUIRED — the client_id, wtrealm, AppliesTo, SPN, entityID
//   kind        one of KIND_IDS, or a LIST of them where an application is
//               genuinely several things at once — a wtrealm is both a
//               WS-Federation application and the audience of the assertion it
//               was handed. A list is one sighting and counts once
//   protocol    the family name, as /admin/users spells it
//   name        a friendly name, where there is one
//   fields      {schemaAttribute: value}, applied through setField()
//   sessionId   the sign-on session this happened on, when there is one
//   user        the identity key of whoever authenticated, when there is one
//   counts      false to record the appearance WITHOUT counting an
//               authentication — an authorization request is not an
//               authentication, and counting one there would double every
//               code flow
//
// ON THE DISTINCT COUNTS. `appSessions` and `appUsers` are counts of distinct
// ids, and the ids themselves are deliberately not kept on the entry — so this
// function cannot check whether the session it is looking at was already
// counted. It increments when the caller passes one that differs from the LAST
// one recorded, which is right for the ordinary case (a session signs in to an
// application once) and undercounts a person who alternates between two
// applications and back. That is the honest trade for not putting an unbounded
// list of session ids in a directory entry, and it is why the schema calls
// these counts rather than lists.
// ---------------------------------------------------------------------------
function seen(detail) {
  log.debug("Entering seen().");
  const info = detail || {};
  const identifier = String(info.identifier == null ? '' :
                            info.identifier).trim();
  // Normalised ONCE, because three lines below print it and a bare `info.kind`
  // renders a list as "a,b" in one of them and not in the others.
  const statedKinds = (Array.isArray(info.kind) ? info.kind : [info.kind])
    .filter(Boolean).map(function (one) { return String(one); });
  const kindPhrase = statedKinds.length ? ' (' + statedKinds.join(', ') + ')' :
                     '';
  log.debug("Entering seen(). identifier=" + (identifier || '(none)') +
            ", kind=" + (statedKinds.join(', ') || '(unstated)'));
  if (!identifier) {
    log.debug("Leaving seen(). There was no identifier to record.");
    log.debug("Leaving seen().");
    return null;
  }
  const loaded = load(identifier);
  const record = loaded.record;
  const known = loaded.known;
  // **PRODUCT MODE RECORDS A SIGHTING AND CREATES NOTHING** (2026-09-06). An
  // application entry appearing because a protocol ACCEPTED an identifier is
  // the behaviour that lets a client point at this service with any client_id
  // and get a working exchange — which is most of what makes it a mock, and
  // exactly what product mode removes.
  //
  // **IT RETURNS NULL RATHER THAN THROWING, AND THE CALLER DECIDES.** This
  // function is reached from a score of protocol sites, all of them in the
  // middle of an exchange, and none of them wants the registry to be able to
  // fail a request: the REFUSAL belongs at the protocol's own door, where it
  // can be said in that protocol's own vocabulary. What this guarantees is
  // only that nothing was written.
  if (!known && !mode.autoCreates()) {
    log.info('applications: product mode, so "' + identifier + '"' +
             kindPhrase +
             ' was NOT created on sight. An application must be provisioned ' +
             'ahead of time, through the console, /admin-api or an LDAP add.');
    log.debug("Leaving seen(). Product mode creates nothing.");
    return null;
  }
  const now = Date.now();
  let changed = !known;

  // ONE SIGHTING MAY NAME SEVERAL KINDS, and two protocols need it to. A
  // wtrealm handed a SAML 1.1 assertion is a WS-Federation application AND the
  // audience of that assertion — both are true of the same request, and the
  // registry accumulates rather than choosing. Passing a list rather than
  // calling seen() twice matters: a second call would count a second
  // authentication for one act, which is the trap `counts: false` exists for
  // one field over.
  statedKinds.forEach(function (kind) {
    if (KIND_IDS.indexOf(kind) < 0) {
      log.warn('applications: "' + kind + '" is not one of the kinds this ' +
               'registry knows ' +
               '(' + KIND_IDS.join(', ') + '). It is recorded as ' +
               'given, which is how one application comes to be listed under ' +
               'two spellings — fix the caller or add a row to KINDS.');
    }
    if (addTo(record.kinds, kind)) changed = true;
  });
  if (info.protocol && addTo(record.protocols, info.protocol)) changed = true;
  if (info.name) {
    const name = String(info.name);
    if (record.name !== name) {
      record.name = name;
      changed = true;
    }
  }
  if (info.note && addTo(record.descriptions, info.note)) changed = true;

  // **A SIGHTING MAY NOT WRITE A RETURN ADDRESS WHERE ONLY A REGISTERED ONE IS
  // BELIEVED** (2026-09-12). A family's `redirectAttribute` — an ACS URL, a
  // wreply, a redirect URI — is what product mode checks a request's return
  // address AGAINST (`mode.acceptsUnregisteredAddresses()`). Development writes
  // what it observed into that same attribute, and that is fine while nothing
  // trusts it; in product it would make the check circular, since the request
  // being judged would be the one that put the address on the list. So a
  // sighting's value for any of those attributes is dropped here, in the one
  // funnel every protocol site reaches, and the entry holds only what was
  // DECLARED.
  //
  // **AND WHAT DEVELOPMENT DOES WRITE IS MARKED AS OBSERVED (2026-09-12).**
  // This comment used to end: "What this does not undo is a realm switched from
  // development to product, whose entries still carry the addresses development
  // observed — … the thing an operator has to review by hand before the
  // switch." Every address a development sighting ADDS now gets a mark on
  // `appReturnAddressObserved`, and returnAddressesOf() — which every
  // return-address check asks — withholds a marked address in product until an
  // operator confirms it. What is still a review by hand is an address recorded
  // before the mark existed, because nothing can tell it from a registration.
  const guarded = mode.acceptsUnregisteredAddresses() ? [] :
                  RETURN_ADDRESS_ATTRIBUTES;
  Object.keys(info.fields || {}).forEach(function (name) {
    if (guarded.indexOf(name) >= 0) {
      log.info('applications: product mode, so a sighting of "' + identifier +
               '" ' +
               'did not write ' + name + ' — a return address is registered, ' +
               'never learnt from the request it would be checked against.');
      return;
    }
    const isAddress = RETURN_ADDRESS_ATTRIBUTES.indexOf(name) >= 0;
    const before = isAddress ? valuesOf(record.fields[name]) : [];
    if (setField(record, name, info.fields[name])) changed = true;
    if (isAddress && markObservedAddresses(record, name, before)) {
      log.info('applications: a sighting of "' + identifier + '" wrote a new ' +
               name +
               ' and marked it OBSERVED. Development uses it as it is; ' +
               'product will refuse it until it is confirmed on the ' +
               'application\'s page.');
      changed = true;
    }
  });

  record.firstAt = record.firstAt || now;
  record.lastAt = now;
  if (info.counts !== false) {
    record.authentications++;
    changed = true;
  }
  // See the note above about what these can and cannot know.
  if (info.sessionId &&
      record.fields.appLastSession !== String(info.sessionId)) {
    record.sessionCount++;
    setField(record, 'appLastSession', info.sessionId);
    changed = true;
  }
  if (info.user && record.fields.appLastUser !== String(info.user)) {
    record.userCount++;
    setField(record, 'appLastUser', info.user);
    changed = true;
  }
  record.sessions = new Array(record.sessionCount);
  record.users = new Array(record.userCount);

  if (!changed) {
    log.debug("Leaving seen(). It was already known and said nothing new.");
    log.debug("Leaving seen().");
    return record;
  }
  if (!save(record) && store()) {
    // A directory is there and would not take the entry — the container is at
    // applications.max. Nothing else records it: the protocol exchange that
    // made this sighting goes on regardless, and the audit row below describes
    // what was SEEN rather than what was written.
    audit.failure('STS-REG-0020', {
      protocol: String(info.protocol || 'unstated'), channel: 'internal',
      actor: info.user || '', target: identifier,
      summary: 'The application registry could not write "' + identifier +
               '": the ou=applications container is full (applications.max) ' +
               'or the directory refused the entry.',
      outcome: 'error'
    });
  }

  if (!known) {
    log.debug('applications: first sight of "' + identifier + '"' +
              kindPhrase + '. ' + count() +
              ' application(s) in the directory.');
  }

  // The audit row. `application.create` on first sight and
  // `application.update` when an existing record learned something — never for
  // a repeat that changed nothing, or every token request would produce a row
  // saying nothing happened.
  //
  // audit() cannot throw (see its header) and carries no credential: neither
  // the client secret nor the registration access token that may be on this
  // record is ever a field here.
  audit.audit({
    action: known ? 'application.update' : 'application.create',
    actor: info.user || '',
    protocol: String(info.protocol || 'unstated'),
    channel: 'internal',
    target: identifier,
    summary: (known ? 'Application "' : 'A new application "') + identifier +
             (known ? '" recorded something new' : '" was seen for the first ' +
                                                   'time') +
             kindPhrase,
    detail: {
      identifier: identifier,
      kinds: record.kinds.join(', '),
      protocols: record.protocols.join(', '),
      authentications: record.authentications,
      registered: record.registered
    }
  });
  log.debug("Leaving seen(). " +
            (known ? "It was already known." : "It is new."));
  log.debug("Leaving seen().");
  return record;
}

// ---------------------------------------------------------------------------
// DYNAMIC CLIENT REGISTRATION (RFC 7591) LIVES IN THE DIRECTORY.
//
// It used to be a `registeredClients` Map in oauth2.js. It moved for the
// one-store rule: this registry would otherwise hold half of what is known
// about a client and that Map the other half, and the first time the two
// disagreed about a redirect URI it would be an RFC 9700 refusal nobody could
// explain. oauth2.js now reads through `registrationOf()` and writes through
// these three functions, which is the same number of call sites it had.
//
// The document is stored WHOLE in `appRegistrationJson` — see that row in the
// schema for why an attribute set cannot replace it — and the members that DO
// have attributes are written to them as well, because those attributes are
// what the checks read and what an operator edits.
// ---------------------------------------------------------------------------
function applyRegistrationFields(record, registration, statement) {
  log.debug("Entering applyRegistrationFields().");
  const meta = registration || {};
  // HOW A SOFTWARE STATEMENT LET IT IN (RFC 7591 section 2.3, 2026-09-13), as
  // three facts `oauth-oidc/software_statement.ts` verified — never read off
  // the document, whose `software_statement` member is only the string the
  // client sent. An ABSENT statement CLEARS all three, for RFC 9701's reason
  // below: RFC 7592 section 2.2 replaces the whole registration.
  softwareStatementFactNames().forEach(function (name) {
    delete record.fields[name];
  });
  if (statement && statement.issuer) {
    setField(record, 'appSoftwareStatementIssuer', statement.issuer);
    setField(record, 'appSoftwareStatementTrusted',
             statement.trusted ? 'TRUE' : 'FALSE');
    setField(record, 'appSoftwareStatementPublisher', statement.publisher);
  }
  setField(record, 'appRegistrationJson', JSON.stringify(meta));
  setField(record, 'appRegistrationAccessToken',
           meta.registration_access_token);
  setField(record, 'oauthClientId', record.identifier);
  setField(record, 'oauthClientSecret', meta.client_secret);
  // RFC 7591's key members. `jwks` is stored as text because that is what the
  // verifier parses and what an operator edits; `jwks_uri` is recorded and
  // never followed (see its schema row).
  if (meta.jwks) {
    setField(record, 'oauthJwks',
             typeof meta.jwks === 'string' ? meta.jwks :
             JSON.stringify(meta.jwks));
  }
  setField(record, 'oauthJwksUri', meta.jwks_uri);
  // RFC 8705 section 2.1.2's five subject parameters and section 3.4's flag,
  // and an ABSENT member is CLEARED — the RFC 9701 rule below, for its reason:
  // RFC 7592 section 2.2 replaces the whole registration, and a client that
  // moved from one subject parameter to another must not end up holding both,
  // which `mtlsMetadataProblem()` refuses and the verifier refuses again.
  certificateSubject.MEMBER_NAMES.forEach(function (member) {
    const attribute = certificateSubject.MEMBERS[member].attribute;
    delete record.fields[attribute];
    if (typeof meta[member] === 'string' && meta[member].trim()) {
      setField(record, attribute, meta[member].trim());
    }
  });
  if (typeof meta.tls_client_certificate_bound_access_tokens === 'boolean') {
    setField(record, TLS_BOUND_TOKENS_ATTRIBUTE,
             meta.tls_client_certificate_bound_access_tokens ? 'TRUE' :
                                                              'FALSE');
  } else {
    delete record.fields[TLS_BOUND_TOKENS_ATTRIBUTE];
  }
  // RFC 9701 section 6's three, and an ABSENT member is CLEARED rather than
  // left alone — unlike the members above, and on purpose. RFC 7592 section
  // 2.2 replaces the whole registration, so a client that updates without
  // `introspection_encrypted_response_alg` has withdrawn it; keeping the stored
  // one would go on encrypting responses to a key the client may have retired,
  // which it would see as introspection having stopped working.
  Object.keys(INTROSPECTION_ATTRIBUTES).forEach(function (member) {
    const attribute = INTROSPECTION_ATTRIBUTES[member];
    const value = String(meta[member] || '').trim();
    if (value) {
      setField(record, attribute, value);
    } else {
      delete record.fields[attribute];
    }
  });
  // RFC 9101's five, CLEARED when absent for the introspection members'
  // reason: an RFC 7592 update replaces the registration, and a request_uri
  // the client withdrew must stop being one this service will fetch.
  delete record.fields.oauthRequestUri;
  if (Array.isArray(meta.request_uris) && meta.request_uris.length) {
    setField(record, 'oauthRequestUri', meta.request_uris.map(function (one) {
      return String(one).trim();
    }));
  }
  ['request_object_signing_alg', 'request_object_encryption_alg',
   'request_object_encryption_enc'].forEach(function (member) {
    const attribute = REQUEST_OBJECT_ATTRIBUTES[member];
    const value = String(meta[member] || '').trim();
    if (value) {
      setField(record, attribute, value);
    } else {
      delete record.fields[attribute];
    }
  });
  if (typeof meta.require_signed_request_object === 'boolean') {
    setField(record, 'oauthRequireSignedRequestObject',
             meta.require_signed_request_object ? 'TRUE' : 'FALSE');
  } else {
    delete record.fields.oauthRequireSignedRequestObject;
  }
  // RFC 9126 section 6, the same way: an update that omits it clears it.
  if (typeof meta.require_pushed_authorization_requests === 'boolean') {
    setField(record, 'oauthRequirePushedAuthorizationRequests',
             meta.require_pushed_authorization_requests ? 'TRUE' : 'FALSE');
  } else {
    delete record.fields.oauthRequirePushedAuthorizationRequests;
  }
  // OIDC Core sections 8 and 9 (#118), the same way: an update that omits
  // one clears it.
  Object.keys(OIDC_SUBJECT_ATTRIBUTES).forEach(function (member) {
    const value = String(meta[member] || '').trim();
    if (value) {
      setField(record, OIDC_SUBJECT_ATTRIBUTES[member], value);
    } else {
      delete record.fields[OIDC_SUBJECT_ATTRIBUTES[member]];
    }
  });
  // RFC 9396 section 10, the same way: an update that omits it clears it.
  delete record.fields.oauthAuthorizationDetailsTypes;
  if (Array.isArray(meta.authorization_details_types) &&
      meta.authorization_details_types.length) {
    setField(record, 'oauthAuthorizationDetailsTypes',
             meta.authorization_details_types.map(String));
  }
  setField(record, 'oauthRedirectUri', meta.redirect_uris);
  // A REGISTRATION IS AN EXPLICIT STATEMENT, so a redirect URI it names is
  // registered however it first got onto the entry — the same rule an
  // explicit `add` follows in updateApplication(). Without this a client that
  // re-registered through RFC 7592 the callback development had learnt would
  // still be refused in product for a mark its own registration contradicts.
  valuesOf(meta.redirect_uris).forEach(function (uri) {
    clearObservedMark(record, 'oauthRedirectUri', uri);
  });
  setField(record, 'oauthPostLogoutRedirectUri',
           meta.post_logout_redirect_uris);
  // Front-Channel Logout 1.0 section 2. The boolean is written as the string
  // TRUE/FALSE the directory holds, and only when the registration SAID
  // something: RFC 7591 section 2 makes an omitted member false, but "false"
  // and "not stated" are different facts about a client and this registry
  // records which one happened. clientConfigOf() below applies the default.
  setField(record, 'oauthFrontchannelLogoutUri', meta.frontchannel_logout_uri);
  if (meta.frontchannel_logout_session_required !== undefined) {
    setField(record, 'oauthFrontchannelLogoutSessionRequired',
             meta.frontchannel_logout_session_required ? 'TRUE' : 'FALSE');
  }
  // Back-Channel Logout 1.0 section 2.2, the same way (2026-09-17, #36).
  setField(record, 'oauthBackchannelLogoutUri', meta.backchannel_logout_uri);
  if (meta.backchannel_logout_session_required !== undefined) {
    setField(record, 'oauthBackchannelLogoutSessionRequired',
             meta.backchannel_logout_session_required ? 'TRUE' : 'FALSE');
  }
  // RFC 7591 section 2 `client_uri`: "URL string of a web page providing
  // information about the client". That is the application's home page, which
  // is the fact appHomePageUrl holds, so a registered client arrives with one
  // already set and /portal/applications can link it without anybody editing
  // the entry. Unchecked here on purpose — applyRegistrationFields() records
  // what a registration SAID, and homePageOf() refuses to draw a link to
  // anything that is not http or https when it reads.
  setField(record, 'appHomePageUrl', meta.client_uri);
  setField(record, 'oauthGrantType', meta.grant_types);
  setField(record, 'oauthResponseType', meta.response_types);
  // RFC 7591 section 2's `scope` is a DECLARATION — "the list that the
  // client can use when requesting access tokens" — so it goes on the
  // declared attribute and never on `oauthScope`, which is what the client
  // has ASKED for (#110). CLEARED when absent, for RFC 9701's reason above:
  // RFC 7592 section 2.2 replaces the whole registration. The registration
  // endpoint has already refused a protected scope in it
  // (`common/scope_policy.ts`); a seeded row is this service's own and may
  // declare one.
  delete record.fields.oauthAllowedScope;
  const declaredScope = String(meta.scope || '').split(/\s+/)
    .filter(function (one) { return !!one; });
  if (declaredScope.length) {
    setField(record, 'oauthAllowedScope', declaredScope);
  }
  // RFC 7591 section 2: an omitted method means client_secret_basic, so the
  // attribute states the EFFECTIVE value rather than the absence. An entry
  // saying nothing here would read as "unknown", and RFC 9700 mode's answer for
  // this client is not unknown — it is confidential.
  const method = meta.token_endpoint_auth_method === undefined
    ? 'client_secret_basic' : String(meta.token_endpoint_auth_method);
  setField(record, 'oauthTokenEndpointAuthMethod', method);
  setField(record, 'oauthConfidential',
           method && method !== 'none' ? 'TRUE' : 'FALSE');
  log.debug("Leaving applyRegistrationFields().");
}

// `options.softwareStatement` is `software_statement.resolve()`'s account of a
// statement the registration carried — see applyRegistrationFields().
function register(clientId, registration, options) {
  log.debug("Entering register(). client_id=" + clientId);
  // THE BACKSTOP. The registration endpoint asks registrationUriProblem() and
  // introspectionResponseProblem() and answers 400 before calling this; a
  // caller that did not is refused here rather than writing an address or an
  // algorithm nothing would then check.
  const uriProblem = registrationUriProblem(registration) ||
                     introspectionResponseProblem(registration) ||
                     idTokenEncryptionMetadataProblem(registration) ||
                     requestObjectMetadataProblem(registration) ||
                     pushedAuthorizationMetadataProblem(registration) ||
                     oidcSubjectMetadataProblem(registration) ||
                     mtlsMetadataProblem(registration) ||
                     authorizationDetailsMetadataProblem(registration);
  if (uriProblem) {
    log.warn(errorCodes.tag(uriProblem.errorCode) + 'applications: client "' +
             clientId + '" was not registered: ' + uriProblem.description);
    log.debug("Leaving register(). An unusable address.");
    return null;
  }
  const loaded = load(clientId);
  const record = loaded.record;
  const now = Date.now();
  record.registered = true;
  // Only when nobody registered it first: an administrator's entry that later
  // registers through RFC 7591 was still put here by the administrator.
  if (!record.fields.appRegisteredBy) {
    setField(record, 'appRegisteredBy', 'rfc7591');
  }
  record.firstAt = record.firstAt || now;
  record.lastAt = now;
  addTo(record.kinds, 'oauth2-client');
  addTo(record.protocols, 'OAuth 2.0');
  addTo(record.descriptions, 'registered through RFC 7591 dynamic client ' +
                             'registration');
  if (registration.client_name) record.name = String(registration.client_name);
  applyRegistrationFields(record, registration,
                          (options || {}).softwareStatement);
  const written = save(record);
  audit.audit({
    action: loaded.known ? 'application.update' : 'application.create',
    actor: '', protocol: 'OAuth 2.0', channel: 'internal',
    target: String(clientId),
    summary: 'Client "' + clientId + '" registered through RFC 7591',
    detail: { identifier: String(clientId), registered: true,
              redirectUris: (registration.redirect_uris || []).length,
              storedInDirectory: written }
  });
  if (!written) {
    log.warn(errorCodes.tag(store() ? 'STS-REG-0020' : 'STS-REG-0002') +
             'applications: client "' + clientId + '" was registered but ' +
             'could not be stored — there is no directory (see store()) or ' +
             'it is full. The response to the client is still correct; the ' +
             'RFC 7592 management operations on it will answer 404, because ' +
             'the directory is where they read from.');
  }
  log.debug("Leaving register().");
  return record;
}

function updateRegistration(clientId, registration, options) {
  log.debug("Entering updateRegistration(). client_id=" + clientId);
  // The same backstop as register().
  const uriProblem = registrationUriProblem(registration) ||
                     introspectionResponseProblem(registration) ||
                     idTokenEncryptionMetadataProblem(registration) ||
                     requestObjectMetadataProblem(registration) ||
                     pushedAuthorizationMetadataProblem(registration) ||
                     mtlsMetadataProblem(registration) ||
                     authorizationDetailsMetadataProblem(registration);
  if (uriProblem) {
    log.warn(errorCodes.tag(uriProblem.errorCode) + 'applications: client "' +
             clientId + '" was not updated: ' + uriProblem.description);
    log.debug("Leaving updateRegistration(). An unusable address.");
    return null;
  }
  const loaded = load(clientId);
  if (!loaded.known) {
    log.debug("Leaving updateRegistration(). No such application.");
    return null;
  }
  const record = loaded.record;
  record.lastAt = Date.now();
  if (registration.client_name) record.name = String(registration.client_name);
  applyRegistrationFields(record, registration,
                          (options || {}).softwareStatement);
  save(record);
  log.debug("Leaving updateRegistration().");
  return record;
}

// RFC 7592's delete. The REGISTRATION goes; the application entry stays, with
// `appRegistered` back to FALSE. That is not a half-measure — this registry
// records what this service has SEEN, and deleting the history of an
// application because its registration was withdrawn would lose the fact that
// it was ever here. What RFC 9700 mode reads afterwards is the ATTRIBUTES, not
// this flag: the redirect URIs the registration wrote stay on the entry and
// are still what the client is judged against, and with the secret gone an
// entry declaring a confidential method has nothing on file to check.
//
// The secret and the registration access token are REMOVED with it rather than
// left on the entry: they are credentials for a registration that no longer
// exists, and an entry that kept them would let the deleted client go on
// authenticating in RFC 9700 mode.
function forgetRegistration(clientId) {
  log.debug("Entering forgetRegistration(). client_id=" + clientId);
  const loaded = load(clientId);
  if (!loaded.known) {
    log.debug("Leaving forgetRegistration(). No such application.");
    return false;
  }
  const record = loaded.record;
  record.registered = false;
  if (record.fields.appRegisteredBy === 'rfc7591') {
    delete record.fields.appRegisteredBy;
  }
  delete record.fields.appRegistrationJson;
  delete record.fields.appRegistrationAccessToken;
  delete record.fields.oauthClientSecret;
  // How a software statement let the registration in is a fact about the
  // registration, and goes with it.
  softwareStatementFactNames().forEach(function (name) {
    delete record.fields[name];
  });
  setField(record, 'oauthConfidential', 'FALSE');
  addTo(record.descriptions, 'its RFC 7592 registration was deleted');
  record.lastAt = Date.now();
  save(record);
  log.debug("Leaving forgetRegistration(). The registration is gone; the " +
            "entry stays.");
  return true;
}

// The three attributes applyRegistrationFields() writes about a software
// statement, named once.
function softwareStatementFactNames() {
  log.debug("Entering softwareStatementFactNames().");
  log.debug("Leaving softwareStatementFactNames().");
  return ['appSoftwareStatementIssuer', 'appSoftwareStatementTrusted',
          'appSoftwareStatementPublisher'];
}

// ---------------------------------------------------------------------------
// HOW A REGISTERED CLIENT GOT IN, as far as a software statement goes, or null
// when it presented none. `oauth2.js` asks it before an RFC 7592 update, which
// must carry a statement from the same issuer where the endpoint is closed
// (`software_statement.updateProblem()`), and the application's page draws it.
// ---------------------------------------------------------------------------
function softwareStatementFactsOf(clientId) {
  log.debug("Entering softwareStatementFactsOf().");
  const loaded = load(clientId);
  const fields = loaded.known ? (loaded.record.fields || {}) : {};
  const one = function (name) {
    log.debug("Entering one().");
    const values = valuesOf(fields[name]);
    log.debug("Leaving one().");
    return values.length ? String(values[0]) : '';
  };
  const issuer = one('appSoftwareStatementIssuer');
  if (!issuer) {
    log.debug("Leaving softwareStatementFactsOf(). None.");
    return null;
  }
  log.debug("Leaving softwareStatementFactsOf().");
  return { issuer: issuer,
           trusted: one('appSoftwareStatementTrusted') === 'TRUE',
           publisher: one('appSoftwareStatementPublisher') };
}

// What oauth2.js's `registeredClients.get(id)` used to answer: the RFC 7591
// record, or null for an application that merely turned up. "Registered" is the
// distinction RFC 9700 mode's redirect URI and client authentication rules turn
// on, so an application with no registration must answer null rather than a
// half-filled object.
//
// THE ATTRIBUTES WIN. The stored document is the starting point — it is the
// only thing that can carry a member with no attribute of its own — and then
// every member that has one is overwritten from it. That is what makes an
// `ldapmodify` of `oauthRedirectUri` a configuration change rather than a note.
function registrationOf(clientId) {
  log.debug("Entering registrationOf().");
  const loaded = load(clientId);
  if (!loaded.known || !loaded.record.registered) {
    log.debug("Leaving registrationOf().");
    return null;
  }
  const record = loaded.record;
  /** @type {any} */
  let document = {};
  const raw = record.fields.appRegistrationJson;
  if (raw) {
    try {
      document = JSON.parse(raw);
    } catch (e) {
      // Somebody edited the attribute by hand and left it unparseable. The
      // attributes below still describe this client, so the registration is
      // rebuilt from them alone rather than the client being told it does not
      // exist — and the reason is logged, because a hand-edited entry silently
      // losing half its members is worse than either outcome.
      log.warn(errorCodes.tag('STS-REG-0024') +
               'applications: appRegistrationJson on "' + clientId + '" is ' +
               'not valid JSON and was ignored; the registration is rebuilt ' +
               'from the attributes beside it. ' + e.message);
      document = {};
    }
  }
  const fields = record.fields;
  if (fields.oauthClientSecret !== undefined) document.client_secret =
      fields.oauthClientSecret;
  if (fields.appRegistrationAccessToken !== undefined) {
    document.registration_access_token = fields.appRegistrationAccessToken;
  }
  if (fields.oauthRedirectUri) document.redirect_uris =
      fields.oauthRedirectUri.slice(0);
  if (fields.oauthPostLogoutRedirectUri) {
    document.post_logout_redirect_uris =
        fields.oauthPostLogoutRedirectUri.slice(0);
  }
  if (fields.oauthFrontchannelLogoutUri !== undefined) {
    document.frontchannel_logout_uri = fields.oauthFrontchannelLogoutUri;
  }
  if (fields.oauthFrontchannelLogoutSessionRequired !== undefined) {
    document.frontchannel_logout_session_required =
      String(fields.oauthFrontchannelLogoutSessionRequired).toUpperCase() === 'TRUE';
  }
  if (fields.oauthBackchannelLogoutUri !== undefined) {
    document.backchannel_logout_uri = fields.oauthBackchannelLogoutUri;
  }
  if (fields.oauthBackchannelLogoutSessionRequired !== undefined) {
    document.backchannel_logout_session_required =
      String(fields.oauthBackchannelLogoutSessionRequired)
        .toUpperCase() === 'TRUE';
  }
  if (fields.oauthGrantType) document.grant_types = fields.oauthGrantType.slice(
      0);
  if (fields.oauthResponseType) document.response_types =
      fields.oauthResponseType.slice(0);
  if (fields.oauthTokenEndpointAuthMethod !== undefined) {
    document.token_endpoint_auth_method = fields.oauthTokenEndpointAuthMethod;
  }
  // RFC 7591 section 3.2.1 returns the registered `scope`, and the
  // attribute is what an operator edits (#110) — so it is read from there,
  // and a list cleared on the console is a member the document no longer
  // carries.
  const allowedScope = valuesOf(fields.oauthAllowedScope).map(String)
    .filter(function (one) { return !!one.trim(); });
  if (allowedScope.length) {
    document.scope = allowedScope.join(' ');
  } else {
    delete document.scope;
  }
  // RFC 9701's three, from the attributes, so an operator's edit is what RFC
  // 7592's read hands back — and an attribute cleared on the console is a
  // member the document no longer carries.
  Object.keys(INTROSPECTION_ATTRIBUTES).forEach(function (member) {
    const held = fields[INTROSPECTION_ATTRIBUTES[member]];
    if (held !== undefined && String(held).trim()) {
      document[member] = String(held);
    } else {
      delete document[member];
    }
  });
  // OIDC Core sections 8 and 9's three (#118), the same way.
  Object.keys(OIDC_SUBJECT_ATTRIBUTES).forEach(function (member) {
    const held = fields[OIDC_SUBJECT_ATTRIBUTES[member]];
    if (held !== undefined && String(held).trim()) {
      document[member] = String(held);
    } else {
      delete document[member];
    }
  });
  // And RFC 9101's five, the same way.
  const requestUris = valuesOf(fields.oauthRequestUri).map(String);
  if (requestUris.length) {
    document.request_uris = requestUris;
  } else {
    delete document.request_uris;
  }
  ['request_object_signing_alg', 'request_object_encryption_alg',
   'request_object_encryption_enc'].forEach(function (member) {
    const held = fields[REQUEST_OBJECT_ATTRIBUTES[member]];
    if (held !== undefined && String(held).trim()) {
      document[member] = String(held);
    } else {
      delete document[member];
    }
  });
  if (fields.oauthRequireSignedRequestObject !== undefined &&
      String(fields.oauthRequireSignedRequestObject).trim()) {
    document.require_signed_request_object =
      String(fields.oauthRequireSignedRequestObject).toUpperCase() === 'TRUE';
  } else {
    delete document.require_signed_request_object;
  }
  if (fields.oauthRequirePushedAuthorizationRequests !== undefined &&
      String(fields.oauthRequirePushedAuthorizationRequests).trim()) {
    document.require_pushed_authorization_requests =
      String(fields.oauthRequirePushedAuthorizationRequests).toUpperCase() ===
      'TRUE';
  } else {
    delete document.require_pushed_authorization_requests;
  }
  // And RFC 8705's six, the same way (2026-09-13).
  certificateSubject.MEMBER_NAMES.forEach(function (member) {
    const held = fields[certificateSubject.MEMBERS[member].attribute];
    if (held !== undefined && String(held).trim()) {
      document[member] = String(held);
    } else {
      delete document[member];
    }
  });
  if (fields[TLS_BOUND_TOKENS_ATTRIBUTE] !== undefined &&
      String(fields[TLS_BOUND_TOKENS_ATTRIBUTE]).trim()) {
    document.tls_client_certificate_bound_access_tokens =
      String(fields[TLS_BOUND_TOKENS_ATTRIBUTE]).toUpperCase() === 'TRUE';
  } else {
    delete document.tls_client_certificate_bound_access_tokens;
  }
  const detailsTypes = valuesOf(fields.oauthAuthorizationDetailsTypes)
    .map(String);
  if (detailsTypes.length) {
    document.authorization_details_types = detailsTypes;
  } else {
    delete document.authorization_details_types;
  }
  document.client_id = record.identifier;
  log.debug("Leaving registrationOf().");
  return document;
}

// ---------------------------------------------------------------------------
// WHAT RFC 9700 MODE READS, normalised into one object.
//
// `registrationOf()` above answers "what did this client REGISTER", which is an
// RFC 7591/7592 question. This answers a different one: "what is this client
// ALLOWED to do", which is what the security checks need — and the two stopped
// being the same question the moment the console could create an application
// and give it redirect URIs without a registration behind it.
//
// So this is built from the ATTRIBUTES and not from the registration document.
// That is the same precedence rule `registrationOf()` follows and it is the
// whole point of the directory being the source of truth: an `oauthRedirectUri`
// added by `ldapmodify`, by the console, by the management API or by
// registration is the same attribute, and the check cannot tell — or care —
// which put it there. `appRegistered` records HOW an application got here, not
// whether what it holds counts.
//
// `known: false` means this service has never seen the identifier at all, which
// is a different answer from an entry with nothing on it: the first falls back
// to the `oauth2.redirectUris` setting, the second is a client somebody has
// begun configuring and has not finished.
// ---------------------------------------------------------------------------
function declaredClient(record, fields, redirectCount) {
  log.debug("Entering declaredClient().");
  const has = function (name) {
    return valuesOf(fields[name]).some(function (one) {
      return String(one).trim() !== '';
    });
  };
  const allowed = valuesOf(fields.appAllowedProtocol).map(String);
  const declared = !!record.registered || redirectCount > 0 ||
    ['oauthTokenEndpointAuthMethod', 'oauthClientSecret', 'oauthJwks',
     'oauthJwksUri', 'oauthAssertionJwks', 'oauthAssertionIssuer',
     'oauthSamlAssertionIssuer', 'oauthSamlAssertionSigningCertificate',
     'oauthSamlAssertionCertificate',
     'oauthTlsClientCertificateThumbprint', TLS_BOUND_TOKENS_ATTRIBUTE]
      .concat(TLS_SUBJECT_ATTRIBUTES).some(has) ||
    allowed.indexOf('oauth2') >= 0 || allowed.indexOf('oidc') >= 0 ||
    allowed.indexOf('oid4vci') >= 0;
  log.debug("Leaving declaredClient(). " + declared);
  return declared;
}

function clientConfigOf(identifier) {
  log.debug("Entering clientConfigOf(). identifier=" + identifier);
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving clientConfigOf(). Never seen.");
    return { known: false, registered: false, declared: false,
             redirect_uris: [],
             post_logout_redirect_uris: [], token_endpoint_auth_method: '',
             frontchannel_logout_uri: '',
             frontchannel_logout_session_required: false,
             backchannel_logout_uri: '',
             backchannel_logout_session_required: false,
             subject_type: 'public', sector_identifier_uri: '',
             token_endpoint_auth_signing_alg: '',
             client_secret: '' };
  }
  const fields = loaded.record.fields;
  // RFC 7591 section 2 makes client_secret_basic the default when a
  // REGISTRATION omits the member — so an omission means confidential for a
  // registered client and says nothing at all for one that was created by hand.
  // The two are told apart here rather than at the check, because this is where
  // both facts are.
  const method = fields.oauthTokenEndpointAuthMethod !== undefined
    ? String(fields.oauthTokenEndpointAuthMethod)
    : (loaded.record.registered ? 'client_secret_basic' : '');
  // THE REDIRECT URIs GO THROUGH returnAddressesOf() (2026-09-12), so that a
  // callback development LEARNT — `common/oidc_rp.ts` teaches the console's and
  // portal's own clients the address they were reached at — is not a registered
  // redirect URI in product until somebody confirms it. That is what every
  // reader of this member gets, RFC 9700 mode's exact-match check included,
  // and `unconfirmed_redirect_uris` is beside it so a refusal can say why. In
  // development the two lists are what they always were: all of them, and none.
  const redirects = returnAddressesOf(fields, 'oauthRedirectUri');
  const config = {
    known: true,
    registered: loaded.record.registered,
    // WHETHER ANYTHING ON THE ENTRY WAS DECLARED rather than SIGHTED
    // (2026-09-13). OAuth 2.1 mode refuses a token request from a client that
    // declares nothing, and "has an entry" cannot be the test: every client_id
    // that ever reached an endpoint here has one, written by `seen()`. What a
    // sighting writes for OAuth is `oauthClientId`, `appAuthorizationServer`,
    // `oauthScope`, `oauthResponseType`, `oauthGrantType` and
    // `appRedirectUriObserved` — so declared is anything else that says what
    // this client IS: a registration, a redirect URI of its own, an
    // authentication method, a credential, an assertion issuer, or a declared
    // OAuth protocol family.
    declared: declaredClient(loaded.record, fields,
                             redirects.registered.length +
                             redirects.unconfirmed.length),
    redirect_uris: redirects.registered.slice(0),
    // Not an RFC 7591 member, and spelled like one only so that it sits beside
    // the member it qualifies. Nothing serialises this object to a client.
    unconfirmed_redirect_uris: redirects.unconfirmed.slice(0),
    post_logout_redirect_uris: (fields.oauthPostLogoutRedirectUri || []).slice(
        0),
    // Where a sign-out notifies this client, and whether it wants to be told
    // WHICH session ended. The boolean defaults FALSE per RFC 7591 section 2's
    // rule for an omitted member — the same rule the auth method above follows
    // — so a client that registered a URI and said nothing else is notified
    // without iss and sid, which is what it asked for.
    frontchannel_logout_uri: fields.oauthFrontchannelLogoutUri === undefined
      ? '' : String(fields.oauthFrontchannelLogoutUri),
    frontchannel_logout_session_required:
      String(fields.oauthFrontchannelLogoutSessionRequired ||
             '').toUpperCase() === 'TRUE',
    // Where a sign-out POSTs this client a Logout Token (Back-Channel Logout
    // 1.0, 2026-09-17), and whether it asked for `sid` in it — defaulted
    // FALSE by the same RFC 7591 rule.
    backchannel_logout_uri: fields.oauthBackchannelLogoutUri === undefined
      ? '' : String(fields.oauthBackchannelLogoutUri),
    backchannel_logout_session_required:
      String(fields.oauthBackchannelLogoutSessionRequired ||
             '').toUpperCase() === 'TRUE',
    token_endpoint_auth_method: method,
    client_secret: fields.oauthClientSecret === undefined
      ? '' : String(fields.oauthClientSecret),
    // ROTATION AND EXPIRY (#49 P5): the secret a rotation replaced and until
    // when it is accepted (ms), and when the current one expires (seconds,
    // 0 for never) — the attribute, or a registration's own
    // client_secret_expires_at when only that says.
    client_secret_previous: fields.oauthClientSecretPrevious === undefined
      ? '' : String(fields.oauthClientSecretPrevious),
    client_secret_previous_until: Number(valuesOf(
      fields.oauthClientSecretPreviousUntil)[0]) || 0,
    client_secret_expires_at: secretExpiryOf(fields),
    // What an ASYMMETRIC method verifies against. Public key material and two
    // certificate facts — none of them a secret, which is the property RFC 9700
    // section 2.5 is recommending them for.
    jwks: fields.oauthJwks === undefined ? '' : String(fields.oauthJwks),
    jwks_uri: fields.oauthJwksUri === undefined ? '' :
              String(fields.oauthJwksUri),
    // THE JWKS THIS SERVICE ISSUED, from its own certificate authority
    // (2026-09-10). A SECOND member beside `jwks` rather than a fallback into
    // it: the issue path must not overwrite keys a client registered, and a
    // client holding both was given both deliberately. `client_auth.js` ORs
    // them and `assertion_grant.js` does the same for the other half of RFC
    // 7523.
    assertion_jwks: fields.oauthAssertionJwks === undefined
      ? '' : String(fields.oauthAssertionJwks),
    // RFC 7522's two, and they are two MORE members rather than a fallback
    // into either of the three above: a SAML assertion is verified only
    // against a certificate registered under these names, and a client that
    // holds a JWT key pair and no SAML one has nothing registered for that
    // profile. `saml_assertion_grant.js`'s header argues why the sets may not
    // be merged.
    saml_signing_certificate:
      fields.oauthSamlAssertionSigningCertificate === undefined
      ? '' : String(fields.oauthSamlAssertionSigningCertificate),
    saml_assertion_certificate:
      fields.oauthSamlAssertionCertificate === undefined
      ? '' : String(fields.oauthSamlAssertionCertificate),
    // The chain above it (2026-09-13): for an external authority's
    // certificate uploaded in place of an issued one, the issuers are held
    // nowhere else, and the revocation check needs them to verify a list.
    saml_assertion_certificate_chain:
      fields.oauthSamlAssertionCertificateChain === undefined
      ? '' : String(fields.oauthSamlAssertionCertificateChain),
    tls_client_auth_subject_dn: fields.oauthTlsClientAuthSubjectDn === undefined
      ? '' : String(fields.oauthTlsClientAuthSubjectDn),
    // RFC 8705 section 2.1.2's other four, spelled as the registration members
    // because `certificate_subject.registeredOf()` reads them by those names.
    tls_client_auth_san_dns: fields.oauthTlsClientAuthSanDns === undefined
      ? '' : String(fields.oauthTlsClientAuthSanDns),
    tls_client_auth_san_uri: fields.oauthTlsClientAuthSanUri === undefined
      ? '' : String(fields.oauthTlsClientAuthSanUri),
    tls_client_auth_san_ip: fields.oauthTlsClientAuthSanIp === undefined
      ? '' : String(fields.oauthTlsClientAuthSanIp),
    tls_client_auth_san_email: fields.oauthTlsClientAuthSanEmail === undefined
      ? '' : String(fields.oauthTlsClientAuthSanEmail),
    // RFC 8705 section 3.4. RFC 7591 section 2's rule for an omitted boolean:
    // FALSE.
    tls_client_certificate_bound_access_tokens:
      String(fields[TLS_BOUND_TOKENS_ATTRIBUTE] || '').toUpperCase() ===
      'TRUE',
    // THE ENTRY'S OWN NAME (2026-09-13), for RFC 8705's implicit mapping: a
    // certificate this realm issued names an application by the identifier the
    // registry holds, which need not be the client_id this request presented —
    // an application answers to several.
    identifier: String(loaded.record.identifier || ''),
    // OIDC Core sections 8 and 9 (#118), spelled as the registration members.
    // An empty subject_type is `public`, the section 8 default.
    subject_type: String(fields.oauthSubjectType || '').trim() || 'public',
    sector_identifier_uri: fields.oauthSectorIdentifierUri === undefined
      ? '' : String(fields.oauthSectorIdentifierUri),
    token_endpoint_auth_signing_alg:
      fields.oauthTokenEndpointAuthSigningAlg === undefined
      ? '' : String(fields.oauthTokenEndpointAuthSigningAlg),
    certificate_thumbprint:
      fields.oauthTlsClientCertificateThumbprint === undefined
      ? '' : String(fields.oauthTlsClientCertificateThumbprint),
    // RFC 9701 section 6, spelled as the registration members because
    // `oauth-oidc/introspection_jwt.ts` reads them by those names. Empty is
    // "not registered", and that file applies the section's defaults.
    introspection_signed_response_alg:
      fields.oauthIntrospectionSignedResponseAlg === undefined
      ? '' : String(fields.oauthIntrospectionSignedResponseAlg),
    introspection_encrypted_response_alg:
      fields.oauthIntrospectionEncryptedResponseAlg === undefined
      ? '' : String(fields.oauthIntrospectionEncryptedResponseAlg),
    introspection_encrypted_response_enc:
      fields.oauthIntrospectionEncryptedResponseEnc === undefined
      ? '' : String(fields.oauthIntrospectionEncryptedResponseEnc),
    // RFC 9101 / OpenID Connect Registration, spelled as the registration
    // members because `oauth-oidc/request_object.ts` reads them by those names.
    request_uris: valuesOf(fields.oauthRequestUri).map(String),
    request_object_signing_alg:
      fields.oauthRequestObjectSigningAlg === undefined
      ? '' : String(fields.oauthRequestObjectSigningAlg),
    request_object_encryption_alg:
      fields.oauthRequestObjectEncryptionAlg === undefined
      ? '' : String(fields.oauthRequestObjectEncryptionAlg),
    request_object_encryption_enc:
      fields.oauthRequestObjectEncryptionEnc === undefined
      ? '' : String(fields.oauthRequestObjectEncryptionEnc),
    require_signed_request_object:
      String(fields.oauthRequireSignedRequestObject || '').toUpperCase() ===
      'TRUE',
    // RFC 9126 section 6, read by `pushedRequestPolicyRefusal()`.
    require_pushed_authorization_requests:
      String(fields.oauthRequirePushedAuthorizationRequests || '')
        .toUpperCase() === 'TRUE',
    // RFC 9396 section 10, read by `oauth-oidc/authorization_details.ts`.
    // Empty is "any type this authorization server supports".
    authorization_details_types:
      valuesOf(fields.oauthAuthorizationDetailsTypes).map(String)
  };
  log.debug("Leaving clientConfigOf(). " + config.redirect_uris.length +
            " redirect URI(s), method=" + (method || '(unstated)') + ".");
  return config;
}

// ---------------------------------------------------------------------------
// The authentication funnel's half of it. `admin_stats.recordAuthentication()`
// calls this for every accepted credential that names an application, which
// covers the grants where the client IS the identity (client_credentials) and
// every protocol that passes a client_id along. The protocols whose application
// identifier never reaches that funnel call `seen()` directly — see its header.
// ---------------------------------------------------------------------------
function recordAuthentication(info) {
  log.debug("Entering recordAuthentication().");
  const detail = info || {};
  const identifier = String(detail.client_id || '').trim();
  if (!identifier) {
    log.debug("Leaving recordAuthentication().");
    return null;
  }
  log.debug("Entering recordAuthentication(). client_id=" + identifier);
  const kind = detail.applicationKind || 'oauth2-client';
  // Which ATTRIBUTE the identifier lands in follows the kind, because these are
  // three different things that happen to arrive through one field: a client_id
  // at the token endpoint, the Verifier's own client_id, and a service
  // principal name. Writing all three to `oauthClientId` would put an SPN in
  // the attribute RFC 9700 mode reads, which is the sort of thing that looks
  // harmless until something enforces it.
  const fields = {};
  if (kind === 'oid4vp-verifier') {
    fields.oid4vpClientId = identifier;
  } else if (kind === 'kerberos-service') {
    fields.krb5ServicePrincipalName = identifier;
  } else {
    fields.oauthClientId = identifier;
  }
  const record = seen({
    identifier: identifier,
    kind: kind,
    protocol: detail.protocol || 'OAuth 2.0',
    sessionId: detail.sessionId || '',
    user: detail.user || '',
    note: detail.note || '',
    fields: fields
  });
  log.debug("Leaving recordAuthentication().");
  log.debug("Leaving recordAuthentication().");
  return record;
}

// ---------------------------------------------------------------------------
// WRITING — the console's and the management API's half.
//
// Every one of these does the same read-modify-write `seen()` does, through the
// same two conversions, so the console is not a second door onto this registry:
// it is the same door with a form in front of it. That is what keeps the
// one-store rule intact now that there are three ways in — the protocol
// endpoints, LDAP, and these — rather than three stores that agree until they
// do not.
//
// None of them counts an authentication. `seen()` is the only thing that does,
// because only a protocol accepting a credential is one; an operator adding a
// redirect URI has not authenticated anybody, and a counter that moved when
// somebody edited a form would make the number mean nothing.
// ---------------------------------------------------------------------------

// A name that could be a person, a group, or this service's own container. The
// registry is not the place to file one, and an entry created here with a DN
// that collides with something else in the tree is a directory problem rather
// than a refusal somebody can act on — so the shapes are refused by name.
function identifierProblem(identifier) {
  log.debug("Entering identifierProblem().");
  const text = String(identifier || '').trim();
  if (!text) {
    log.debug("Leaving identifierProblem().");
    return 'An identifier is required — the client_id, wtrealm, AppliesTo, ' +
           'entityID or service principal name this application is known by.';
  }
  if (text.length > 512) {
    log.debug("Leaving identifierProblem().");
    return 'That identifier is ' + text.length + ' characters. The longest ' +
           'this registry will hold is 512, which is already far past ' +
           'anything a client_id or an entityID should be.';
  }
  if (/[\r\n\0]/.test(text)) {
    log.debug("Leaving identifierProblem().");
    return 'An identifier cannot contain a line break or a NUL.';
  }
  log.debug("Leaving identifierProblem().");
  return null;
}

function createApplication(detail) {
  log.debug("Entering createApplication().");
  const info = detail || {};
  const identifier = String(info.identifier || '').trim();
  log.debug("Entering createApplication(). identifier=" + identifier);
  const problem = identifierProblem(identifier);
  if (problem) {
    log.debug("Leaving createApplication(). " + problem);
    log.debug("Leaving createApplication().");
    return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0001');
  }
  if (!store()) {
    log.debug("Leaving createApplication(). There is no directory to create " +
              "it in.");
    log.debug("Leaving createApplication().");
    return errorCodes.mark({ ok: false, errors: ['There is no directory ' +
                                 'loaded in this process, so there is no ' +
                                 'ou=applications container and nothing to ' +
                                 'create. The registry has no store of its ' +
                                 'own on purpose.'] }, 'STS-REG-0002');
  }
  const loaded = load(identifier);
  if (loaded.known) {
    log.debug("Leaving createApplication(). It is already here.");
    log.debug("Leaving createApplication().");
    return errorCodes.mark({ ok: false, errors: ['"' + identifier + '" is ' +
                                 'already in this registry. Change what it ' +
                                 'holds instead of creating it again — an ' +
                                 'identifier names one application here ' +
                                 'whatever protocol brought it.'] },
                           'STS-REG-0003');
  }
  const kind = String(info.kind || '').trim();
  if (kind && KIND_IDS.indexOf(kind) < 0) {
    log.debug("Leaving createApplication(). Unknown kind.");
    // The count comes from the list, not from a word typed beside it. It said
    // "eight" over nine kinds from the day `kerberos-service` was added — a
    // sentence that is wrong about the one thing it exists to explain, in the
    // reply somebody reads precisely when they are guessing at the vocabulary.
    return errorCodes.mark({ ok: false, errors: ['"' + kind + '" is not one ' +
                                 'of the kinds this registry knows. ' +
                                 'The ' + numberWord(KIND_IDS.length) +
                                 ' are: ' + KIND_IDS.join(', ') + '.'] },
                           'STS-REG-0004');
  }
  // THE DECLARED PROTOCOL FAMILIES, validated before anything is written, for
  // the reason the kind above is: a create that half-succeeded — the entry
  // there, one of the ticked boxes silently dropped — is worse than a refusal,
  // because the entry then reads as a complete declaration.
  const asked = normaliseProtocols(info.protocols === undefined ? [] :
                                   info.protocols);
  if (!asked.ok) {
    log.debug("Leaving createApplication(). Unknown protocol family.");
    log.debug("Leaving createApplication().");
    return errorCodes.mark({ ok: false, errors: asked.errors }, 'STS-REG-0005');
  }
  // THE ATTRIBUTES THE CREATE CARRIES — the per-family identifiers and the
  // redirect URIs the form asks for, and anything else editable a caller sends.
  // Validated before the entry exists, for the reason the families above are:
  // an entry created with a client_id and without the redirect URI somebody
  // typed beside it is an entry that reads as finished.
  //
  // THIS PARAMETER WAS BEING IGNORED. `saml2Action()` and `saml11Action()` in
  // admin.js have passed `fields: { samlEntityId: identifier }` since they were
  // written and it went nowhere — so registering a service provider from the
  // console produced an entry with no entityID on it, and the attribute only
  // appeared later when a real AuthnRequest arrived and seen() wrote it. Both
  // now work, which is a change in what those two buttons produce.
  const given = normaliseFields(info.fields);
  if (!given.ok) {
    log.debug("Leaving createApplication(). " + given.errors.length + " bad " +
        "field(s).");
    log.debug("Leaving createApplication().");
    return errorCodes.mark({ ok: false, errors: given.errors },
                           errorCodes.codeOf(given));
  }
  // AND THE FAMILY RULE, against the families this create is ABOUT TO WRITE
  // rather than against an entry that does not exist yet. That is the whole
  // reason familyRefusal() takes the list as a parameter: an update reads it
  // off `appAllowedProtocol` and a create has not written that attribute at
  // this point, and one function has to answer both or the form that ticks
  // OAuth 2.0 and fills the field in one submission would be refused by a check
  // reading an empty entry.
  const wrongFamily = Object.keys(given.fields).map(function (name) {
    return familyRefusal(name, asked.protocols, identifier);
  }).filter(function (one) { return !!one; });
  if (wrongFamily.length) {
    log.debug("Leaving createApplication(). " + wrongFamily.length +
              " field(s) do not apply to the families declared.");
    log.debug("Leaving createApplication().");
    return errorCodes.mark({ ok: false, errors: wrongFamily }, 'STS-REG-0010');
  }
  const record = loaded.record;
  const now = Date.now();
  record.firstAt = now;
  record.lastAt = now;
  if (info.name) record.name = String(info.name);
  if (kind) addTo(record.kinds, kind);
  // Registered by an operator — see appRegisteredBy's row for why this is not
  // appRegistered, which would make the entry an RFC 7591 client.
  setField(record, 'appRegisteredBy', 'administrator');
  // The declaration goes on `appAllowedProtocol` and DELIBERATELY NOT on
  // `appKind` or `appProtocol`, even though every row of the PROTOCOLS table
  // names the kind its family would produce. Ticking SAML 2.0 is a statement
  // about what this application is FOR; writing `saml2-service-provider` into
  // its kinds would be this registry claiming it has SEEN one, which is the
  // derived-versus-declared line EDITABLE's header draws, and the kinds are on
  // the wrong side of it. So the page shows what the kind WOULD be and the
  // entry says nothing until a protocol actually recognises the identifier.
  if (asked.protocols.length) {
    setField(record, 'appAllowedProtocol', asked.protocols);
  }
  // Through setField(), so a `multi` attribute accumulates and a `single` one
  // is assigned exactly as they would on any other write. The record is blank
  // here so nothing can be accumulated ONTO — but going round setField() would
  // be a second place that decision is made, and the first time the two
  // disagreed would be the first time somebody created an application over one
  // that had just been deleted.
  Object.keys(given.fields).forEach(function (name) {
    setField(record, name, given.fields[name]);
  });
  // ---------------------------------------------------------------------
  // AN APPLICATION DECLARED FOR SAML GETS AN ENTITYID, added 2026-08-27.
  //
  // Ticking SAML 2.0 or SAML 1.1 on /admin/applications/new and typing no
  // entityID used to produce an entry that could not be used as a service
  // provider at all: `samlEntityId` is what /saml2 and /saml11 file an
  // application under and what their per-service-provider metadata is
  // published for, so without it the declaration was a note and nothing more.
  //
  // THE DEFAULT IS THE IDENTIFIER, and that is not an arbitrary pick — it is
  // what the same application would have got by arriving on its own. A service
  // provider that turns up with an AuthnRequest is filed under its entityID,
  // so identifier and entityID are ALREADY one string on every SAML entry this
  // registry has ever created for itself. Doing anything else here would make
  // a hand-made entry the odd one out.
  //
  // IT IS A DEFAULT AND NOT A RULE. An explicit `samlEntityId` in the create
  // wins — the loop above has already run — and this only fills a gap. Nothing
  // is refused: this service accepts any entityID on sight and creates the
  // entry, so refusing to CREATE one here would be the only place in the SAML
  // path that turned somebody away, which is the opposite of what the rest of
  // this file does.
  //
  // The metadata is then live immediately, at /saml2/metadata/{slug} and
  // /saml11/metadata/{rp}, because those endpoints mint a document for
  // anything asked of them — see saml/CLAUDE.md's decision 1.
  const declaredSaml = asked.protocols.filter(function (id) {
    return id === 'saml2' || id === 'saml11';
  });
  if (declaredSaml.length && !valuesOf(record.fields.samlEntityId).length) {
    setField(record, 'samlEntityId', identifier);
    log.debug('applications: "' + identifier + '" is declared for ' +
              declaredSaml.join(' and ') + ' and carried no entityID, so its ' +
              'identifier is being used as one. Its per-service-provider ' +
              'metadata is live from now — /admin/applications names the ' +
              'URL, which carries a slug this module deliberately does not ' +
              'compute (slugOf() belongs to saml/saml2_sso.ts, and requiring ' +
              'it here would point this module at a protocol). Set ' +
              'samlEntityId explicitly to use a different name.');
  }
  // ---------------------------------------------------------------------
  // AN APPLICATION DECLARED FOR OAUTH 2.0 OR OIDC GETS A CLIENT
  // AUTHENTICATION METHOD, added 2026-09-18.
  //
  // A create that ticked OAuth 2.0 or OpenID Connect and named no
  // `oauthTokenEndpointAuthMethod` used to write none at all, and an entry
  // with no method is read two ways: `oauth2_bcp.js`'s `isConfidential()`
  // calls it public (it cannot SEE a confidential client), while product
  // mode's gate applies RFC 7591 section 2's default, client_secret_basic,
  // and requires a credential. So a browser application created by hand with
  // no secret was refused `invalid_client` at the token endpoint on its
  // first code exchange, by a log line calling it public — found on
  // test-idp.iyasec.io the day product mode began allowing public clients.
  //
  // THE METHOD FOLLOWS THE CREDENTIAL THE CREATE CARRIED, because that is
  // what the person filling in the form said: a secret is
  // client_secret_basic (RFC 7591's own default for a client that has one),
  // a JWK Set or its URI is private_key_jwt, and NOTHING is `none` — a public
  // client, held to PKCE and RFC 9700 in product mode rather than refused.
  // An explicit `oauthTokenEndpointAuthMethod` wins, as samlEntityId's does
  // above; this only fills a gap, so every entry this create writes for
  // those families says what it will be held to.
  const declaredOauth = asked.protocols.filter(function (id) {
    return id === 'oauth2' || id === 'oidc';
  });
  if (declaredOauth.length &&
      !valuesOf(record.fields.oauthTokenEndpointAuthMethod).length) {
    const has = function (name) {
      return valuesOf(record.fields[name]).some(function (v) {
        return String(v).trim() !== '';
      });
    };
    const method = has('oauthClientSecret') ? 'client_secret_basic' :
      (has('oauthJwks') || has('oauthJwksUri')) ? 'private_key_jwt' : 'none';
    setField(record, 'oauthTokenEndpointAuthMethod', method);
    log.debug('applications: "' + identifier + '" is declared for ' +
              declaredOauth.join(' and ') + ' and named no ' +
              'token_endpoint_auth_method, so it is ' + method +
              (method === 'none' ?
               ' — a PUBLIC client, since the create carried no credential' :
               ', from the credential the create carried') +
              '. Set oauthTokenEndpointAuthMethod explicitly to change it.');
  }
  // WHERE IT CAME FROM, said on the entry itself. An application created here
  // has never authenticated anything and its counters are zero; without this
  // line a reader would have to infer that from the zeros, and "created by
  // hand" and "turned up once and never again" would look alike.
  addTo(record.descriptions, 'created from the console; nothing has ' +
                             'authenticated for it yet');
  if (!save(record)) {
    log.debug("Leaving createApplication(). The container would not take it.");
    log.debug("Leaving createApplication().");
    return errorCodes.mark({ ok: false, errors: ['The ou=applications ' +
                                 'container is full (applications.max) or ' +
                                 'the directory is. Nothing was ' +
                                 'created.'] }, 'STS-REG-0020');
  }
  audit.audit({
    action: 'application.create', actor: info.actor || '', protocol: 'console',
    channel: 'internal', target: identifier,
    summary: 'Application "' + identifier + '" was created from the console' +
             (kind ? ' (' + kind + ')' : ''),
    detail: { identifier: identifier, kind: kind || '', createdByHand: true,
              protocols: asked.protocols.join(', '),
              // The NAMES only. One of the editable attributes a create can
              // carry is oauthClientSecret, and audit.js's no-credential rule
              // is not something this caller gets to make an exception to.
              attributes: Object.keys(given.fields).join(', ') }
  });
  log.debug('applications: "' + identifier + '" was created by hand' +
            (asked.protocols.length ?
             ', declared for ' + asked.protocols.join(', ') : '') +
            '. ' + count() + ' application(s) in the directory.');
  log.debug("Leaving createApplication(). Created.");
  log.debug("Leaving createApplication().");
  return { ok: true, application: viewAfterWrite(identifier, record) };
}

// What an action hands back about the application it just wrote: the ENTRY as
// the directory now holds it, re-read rather than reconstructed from the record
// in hand. Re-reading is not ceremony — the record does not know the DN, the
// origin or modifyTimestamp, all three of which the directory decides, so a
// reply built from it would be missing exactly the facts this shape was widened
// to carry. The fallback covers the one case where the write did not land (no
// directory attached, or the container full): the caller still gets the
// application it asked about, with `dn` null saying why.
function viewAfterWrite(identifier, record) {
  log.debug("Entering viewAfterWrite().");
  log.debug("Leaving viewAfterWrite().");
  return get(identifier) || view(record, null);
}

// One attribute changed, in the mode its schema row allows. `mode` is checked
// against the row rather than trusted, because a `set` on a multi-valued
// attribute would replace a list of redirect URIs with one and read afterwards
// as the others having been forgotten.
function updateApplication(identifier, change) {
  log.debug("Entering updateApplication().");
  const asked = change || {};
  const attribute = String(asked.attribute || '');
  const mode = String(asked.mode || '');
  log.debug("Entering updateApplication(). identifier=" + identifier +
            ", attribute=" + attribute + ", mode=" + mode);
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving updateApplication(). No such application.");
    log.debug("Leaving updateApplication().");
    return errorCodes.mark({ ok: false, errors: ['There is no application ' +
                                                 'called ' +
                                                 '"' + identifier + '" ' +
                                 'in this registry. An entry appears when an ' +
                                 'identifier is ACCEPTED by a protocol, or ' +
                                 'when one is created ' +
                                 'here.'] }, 'STS-REG-0021');
  }
  const row = ATTRIBUTE_BY_NAME[attribute];
  if (!row) {
    log.debug("Leaving updateApplication(). Not in the schema.");
    log.debug("Leaving updateApplication().");
    return errorCodes.mark({ ok: false, errors: ['"' + attribute + '" is not ' +
                                 'in the published schema. GET ' +
                                 '/admin/ldap/applications lists every ' +
                                 'attribute an entry may carry; adding one ' +
                                 'that is not there means adding a row to ' +
                                 'SCHEMA.attributes, not writing it through ' +
                                 'this.'] }, 'STS-REG-0006');
  }
  if (!row.editable) {
    log.debug("Leaving updateApplication(). Not editable.");
    log.debug("Leaving updateApplication().");
    return errorCodes.mark({ ok: false, errors: ['"' + attribute + '" is not ' +
                                 'editable here. It is DERIVED — what ' +
                                 'happened rather than what this application ' +
                                 'may do — and a form that could rewrite it ' +
                                 'would make this page lie about the ' +
                                 'service\'s own behaviour. The ' +
                                 editableAttributes().length + ' that are ' +
                                     'editable are: ' +
                                 editableAttributes().map(function (one) {
                                   return one.name;
                                 }).join(', ') + '.'] }, 'STS-REG-0007');
  }
  if (row.editable === 'set' && mode !== 'set') {
    log.debug("Leaving updateApplication().");
    return errorCodes.mark({ ok: false, errors: ['"' + attribute + '" holds ' +
                                 'ONE value, so it is set rather than added ' +
                                 'to or removed from.'] }, 'STS-REG-0008');
  }
  if (row.editable === 'multi' && mode !== 'add' && mode !== 'remove') {
    log.debug("Leaving updateApplication().");
    return errorCodes.mark({ ok: false, errors: ['"' + attribute + '" holds ' +
                                 'a LIST, so values are added and removed ' +
                                 'rather than set — a set would replace the ' +
                                 'list with one value and read afterwards as ' +
                                 'the others having been ' +
                                 'forgotten.'] }, 'STS-REG-0008');
  }
  let value = String(asked.value == null ? '' : asked.value);
  if (mode !== 'set' && !value) {
    log.debug("Leaving updateApplication().");
    return errorCodes.mark({ ok: false,
                             errors: ['A value is required to ' + mode + '.'] },
                           'STS-REG-0009');
  }
  // THE ONE EDITABLE ATTRIBUTE WITH A CLOSED VOCABULARY, checked here so that
  // this edit and the create form cannot disagree about what a protocol family
  // is — a `create` that refuses "saml-2" beside an `add` that records it would
  // leave the registry holding two spellings of one family, which is the exact
  // failure the KINDS table's comment describes.
  //
  // ONLY AN ADD IS CHECKED, deliberately. A remove has to name a value that is
  // ALREADY on the entry, and `ldapmodify` reaches this attribute like every
  // other — so refusing to remove a value this table does not recognise would
  // shut the one door that could tidy up what LDAP had put there.
  if (attribute === 'appAllowedProtocol' && mode === 'add') {
    const known = normaliseProtocols(value);
    if (!known.ok) {
      log.debug("Leaving updateApplication(). Unknown protocol family.");
      return errorCodes.mark({ ok: false, errors: known.errors },
                             'STS-REG-0005');
    }
  }

  // ---------------------------------------------------------------------------
  // AND THE RULE THAT READS THAT ATTRIBUTE BACK: an attribute scoped to a
  // protocol family may only be written onto an entry declared for one of them.
  // See familyRefusal() and the block above `oauthTokenExchangeRefreshToken`,
  // the first row to carry `families` (fifteen do today).
  //
  // HERE rather than in the console for the reason every rule in this function
  // is: this is the ONE door the form and `POST /admin-api/applications/update`
  // both go through, and a refusal enforced in either alone is a refusal the
  // other walks around.
  //
  // A CLEAR IS ALWAYS ALLOWED — `mode === 'set'` with an empty value — which is
  // the same asymmetry the permission rules and `appAllowedProtocol` have, read
  // one step further. A value can arrive here by `ldapmodify`, or be left
  // behind by a family being untimed from the entry after it was set, and
  // refusing to remove it would shut the one door that could tidy it up.
  if ((mode === 'set' && value) || mode === 'add') {
    const wrongFamily = familyRefusal(attribute,
                                      declaredFamiliesOf(loaded.record),
                                      identifier);
    if (wrongFamily) {
      log.debug("Leaving updateApplication(). The attribute does not apply " +
                "to this entry.");
      return errorCodes.mark({ ok: false, errors: [wrongFamily] },
                             'STS-REG-0010');
    }
  }

  // ---------------------------------------------------------------------------
  // THE DELEGATED PERMISSION RULES, AND THEY ARE HERE FOR THE REASON THE
  // PROTOCOL FAMILY CHECK ABOVE IS: this function is the ONE door the console
  // form and `POST /admin-api/applications/update` both go through, and a rule
  // enforced in either of them alone would be a rule the other could walk
  // around. `common/app_permissions.ts`'s five actions call this function too,
  // so there is one implementation of each rule and not five.
  //
  // Three rules, and each of them is about something that would otherwise fail
  // silently rather than loudly:
  //
  //   * A BASE URI MUST BE ABSOLUTE, because it becomes an access token's
  //     `aud`.
  //   * A PERMISSION NEEDS A BASE URI ALREADY ON THE ENTRY, because base + name
  //     is the identifier and a permission with no base is one no client can
  //     ever name — it would sit on the entry looking defined and match
  //     nothing.
  //   * A GRANT MUST NAME A PERMISSION THAT EXISTS. This is the ordering rule
  //     the feature was asked for: define the permission, then grant it.
  //
  // ONLY AN ADD OR A SET IS CHECKED, the same asymmetry `appAllowedProtocol`
  // has above and for the same reason: a remove names a value already on the
  // entry, and refusing to remove what an `ldapmodify` put there would shut the
  // one door that could tidy it up. Clearing the base is likewise allowed even
  // where permissions still hang off it — the console reports those as having
  // no identifier, which is the honest state, and refusing the clear would mean
  // an entry could not be dismantled in any order.
  // THE HOME PAGE, checked for the reason the base URI below it is: this
  // function is the ONE door the console form and
  // `POST /admin-api/applications/update` both go through. Only a `set`
  // carrying a value — clearing it is how an entry stops naming a home page,
  // and that is a state /portal/applications draws rather than an error.
  if (attribute === 'ssfAllowedEvents' &&
      (mode === 'add' || (mode === 'set' && value))) {
    const problem = ssfAllowedEventProblem(value);
    if (problem) {
      log.debug("Leaving updateApplication(). Not an event type or profile.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0053');
    }
  }
  // RFC 9701's three: an algorithm this service can sign or encrypt with, and
  // no `enc` onto an entry with no `alg`. A clear is never refused.
  if (mode === 'set' && value) {
    const problem = introspectionAttributeProblem(attribute, value,
                                                  loaded.record.fields);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable introspection " +
                "response algorithm.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0073');
    }
  }
  // RFC 9101's five, on an ADD or a SET that carries a value.
  if ((mode === 'set' || mode === 'add') && value) {
    const problem = requestObjectAttributeProblem(attribute, value,
                                                  loaded.record.fields);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable request object " +
                "setting.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0101');
    }
  }
  // RFC 9126's one, on a SET that carries a value.
  if (mode === 'set' && value) {
    const problem = pushedAuthorizationAttributeProblem(attribute, value);
    if (problem) {
      log.debug("Leaving updateApplication(). Not TRUE or FALSE.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0121');
    }
  }
  // OIDC Core sections 8 and 9 (#118), on a SET that carries a value.
  if (mode === 'set' && value) {
    const problem = oidcSubjectAttributeProblem(attribute, value,
                                                loaded.record.fields);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable subject or " +
                "signing setting.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0168');
    }
  }
  // RFC 8705's six, on a SET that carries a value: the value's grammar, and no
  // second certificate subject parameter beside the one the entry holds.
  if (mode === 'set' && value) {
    const problem = mtlsAttributeProblem(attribute, value,
                                         loaded.record.fields);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable RFC 8705 value.");
      return errorCodes.mark({ ok: false, errors: [problem.message] },
                             problem.code);
    }
  }
  // RFC 9396's two, on an ADD or a SET that carries a value.
  if ((mode === 'set' || mode === 'add') && value) {
    const problem = authorizationDetailsAttributeProblem(attribute, value);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable authorization " +
                "details value.");
      return errorCodes.mark({ ok: false, errors: [problem.message] },
                             problem.code);
    }
  }
  // RFC 9470's two, on a SET that carries a value.
  if (mode === 'set' && value) {
    const problem = stepUpAttributeProblem(attribute, value);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable step-up " +
                "requirement.");
      return errorCodes.mark({ ok: false, errors: [problem.message] },
                             problem.code);
    }
  }
  if (KEY_SOURCE_ATTRIBUTES.indexOf(attribute) >= 0 && mode === 'set' &&
      value && KEY_SOURCES.indexOf(value) < 0) {
    log.debug("Leaving updateApplication(). Not a key source.");
    return errorCodes.mark({ ok: false, errors: ['"' + value + '" is not a ' +
                             'key source. `' + attribute + '` records where ' +
                             'a key pair came from and holds one of ' +
                             KEY_SOURCES.join(', ') + '.'] }, 'STS-REG-0060');
  }
  // THE ADDRESSES, on an ADD or a SET that carries a value — and for a SET only
  // a value not already on the entry, so an address an `ldapmodify` put there
  // before this check existed does not block every later edit of the list.
  // A remove and a clear are never refused (the rule every check here keeps).
  if (ADDRESS_ATTRIBUTES[attribute] && value &&
      (mode === 'add' || mode === 'set') &&
      valuesOf(loaded.record.fields[attribute]).indexOf(value) < 0) {
    const problem = addressProblem(attribute, value);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable address.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0071');
    }
    // Front-Channel Logout section 2, against the entry's redirect URIs.
    if (attribute === 'oauthFrontchannelLogoutUri') {
      const originProblem = frontchannelOriginProblem(value,
        loaded.record.fields.oauthRedirectUri);
      if (originProblem) {
        log.debug("Leaving updateApplication(). The front-channel origin.");
        return errorCodes.mark({ ok: false, errors: [originProblem] },
                               'STS-REG-0171');
      }
    }
  }
  if ((attribute === 'oauthResourceMetadata' ||
       attribute === 'oauthResourceMetadataUrl') && mode === 'set' && value) {
    const problem = attribute === 'oauthResourceMetadata'
      ? resourceMetadataProblem(value) : resourceMetadataUrlProblem(value);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable RFC 9728 value.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0089');
    }
  }
  // THE CORS ORIGINS. An ADD is checked and the value it stores is the
  // normalised one, so `HTTPS://App.Example.com/` and `https://app.example.com`
  // are one value rather than two that look different and match the same
  // header. A REMOVE is never refused, and removes the value as typed or, when
  // that is not on the entry, its normalised spelling — so an origin an
  // `ldapmodify` wrote in another case can still be taken off.
  if (attribute === 'appCorsOrigin' && mode === 'add') {
    const problem = corsOriginWriteProblem(value);
    if (problem) {
      log.debug("Leaving updateApplication(). Not a usable origin.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0150');
    }
    value = validation.normaliseOrigin(value);
  }
  if (attribute === 'appCorsOrigin' && mode === 'remove' &&
      valuesOf(loaded.record.fields[attribute]).indexOf(value) < 0 &&
      validation.normaliseOrigin(value)) {
    value = validation.normaliseOrigin(value);
  }
  if (attribute === 'appHomePageUrl' && mode === 'set' && value) {
    const problem = homePageProblem(value);
    if (problem) {
      log.debug("Leaving updateApplication(). The home page is not a usable " +
                "URL.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0011');
    }
  }
  if (attribute === 'oauthPermissionBaseUri' && mode === 'set' && value) {
    const problem = permissionBaseProblem(value);
    if (problem) {
      log.debug("Leaving updateApplication(). The base URI is not absolute.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0012');
    }
  }
  if (attribute === 'oauthPermission' && mode === 'add') {
    const parsed = parsePermissionValue(value);
    const problem = permissionNameProblem(parsed.name);
    if (problem) {
      log.debug("Leaving updateApplication(). The permission name is not " +
                "usable.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0013');
    }
    const already = permissionsOf(loaded.record).filter(function (one) {
      return one.name === parsed.name;
    })[0];
    if (already) {
      // REFUSED RATHER THAN MERGED, because the two values would be two
      // descriptions of one permission and `permissionsOf()` returns both — so
      // the console would list `write` twice and the second row would be
      // unreachable. Remove and re-add is how a description is changed, and the
      // message says so rather than leaving somebody to discover it.
      log.debug("Leaving updateApplication(). That permission is already " +
                "defined.");
      return errorCodes.mark({ ok: false, errors: ['This application already ' +
                                                   'defines a permission ' +
                                                   'called "' +
                                   parsed.name + '"' +
                                   (already.description ?
                                    ' (' + already.description + ')' : '') +
                                   '. A permission has one description, so ' +
                                   'change it by removing ' +
                                   '"' + already.raw + '" and ' +
                                   'adding the new value — adding a second ' +
                                   'would put two rows with one name on ' +
                                   'every page that lists ' +
                                   'them.'] }, 'STS-REG-0014');
    }
    if (!permissionBaseOf((loaded.record.fields ||
                           {}).oauthPermissionBaseUri)) {
      log.debug("Leaving updateApplication(). No base URI on the entry.");
      return errorCodes.mark({ ok: false, errors: ['This application has no ' +
                                   '`oauthPermissionBaseUri`, so a ' +
                                   'permission on it would have no ' +
                                   'identifier: a permission is named by its ' +
                                   'base URI followed by its name, and a ' +
                                   'client asks for it by putting that whole ' +
                                   'string in a `scope`. Set the base first ' +
                                   '— `https://example.com/` is the shape, ' +
                                   'and Entra ID spells the same thing ' +
                                   '`api://<guid>`.'] }, 'STS-REG-0015');
    }
  }
  if (attribute === 'oauthDelegatedPermission' && mode === 'add') {
    const defines = forPermission(value);
    if (!defines) {
      log.debug("Leaving updateApplication(). No application defines that " +
                "permission.");
      return errorCodes.mark({ ok: false, errors: ['No application in this ' +
                                                   'registry defines the ' +
                                                   'permission "' +
                                   value + '", and a permission must be ' +
                                   'DEFINED before it can be GRANTED — that ' +
                                   'is the one ordering rule this feature ' +
                                   'has. Give the resource application an ' +
                                   '`oauthPermissionBaseUri` and an ' +
                                   '`oauthPermission`, then grant the two ' +
                                   'joined together. The identifier is an ' +
                                   'exact match rather than a prefix of a ' +
                                   'registered base, so that a client cannot ' +
                                   'address a token to somebody\'s API by ' +
                                   'inventing a word after their base URI. ' +
                                   '`ldapmodify` reaches this attribute like ' +
                                   'every other and is not checked, which is ' +
                                   'what /admin/delegation reports as a ' +
                                   'DANGLING grant.'] },
                             'STS-REG-0016');
    }
    if (defines.identifier === identifier) {
      // AN APPLICATION GRANTING ITSELF ITS OWN PERMISSION. Refused because the
      // token it would produce is a token addressed to itself — which is what
      // an ID Token already is — and because the picture would draw a line from
      // a box back to the same box. The same decision audienceScopes() makes
      // about a client naming its own client_id as a scope, made here so that
      // the two cannot disagree.
      log.debug("Leaving updateApplication(). An application cannot grant " +
                "itself.");
      return errorCodes.mark({ ok: false, errors: ['"' + identifier + '" is ' +
          'the application that DEFINES "' +
                                   value + '", so granting it to itself ' +
                                   'would address a token to its own API — ' +
                                   'which is what an ID Token already is, ' +
                                   'and which draws as a line from a box ' +
                                   'back to the same box. A grant is between ' +
                                   'two applications.'] }, 'STS-REG-0017');
    }
  }
  // A GLOBAL CONSENT MUST BE A LEGAL SCOPE TOKEN, and that is the whole of the
  // rule — there is no ordering rule here and deliberately not. A grant has to
  // name a permission that EXISTS because the identifier is composed from two
  // attributes and a value that resolves to nothing can never be asked for; a
  // consent names whatever a client will put in its `scope`, and most scopes
  // are not permissions this registry has heard of. Refusing an unrecognised
  // one would make it impossible to consent `openid`.
  //
  // ONLY AN ADD IS CHECKED, the same asymmetry the two rules above have and for
  // their reason: a remove names a value already on the entry, and an
  // `ldapmodify` reaches this attribute like every other.
  if (attribute === 'oauthGlobalConsent' && mode === 'add') {
    const problem = scopeTokenProblem(value);
    if (problem) {
      log.debug("Leaving updateApplication(). The consented scope is not a " +
                "scope token.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0018');
    }
  }
  // A DECLARED SCOPE (#110) the same way, and only an add for the same
  // asymmetry: a remove names a value already on the entry.
  if (attribute === 'oauthAllowedScope' && mode === 'add') {
    const problem = scopeTokenProblem(value);
    if (problem) {
      log.debug("Leaving updateApplication(). The declared scope is not a " +
                "scope token.");
      return errorCodes.mark({ ok: false, errors: [problem] }, 'STS-REG-0172');
    }
  }
  // ---------------------------------------------------------------------------
  // A SAML SIGNING CERTIFICATE IS A TRUST ANCHOR SINCE 2026-09-17 (#37), so
  // it is normalised to base64 DER — PEM armour and whitespace off, which is
  // what `ds:X509Certificate` carries and what every reader compares — and a
  // value whose key signs nothing this service verifies (any key
  // `common/crypto.js` section 1a knows, not only RSA) is refused at the door
  // rather than at the next signed request, where the only symptom would be
  // every signature from that service provider being refused. A REMOVE is
  // normalised and not checked, the asymmetry every rule here has: it names a
  // value already on the entry.
  // ---------------------------------------------------------------------------
  if (SAML_CERTIFICATE_ATTRIBUTES.indexOf(attribute) >= 0 && value) {
    value = samlCertificateBase64(value);
    if (mode !== 'remove') {
      const problem = samlCertificateProblem(value);
      if (problem) {
        log.debug("Leaving updateApplication(). Not a usable certificate.");
        return errorCodes.mark({ ok: false, errors: ['`' + attribute + '` ' +
                                 'must be an X.509 certificate whose key ' +
                                 'makes an XML signature this service ' +
                                 'verifies, ' +
                                 'base64 DER or PEM, and this one is not: ' +
                                 problem +
                                 '. Nothing was written.'] },
                               'STS-REG-0160');
      }
    }
  }
  // ---------------------------------------------------------------------------
  // PRIVATE KEY MATERIAL IS SEALED HERE, WHICH IS BEFORE ANYTHING ELSE IN THIS
  // FUNCTION TOUCHES THE VALUE — including the sentence that goes to the audit
  // log, which quotes it. See SEALED_FIELDS: this is the ONE door the console
  // form, `POST /admin-api/applications/set`, `POST /admin-api/pki/issue` and
  // `admin-ui/pki_admin.ts`'s Issue control all go through, so there is one
  // place a signing key can be written and one place it is encrypted.
  //
  // A CLEAR IS UNTOUCHED — an empty value takes the attribute off, and there is
  // nothing to seal. A REMOVE cannot reach here with one of these: they are
  // single-valued, so `mode` is `set`.
  // ---------------------------------------------------------------------------
  if (SEALED_FIELDS.indexOf(attribute) >= 0 && value) {
    const sealedValue = sealFieldValue(attribute, value);
    if (sealedValue === null) {
      log.error(errorCodes.tag('STS-REG-0019') +
                'applications: a private key for "' + identifier + '" could ' +
                'not be sealed, so it was NOT written. Storing it in the ' +
                'clear in product mode would put a working signing ' +
                'credential in every directory dump.');
      log.debug("Leaving updateApplication(). The private key could not be " +
                "sealed.");
      return errorCodes.mark({ ok: false,
               errors: ['`' + attribute + '` is private key material and ' +
                        'this service could not encrypt it, so it was not ' +
                        'stored. Nothing was written and no key pair is on ' +
                        'the entry. The key-encryption key is the one ' +
                        '/admin/persistence reports on; product mode cannot ' +
                        'run without it.'] }, 'STS-REG-0019');
    }
    value = sealedValue;
  }

  const record = loaded.record;
  let changed = false;
  let what = '';

  // `appName` and `description` are not schema FIELDS — they are computed from
  // the record in attributesFor() — so they are written to the record itself.
  // Everything else is a field. This is the one place that distinction leaks
  // out of the two conversions, and it leaks here rather than into the caller.
  if (attribute === 'appName') {
    changed = record.name !== value;
    record.name = value;
    what = 'appName is now "' + value + '"';
  } else if (attribute === 'description') {
    if (mode === 'add') {
      changed = addTo(record.descriptions, value);
      what = 'added a description';
    } else {
      const before = record.descriptions.length;
      record.descriptions = record.descriptions.filter(
          function (one) { return one !== value; });
      changed = record.descriptions.length !== before;
      what = 'removed a description';
    }
  } else if (mode === 'set') {
    changed = setField(record, attribute, value);
    // setField() ignores an empty value, which is how a caller CLEARS one — so
    // the clear is done here rather than left as a silent no-op that reads as
    // the form not working.
    if (!value && record.fields[attribute] !== undefined) {
      delete record.fields[attribute];
      changed = true;
    }
    // A CREDENTIAL'S VALUE IS NEVER QUOTED (2026-09-13). `what` goes into the
    // audit row's summary, the log line below and the reply, and the comment
    // on the audit call already says the value is kept out of the DETAIL
    // because two of these attributes are credentials — while this sentence
    // put it back into the summary beside it. So a secret set from the
    // console landed in the audit ring and the service log in the clear.
    what = !value ? attribute + ' was cleared'
      : (row.sensitive || row.secret)
        ? attribute + ' was set (a credential; its value is not repeated here)'
        : attribute + ' is now "' + value + '"';
  } else if (mode === 'add') {
    const before = valuesOf(record.fields[attribute]);
    changed = setField(record, attribute, value);
    what = 'added "' + value + '" to ' + attribute;
    // -----------------------------------------------------------------------
    // PROVENANCE, for the three return-address attributes. See
    // returnAddressesOf(). Two callers reach this branch meaning opposite
    // things, and `asked.observed` is how they are told apart:
    //
    //   * an OPERATOR — the console form, `POST /admin-api/applications/add`,
    //     every caller that does not pass the flag — is REGISTERING the
    //     address, so a mark on it is taken off. Adding an address that is
    //     already on the entry as observed is therefore how an explicit write
    //     confirms it, and it is a change even though the value was there.
    //   * `common/oidc_rp.ts` teaching its own client the address it was
    //     reached at, which is a SIGHTING wearing an update's shape. It passes
    //     `observed: true` and the address is marked — but only where it was
    //     newly added (a sighting may not demote a registration) and only in a
    //     mode that accepts unregistered addresses, since product learns
    //     nothing and a flag arriving there must not be able to mark anything.
    //
    // Neither admin door passes the flag through: `applicationsAction()`
    // builds the change from `mode`, `attribute` and `value` alone, so a body
    // carrying `observed` cannot demote a registration from outside.
    // -----------------------------------------------------------------------
    // AN EXPLICIT ADD OF THE OBSERVED SIGNING CERTIFICATE CONFIRMS IT — the
    // same rule an explicit add of an observed return address follows, for
    // the same reason: writing it by hand is a registration.
    if (attribute === 'samlSigningCertificate' &&
        String(record.fields[OBSERVED_CERTIFICATE_ATTRIBUTE] || '') === value) {
      delete record.fields[OBSERVED_CERTIFICATE_ATTRIBUTE];
      changed = true;
      what = 'registered "' + attribute + '" from the certificate the last ' +
             'signed request carried (it was OBSERVED and is trusted now)';
    }
    if (RETURN_ADDRESS_ATTRIBUTES.indexOf(attribute) >= 0) {
      if (asked.observed === true && acceptsSightedAddresses()) {
        if (markObservedAddresses(record, attribute, before)) {
          changed = true;
          what += ', marked as OBSERVED rather than registered';
        }
      } else if (clearObservedMark(record, attribute, value)) {
        changed = true;
        what = before.indexOf(value) >= 0
          ? 'confirmed "' + value + '" on ' + attribute + ' (it was there as ' +
            'an OBSERVED address and is registered now)'
          : what;
      }
    }
  } else {
    // A REMOVE TAKES THE ADDRESS'S PROVENANCE MARK WITH IT — which is what
    // makes a discard and a plain remove one outcome — before the value itself
    // goes, so that a mark is never left naming an address that is not there.
    const unmarked = RETURN_ADDRESS_ATTRIBUTES.indexOf(attribute) >= 0 &&
      clearObservedMark(record, attribute, value);
    const have = record.fields[attribute] || [];
    const left = have.filter(function (one) { return one !== value; });
    changed = unmarked || left.length !== have.length;
    if (left.length) {
      record.fields[attribute] = left;
    } else {
      // The last value takes the attribute with it, which is what the LDAP
      // modify handler in ldap_server.js does for every other entry (result
      // code 16 territory) and what an operator reading this directory with an
      // LDAP client will expect to see.
      delete record.fields[attribute];
    }
    what = 'removed "' + value + '" from ' + attribute;
  }

  if (!changed) {
    log.debug("Leaving updateApplication(). Nothing changed.");
    log.debug("Leaving updateApplication().");
    return { ok: true, changed: false,
             application: viewAfterWrite(identifier, record),
             message: 'Nothing changed: ' + attribute + ' already said that.' };
  }
  record.lastAt = record.lastAt || Date.now();
  save(record);
  audit.audit({
    action: 'application.update', actor: asked.actor || '', protocol: 'console',
    channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '": ' + what,
    // The ATTRIBUTE is named and the value is not, because two of the editable
    // attributes are credentials. That is the same rule every LDAP row in this
    // service follows and it is why it is applied here rather than judged per
    // attribute — a rule with an exception in it is one somebody will get wrong
    // when the next credential attribute is added.
    detail: { identifier: String(identifier), attribute: attribute, mode: mode,
              editedByHand: true }
  });
  log.info('applications: "' + identifier + '" — ' + what + '.');
  log.debug("Leaving updateApplication(). " + what + ".");
  log.debug("Leaving updateApplication().");
  return { ok: true, changed: true,
           application: viewAfterWrite(identifier, record),
           message: what + '.' };
}

// ---------------------------------------------------------------------------
// WHAT A CLIENT SECRET LOOKS LIKE, decided once (2026-09-18).
//
// `oauth2.registeredSecretBytes` random bytes, base64url — the way `POST
// /oauth2/register` mints one. It was a line inside regenerateClientSecret()
// until /admin/applications/new grew a *Generate Secret* button, which needs
// a secret for an application that does not exist yet; two copies of that
// line would be two definitions of a client secret, which is what the header
// below says this module exists to prevent. It writes nothing: the caller
// decides where the value goes.
// ---------------------------------------------------------------------------
function clientSecretBytes() {
  log.debug("Entering clientSecretBytes().");
  log.debug("Leaving clientSecretBytes().");
  return Number(config.value('oauth2.registeredSecretBytes')) || 24;
}

function mintClientSecret() {
  log.debug("Entering mintClientSecret().");
  log.debug("Leaving mintClientSecret().");
  return randomId(clientSecretBytes());
}

// ---------------------------------------------------------------------------
// A NEW CLIENT SECRET, MINTED HERE (2026-09-13).
//
// The console's Set could always write `oauthClientSecret`, but only with a
// value somebody TYPED — and a secret an operator makes up is the weakest one
// this service ever holds. This mints it the way `POST /oauth2/register` does,
// at `oauth2.registeredSecretBytes`, and REPLACES what is there: the old
// secret stops authenticating at the token endpoint on the very next request,
// wherever that endpoint checks a secret at all (RFC 9700 mode, or product
// mode).
//
// **THE REPLY CARRIES THE NEW SECRET, AND NOTHING ELSE DOES.** The audit row
// names the attribute and not the value, the log line says it was regenerated,
// and the registration document is updated in place so that RFC 7592's read
// returns the secret a client now needs. `client_secret_expires_at` is
// recomputed from `oauth2.registeredSecretLifetimeS` where the document
// carries one, because a secret minted now with an expiry counted from the
// original registration would be published as already partly spent.
//
// It is here rather than in the console's action for the reason every write
// in this registry is: an `ldapmodify`, the console and the management API are
// three doors onto one entry, and minting in one of them would be a second
// definition of what a client secret looks like.
// ---------------------------------------------------------------------------
// When an entry's current secret expires, in seconds since the epoch, or 0
// for never (#49 P5): its own attribute, or — for a client registered before
// the attribute existed — the client_secret_expires_at its registration
// document published.
function secretExpiryOf(fields) {
  log.debug("Entering secretExpiryOf().");
  const own = Number(valuesOf(fields.oauthClientSecretExpiresAt)[0]);
  if (own > 0) {
    log.debug("Leaving secretExpiryOf(). The attribute.");
    return own;
  }
  let fromDocument = 0;
  const text = valuesOf(fields.appRegistrationJson)[0];
  if (text) {
    try {
      fromDocument = Number(JSON.parse(String(text))
        .client_secret_expires_at) || 0;
    } catch (e) {
      // A document that does not parse publishes no expiry.
      log.debug("Caught in secretExpiryOf(): " + ((e && e.message) || e));
      fromDocument = 0;
    }
  }
  log.debug("Leaving secretExpiryOf().");
  return fromDocument > 0 ? fromDocument : 0;
}

// THE DAILY CLIENT-SECRET SWEEP (#49 P5, rcbj's answer), which the scheduler
// job `oauth2.client-secret-expiry` runs in each realm: an audit row and a
// warning for every secret expiring within
// oauth2.clientSecretExpiryWarningDays, one for every secret that has
// expired, and the previous secret of every rotation whose overlap has
// passed CLEARED from its entry. Answers the three lists of identifiers.
function sweepClientSecrets(nowMs) {
  log.debug("Entering sweepClientSecrets().");
  const now = Number(nowMs) || Date.now();
  const nowS = Math.floor(now / 1000);
  const warnS = Number(config.value('oauth2.clientSecretExpiryWarningDays')) *
                86400;
  const out = { expiring: [], expired: [], cleared: [] };
  list().forEach(function (row) {
    const fields = row.fields || {};
    if (!valuesOf(fields.oauthClientSecret)[0]) {
      return;
    }
    const expiresAt = secretExpiryOf(fields);
    if (expiresAt > 0 && expiresAt <= nowS) {
      out.expired.push(row.identifier);
    } else if (expiresAt > 0 && expiresAt - nowS <= warnS) {
      out.expiring.push(row.identifier);
    }
    const until = Number(valuesOf(fields.oauthClientSecretPreviousUntil)[0]);
    if (valuesOf(fields.oauthClientSecretPrevious)[0] && until > 0 &&
        until <= now) {
      const loaded = load(row.identifier);
      if (loaded.known) {
        delete loaded.record.fields.oauthClientSecretPrevious;
        delete loaded.record.fields.oauthClientSecretPreviousUntil;
        save(loaded.record);
        out.cleared.push(row.identifier);
      }
    }
  });
  out.expiring.forEach(function (id) {
    audit.audit({ action: 'application.secret-expiring', actor: 'scheduler',
      protocol: 'console', channel: 'internal', target: String(id),
      summary: 'Application "' + id + '": its client secret expires within ' +
               'oauth2.clientSecretExpiryWarningDays; rotate it on ' +
               '/admin/applications', detail: { identifier: String(id) } });
  });
  out.expired.forEach(function (id) {
    audit.audit({ action: 'application.secret-expired', actor: 'scheduler',
      protocol: 'console', channel: 'internal', target: String(id),
      outcome: 'failure', errorCode: 'STS-REG-0166',
      summary: 'Application "' + id + '": its client secret has expired',
      detail: { identifier: String(id) } });
  });
  out.cleared.forEach(function (id) {
    audit.audit({ action: 'application.update', actor: 'scheduler',
      protocol: 'console', channel: 'internal', target: String(id),
      summary: 'Application "' + id + '": the secret a rotation replaced ' +
               'stopped being accepted, its overlap having passed',
      detail: { identifier: String(id),
                attribute: 'oauthClientSecretPrevious', mode: 'cleared' } });
  });
  if (out.expiring.length || out.expired.length) {
    log.warn(errorCodes.tag('STS-REG-0166') + 'applications: ' +
             out.expired.length + ' client secret(s) expired (' +
             out.expired.join(', ') + ') and ' + out.expiring.length +
             ' expire soon (' + out.expiring.join(', ') + '). Rotate them ' +
             'on /admin/applications.');
  }
  log.debug("Leaving sweepClientSecrets(). " + JSON.stringify({
    expiring: out.expiring.length, expired: out.expired.length,
    cleared: out.cleared.length }));
  return out;
}

// ROTATE — a new secret, with the old one still accepted for
// oauth2.clientSecretOverlapS (#49 P5, rcbj's answer). The Admin Write act
// the console and `POST /admin-api/applications/rotate-secret` share.
function rotateClientSecret(identifier, options) {
  log.debug("Entering rotateClientSecret(). identifier=" + identifier);
  const out = regenerateClientSecret(identifier,
    Object.assign({}, options || {}, { keepPrevious: true }));
  log.debug("Leaving rotateClientSecret().");
  return out;
}

function regenerateClientSecret(identifier, options) {
  log.debug("Entering regenerateClientSecret(). identifier=" + identifier);
  const opts = options || {};
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving regenerateClientSecret(). No such application.");
    return errorCodes.mark({ ok: false, errors: ['There is no application ' +
                                                 'called "' + identifier +
                                                 '" in this registry.'] },
                           'STS-REG-0021');
  }
  // THE MANAGEMENT API'S OWN CLIENT, WHILE ITS SECRET IS PINNED. Seeding
  // writes `adminApi.clientSecret` onto a FRESH entry and never over an
  // existing one, so a secret regenerated here would go on disagreeing with
  // the setting every launcher and deployment mints its API token with — and
  // wherever a secret is checked, nobody could obtain one. The setting is the
  // one place that secret is decided; this refuses rather than making a
  // second.
  if (String(identifier) === 'sts-management-api' && realms.isDefault() &&
      String(config.value('adminApi.clientSecret') || '')) {
    log.debug("Leaving regenerateClientSecret(). The secret is pinned.");
    return errorCodes.mark({ ok: false, errors: ['The client secret of ' +
                             '"sts-management-api" is pinned by the ' +
                             'adminApi.clientSecret setting, which is what ' +
                             'every token for /admin-api is minted with. ' +
                             'Regenerating it here would leave the entry and ' +
                             'the setting disagreeing, and the management ' +
                             'API unreachable wherever the secret is ' +
                             'checked. Change the setting instead.'] },
                           'STS-REG-0061');
  }
  const record = loaded.record;
  const bytes = clientSecretBytes();
  const secret = mintClientSecret();
  const replaced = !!record.fields.oauthClientSecret;
  const previous = valuesOf(record.fields.oauthClientSecret)[0];
  // A ROTATION (#49 P5) keeps the secret it replaces working for
  // oauth2.clientSecretOverlapS; a regeneration ends it now, and ends any
  // overlap an earlier rotation left.
  const overlapMs = Number(config.value('oauth2.clientSecretOverlapS')) * 1000;
  const keeps = !!opts.keepPrevious && !!previous && overlapMs > 0;
  if (keeps) {
    setField(record, 'oauthClientSecretPrevious', String(previous));
    setField(record, 'oauthClientSecretPreviousUntil',
             String(Date.now() + overlapMs));
  } else {
    delete record.fields.oauthClientSecretPrevious;
    delete record.fields.oauthClientSecretPreviousUntil;
  }
  setField(record, 'oauthClientSecret', secret);
  if (record.fields.appRegistrationJson) {
    try {
      const document = JSON.parse(record.fields.appRegistrationJson);
      document.client_secret = secret;
      if (Object.prototype.hasOwnProperty.call(document,
                                               'client_secret_expires_at')) {
        const seconds = Number(
            config.value('oauth2.registeredSecretLifetimeS'));
        document.client_secret_expires_at = isFinite(seconds) && seconds > 0
          ? nowSec() + Math.floor(seconds) : 0;
        setField(record, 'oauthClientSecretExpiresAt',
                 String(document.client_secret_expires_at));
      }
      setField(record, 'appRegistrationJson', JSON.stringify(document));
    } catch (e) {
      log.debug("Caught in regenerateClientSecret(): " +
                ((e && e.message) || e));
      // A hand-edited document that no longer parses: the attribute is what
      // the checks read and it is written above, and registrationOf() already
      // rebuilds a document it cannot parse from the attributes beside it.
      log.warn(errorCodes.tag('STS-REG-0024') + 'applications: ' +
               'appRegistrationJson on "' + identifier + '" is not valid ' +
               'JSON, so the new client secret is on the attribute and not ' +
               'in the stored document. ' + e.message);
    }
  }
  record.lastAt = record.lastAt || Date.now();
  save(record);
  audit.audit({
    action: 'application.update', actor: opts.actor || '',
    protocol: 'console', channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '": the client secret was ' +
             (replaced ? 'regenerated' : 'generated'),
    // The attribute and never the value — see updateApplication()'s row.
    detail: { identifier: String(identifier), attribute: 'oauthClientSecret',
              mode: keeps ? 'rotate' : 'regenerate', replaced: replaced,
              overlapUntil: keeps ? Date.now() + overlapMs : 0 }
  });
  log.info('applications: "' + identifier + '" — the client secret was ' +
           (replaced ? 'regenerated' : 'generated') + '.');
  log.debug("Leaving regenerateClientSecret().");
  return { ok: true, changed: true, replaced: replaced, clientSecret: secret,
           application: viewAfterWrite(identifier, record),
           overlapUntil: keeps ? Date.now() + overlapMs : 0,
           message: (keeps
             ? 'A new client secret replaced the old one, which goes on ' +
               'authenticating at the token endpoint until ' +
               new Date(Date.now() + overlapMs).toISOString() +
               ' (oauth2.clientSecretOverlapS), so the client can change ' +
               'over.'
             : replaced
             ? 'A new client secret replaced the old one, which stops ' +
               'authenticating at the token endpoint now.'
             : 'A client secret was generated.') + ' It is ' + bytes +
             ' random bytes, base64url, minted the way a registration mints ' +
             'one.' };
}

// ---------------------------------------------------------------------------
// CONFIRM AND DISCARD: WHAT AN OPERATOR DOES WITH AN OBSERVED RETURN ADDRESS
// (2026-09-12).
//
// Two actions rather than one with a flag, because they are opposite answers
// to one question — *is this address this application's?* — and a console
// that drew them as one control with a checkbox would be a control whose
// wrong setting is the dangerous one. CONFIRM takes the mark off and keeps the
// address, so product believes it from the next request. DISCARD takes both
// off, so no mode believes it.
//
// **BOTH REFUSE AN ADDRESS THAT IS NOT MARKED**, by name. Confirming a
// registered address would be a no-op that reads as having done something,
// and discarding one would be a REMOVE of a registration by a control labelled
// as tidying up a sighting — `remove` is the door for that and says so.
//
// **A MARK WHOSE ADDRESS HAS GONE IS DISCARDABLE AND CONFIRMABLE ALIKE**, and
// both just take the mark off: an `ldapmodify` can remove the value and leave
// the mark, and a confirm that refused would leave the one row nothing else
// could tidy. The message says the address is not on the entry.
//
// They go through the same load, save and audit as updateApplication(), and
// are not branches of it because neither is a write of the attribute's own
// value in any mode that function has.
// ---------------------------------------------------------------------------
function observedAddressRequest(identifier, change, verb) {
  log.debug("Entering observedAddressRequest(). verb=" + verb);
  const asked = change || {};
  const attribute = String(asked.attribute || '').trim();
  const value = String(asked.value == null ? '' : asked.value).trim();
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving observedAddressRequest(). No such application.");
    return errorCodes.mark({ ok: false, errors: ['There is no application ' +
                                                 'called "' + identifier +
                             '" in this registry.'] }, 'STS-REG-0021');
  }
  if (RETURN_ADDRESS_ATTRIBUTES.indexOf(attribute) < 0) {
    log.debug("Leaving observedAddressRequest(). Not a return-address " +
              "attribute.");
    return errorCodes.mark({ ok: false,
                             errors: ['"' + (attribute || '(none)') + '" ' +
                             'is not a return-address attribute, so nothing ' +
                             'on it is ever marked as observed. ' +
                             'The ' + numberWord(
                                 RETURN_ADDRESS_ATTRIBUTES.length) +
                             ' that are: ' + RETURN_ADDRESS_ATTRIBUTES.join(
                                 ', ') + '.'] },
                           'STS-REG-0051');
  }
  if (!value) {
    log.debug("Leaving observedAddressRequest(). No address named.");
    return errorCodes.mark({ ok: false,
                             errors: ['A value is required to ' + verb + ': ' +
                             'the address, exactly as ' +
                             'appReturnAddressObserved holds it.'] },
                           'STS-REG-0052');
  }
  const row = observedReturnAddresses(loaded.record.fields).filter(
      function (one) {
    return one.attribute === attribute && one.value === value;
  })[0];
  if (!row) {
    const marked = observedReturnAddresses(loaded.record.fields).map(
        function (one) {
      return observedMarkFor(one.attribute, one.value);
    });
    const onEntry = valuesOf(loaded.record.fields[attribute]).indexOf(
        value) >= 0;
    log.debug("Leaving observedAddressRequest(). That address is not marked.");
    return errorCodes.mark({ ok: false,
                             errors: ['"' + value + '" on ' + attribute + ' ' +
        'of "' +
                             identifier + '" is not marked as observed, so ' +
                             'there is nothing to ' + verb + '. ' +
                             (onEntry
                               ? 'It is on the entry with no mark, which is ' +
                                 'what a registered address looks like — ' +
                                 (verb === 'discard'
                                   ? 'take it off with `remove` if it should ' +
                                     'not be there.'
                                   : 'product mode already believes it.')
                               : 'It is not on the entry either.') +
                             (marked.length
                               ? ' The addresses marked observed are: ' +
                                 marked.join(', ') + '.'
                               : ' Nothing on this entry is marked ' +
                                 'observed.')] },
                           'STS-REG-0050');
  }
  log.debug("Leaving observedAddressRequest(). Marked, held=" + row.held + ".");
  return { ok: true, loaded: loaded, attribute: attribute, value: value,
           held: row.held };
}

function saveObservedAddressChange(identifier, found, record, verb, what,
                                   actor) {
  log.debug("Entering saveObservedAddressChange().");
  record.lastAt = record.lastAt || Date.now();
  save(record);
  audit.audit({
    action: 'application.update', actor: actor || '', protocol: 'console',
    channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '": ' + what,
    // The attribute and the verb, and — unlike updateApplication(), which
    // names no value because two editable attributes are credentials — the
    // address too: a return address is never a credential, and an audit row
    // that said "an observed address was confirmed" without saying which would
    // be the one row an operator reviewing a mode switch could not use.
    detail: { identifier: String(identifier), attribute: found.attribute,
              mode: verb + '-address', address: found.value,
              editedByHand: true }
  });
  log.info('applications: "' + identifier + '" — ' + what + '.');
  log.debug("Leaving saveObservedAddressChange().");
  return { ok: true, changed: true,
           application: viewAfterWrite(identifier, record),
           message: what + '.' };
}

function confirmReturnAddress(identifier, change) {
  log.debug("Entering confirmReturnAddress(). identifier=" + identifier);
  const found = observedAddressRequest(identifier, change, 'confirm');
  if (!found.ok) {
    log.debug("Leaving confirmReturnAddress(). Refused.");
    return found;
  }
  const record = found.loaded.record;
  clearObservedMark(record, found.attribute, found.value);
  const what = found.held
    ? 'confirmed "' + found.value + '" on ' + found.attribute + '. It was ' +
      'recorded from a request in development mode and is now a registered ' +
      'address, which product mode believes from the next request'
    : 'took the observed mark off "' + found.value + '" on ' + found.attribute +
      '. The address itself is no longer on the entry, so there was nothing ' +
      'to confirm and nothing is registered by this';
  const answer = saveObservedAddressChange(identifier, found, record, 'confirm',
                                           what,
                                           (change || {}).actor);
  log.debug("Leaving confirmReturnAddress(). held=" + found.held + ".");
  return answer;
}

function discardReturnAddress(identifier, change) {
  log.debug("Entering discardReturnAddress(). identifier=" + identifier);
  const found = observedAddressRequest(identifier, change, 'discard');
  if (!found.ok) {
    log.debug("Leaving discardReturnAddress(). Refused.");
    return found;
  }
  const record = found.loaded.record;
  clearObservedMark(record, found.attribute, found.value);
  const left = valuesOf(record.fields[found.attribute]).filter(function (one) {
    return one !== found.value;
  });
  if (left.length) {
    record.fields[found.attribute] = left;
  } else {
    delete record.fields[found.attribute];
  }
  const what = 'discarded "' + found.value + '" from ' + found.attribute +
    '. ' +
    'It was recorded from a request in development mode and nobody confirmed ' +
    'it, so it is gone from the entry: product mode refuses it, and ' +
    'development records it again, marked, if a request names it again' +
    (found.held ? '' :
     ' (the address had already gone; only its mark was left)');
  const answer = saveObservedAddressChange(identifier, found, record, 'discard',
                                           what,
                                           (change || {}).actor);
  log.debug("Leaving discardReturnAddress().");
  return answer;
}

// ---------------------------------------------------------------------------
// A SAML SIGNING CERTIFICATE: ITS ONE SPELLING, AND WHETHER IT IS USABLE
// (2026-09-17, #37).
//
// base64 DER with no whitespace is what a `ds:X509Certificate` carries, what
// metadata publishes and what `samlObservedSigningCertificate` is compared
// against, so every value is brought to it before it is stored or compared. A
// PEM is accepted and its armour taken off; anything else is left for the
// check to refuse.
// ---------------------------------------------------------------------------
function samlCertificateBase64(value) {
  log.debug("Entering samlCertificateBase64().");
  log.debug("Leaving samlCertificateBase64().");
  return String(value == null ? '' : value)
    .replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, '');
}

// '' for an X.509 certificate whose key makes an XML signature this service
// verifies, and otherwise a sentence. Until the #37 follow-up that meant RSA
// only, because nothing verified anything else; `common/crypto.js` section 1a
// now verifies EC, EdDSA, DSA and the post-quantum families too, and asking
// it keeps the door and the verifier from disagreeing.
function samlCertificateProblem(value) {
  log.debug("Entering samlCertificateProblem().");
  const der = samlCertificateBase64(value);
  if (!der) {
    log.debug("Leaving samlCertificateProblem(). Empty.");
    return 'it is empty';
  }
  if (!/^[A-Za-z0-9+/]+=*$/.test(der)) {
    log.debug("Leaving samlCertificateProblem(). Not base64.");
    return 'it is not base64';
  }
  // ANY KEY `common/crypto.js` VERIFIES AN XML SIGNATURE WITH (section 1a,
  // since the #37 follow-up): RSA, EC, Ed25519, Ed448, DSA, ML-DSA, SLH-DSA.
  const problem = stsCrypto.xmlSignatureKeyProblem(der);
  if (problem) {
    log.debug("Leaving samlCertificateProblem(). " + problem);
    return problem;
  }
  log.debug("Leaving samlCertificateProblem(). Usable.");
  return '';
}

// ---------------------------------------------------------------------------
// WRITE WHAT CONSUMING A SERVICE PROVIDER'S METADATA FOUND, IN ONE SAVE
// (2026-09-17, #37).
//
// `replacements` maps an attribute in SAML_METADATA_FIELDS to its new value:
// a string or a list REPLACES the attribute, '' or an empty list REMOVES it,
// and an attribute not named is left alone. Two members are not plain
// replacements, because what metadata says about them is only PART of what
// the entry holds:
//
//   * `samlAssertionConsumerService` and `samlSingleLogoutService` also hold
//     addresses an operator declared and — for the first — addresses a
//     development request recorded. So `retire` names the locations the LAST
//     consumption wrote, which are taken off unless the new document names
//     them again, and the new ones are ADDED. An address written here is an
//     explicit registration, so its observed mark goes, as `add` does.
//
// It is NOT a door: no console form or API operation reaches it with a
// caller's attribute names. `saml/sp_metadata.ts`'s `consume()` is the one
// caller, and the attributes it writes are derived from a document the
// operator chose.
// ---------------------------------------------------------------------------
function replaceSamlMetadataFields(identifier, replacements, options) {
  log.debug("Entering replaceSamlMetadataFields(). identifier=" + identifier);
  const opts = options || {};
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving replaceSamlMetadataFields(). No such application.");
    return errorCodes.mark({ ok: false, errors: ['There is no application ' +
                             'called "' + identifier + '" in this ' +
                             'registry.'] }, 'STS-REG-0021');
  }
  const wanted = replacements || {};
  const stray = Object.keys(wanted).filter(function (name) {
    return SAML_METADATA_FIELDS.indexOf(name) < 0;
  });
  if (stray.length) {
    // A programming error rather than a caller's, and refused loudly so that
    // it is found in a test rather than in a directory.
    log.debug("Leaving replaceSamlMetadataFields(). Not metadata fields.");
    return errorCodes.mark({ ok: false, errors: ['Consuming metadata may not ' +
                             'write ' + stray.join(', ') + '.'] },
                           'STS-REG-0161');
  }
  const record = loaded.record;
  const retire = opts.retire || {};
  Object.keys(wanted).forEach(function (name) {
    const row = ATTRIBUTE_BY_NAME[name];
    const list = valuesOf(wanted[name]);
    if (name === 'samlAssertionConsumerService' ||
        name === 'samlSingleLogoutService') {
      const leaving = valuesOf(retire[name]).filter(function (one) {
        return list.indexOf(one) < 0;
      });
      const kept = valuesOf(record.fields[name]).filter(function (one) {
        return leaving.indexOf(one) < 0;
      });
      leaving.forEach(function (one) {
        clearObservedMark(record, name, one);
      });
      list.forEach(function (one) {
        if (kept.indexOf(one) < 0) {
          kept.push(one);
        }
        if (RETURN_ADDRESS_ATTRIBUTES.indexOf(name) >= 0) {
          clearObservedMark(record, name, one);
        }
      });
      if (kept.length) {
        record.fields[name] = kept;
      } else {
        delete record.fields[name];
      }
      return;
    }
    if (!list.length) {
      delete record.fields[name];
      return;
    }
    record.fields[name] = row && row.kind === 'multi' ? list : list[0];
  });
  // A certificate the metadata now registers is no longer merely observed.
  const observed = String(record.fields[OBSERVED_CERTIFICATE_ATTRIBUTE] || '');
  if (observed &&
      valuesOf(record.fields.samlSigningCertificate).indexOf(observed) >= 0) {
    delete record.fields[OBSERVED_CERTIFICATE_ATTRIBUTE];
  }
  record.lastAt = record.lastAt || Date.now();
  if (!save(record) && store()) {
    log.debug("Leaving replaceSamlMetadataFields(). The entry would not " +
              "take it.");
    return errorCodes.mark({ ok: false, errors: ['The application entry ' +
                             'would not take the consumed metadata.'] },
                           'STS-REG-0162');
  }
  audit.audit({
    action: 'application.update', actor: opts.actor || '',
    protocol: 'SAML 2.0', channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '": its service provider ' +
             'metadata was consumed (' + (opts.how || 'unstated') + ')',
    detail: { identifier: String(identifier),
              attributes: Object.keys(wanted), mode: 'consume-metadata' }
  });
  log.info('applications: "' + identifier + '" — service provider metadata ' +
           'consumed (' + (opts.how || 'unstated') + ').');
  log.debug("Leaving replaceSamlMetadataFields().");
  return { ok: true, changed: true,
           application: viewAfterWrite(identifier, record) };
}

// ---------------------------------------------------------------------------
// THE OBSERVED SIGNING CERTIFICATE: CONFIRM IT, OR DISCARD IT (2026-09-17,
// #37). confirmReturnAddress()'s pair for the one thing a SAML request brings
// with it that could become a trust anchor. Confirming MOVES it onto
// `samlSigningCertificate` — one save, so it is never on both or neither —
// and is refused for a certificate that is not RSA, for updateApplication()'s
// reason. Discarding takes it off.
// ---------------------------------------------------------------------------
function observedCertificateRequest(identifier, verb) {
  log.debug("Entering observedCertificateRequest(). verb=" + verb);
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving observedCertificateRequest(). No such application.");
    return errorCodes.mark({ ok: false, errors: ['There is no application ' +
                             'called "' + identifier + '" in this ' +
                             'registry.'] }, 'STS-REG-0021');
  }
  const observed = String(
    loaded.record.fields[OBSERVED_CERTIFICATE_ATTRIBUTE] || '');
  if (!observed) {
    log.debug("Leaving observedCertificateRequest(). Nothing observed.");
    return errorCodes.mark({ ok: false, errors: ['"' + identifier + '" has ' +
                             'no observed signing certificate, so there is ' +
                             'nothing to ' + verb + '. One is recorded when ' +
                             'a signed request carries a certificate in its ' +
                             'ds:KeyInfo that is not already registered.'] },
                           'STS-REG-0163');
  }
  log.debug("Leaving observedCertificateRequest().");
  return { ok: true, loaded: loaded, observed: observed };
}

function saveObservedCertificateChange(identifier, record, verb, what, actor) {
  log.debug("Entering saveObservedCertificateChange().");
  record.lastAt = record.lastAt || Date.now();
  save(record);
  audit.audit({
    action: 'application.update', actor: actor || '', protocol: 'console',
    channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '": ' + what,
    detail: { identifier: String(identifier),
              attribute: OBSERVED_CERTIFICATE_ATTRIBUTE,
              mode: verb + '-certificate', editedByHand: true }
  });
  log.info('applications: "' + identifier + '" — ' + what + '.');
  log.debug("Leaving saveObservedCertificateChange().");
  return { ok: true, changed: true,
           application: viewAfterWrite(identifier, record),
           message: what + '.' };
}

function confirmSigningCertificate(identifier, options) {
  log.debug("Entering confirmSigningCertificate(). identifier=" + identifier);
  const found = observedCertificateRequest(identifier, 'confirm');
  if (!found.ok) {
    log.debug("Leaving confirmSigningCertificate(). Refused.");
    return found;
  }
  const problem = samlCertificateProblem(found.observed);
  if (problem) {
    log.debug("Leaving confirmSigningCertificate(). Not usable.");
    return errorCodes.mark({ ok: false, errors: ['The observed certificate ' +
                             'cannot be registered: ' + problem + '. ' +
                             'Discard it instead.'] }, 'STS-REG-0160');
  }
  const record = found.loaded.record;
  const registered = valuesOf(record.fields.samlSigningCertificate);
  if (registered.indexOf(found.observed) < 0) {
    registered.push(found.observed);
  }
  record.fields.samlSigningCertificate = registered;
  delete record.fields[OBSERVED_CERTIFICATE_ATTRIBUTE];
  const answer = saveObservedCertificateChange(identifier, record, 'confirm',
    'confirmed the observed signing certificate: it is on ' +
    'samlSigningCertificate now, and this service provider\'s signatures ' +
    'are verified against it from the next request',
    (options || {}).actor);
  log.debug("Leaving confirmSigningCertificate().");
  return answer;
}

function discardSigningCertificate(identifier, options) {
  log.debug("Entering discardSigningCertificate(). identifier=" + identifier);
  const found = observedCertificateRequest(identifier, 'discard');
  if (!found.ok) {
    log.debug("Leaving discardSigningCertificate(). Refused.");
    return found;
  }
  const record = found.loaded.record;
  delete record.fields[OBSERVED_CERTIFICATE_ATTRIBUTE];
  const answer = saveObservedCertificateChange(identifier, record, 'discard',
    'discarded the observed signing certificate. It was never trusted; a ' +
    'signed request carrying it again records it again',
    (options || {}).actor);
  log.debug("Leaving discardSigningCertificate().");
  return answer;
}

// The entry goes entirely. Different from forgetRegistration(), which keeps it
// and takes only the registration away: this is for an application that should
// not be in the registry at all — a client_id somebody typed wrong, a realm
// from a test that is over. It is the one operation here that LOSES a fact, so
// it says so in the message rather than reporting a tidy success.
function deleteApplication(identifier, options) {
  log.debug("Entering deleteApplication().");
  const opts = options || {};
  log.debug("Entering deleteApplication(). identifier=" + identifier);
  const backing = store();
  if (!backing || !backing.deleteApplication) {
    log.debug("Leaving deleteApplication(). There is no directory.");
    log.debug("Leaving deleteApplication().");
    return errorCodes.mark({ ok: false, errors: ['There is no directory ' +
                                 'loaded in this process, so there is ' +
                                 'nothing to delete from.'] }, 'STS-REG-0002');
  }
  const loaded = load(identifier);
  if (!loaded.known) {
    log.debug("Leaving deleteApplication(). No such application.");
    log.debug("Leaving deleteApplication().");
    return errorCodes.mark({ ok: false, errors: ['There is no application ' +
                                                 'called ' +
                                                 '"' + identifier + '" ' +
        'here.'] },
                           'STS-REG-0021');
  }
  const gone = backing.deleteApplication(String(identifier));
  if (!gone) {
    log.debug("Leaving deleteApplication().");
    return errorCodes.mark({ ok: false, errors: ['The directory would not ' +
                                                 'delete ' +
                                                 '"' + identifier + '".'] },
                           'STS-REG-0022');
  }
  audit.audit({
    action: 'application.delete', actor: opts.actor || '', protocol: 'console',
    channel: 'internal', target: String(identifier),
    summary: 'Application "' + identifier + '" was deleted from the registry',
    detail: { identifier: String(identifier),
              authentications: loaded.record.authentications,
              registered: loaded.record.registered }
  });
  log.info('applications: "' + identifier + '" was deleted. ' + count() + ' ' +
      'left.');
  log.debug("Leaving deleteApplication(). Gone.");
  log.debug("Leaving deleteApplication().");
  return { ok: true,
           message: '"' + identifier + '" is gone from the registry, along ' +
                    'with what it had ' +
                    'recorded: ' + loaded.record.authentications + ' ' +
                    'authentication(s) and whatever attributes it carried. ' +
                    'It will reappear, empty, the next time that identifier ' +
                    'is accepted by a protocol.' };
}

// ---------------------------------------------------------------------------
// Reading the registry. Every one of these is a directory read; there is no
// cache, which is what keeps an ldapmodify effective on the next request rather
// than after a restart.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ONE APPLICATION AS EVERY PAGE AND EVERY API REPLY SEES IT.
//
// `record` is what this module understands about it; `entry` is what the
// directory holds. Both, because they are not the same set and the difference
// was invisible from outside:
//
//   * `attributes` IS THE WHOLE ENTRY now, canonically spelled, operational
//     attributes and `entryDN` included. It used to be `record.fields`, which
//     is the schema half MINUS the twelve names recordFromAttributes() reads
//     into named members instead — so `objectClass`, `cn`, `appIdentifier`,
//     `appName`, `appKind`, `appProtocol`, `description`, both timestamps, the
//     three counters and `appRegistered` were all missing from a table headed
//     "every attribute the entry carries", and so was anything an ldapmodify
//     had written by hand. The named members are still here beside it: a caller
//     that wants the identifier should not have to know which attribute holds
//     it.
//   * `dn` is where the entry IS. Not an attribute — the key it is stored under
//     — so it could not have appeared in the old map however complete that map
//     was. It is repeated inside `attributes` as `entryDN`, the RFC 5020 name,
//     because that is the name an ldapsearch filter matches it by here and a
//     dump that called the same fact two things would teach the reader a wrong
//     one.
//   * `operational` names which attributes a SEARCH would have withheld unless
//     asked for by name (RFC 4511 section 4.5.1.8), so a page can mark them
//     rather than pretend the distinction does not exist. This is a dump of the
//     store and not a search, so it shows them always.
//
// `entry` is absent — null — only when no directory is loaded in this process,
// which is the state store() warns about once and in which there is no registry
// at all. It is not the same as an entry carrying nothing.
// ---------------------------------------------------------------------------
function view(record, entry) {
  log.debug("Entering view().");
  log.debug("Leaving view().");
  return {
    identifier: record.identifier,
    dnLabel: record.label,
    dn: entry ? entry.dn : null,
    name: record.name,
    kinds: record.kinds.slice(0),
    protocols: record.protocols.slice(0),
    // The DECLARED families, beside the observed ones above. It is lifted out
    // of `fields` — where it also still appears, because every schema attribute
    // does — so that a caller reading this shape does not have to know that one
    // of the two protocol lists is a top-level member and the other is not.
    // `recordedProtocols` is the same vocabulary again, worked out from the
    // KINDS this record carries rather than from `protocols` — see the
    // PROTOCOLS table's header, where matching on the protocol LABELS is
    // recorded as the wrong answer and why: a federation partner's sighting is
    // written under the protocol its relationship speaks, so by label every
    // OAuth client read as a federation partner.
    //
    // IT IS NOT "HAS AUTHENTICATED", and the name says so. A kind is usually
    // written when a protocol recognises the identifier, but
    // createApplication() takes one as well — so a hand-made entry can be
    // recorded in a family it has never connected in, and `authentications` is
    // the number that answers whether anything has actually happened.
    allowedProtocols: valuesOf(record.fields.appAllowedProtocol),
    recordedProtocols: protocolIdsForKinds(record.kinds),
    // THE KINDS THE DECLARATION AMOUNTS TO (2026-09-18), beside `kinds` and
    // not in it: `kinds` stays what was recorded, and GNAP's grants read it
    // to decide things, so folding a declaration in would change behaviour
    // rather than a page. The console shows the two together — an
    // application declared for SAML 2.0 IS a service provider, and "Kind:
    // unstated" beside that declaration read as the create having lost it.
    declaredKinds: declaredKindsOf(record.fields),
    // How it was registered, or '' for one that merely turned up. An RFC 7591
    // registration from before the attribute existed still answers.
    registeredBy: String(record.fields.appRegisteredBy ||
                         (record.registered ? 'rfc7591' : '')),
    // THE RETURN ADDRESSES A DEVELOPMENT-MODE REQUEST PUT HERE AND NOBODY HAS
    // CONFIRMED (2026-09-12), lifted out of `fields` for the reason
    // `allowedProtocols` is: a caller should not have to parse
    // `<attribute> <address>` to learn which addresses product will refuse.
    // `trusted` is the answer in THIS realm's mode, from returnAddressesOf() —
    // true in development, false in product — so a reader never has to know
    // which mode decides it.
    returnAddressesObserved: observedReturnAddresses(record.fields).map(
        function (row) {
      return { attribute: row.attribute, value: row.value, held: row.held,
               trusted: row.held &&
                 returnAddressesOf(record.fields, row.attribute).registered
                   .indexOf(row.value) >= 0 };
    }),
    registered: record.registered,
    firstSeen: record.firstAt ? new Date(record.firstAt).toISOString() : '',
    lastSeen: record.lastAt ? new Date(record.lastAt).toISOString() : '',
    authentications: record.authentications,
    sessions: record.sessionCount,
    users: record.userCount,
    descriptions: record.descriptions.slice(0),
    // The entry's own facts, which are facts about the ENTRY rather than about
    // the application: when the directory created it, when it last changed, and
    // whether this service wrote it or a client did.
    origin: entry ? entry.origin : null,
    createdAt: entry ? entry.createdAt : null,
    modifiedAt: entry ? entry.modifiedAt : null,
    operational: entry ? entry.operational.slice(0) : [],
    // WITHHELD as well as spelled canonically — see WITHHELD_FIELDS.
    attributes: entry ? withholdFields(entry.attributes) : {},
    // The schema half on its own, kept because it is a different question —
    // "what has this module recorded about it" rather than "what does the entry
    // carry" — and because dropping it would silently change what a caller of
    // this API had already parsed.
    // OPENED, for the one attribute in this table that is private key
    // material. See SEALED_FIELDS: `fields` is what this module has recorded
    // about the application and `attributes` above is what the ENTRY carries,
    // so a caller that came through this module gets the PEM and a dump of the
    // store gets the ciphertext the store holds.
    fields: withholdFields(openSealedFields(record.fields, record.identifier))
  };
}

function list() {
  log.debug("Entering list().");
  const backing = store();
  if (!backing) {
    log.debug("Leaving list().");
    return [];
  }
  const rows = backing.allApplications().map(function (entry) {
    return view(recordFromAttributes(entry.attributes), entry);
  });
  // Newest activity first. `lastSeen` comes off the entry as GeneralizedTime,
  // which has ONE-SECOND resolution, so applications touched in the same second
  // tie — and a tie keeps directory order, which is the order they were created
  // in. That is stable and it is why a burst of client_ids registered together
  // reads in the order they arrived rather than jumbled; it is not the sort
  // failing to work.
  rows.sort(function (a, b) {
    return String(b.lastSeen).localeCompare(String(a.lastSeen));
  });
  log.debug("Leaving list().");
  return rows;
}

// ---------------------------------------------------------------------------
// THE PER-APPLICATION SETTING OVERRIDE, added 2026-08-27.
//
// `settingFor('urn:sp', 'saml2.signAssertion', config)` answers what THAT
// application should get: the value on its entry if it carries one, and the
// setting's own value if it does not. It is the whole of what makes the ten
// `saml2*`/`saml11*` attributes above mean anything — and every override row
// added since, in the OAuth, WS-Federation and group-claim groups.
//
// THREE PROPERTIES WORTH KNOWING BEFORE CHANGING IT.
//
// **The attribute is found from the SCHEMA, not from a second table.** Each
// override row carries `overrides: '<setting key>'`, and this scans for it. A
// map here from key to attribute name would be the second place that mapping
// lived, and the first thing to disagree with the schema when somebody added an
// eleventh.
//
// **`config` is PASSED IN.** This module requires `config.js` itself by now
// (see the header), so the parameter no longer keeps its require list short;
// what it still does is keep this function testable with a stub, which is how
// the bounds behaviour below was checked.
//
// **A value that will not parse is IGNORED and logged, never thrown.** An
// `ldapmodify` can put "yes" on `saml2SignAssertion`, and an identity provider
// that stopped issuing because of it would be a mock that stopped answering.
// The setting's own value is used and the log names the entry, the attribute
// and the reason, which is the only way somebody finds out that the exception
// they typed is not in force.
// THE LARGEST VALUE a per-application setting takes across this realm's
// entries, or the setting's own value when no entry overrides it higher —
// for a question about EVERY client at once, such as how long the longest
// token a key signed can live (`common/signing_rotation.ts`, #42).
function largestSetting(settingKey, config) {
  log.debug("Entering largestSetting(). setting=" + settingKey);
  let most = Number(config.value(settingKey)) || 0;
  if (!OVERRIDE_ATTRIBUTES[settingKey]) {
    log.debug("Leaving largestSetting(). Not per-application.");
    return most;
  }
  list().forEach(function (record) {
    const v = Number(settingFor(record.identifier, settingKey, config)) || 0;
    if (v > most) {
      most = v;
    }
  });
  log.debug("Leaving largestSetting(). " + most);
  return most;
}

function settingFor(identifier, settingKey, config) {
  log.debug("Entering settingFor(). identifier=" + (identifier || '(none)') +
            ", setting=" + settingKey);
  const fallback = config.value(settingKey);
  if (!identifier) {
    log.debug("Leaving settingFor(). No application named; the setting " +
              "decides.");
    return fallback;
  }
  const attribute = OVERRIDE_ATTRIBUTES[settingKey];
  if (!attribute) {
    // Not an overridable setting. Not an error: it is what every caller asking
    // about a setting with no per-application row gets, and the answer is the
    // setting, which is what it would have used anyway.
    log.debug("Leaving settingFor(). " + settingKey +
              " is not per-application.");
    return fallback;
  }
  const record = get(identifier);
  if (!record) {
    log.debug("Leaving settingFor(). No entry for it; the setting decides.");
    return fallback;
  }
  const raw = valuesOf(record.fields[attribute])[0];
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    log.debug("Leaving settingFor(). Nothing on the entry; the setting " +
              "decides.");
    return fallback;
  }
  const parsed = config.parseAs(settingKey, raw);
  if (!parsed.ok) {
    log.warn(errorCodes.tag('STS-REG-0025') +
             'applications: ' + identifier + ' carries ' + attribute + '="' +
             raw +
             '", which is not usable — ' + parsed.problem + '. The ' +
                 'service-wide ' +
             settingKey + ' is being used instead. Fix the attribute or ' +
             'remove it; nothing here refuses an assertion over it.');
    log.debug("Leaving settingFor(). Unusable; the setting decides.");
    return fallback;
  }
  log.debug("Leaving settingFor(). " + identifier + " overrides " + settingKey +
            ".");
  return parsed.value;
}

// Which attribute overrides which setting, built ONCE from the schema rows'
// own `overrides` member. Built rather than written so that adding an
// eleventh override is a row in SCHEMA and nothing else.
const OVERRIDE_ATTRIBUTES = {};
SCHEMA.attributes.forEach(function (attribute) {
  if (attribute.overrides) {
    OVERRIDE_ATTRIBUTES[attribute.overrides] = attribute.name;
  }
});

// The reverse, for a page that has an application and wants to know which of
// its settings it is answering for. Both directions come off the one table.
function overridableSettings() {
  log.debug("Entering overridableSettings().");
  log.debug("Leaving overridableSettings().");
  return Object.keys(OVERRIDE_ATTRIBUTES).map(function (key) {
    return { setting: key, attribute: OVERRIDE_ATTRIBUTES[key] };
  });
}

function get(identifier) {
  log.debug("Entering get().");
  const loaded = load(identifier);
  log.debug("Leaving get().");
  return loaded.known ? view(loaded.record, loaded.entry) : null;
}

// ---------------------------------------------------------------------------
// DELEGATED PERMISSIONS: THE SCHEMA'S HALF OF THE FEATURE.
//
// The MODEL — the register, both directions, the actions and the picture — is
// `common/app_permissions.ts`, and it is a separate file for the reason
// `delegation_map.js` is separate from `delegation.js`: this module owns the
// SCHEMA and therefore owns how a permission is spelled on an entry and how a
// spelling is read back, and that module owns what the two halves MEAN when
// read against each other. What is here is everything a reader of one entry
// needs; what is there is everything that needs two.
//
// Five functions and they are all this module contributes:
//
//   * `permissionIdOf(base, name)` — the concatenation, in ONE place, because
//     a second copy of it in the console and a third at the token endpoint is
//     three chances for `https://example.comwrite`.
//   * `permissionsOf(record)` — the permissions one entry DEFINES.
//   * `forPermission(id)` — which application defines this identifier, the
//     fourth lookup beside forAudience(), forClientId() and forAppliesTo() and
//     built the same way, for the same reason and with the same three
//     disclaimers: it is a LOOKUP and not a permission, it is not case-folded,
//     and it walks the container.
//   * `forPermissionBase(base)` — which application exposes its API under this
//     base URI, the FIFTH lookup. `forPermission()` asked one level up, for a
//     reader holding an ISSUED token: the base is what such a token carries as
//     its `aud`, and none of the four above can turn that back into an entry.
//   * `holdsPermission(clientId, id)` — whether a client has been GRANTED it.
//     Separate from the above because the two answer different questions and
//     collapsing them is how "this permission exists" comes to be read as
//     "this client may have it", which is the whole distinction this feature
//     is about.
// ---------------------------------------------------------------------------

// The one place base and name are joined. A base that does not end in a
// separator gets a `/`, which is what makes `https://example.com` + `write`
// produce `https://example.com/write` rather than one word — see the
// attribute's own row, which says that an ldapmodify is not normalised and
// therefore means exactly what it says.
function permissionBaseOf(value) {
  log.debug("Entering permissionBaseOf().");
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    log.debug("Leaving permissionBaseOf().");
    return '';
  }
  log.debug("Leaving permissionBaseOf().");
  return /[/#:]$/.test(text) ? text : text + '/';
}

function permissionIdOf(base, name) {
  log.debug("Entering permissionIdOf().");
  const prefix = permissionBaseOf(base);
  const leaf = String(name == null ? '' : name).trim();
  log.debug("Leaving permissionIdOf().");
  return (prefix && leaf) ? prefix + leaf : '';
}

// `write` or `write|Change widgets on somebody's behalf`. The FIRST `|` is the
// delimiter and every later one is part of the description, which is why this
// is an indexOf and not a split — a split would silently drop the tail of a
// description that contained the character, and the value would still look
// right on the entry.
function parsePermissionValue(value) {
  log.debug("Entering parsePermissionValue().");
  const text = String(value == null ? '' : value);
  const at = text.indexOf('|');
  const name = (at < 0 ? text : text.slice(0, at)).trim();
  const description = at < 0 ? '' : text.slice(at + 1).trim();
  log.debug("Leaving parsePermissionValue().");
  return { name: name, description: description };
}

function permissionValueOf(name, description) {
  log.debug("Entering permissionValueOf().");
  const leaf = String(name == null ? '' : name).trim();
  const what = String(description == null ? '' : description).trim();
  log.debug("Leaving permissionValueOf().");
  return what ? leaf + '|' + what : leaf;
}

// RFC 6749 section 3.3's `scope-token`: %x21 / %x23-5B / %x5D-7E — every
// printable ASCII character except space, double quote and backslash. Checked
// because the name IS what a client sends in a `scope` parameter and what comes
// back on the token's `scope` claim, and a name with a space in it would arrive
// at the token endpoint as two scopes neither of which is a permission.
//
// `|` is refused BEYOND the RFC, because it is this schema's own delimiter and
// a name carrying one could never be read back as the name that was written.
function permissionNameProblem(name) {
  log.debug("Entering permissionNameProblem().");
  const text = String(name == null ? '' : name);
  if (!text.trim()) {
    log.debug("Leaving permissionNameProblem().");
    return 'A permission needs a name — the word a client will put in its ' +
           '`scope`, such as `read` or `Widgets.ReadWrite.All`.';
  }
  if (text !== text.trim()) {
    log.debug("Leaving permissionNameProblem().");
    return 'A permission name may not begin or end with whitespace: it is ' +
           'sent as one word in an OAuth `scope` parameter, which is ' +
           'space-delimited.';
  }
  if (text.indexOf('|') >= 0) {
    log.debug("Leaving permissionNameProblem().");
    return 'A permission name may not contain "|". That character separates ' +
           'the name from the description in the `oauthPermission` ' +
           'attribute, so a name carrying one could never be read back as ' +
           'the name that was written — put the text after the first "|" and ' +
           'it becomes the description.';
  }
  if (!/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(text)) {
    log.debug("Leaving permissionNameProblem().");
    return '"' + text + '" is not a legal OAuth scope token. RFC 6749 ' +
           'section 3.3 allows any printable ASCII except space, double ' +
           'quote and backslash, because a scope list is space-delimited — a ' +
           'name outside that set cannot survive the round trip through a ' +
           '`scope` parameter.';
  }
  log.debug("Leaving permissionNameProblem().");
  return '';
}

// ---------------------------------------------------------------------------
// RFC 6749 SECTION 3.3'S `scope-token`, ON ITS OWN, BECAUSE TWO ATTRIBUTES NOW
// NEED IT AND THEY NEED DIFFERENT THINGS AROUND IT.
//
// `permissionNameProblem()` above is this rule PLUS a refusal of `|`, because a
// permission name shares an attribute value with its description. A globally
// consented scope has no delimiter to protect and may legitimately be a whole
// permission identifier, so it gets the RFC's rule and nothing more.
//
// It lives HERE rather than in `common/consent.ts` for the reason the ordering
// rule lives in updateApplication(): this module owns the SCHEMA, so it owns
// what a value of one of its attributes may be, and a second copy of the
// grammar over there would be the thing that eventually disagreed. That module
// calls this one; the dependency already runs in that direction.
// ---------------------------------------------------------------------------
function scopeTokenProblem(value) {
  log.debug("Entering scopeTokenProblem().");
  const text = String(value == null ? '' : value);
  if (!text.trim()) {
    log.debug("Leaving scopeTokenProblem().");
    return 'Which scope? It is the word a client puts in its `scope` ' +
           'parameter — `openid`, `profile`, or a whole delegated permission ' +
           'identifier such as `https://example.com/write`.';
  }
  if (text !== text.trim()) {
    log.debug("Leaving scopeTokenProblem().");
    return 'A scope may not begin or end with whitespace: a `scope` ' +
           'parameter is space-delimited, so the value would arrive at the ' +
           'authorization endpoint as a different word from the one written ' +
           'here and would never match.';
  }
  if (!/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(text)) {
    log.debug("Leaving scopeTokenProblem().");
    return '"' + text + '" is not a legal OAuth scope token. RFC 6749 ' +
           'section 3.3 allows any printable ASCII except space, double ' +
           'quote and backslash, because a scope list is space-delimited. A ' +
           'value outside that set can never match a scope a client asked ' +
           'for, so consenting it would consent nothing.';
  }
  log.debug("Leaving scopeTokenProblem().");
  return '';
}

// A base URI has to be absolute, for the reason RFC 8707 gives about `resource`
// and for one of this feature's own: it becomes the `aud` of an access token,
// and a relative string there is an audience nothing can compare against.
// A FRAGMENT IS ALLOWED where RFC 8707 refuses one, and that is deliberate
// rather than an oversight — this is not a resource indicator, it is a name
// this service concatenates onto, and `https://example.com/api#` is a perfectly
// readable base whose permissions are `https://example.com/api#read`.
function permissionBaseProblem(value) {
  log.debug("Entering permissionBaseProblem().");
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    log.debug("Leaving permissionBaseProblem().");
    return '';
  }
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (e) {
    log.debug("Caught in permissionBaseProblem(): " + ((e && e.message) || e));
    log.debug("Leaving permissionBaseProblem().");
    // Not a URI at all. The message names what was sent rather than the
    // exception, which says only "Invalid URL" and would send somebody looking
    // at their client.
    return '"' + text + '" is not an absolute URI. A permission base is what ' +
           'an access token asking for one of this application\'s ' +
           'permissions is AUDIENCED to, and an audience that is not ' +
           'absolute is one nothing can compare against. Microsoft Entra ID ' +
           'spells this `api://<guid>`; anything absolute works here.';
  }
  if (!parsed.protocol) {
    log.debug("Leaving permissionBaseProblem().");
    return '"' + text + '" has no scheme.';
  }
  log.debug("Leaving permissionBaseProblem().");
  return '';
}

// The permissions ONE ENTRY defines, in the order the attribute holds them.
// Takes a record (what load() returns) or a view (what get() and list()
// return) — both carry `fields`, which is the whole of what this reads, so one
// function serves the pages and the token endpoint rather than two that could
// come to disagree about what a permission is.
function permissionsOf(source) {
  log.debug("Entering permissionsOf().");
  const fields = (source && source.fields) || {};
  const base = permissionBaseOf(fields.oauthPermissionBaseUri);
  log.debug("Leaving permissionsOf().");
  return valuesOf(fields.oauthPermission).map(function (value) {
    const parsed = parsePermissionValue(value);
    return {
      name: parsed.name,
      description: parsed.description,
      // EMPTY WHERE THERE IS NO BASE, and that is a state worth carrying rather
      // than hiding: an entry can hold `oauthPermission` with no
      // `oauthPermissionBaseUri` — an ldapmodify can write one without the
      // other, and so can somebody who removed the base afterwards — and a
      // permission with no identifier is one no client can ever ask for. The
      // console says so; a computed id here would invent one.
      id: base ? base + parsed.name : '',
      raw: String(value)
    };
  });
}

// WHICH APPLICATION DEFINES THIS PERMISSION IDENTIFIER, or null.
//
// The fourth lookup in this module, and it is the same shape as the three
// further down (forAudience(), forClientId(), forAppliesTo()) for the same
// reasons — it walks the container, it is not case-folded, and it
// REFUSES NOTHING. What it adds over them is that the answer names two things:
// the application AND which of its permissions was matched, because the caller
// needs both (the base becomes the audience, the name becomes the scope) and a
// caller that had to re-derive the second from the first would be the second
// place `base + name` was taken apart.
//
// The match is EXACT against the composed identifier rather than a prefix test
// on the base. A prefix test would match `https://example.com/write` against a
// base of `https://example.com/` even where no `write` permission was ever
// defined, which is precisely the case this feature exists to distinguish: a
// scope naming a permission that does not exist is an ordinary scope, and
// turning it into an audience would let any client address a token to any
// registered base by inventing a word.
function forPermission(id) {
  log.debug("Entering forPermission(). id=" + id);
  const wanted = String(id == null ? '' : id).trim();
  if (!wanted) {
    log.debug("Leaving forPermission(). Nothing was asked for.");
    return null;
  }
  let answer = null;
  list().some(function (row) {
    const found = permissionsOf(row).filter(function (one) {
      return one.id && one.id === wanted;
    })[0];
    if (!found) {
      return false;
    }
    answer = {
      identifier: row.identifier,
      application: row,
      baseUri: permissionBaseOf(row.fields.oauthPermissionBaseUri),
      name: found.name,
      description: found.description,
      id: found.id
    };
    return true;
  });
  if (!answer) {
    log.debug("Leaving forPermission(). No application defines it.");
    return null;
  }
  log.debug("Leaving forPermission(). " + answer.identifier + " defines " +
            answer.name + ".");
  return answer;
}

// WHICH APPLICATION EXPOSES ITS API UNDER THIS BASE URI, or null.
//
// The FIFTH lookup, and it is `forPermission()` above asked one level up: that
// one takes a whole identifier and answers which application defines it, and
// this one takes the BASE ALONE and answers which application the base belongs
// to. It exists because of what `oauth2.js`'s `audienceScopes()` writes onto a
// token — the base URI becomes the `aud` and the bare names become the `scope`
// — so a reader holding an ISSUED token holds the base and nothing else, and
// the other four lookups cannot turn it back into an application:
// `forAudience()` reads `oauthAudience`, which is a DIFFERENT attribute that a
// resource is under no obligation to have set; `forClientId()` reads a bare
// name; and `forPermission()` needs a name on the end that the reader is trying
// to work out.
//
// `common/user_graph.ts` is the caller and its `permissionsAddressedTo()` says
// what it does with the answer. Doing it there instead would have meant a
// second walk of the container per scope value — one `forPermission()` call per
// name — where this is one walk per audience and then a read of the entry the
// caller already has.
//
// IT NORMALISES BOTH SIDES AND MATCHES EXACTLY OTHERWISE. `permissionBaseOf()`
// is what added the trailing separator when the identifier was composed, so a
// base stored by an `ldapmodify` as `https://example.com` and an `aud` carrying
// `https://example.com/` are the same API and must land on the same entry —
// that is the one difference this lookup has from `forAudience()`, and it is
// not a softening of the rule but the same rule applied to a value THIS module
// composed. It is still not case-folded, for `forAudience()`'s reason.
//
// AN ENTRY WITH NO BASE IS NEVER MATCHED, because `permissionBaseOf('')` is the
// empty string and an empty base would otherwise match every entry that has
// none. That is the state `permissionsOf()`'s `id` comment describes.
function forPermissionBase(base) {
  log.debug("Entering forPermissionBase(). base=" + base);
  const wanted = permissionBaseOf(base);
  if (!wanted) {
    log.debug("Leaving forPermissionBase(). Nothing was asked for.");
    return null;
  }
  const found = list().filter(function (row) {
    return permissionBaseOf((row.fields ||
                             {}).oauthPermissionBaseUri) === wanted;
  });
  if (!found.length) {
    log.debug("Leaving forPermissionBase(). No application exposes it.");
    return null;
  }
  if (found.length > 1) {
    // Two entries exposing one base is a configuration mistake rather than a
    // state to resolve here — the same sentence forAudience() and forClientId()
    // say about their own attributes, with this consequence: a permission
    // identifier is base + name, so two entries under one base means one string
    // naming two permissions and `forPermission()` answering with whichever it
    // walked into first.
    log.warn(errorCodes.tag('STS-REG-0026') +
             'applications: ' + found.length + ' applications expose their ' +
             'permissions under the base URI "' + wanted + '" (' +
             found.map(function (row) { return row.identifier; }).join(', ') +
             '). A base URI names one API; a permission identifier is that ' +
             'base followed by a name, so two entries under one base are two ' +
             'permissions that cannot be told apart. Remove it from the ' +
             'others.');
  }
  log.debug("Leaving forPermissionBase(). " + found[0].identifier + ".");
  return found[0];
}

// WHETHER A CLIENT HAS BEEN GRANTED A PERMISSION.
//
// The client is named the way a token request names it — by `client_id` — so
// this goes through forClientId() rather than through get(): an application
// created from the console under one name and registered under another answers
// to both, and a lookup by identifier would find the grant on only one of them.
// It falls back to get() for a caller holding the registry identifier itself,
// because those are the same entry in the ordinary case and a caller should not
// have to know which spelling it is holding.
//
// IT IS A QUESTION AND NOT A GATE. Nothing in this module refuses anything for
// its answer; oauth2.ts's permissionRefusal() turns a false into a refusal —
// always in product mode, and in development when
// `oauth2.delegatedPermissionsEnforced` is on (#110).
function holdsPermission(clientId, id) {
  log.debug("Entering holdsPermission().");
  const wanted = String(id == null ? '' : id).trim();
  const who = String(clientId == null ? '' : clientId).trim();
  if (!wanted || !who) {
    log.debug("Leaving holdsPermission(). Nothing was asked for.");
    return false;
  }
  const found = forClientId(who) || get(who);
  if (!found) {
    log.debug("Leaving holdsPermission(). No such client in the registry.");
    return false;
  }
  const held = valuesOf((found.fields || {}).oauthDelegatedPermission)
    .indexOf(wanted) >= 0;
  log.debug("Leaving holdsPermission(). " + (held ? 'held' : 'not held') + ".");
  return held;
}

// ---------------------------------------------------------------------------
// THE SCOPES A CLIENT DECLARED (#110, 2026-09-22): its `oauthAllowedScope`,
// or NULL when it declares none — and the difference between an empty list and
// no list is the whole of what `common/scope_policy.ts` reads it for. A client
// that lists nothing gets the documented default set in product; a client that
// lists something gets exactly that.
//
// Looked up the way holdsPermission() looks a grant up, and for its reason:
// by `client_id` first, because that is what a token names, and then by the
// registry identifier, which is what a GNAP token names (its instanceId is the
// application's identifier). IN THE AMBIENT REALM: a client_id names a client
// in one realm, and the caller runs this inside the realm whose token it is.
//
// A QUESTION AND NOT A GATE, like its neighbour: nothing here refuses.
// ---------------------------------------------------------------------------
function allowedScopesOf(clientId) {
  log.debug("Entering allowedScopesOf().");
  const who = String(clientId == null ? '' : clientId).trim();
  if (!who) {
    log.debug("Leaving allowedScopesOf(). No client named.");
    return null;
  }
  const found = forClientId(who) || get(who);
  if (!found) {
    log.debug("Leaving allowedScopesOf(). No such client in the registry.");
    return null;
  }
  const held = valuesOf((found.fields || {}).oauthAllowedScope).map(String)
    .map(function (one) { return one.trim(); })
    .filter(function (one) { return !!one; });
  log.debug("Leaving allowedScopesOf(). " +
            (held.length ? held.length + " declared." : "None declared."));
  return held.length ? held : null;
}

// ---------------------------------------------------------------------------
// WHICH APPLICATION ANSWERS TO THIS AUDIENCE, or null.
//
// The first lookup in this module that is not by identifier, and the only
// thing in this service that READS `oauthAudience`. The token endpoint calls
// it when it records a delegation: a client exchanging a token for
// `https://esb1.example.com` has named a resource rather than a client_id, and
// a register that filed the act under the URL would draw a box in
// /admin/delegation/map that nothing else in the picture ever mentions — while
// the application it means is sitting in this registry two rows away.
//
// THREE THINGS IT DELIBERATELY IS NOT.
//
// It is not a PERMISSION. An audience nobody registered returns null and the
// caller records what was asked for, verbatim; nothing is refused, because a
// mock that refused would remove a test case rather than add one. It is not
// CASE-FOLDED or normalised: RFC 8693 leaves an audience as an opaque string
// the authorization server understands, and an audience that differs by a
// character is a different audience — quietly matching `HTTPS://ESB1` to
// `https://esb1` would be this registry deciding a URI comparison rule on the
// caller's behalf. And it does not fall back to the IDENTIFIER:
// `applications.get(audience)` already answers that question, and a lookup that
// tried both would make `audience=esb1` and `audience=https://esb1.example.com`
// indistinguishable in the one place the difference is the point.
//
// It walks the container, which is a linear read per exchange. That is honest
// for a registry capped by `applications.max` and holding tens of entries; an
// index would be a second copy of the attribute, and this module's whole
// argument is that the directory is the one store.
// ---------------------------------------------------------------------------
function forAudience(audience) {
  log.debug("Entering forAudience(). audience=" + audience);
  const wanted = String(audience == null ? '' : audience).trim();
  if (!wanted) {
    log.debug("Leaving forAudience(). Nothing was asked for.");
    return null;
  }
  const found = list().filter(function (row) {
    return valuesOf(row.fields.oauthAudience).indexOf(wanted) >= 0;
  });
  if (!found.length) {
    log.debug("Leaving forAudience(). No application has registered it.");
    return null;
  }
  if (found.length > 1) {
    // Two entries claiming one audience is a configuration mistake rather than
    // a state to resolve here, and the first is as good an answer as any — but
    // it is said out loud, because the consequence is a delegation filed under
    // one of two applications with nothing on the page to say the other exists.
    log.warn(errorCodes.tag('STS-REG-0026') +
             'applications: ' + found.length + ' applications have ' +
             'registered the audience "' + wanted + '" (' +
             found.map(function (row) { return row.identifier; }).join(', ') +
             '). The first is what a token exchange for it will be recorded ' +
             'against. An audience names one resource; remove it from the ' +
             'others.');
  }
  log.debug("Leaving forAudience(). " + found[0].identifier + ".");
  return found[0];
}

// ---------------------------------------------------------------------------
// WHICH APPLICATION ANSWERS TO THIS CLIENT_ID, or null.
//
// The SECOND lookup here that is not by identifier, and it exists because a
// client_id and an identifier are not the same thing even though they are equal
// on almost every entry in this registry: `seen()` files an OAuth client under
// its client_id, so the two agree for anything that turned up on its own — and
// an entry CREATED from the console gets whatever `cn` somebody typed, with the
// client_id in `oauthClientId` beside it. `load()` would find the first and
// miss the second, which is the whole reason this reads the attribute.
//
// It is `forAudience()`'s shape and not `forAudience()` itself, for the reason
// that function's header gives: `oauthAudience` and `oauthClientId` are two
// different registrations and one lookup answering to both would make
// `apigw1` and `https://apigw1.example.com` indistinguishable in the one place
// the difference is the point. The CALLER decides which question it is asking;
// oauth2.js's `audienceScopes()` asks this one, because a scope value is a bare
// name and never a URI.
//
// Same three properties as its neighbour, for the same reasons: it is not a
// permission (an unmatched name returns null and nothing is refused), it is not
// case-folded, and it walks the container rather than keeping an index.
// ---------------------------------------------------------------------------
function forClientId(clientId) {
  log.debug("Entering forClientId(). clientId=" + clientId);
  const wanted = String(clientId == null ? '' : clientId).trim();
  if (!wanted) {
    log.debug("Leaving forClientId(). Nothing was asked for.");
    return null;
  }
  const found = list().filter(function (row) {
    return valuesOf(row.fields.oauthClientId).indexOf(wanted) >= 0;
  });
  if (!found.length) {
    log.debug("Leaving forClientId(). No application has registered it.");
    return null;
  }
  if (found.length > 1) {
    // Two entries claiming one client_id is a configuration mistake rather than
    // a state to resolve here — the same sentence forAudience() says about an
    // audience, and with a sharper consequence: a client_id is what a Token
    // Request authenticates as, so two entries answering to one mean two sets
    // of registration facts for one caller.
    log.warn(errorCodes.tag('STS-REG-0026') +
             'applications: ' + found.length + ' applications have ' +
             'registered the client_id "' + wanted + '" (' +
             found.map(function (row) { return row.identifier; }).join(', ') +
             '). The first is the one anything looking a client up by id ' +
             'will find. A client_id names one client; remove it from the ' +
             'others.');
  }
  log.debug("Leaving forClientId(). " + found[0].identifier + ".");
  return found[0];
}

// ---------------------------------------------------------------------------
// WHICH APPLICATION ANSWERS TO THIS AppliesTo, or null.
//
// The THIRD lookup here that is not by identifier, and it is the WS-Trust and
// SAML spelling of the question `forAudience()` asks for OAuth. An RST naming
// `https://esb.example.com` in <wsp:AppliesTo> has named a SERVICE, and the
// assertion that comes back carries that string as its <saml:Audience> — so a
// delegation act filed under the URI draws a box on /admin/delegation/map that
// nothing else in the picture ever mentions, while the application it means is
// sitting in this registry two rows away. That is the failure forAudience()'s
// header describes, arriving through a different protocol.
//
// IT READS TWO ATTRIBUTES, IN THIS ORDER, AND THAT IS DELIBERATE. The schema
// keeps `wstrustAppliesTo` and `samlEntityId` apart because they are two
// registrations and not two spellings of one — an application may be a WS-Trust
// relying party and no SAML service provider, or the other way about. But this
// caller has ONE string that is both at once: WS-Trust issues a SAML 2.0
// assertion whose audience IS the AppliesTo, which is why wstrust.js's own
// `seen()` call writes the value into both attributes. So the narrower
// registration is asked first and the SAML one stands in behind it, and the
// caller is told WHICH answered — `matchedAttribute` on the reply — because a
// row saying only "the registry named this application" cannot be checked
// against what somebody actually registered.
//
// THE SAME THREE THINGS IT IS NOT, for the same reasons forAudience() gives:
// not a permission (an AppliesTo nobody registered comes back null and the
// caller records the URI verbatim — nothing is refused, because a mock that
// refused would remove a test case rather than add one), not case-folded (an
// AppliesTo is an opaque string the STS understands, and one that differs by a
// character is a different service), and not a fallback to the IDENTIFIER,
// which `get()` already answers.
// ---------------------------------------------------------------------------
function forAppliesTo(appliesTo) {
  log.debug("Entering forAppliesTo(). appliesTo=" + appliesTo);
  const wanted = String(appliesTo == null ? '' : appliesTo).trim();
  if (!wanted) {
    log.debug("Leaving forAppliesTo(). Nothing was asked for.");
    return null;
  }
  const attributes = ['wstrustAppliesTo', 'samlEntityId'];
  for (let i = 0; i < attributes.length; i++) {
    const attribute = attributes[i];
    const found = list().filter(function (row) {
      // THE ENTRY NAMED BY THE ADDRESS ITSELF IS SKIPPED, and this is the one
      // way this lookup differs from forAudience() in behaviour rather than in
      // wording. Nothing creates an entry named after an OAuth `audience`, but
      // wstrust.js's own seen() files every AppliesTo it accepts as an
      // identifier — writing the address into BOTH of these attributes on the
      // way — so this registry always holds an entry called
      // `https://esb.example.com` a moment after the first request for it, and
      // a lookup that could return that one would answer "the application for
      // this address is the address", which is what the caller already does
      // when nothing is found. Skipping it makes the question the useful one:
      // is there an application, known here by ANOTHER name, that has declared
      // this address? Verified the hard way — without this, a two-hop chain
      // still drew as two halves and the log carried only a duplicate warning.
      return row.identifier !== wanted &&
             valuesOf(row.fields[attribute]).indexOf(wanted) >= 0;
    });
    if (!found.length) {
      continue;
    }
    if (found.length > 1) {
      // Said out loud for the reason its two neighbours say it: the act is
      // filed against one of two applications and nothing on the page says the
      // other exists.
      log.warn(errorCodes.tag('STS-REG-0026') +
               'applications: ' + found.length + ' applications have ' +
               'registered "' + wanted + '" on ' + attribute + ' (' +
               found.map(function (row) { return row.identifier; }).join(', ') +
               '). The first is what a token issued for it will be recorded ' +
               'against. An AppliesTo names one service; remove it from the ' +
               'others.');
    }
    log.debug("Leaving forAppliesTo(). " + found[0].identifier + " via " +
              attribute + ".");
    // A COPY with one member added rather than the row itself: the caller wants
    // to say which registration answered, and mutating what list() handed back
    // would put that member on a record other readers share.
    return Object.assign({}, found[0], { matchedAttribute: attribute });
  }
  log.debug("Leaving forAppliesTo(). No application has registered it.");
  return null;
}

// ---------------------------------------------------------------------------
// THE ROLES AN APPLICATION REQUIRES.
//
// The one reader of `appRequiredRole`, so that "absent means EVERYBODY" is a
// property of this function rather than a convention four callers have to
// remember — and the fourth caller is always the one that reads an empty list
// as "require nothing", which is the same words and the opposite meaning.
//
// AN UNKNOWN APPLICATION ALSO REQUIRES EVERYBODY. This service registers an
// application on first sight, so the very first request from a new client
// arrives before its entry exists; refusing it would make this service refuse
// every client once, which is precisely the permissiveness it is for.
// ---------------------------------------------------------------------------
function requiredRolesOf(identifier) {
  log.debug("Entering requiredRolesOf(). identifier=" + identifier);
  const loaded = load(identifier);
  const values = loaded.known
    ? valuesOf((loaded.record && loaded.record.fields || {}).appRequiredRole)
        .map(function (one) { return String(one).trim(); })
        .filter(function (one) { return one.length > 0; })
    : [];
  if (!values.length) {
    log.debug("Leaving requiredRolesOf(). None named, so EVERYBODY.");
    return [roles.DEFAULT_REQUIRED_ROLE];
  }
  log.debug("Leaving requiredRolesOf(). " + values.length + " role(s).");
  return values;
}

// Whether this application has been NARROWED — whether somebody has asked for
// anything beyond the permissive default. The console draws it, and the
// embedded PEP uses it to decide how to behave when the issuance policy is
// missing: an application that requires only EVERYBODY loses nothing by the
// policy being absent, and one that requires `staff` loses the whole point of
// having said so. See `xacml/xacml_role_pep.ts`, which argues that split.
function requiresNarrowedRoles(identifier) {
  log.debug("Entering requiresNarrowedRoles().");
  const required = requiredRolesOf(identifier);
  log.debug("Leaving requiresNarrowedRoles().");
  return !(required.length === 1 &&
           required[0] === roles.DEFAULT_REQUIRED_ROLE);
}

function count() {
  log.debug("Entering count().");
  const backing = store();
  log.debug("Leaving count().");
  return backing ? backing.countApplications() : 0;
}

// Two facts about the STORE rather than about an application, asked for by the
// console and by the management API so that a reply can say where these entries
// live and how many the container will hold. They are ldap_server.js's answers
// — this module does not know where the container is, which is the division the
// header describes — so they are absent when no directory is attached, and the
// callers render that as null rather than as a guess.
function containerDn() {
  log.debug("Entering containerDn().");
  const backing = store();
  log.debug("Leaving containerDn().");
  return (backing && backing.containerDn && backing.containerDn()) || null;
}

function maxApplications() {
  log.debug("Entering maxApplications().");
  const backing = store();
  log.debug("Leaving maxApplications().");
  return (backing && backing.maxApplications &&
          backing.maxApplications()) || null;
}

// ---------------------------------------------------------------------------
// THIS SERVICE'S OWN APPLICATIONS, SEEDED AT STARTUP — TWO WHEN THIS WAS
// WRITTEN; THE USER PORTAL AND THE EMBEDDED DEBUGGER'S TWO HAVE JOINED THEM.
//
// Every other entry in this registry arrives because somebody PRESENTED an
// identifier — a client_id at the authorization endpoint, a wtrealm on a
// wsignin1.0, an SPN in a TGS request. Two applications never do, and they are
// the two a reader is most likely to go looking for: the ADMIN CONSOLE at
// /admin and the MANAGEMENT API at /admin-api. They are surfaces of THIS
// process, so no caller ever names them from outside, and until this ran the
// one question the registry exists to answer — what applications have you
// seen? — came back with everything except the two things the reader was
// standing in.
//
// THEY ARE SEEDED AS FULL RFC 7591 REGISTRATIONS AND NOT AS LABELS, which is
// the decision here. A descriptive entry would be a row on a page; a
// registration is a CLIENT: its secret is what RFC 9700 mode (section 2.5)
// checks, its redirect URI is what that mode matches by exact string, and GET
// /oauth2/register/sts-admin-console answers with the document below to
// whoever holds the registration access token on the entry. So the two rows
// are drivable by the thing this service exists for rather than merely
// visible.
//
// **`/admin/callback` IS SERVED SINCE 2026-09-06, AND THIS PARAGRAPH USED TO
// SAY NOTHING SERVED IT.** It read: *the console's gate is a sign-on session
// and two directory groups, not an OAuth flow, so the redirect URI below is
// what the console WOULD use if that gate ever moved onto OIDC.* That gate has
// moved. `/admin` and `/portal` are RELYING PARTIES of this service's own
// authorization server now: an unauthenticated request is sent to
// `/oauth2/authorize` with the client_id below, comes back to the redirect URI
// below with a code, and the code is redeemed with the secret below at
// `/oauth2/token`. `common/oidc_rp.ts` is the client and argues the whole of
// it. **These rows stopped being descriptions and became load-bearing**, which
// is what the paragraph above was already reaching for when it said a
// registration is a CLIENT rather than a row on a page.
//
// It is ON THE ENTRY rather than in a comment because this container IS the
// registry: an `ldapmodify`, a form on /admin/applications or a PUT to
// /oauth2/register/{id} changes it, and the change is what the checks then
// read. **That now has teeth: deleting one of these entries takes the surface
// it names offline until a restart**, which is the behaviour the seeding rule
// two paragraphs down ("an operator who deleted one of these meant it") always
// promised and could not previously demonstrate. The two scopes on the API's
// registration (`admin:read`, `admin:write`) said here that they GRANT
// NOTHING, because nothing under /admin-api was gated; since 2026-09-09 they
// are what `/admin-api`'s access token is checked for (`mgmt-api/CLAUDE.md`).
//
// THE SECRETS ARE MINTED WHEN AN ENTRY IS SEEDED — except the management
// API's in the default realm, which `adminApi.clientSecret` pins where it is
// set (see its row) — and sit on the entry. That is the decision
// `oauthClientSecret` argues in its schema row, made once more here and for
// the same reason; neither is ever written to the audit log.
//
// SEEDED ONLY WHERE THE IDENTIFIER IS FREE, which is `spiffe_registry.js`'s
// seeding rule and is here for its reason: an operator who deleted one of these
// meant it, and re-creating it would make the delete button appear not to work.
//
// **WHAT A RESTART DOES WITH THAT DEPENDS ON persistence.mode SINCE 2026-08-27,
// AND BOTH ANSWERS ARE THE RIGHT ONE.** In the default `memory` mode nothing is
// written down, so the next start seeds them again — a delete lasts for the
// life of the process, which is what it always did. With a store on, the
// seeding still runs (it happens as `ldap_server.js` fills the directory slot,
// at require time) and is then REPLACED: `persistence.start()` runs after every
// require and swaps each realm's directory for what was written down, so an
// entry deleted in the last run stays deleted. That is the seeding rule getting
// what it always wanted rather than a change to it — "an operator who deleted
// one of these meant it" is more true when it survives a restart, not less.
//
// `applications.seedInternal` turns the whole of this off. It is restart-only
// because it runs once, as `ldap_server.js` fills the directory slot above.
// ---------------------------------------------------------------------------

// Where this service answers, as a URL, at a moment when THERE IS NO REQUEST to
// read a Host header from — `helpers.js` and `vc_did.js` fall back to
// 'localhost:' + PORT at the same wall. It is a starting value and not a fact:
// a deployment behind a proxy wants its own name, and putting one there is an
// ldapmodify of oauthRedirectUri.
//
// **`global.publicBaseUrl` IS THAT NAME WHEN IT IS SET** (2026-09-12), with the
// ambient realm's prefix — `seedInternalApplications()` runs inside
// `realms.run()` for a realm being built, so the prefix is the realm's. That
// matters in product mode, where `common/oidc_rp.ts` no longer LEARNS a
// callback from a request: a seeded entry naming `localhost` would be a console
// nobody reaching the service by its real name could sign in to. Unset, this is
// the localhost starting value it always was, prefix and all left off, which is
// what development then learns past.
function internalBaseUrl() {
  log.debug("Entering internalBaseUrl().");
  const pinned = helpers.pinnedBaseUrl();
  if (pinned) {
    const realmBase = pinned + realms.currentPrefix();
    log.debug("Leaving internalBaseUrl(). base=" + realmBase + " " +
        "(global.publicBaseUrl)");
    return realmBase;
  }
  const scheme = config.value('global.https') ? 'https' : 'http';
  const base = scheme + '://localhost:' + config.value('global.port');
  log.debug("Leaving internalBaseUrl(). base=" + base);
  return base;
}

// ---------------------------------------------------------------------------
// THE EMBEDDED PROTOCOL DEBUGGER'S TWO ENTRIES (2026-09-13), seeded only in a
// process that embeds it (`mode.embedsProtocolDebugger()`), in the default
// realm only — its listener has no realm prefix, and the console roster that
// decides who may use it is the default realm's.
//
// **TWO ENTRIES AND NOT ONE, BECAUSE THEY ARE TWO PARTIES.** `sts-debugger-api`
// is a RESOURCE SERVER: it exposes one delegated permission and signs nobody
// in. `sts-debugger-ui` is the CLIENT a person signs in through, and it holds
// a grant of that permission — the mapping from an application to a
// permission another application exposes, in Microsoft Entra ID's shape
// (`common/app_permissions.ts`). The api row comes first because a permission
// is defined before it is granted.
//
// The identifiers and the permission are `debugger/debugger_access.ts`'s and
// are written out here rather than required: this file is a registry every
// module reads, and a require from it into a feature directory would make the
// registry depend on the feature. `tests/debugger_access.js` compares them.
//
// **THE PERMISSION CARRIES GLOBAL CONSENT** beside the three OpenID Connect
// scopes, for the reason the console's entry carries them: the person signing
// in to their own debugger would otherwise be asked whether they consent to
// it, which has one sensible answer.
// ---------------------------------------------------------------------------
function debuggerBaseUrl() {
  log.debug("Entering debuggerBaseUrl().");
  const pinned = String(config.value('debugger.publicBaseUrl') || '').trim()
    .replace(/\/+$/, '');
  if (pinned) {
    log.debug("Leaving debuggerBaseUrl(). base=" + pinned + " (pinned)");
    return pinned;
  }
  const scheme = config.value('global.https') ? 'https' : 'http';
  const base = scheme + '://localhost:' + config.value('debugger.port');
  log.debug("Leaving debuggerBaseUrl(). base=" + base);
  return base;
}

function debuggerApplications() {
  log.debug("Entering debuggerApplications().");
  if (!mode.embedsProtocolDebugger()) {
    log.debug("Leaving debuggerApplications(). The debugger is not embedded.");
    return [];
  }
  const base = debuggerBaseUrl();
  const issued = nowSec();
  const permission = 'urn:sts:debugger-api:debugger';
  log.debug("Leaving debuggerApplications().");
  return [
    { identifier: 'sts-debugger-api',
      name: 'Protocol debugger api',
      kinds: ['oauth2-client'],
      protocols: ['OAuth 2.0'],
      realmScope: 'default',
      description: 'seeded at startup: the embedded protocol debugger\'s ' +
                   'api, the resource server behind ' + base + '/api ' +
                   '(debugger.enabled)',
      attributes: {
        oauthPermissionBaseUri: 'urn:sts:debugger-api:',
        oauthPermission: ['debugger|Use the identity protocol debugger and ' +
                          'its api']
      },
      // A resource server authenticates at no endpoint here, so the
      // registration names no grant and no redirect: the row exists to
      // DEFINE the permission, which is what makes the UI's grant of it a
      // grant of something.
      registration: {
        client_id: 'sts-debugger-api',
        client_name: 'Protocol debugger api',
        client_id_issued_at: issued,
        client_secret: randomId(24),
        client_secret_expires_at: 0,
        registration_access_token: randomId(24),
        registration_client_uri: internalBaseUrl() +
                                 '/oauth2/register/sts-debugger-api',
        client_uri: base + '/api',
        application_type: 'web',
        redirect_uris: [],
        grant_types: [],
        response_types: [],
        scope: '',
        token_endpoint_auth_method: 'client_secret_basic'
      } },
    { identifier: 'sts-debugger-ui',
      name: 'Protocol debugger',
      kinds: ['oauth2-client', 'oidc-relying-party'],
      protocols: ['OAuth 2.0 / OIDC'],
      realmScope: 'default',
      description: 'seeded at startup: the embedded identity protocol ' +
                   'debugger at ' + base + ' (debugger.enabled)',
      attributes: {
        oauthDelegatedPermission: [permission],
        oauthGlobalConsent: ['openid', 'profile', 'email', 'offline_access',
                             permission]
      },
      registration: {
        client_id: 'sts-debugger-ui',
        client_name: 'Protocol debugger',
        client_id_issued_at: issued,
        registration_access_token: randomId(24),
        registration_client_uri: internalBaseUrl() +
                                 '/oauth2/register/sts-debugger-ui',
        client_uri: base + '/',
        application_type: 'web',
        redirect_uris: [base + '/_sts/callback'],
        post_logout_redirect_uris: [base + '/'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: 'openid profile email offline_access ' + permission,
        token_endpoint_auth_method: 'private_key_jwt'
      } }
  ];
}

// THE CLIENTS THIS SERVICE'S OWN HOSTED SURFACES SIGN IN AS — the three rows
// above and below, by identifier, and `common/oidc_rp.ts`'s SURFACES by
// clientId (`tests/oidc_core_units.js` holds the two lists equal). Each is
// granted `offline_access` by the register's own global consent (#118): a
// surface's session is meant to outlive the sign-on session RUNNING OUT, which
// is what OIDC Core section 11 says the scope is for. What a SIGN-OUT does is
// different, and `authn.ts` reads this list to revoke these clients' refresh
// tokens with the session anyway: the relying-party session holding each one
// ends in the same cascade, so the token is nobody's any more.
const HOSTED_SURFACE_CLIENT_IDS = Object.freeze(['sts-admin-console',
  'sts-user-portal', 'sts-debugger-ui']);

// The rows, built fresh on each call because each carries a credential that is
// generated rather than declared — a registration access token, and a client
// secret for the management API alone: the three hosted surfaces authenticate
// by private_key_jwt with a key `oidc_rp.ts` has issued (#138).
function internalApplications() {
  log.debug("Entering internalApplications().");
  const base = internalBaseUrl();
  const issued = nowSec();
  const rows = [
    { identifier: 'sts-admin-console',
      name: 'Admin console',
      kinds: ['oauth2-client', 'oidc-relying-party'],
      protocols: ['OAuth 2.0 / OIDC'],
      // EVERY REALM SINCE 2026-09-11, AND IT WAS THE DEFAULT REALM AND NOWHERE
      // ELSE. The old comment read: *the console's gate reads the default
      // realm's session in every realm, so one entry is the whole of what it
      // needs and one per realm would be a client nothing signs in to.* The
      // first clause is still exactly true — `oidc_rp.js`'s `sessionRealm` for
      // this surface is `default`, so one console session is still found by the
      // gate from every realm — and the conclusion stopped following when the
      // console's CODE FLOW moved to the ambient realm.
      //
      // It moved so that `/realm/acme/admin` and `/realm/acme/portal` share a
      // sign-on session: the authorization endpoint can only answer out of the
      // realm it is reached in, so a console authorizing in the default realm
      // meant two sign-ins for one person in one browser. That flow presents
      // `client_id=sts-admin-console` at `/realm/acme/oauth2/authorize`, and an
      // authorization server has to be able to find the client — so the entry
      // has to be there. The last clause of the old comment is therefore
      // reversed: a realm WITHOUT this entry is the one nothing can sign in to.
      //
      // **THIS IS NOT WHAT MAKES SOMEBODY AN ADMINISTRATOR.** The client is
      // what the flow authenticates AS; the ROLE is read by `admin_rbac.js` —
      // the default realm's `ou=groups` for the service roster, the realm's
      // own for its administrators (2026-09-14, #32), who are confined to that
      // realm. Somebody who creates a realm gets a client entry in it and no
      // access outside it.
      realmScope: 'every',
      description: 'seeded at startup: this service\'s own admin console at ' +
                   '/admin (applications.seedInternal)',
      attributes: { oauthGlobalConsent: ['openid', 'profile', 'email',
                                         'offline_access'] },
      registration: {
        client_id: 'sts-admin-console',
        client_name: 'Admin console',
        client_id_issued_at: issued,
        registration_access_token: randomId(24),
        registration_client_uri: base + '/oauth2/register/sts-admin-console',
        client_uri: base + '/admin',
        application_type: 'web',
        redirect_uris: [base + '/admin/callback'],
        post_logout_redirect_uris: [base + '/admin'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        // `admin:read admin:write` (#110): the API explorer mints the reader
        // a token as this client, carrying the scopes their console roles
        // grant, and /admin-api asks whether the client declared them.
        scope: 'openid profile email offline_access admin:read admin:write',
        token_endpoint_auth_method: 'private_key_jwt'
      } },
    // THE USER PORTAL, ADDED 2026-09-06 WITH THE MOVE ONTO THE CODE FLOW. It
    // was the admin console's row with one difference, `realmScope: 'every'`,
    // argued against a console seeded in the default realm only; the console's
    // row is `every` too since 2026-09-11 (its own comment says why). The
    // portal's reason stands on its own: `/portal` reads the AMBIENT realm's
    // session, a person in `acme` is a different person from the one in the
    // default realm, and a realm whose portal had no client could not sign
    // anybody in at all.
    { identifier: 'sts-user-portal',
      name: 'User portal',
      kinds: ['oauth2-client', 'oidc-relying-party'],
      protocols: ['OAuth 2.0 / OIDC'],
      realmScope: 'every',
      description: 'seeded at startup: this service\'s own user portal at ' +
                   '/portal (applications.seedInternal)',
      // GLOBAL CONSENT, SEEDED, AND IT IS THE ONE DECISION ON THIS ROW WORTH
      // ARGUING. `oauth2.consentRequired` is ON by default and is the only
      // policy here that is, so without this a person signing in to look at
      // their own account would first be asked whether they consent to this
      // service reading their own profile — a question with one sensible
      // answer, asked in front of every sign-in, whose Deny button makes the
      // portal unreachable. It is an ATTRIBUTE rather than an exemption in
      // `consent.js`: the entry is the register, so an operator who wants the
      // screen removes the values and gets it, which is what makes this a
      // default rather than a special case.
      attributes: { oauthGlobalConsent: ['openid', 'profile', 'email',
                                         'offline_access'] },
      registration: {
        client_id: 'sts-user-portal',
        client_name: 'User portal',
        client_id_issued_at: issued,
        registration_access_token: randomId(24),
        registration_client_uri: base + '/oauth2/register/sts-user-portal',
        client_uri: base + '/portal',
        application_type: 'web',
        redirect_uris: [base + '/portal/callback'],
        post_logout_redirect_uris: [base + '/portal'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: 'openid profile email offline_access',
        token_endpoint_auth_method: 'private_key_jwt'
      } },
    { identifier: 'sts-management-api',
      name: 'Management API',
      kinds: ['oauth2-client'],
      protocols: ['OAuth 2.0'],
      // EVERY REALM SINCE 2026-09-14 (#32), and it was the default realm only.
      // A trust realm has administrators of its own now, and rule 7 owes each
      // of them the machine door to their realm: a token this realm's
      // authorization server issues to this realm's copy of the client works
      // at `/realm/<id>/admin-api` and nowhere else, and never at a
      // service-wide operation (`mgmt-api/admin_api.ts`'s gate and
      // `admin-ui/admin_scope.ts`). The default realm's copy is still the
      // service's and works everywhere.
      realmScope: 'every',
      description: 'seeded at startup: this service\'s own management API at ' +
                   '/admin-api (applications.seedInternal)',
      registration: {
        client_id: 'sts-management-api',
        client_name: 'Management API',
        client_id_issued_at: issued,
        // CONFIGURED WHERE THERE IS ONE, and minted otherwise. Since
        // `/admin-api` began requiring an access token, a secret that is
        // regenerated on every start is a bootstrap hole rather than a
        // convenience: it is readable only THROUGH the API it unlocks, so a
        // restart would leave nobody able to get a token.
        // `adminApi.clientSecret` is how a deployment — and every test launcher
        // — pins it.
        // The PINNED secret is the default realm's alone (2026-09-14, #32): a
        // realm's copy is a different client, and one secret opening every
        // realm's management API would be one credential for every realm.
        client_secret: (realms.isDefault() &&
                        String(config.value('adminApi.clientSecret') || '')) ||
                       randomId(24),
        client_secret_expires_at: 0,
        registration_access_token: randomId(24),
        registration_client_uri: base + '/oauth2/register/sts-management-api',
        client_uri: base + '/admin/api-explorer',
        application_type: 'web',
        // NO redirect URI and no response type: this one is a back-channel
        // client on client_credentials, and a redirect URI on it would be a
        // registration saying it can do a flow it cannot.
        redirect_uris: [],
        grant_types: ['client_credentials'],
        response_types: [],
        scope: 'admin:read admin:write',
        token_endpoint_auth_method: 'client_secret_basic'
      } }
  ].concat(/** @type {any} */ (debuggerApplications()));
  log.debug("Leaving internalApplications(). " + rows.length + " row(s).");
  return rows;
}

// One of them. Returns whether an entry was CREATED, which is not the same as
// whether all is well: an identifier already in the registry is the ordinary
// outcome of an operator having made one by hand, and it is left exactly as it
// is rather than overwritten.
function seedInternalApplication(spec) {
  log.debug("Entering seedInternalApplication(). identifier=" +
            spec.identifier);
  const loaded = load(spec.identifier);
  if (loaded.known) {
    log.debug("Leaving seedInternalApplication(). It is already here and was " +
              "left alone.");
    return false;
  }
  const record = loaded.record;
  const now = Date.now();
  record.registered = true;
  setField(record, 'appRegisteredBy', 'startup');
  record.firstAt = now;
  record.lastAt = now;
  record.name = spec.name;
  spec.kinds.forEach(function (kind) {
    addTo(record.kinds, kind);
  });
  spec.protocols.forEach(function (protocol) {
    addTo(record.protocols, protocol);
  });
  addTo(record.descriptions, spec.description);
  applyRegistrationFields(record, spec.registration);
  // ANYTHING THAT IS NOT AN RFC 7591 MEMBER, and today that is one attribute:
  // `oauthGlobalConsent`. It goes through `setField()` like every other write
  // here, so a name that is not in the schema is REFUSED with a warning rather
  // than written as an attribute nothing publishes — which is the check that
  // makes a typo here visible instead of quietly producing a client that
  // prompts for consent forever.
  Object.keys(spec.attributes || {}).forEach(function (name) {
    setField(record, name, spec.attributes[name]);
  });
  if (!save(record)) {
    log.warn(errorCodes.tag('STS-REG-0020') +
             'applications: "' + spec.identifier + '" was not seeded — the ' +
             'ou=applications container is full (applications.max) or the ' +
             'directory is. Nothing else is affected; the surface it names ' +
             'answers exactly as it did.');
    log.debug("Leaving seedInternalApplication(). The container would not " +
              "take it.");
    return false;
  }
  // The same row an RFC 7591 registration writes, with the channel saying
  // where it came from. NO CREDENTIAL IS NAMED — audit.js's rule, and this is
  // one of the two places in this module that holds one.
  audit.audit({
    action: 'application.create', actor: '', protocol: 'internal',
    channel: 'internal', target: spec.identifier,
    summary: 'Application "' + spec.identifier + '" was seeded at startup (' +
             spec.name + ')',
    detail: { identifier: spec.identifier, kinds: spec.kinds.join(', '),
              registered: true, seeded: true }
  });
  log.debug("Leaving seedInternalApplication(). Created.");
  return true;
}

// Called by `ldap_server.js` the moment it has filled setDirectory() — which is
// the earliest point at which there is a container to write into, and the
// latest at which the entries are there before anything can ask for them.
function seedInternalApplications(options) {
  log.debug("Entering seedInternalApplications(). scope=" +
            String((options || {}).scope || 'default'));
  if (!config.value('applications.seedInternal')) {
    log.info('applications: the console and the management API were not ' +
             'seeded as applications; applications.seedInternal is off.');
    log.debug("Leaving seedInternalApplications(). The setting is off.");
    return 0;
  }
  if (!store()) {
    log.warn(errorCodes.tag('STS-REG-0002') +
             'applications: the console and the management API were not ' +
             'seeded — there is no directory in this process, so there is no ' +
             'ou=applications container to put them in. See store().');
    log.debug("Leaving seedInternalApplications(). There is no directory.");
    return 0;
  }
  // WHICH OF THEM BELONG IN THE REALM BEING SEEDED. `scope` is 'default' when
  // this is the process starting up and 'every' when a trust realm is being
  // built, and each row says which realms it belongs in — see the rows
  // themselves, where the answers are argued separately rather than
  // together. A realm gets the console's, the portal's and the management
  // API's clients; the embedded debugger's two stay in the default realm.
  const wanted = String((options || {}).scope || 'default');
  const rows = internalApplications().filter(function (one) {
    return wanted === 'default' || one.realmScope === 'every';
  });
  let made = 0;
  rows.forEach(function (one) {
    if (seedInternalApplication(one)) made++;
  });
  log.info('applications: ' + made + ' of this service\'s own ' + rows.length +
           ' application(s) were seeded' +
           (wanted === 'default' ? '' : ' into this realm') +
           '. They are ORDINARY entries — edit one, or delete it, and it ' +
           'stays that way until a restart.');
  log.debug("Leaving seedInternalApplications(). " + made + " created.");
  return made;
}

module.exports = {
  HOSTED_SURFACE_CLIENT_IDS: HOSTED_SURFACE_CLIENT_IDS,
  issuedJwtKeyPairValues: issuedJwtKeyPairValues,
  storeIssuedJwtKeyPair: storeIssuedJwtKeyPair,
  frontchannelOriginProblem: frontchannelOriginProblem,
  requiredRolesOf: requiredRolesOf,
  requiresNarrowedRoles: requiresNarrowedRoles,
  KINDS: KINDS,
  KIND_IDS: KIND_IDS,
  // The DECLARED protocol vocabulary, exported whole rather than as a list of
  // ids: the console draws a checkbox per row from the label and the prose, the
  // management API turns the ids into an `enum` in its document, and both read
  // one table — which is what stops a form offering a family the create would
  // refuse, the same property editableAttributes() gives the two edit selects.
  PROTOCOLS: PROTOCOLS,
  PROTOCOL_IDS: PROTOCOL_IDS,
  protocolRow: protocolRow,
  // The kind-to-family translation, exported because the pages compare the
  // declared list with what happened and a second copy of that map would be a
  // second answer to "has this family ever been seen".
  protocolIdsForKinds: protocolIdsForKinds,
  normaliseProtocols: normaliseProtocols,
  // The identifier and redirect-URI attributes the create form is built from,
  // deduped by attribute and carrying the families each one serves. One walk of
  // the PROTOCOLS table serves the console's fields and the management API's
  // document, so neither can offer a field the other has never heard of.
  declarationAttributes: declarationAttributes,
  DECLARATION_ATTRIBUTE_NAMES: DECLARATION_ATTRIBUTE_NAMES,
  // What an application answers to in each family, with the protocol's own
  // word for it. Exported for the delegation pictures — see its header for why
  // the list is built here and not in the renderer.
  identifiersOf: identifiersOf,
  // THE HOME PAGE, and the rule its value obeys. Both exported: the portal
  // READS it and the two write doors REFUSE a value nothing may link to, and a
  // second spelling of "http or https" in the page would be the second opinion
  // this module exists to prevent.
  homePageOf: homePageOf,
  homePageProblem: homePageProblem,
  // THE CORS ORIGINS (2026-09-13): the one entry's list, the entry a request
  // named, and the realm's union — the three questions `common/cors.js` asks.
  corsOriginsOf: corsOriginsOf,
  corsOriginsForClient: corsOriginsForClient,
  ssfAllowedEventsFor: ssfAllowedEventsFor,
  corsOriginsOfRealm: corsOriginsOfRealm,
  ssfAllowedEventProblem: ssfAllowedEventProblem,
  // THE SEALED ATTRIBUTE AND THE PREFIX TEST THAT RECOGNISES ONE. Exported for
  // `admin-ui/admin.ts`, whose application page dumps `attributes` — the entry
  // as the directory holds it — and therefore meets the ciphertext. It shows
  // the opened value from `fields` beside a note saying the store holds it
  // encrypted, which is the one place the two halves of view() are drawn
  // together. `/admin/ldap/applications` deliberately does NOT do that: that
  // page is headed "the registry as the directory sees it", and an opened
  // value there would be a page lying about its own subject.
  SEALED_FIELDS: SEALED_FIELDS,
  WITHHELD_FIELDS: WITHHELD_FIELDS,
  withholdFields: withholdFields,
  isSealed: isSealed,
  normaliseFields: normaliseFields,
  SCHEMA: SCHEMA,
  seen: seen,
  register: register,
  updateRegistration: updateRegistration,
  softwareStatementFactsOf: softwareStatementFactsOf,
  forgetRegistration: forgetRegistration,
  registrationOf: registrationOf,
  clientConfigOf: clientConfigOf,
  registrationUriProblem: registrationUriProblem,
  // RFC 9701 section 6 — the check, the tables it checks against, and which
  // attribute holds which member. `oauth-oidc/introspection_jwt.ts` and the
  // registration endpoint read them; nothing else should keep a copy.
  introspectionResponseProblem: introspectionResponseProblem,
  idTokenEncryptionMetadataProblem: idTokenEncryptionMetadataProblem,
  ID_TOKEN_DEFAULT_ENC: ID_TOKEN_DEFAULT_ENC,
  ID_TOKEN_ENCRYPTION_ALGS: ID_TOKEN_ENCRYPTION_ALGS,
  ID_TOKEN_ENCRYPTION_ENCS: ID_TOKEN_ENCRYPTION_ENCS,
  INTROSPECTION_ATTRIBUTES: INTROSPECTION_ATTRIBUTES,
  INTROSPECTION_DEFAULT_SIGNING_ALG: INTROSPECTION_DEFAULT_SIGNING_ALG,
  INTROSPECTION_DEFAULT_ENC: INTROSPECTION_DEFAULT_ENC,
  INTROSPECTION_SIGNING_ALGS: INTROSPECTION_SIGNING_ALGS,
  INTROSPECTION_ENCRYPTION_ALGS: INTROSPECTION_ENCRYPTION_ALGS,
  INTROSPECTION_ENCRYPTION_ENCS: INTROSPECTION_ENCRYPTION_ENCS,
  // RFC 9101 — the check, its tables, and which attribute holds which member.
  // `oauth-oidc/request_object.ts` and the registration endpoint read them.
  requestObjectMetadataProblem: requestObjectMetadataProblem,
  oidcSubjectMetadataProblem: oidcSubjectMetadataProblem,
  OIDC_SUBJECT_ATTRIBUTES: OIDC_SUBJECT_ATTRIBUTES,
  pushedAuthorizationMetadataProblem: pushedAuthorizationMetadataProblem,
  pushedAuthorizationAttributeProblem: pushedAuthorizationAttributeProblem,
  mtlsMetadataProblem: mtlsMetadataProblem,
  mtlsAttributeProblem: mtlsAttributeProblem,
  TLS_SUBJECT_ATTRIBUTES: TLS_SUBJECT_ATTRIBUTES,
  TLS_BOUND_TOKENS_ATTRIBUTE: TLS_BOUND_TOKENS_ATTRIBUTE,
  // RFC 9396 — what an entry may say about authorization_details, and the
  // definition reader `oauth-oidc/authorization_details.ts` uses.
  AUTHORIZATION_DETAILS_BUILT_IN: AUTHORIZATION_DETAILS_BUILT_IN,
  authorizationDetailsTypeOf: authorizationDetailsTypeOf,
  authorizationDetailsLocationProblem: authorizationDetailsLocationProblem,
  authorizationDetailsTypeNameProblem: authorizationDetailsTypeNameProblem,
  authorizationDetailsMetadataProblem: authorizationDetailsMetadataProblem,
  authorizationDetailsAttributeProblem: authorizationDetailsAttributeProblem,
  stepUpAttributeProblem: stepUpAttributeProblem,
  stepUpRequirementOf: stepUpRequirementOf,
  audienceNamesEntry: audienceNamesEntry,
  requestUriProblem: requestUriProblem,
  REQUEST_OBJECT_ATTRIBUTES: REQUEST_OBJECT_ATTRIBUTES,
  REQUEST_OBJECT_DEFAULT_ENC: REQUEST_OBJECT_DEFAULT_ENC,
  REQUEST_OBJECT_SIGNING_ALGS: REQUEST_OBJECT_SIGNING_ALGS,
  REQUEST_OBJECT_ENCRYPTION_ALGS: REQUEST_OBJECT_ENCRYPTION_ALGS,
  REQUEST_OBJECT_ENCRYPTION_ENCS: REQUEST_OBJECT_ENCRYPTION_ENCS,
  recordAuthentication: recordAuthentication,
  setDirectory: setDirectory,
  // For a test that stubs the slot and has to put back what was there. See
  // directoryInstalled().
  directoryInstalled: directoryInstalled,
  // The two conversions, exported because ldap_server.js seeds and reads
  // entries with them and this module owns the schema they encode.
  attributesFor: attributesFor,
  recordFromAttributes: recordFromAttributes,
  labelFor: labelFor,
  editableAttributes: editableAttributes,
  // The family scope, exported so that the console can leave a field out of the
  // two selects on an entry the action would refuse it on — "a form cannot
  // offer a field the action would refuse", which is the rule
  // editableAttributes() itself exists for. Both halves come off the SCHEMA
  // row's `families` member.
  declaredFamiliesOf: declaredFamiliesOf,
  familyRefusal: familyRefusal,
  createApplication: createApplication,
  seedInternalApplications: seedInternalApplications,
  updateApplication: updateApplication,
  regenerateClientSecret: regenerateClientSecret,
  rotateClientSecret: rotateClientSecret,
  sweepClientSecrets: sweepClientSecrets,
  secretExpiryOf: secretExpiryOf,
  mintClientSecret: mintClientSecret,
  KEY_SOURCES: KEY_SOURCES,
  KEY_SOURCE_ATTRIBUTES: KEY_SOURCE_ATTRIBUTES,
  KEY_PAIR_ATTRIBUTES: KEY_PAIR_ATTRIBUTES,
  // THE PROVENANCE OF A RETURN ADDRESS (2026-09-12). `returnAddressesOf()` is
  // the one decision every return-address check asks — both SAML profiles,
  // WS-Federation and `clientConfigOf()` — and the two actions are what an
  // operator does with an address it withholds. See the block above
  // observedMarkFor().
  RETURN_ADDRESS_ATTRIBUTES: RETURN_ADDRESS_ATTRIBUTES,
  OBSERVED_ADDRESS_ATTRIBUTE: OBSERVED_ADDRESS_ATTRIBUTE,
  returnAddressesOf: returnAddressesOf,
  observedReturnAddresses: observedReturnAddresses,
  confirmReturnAddress: confirmReturnAddress,
  // THE SAML SIGNING-CERTIFICATE PAIR AND METADATA CONSUMPTION (2026-09-17,
  // #37). See the functions.
  confirmSigningCertificate: confirmSigningCertificate,
  discardSigningCertificate: discardSigningCertificate,
  replaceSamlMetadataFields: replaceSamlMetadataFields,
  samlCertificateBase64: samlCertificateBase64,
  samlCertificateProblem: samlCertificateProblem,
  SAML_METADATA_FIELDS: SAML_METADATA_FIELDS,
  discardReturnAddress: discardReturnAddress,
  deleteApplication: deleteApplication,
  list: list,
  get: get,
  settingFor: settingFor,
  largestSetting: largestSetting,
  overridableSettings: overridableSettings,
  // The audience lookup, exported for the token endpoint. See its header for
  // why it is a lookup and not a check.
  forAudience: forAudience,
  // The client_id lookup beside it, exported for oauth2.js's audienceScopes().
  // Two lookups rather than one that tries both — see forClientId()'s header.
  forClientId: forClientId,
  // And the WS-Trust / SAML spelling of forAudience(), exported for
  // wstrust.js's delegation act. Its header says why it reads two attributes
  // where the other two read one.
  forAppliesTo: forAppliesTo,
  // ---------------------------------------------------------------------------
  // THE DELEGATED PERMISSION HALF. Everything a reader of ONE entry needs; what
  // needs two entries is common/app_permissions.ts, which requires this module
  // and is where the register, the actions and the picture live.
  //
  // `permissionIdOf()` and `permissionBaseOf()` are exported rather than kept
  // private because base + name is composed in four places — this module's
  // lookups, that module's register, the console's tables and the token
  // endpoint — and four spellings of a concatenation is four chances for
  // `https://example.comwrite`.
  // ---------------------------------------------------------------------------
  permissionBaseOf: permissionBaseOf,
  permissionIdOf: permissionIdOf,
  parsePermissionValue: parsePermissionValue,
  permissionValueOf: permissionValueOf,
  permissionNameProblem: permissionNameProblem,
  // The RFC 6749 section 3.3 grammar on its own, for common/consent.ts — see
  // the block above it for why the schema owner owns this rule.
  scopeTokenProblem: scopeTokenProblem,
  permissionBaseProblem: permissionBaseProblem,
  permissionsOf: permissionsOf,
  // The fourth lookup, exported for oauth2.js's audienceScopes(). Its header
  // says why the match is exact rather than a prefix test on the base.
  forPermission: forPermission,
  // The FIFTH, exported for user_graph.js's `permissionsAddressedTo()`. Its
  // header says why the four above it cannot answer the question it answers —
  // an ISSUED token carries the base URI and nothing else.
  forPermissionBase: forPermissionBase,
  // And the question the lookup deliberately does not answer: whether the
  // client asking has been GRANTED what it is naming.
  holdsPermission: holdsPermission,
  allowedScopesOf: allowedScopesOf,
  count: count,
  containerDn: containerDn,
  maxApplications: maxApplications
};
