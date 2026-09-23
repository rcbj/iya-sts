// @ts-check
'use strict';
//
// File: federation.js
//
// ===========================================================================
// EVERY FEDERATION RELATIONSHIP THIS SERVICE HAS BEEN CONFIGURED WITH.
//
// A federation relationship is a protocol relationship — a SAML 2.0 assertion,
// a WS-Federation sign-in response, an OpenID Connect ID Token — with ONE fact
// added that changes what has to be true of it: the party on the other end is
// SOMEBODY ELSE'S IDENTITY SERVICE. Every other relationship this service has
// is with a client, and the whole premise of this repository is that a client
// gets whatever it asks for. A federation partner is the opposite case in both
// directions:
//
//   * WHERE THIS SERVICE IS THE SERVICE PROVIDER it CONSUMES an assertion it
//     did not mint, from a signer whose key it does not hold, naming a person
//     it has never heard of. There is nothing here that can be permissive
//     about: an assertion this service cannot verify is not a permissive
//     acceptance, it is an unauthenticated request with XML attached. So this
//     is the one register in this repository that must be CONFIGURED BEFORE IT
//     WILL DO ANYTHING, and every relationship starts disabled.
//
//   * WHERE THIS SERVICE IS THE IDENTITY PROVIDER the partner is a foreign
//     service provider rather than a test client somebody wrote, and what a
//     real federation configures per-partner is WHICH ATTRIBUTES ARE RELEASED
//     TO IT. That is the whole of the identity-provider half here, and it is
//     deliberately narrow — see THE RELEASE FILTER below.
//
// ---------------------------------------------------------------------------
// WHY THIS CANNOT BE MOCKED, WHICH IS THE ONE PLACE THIS FEATURE ARGUES WITH
// THE REST OF THE SERVICE.
//
// `README.md` and every directory `CLAUDE.md` here say the same thing: this
// service checks no password, validates no access token and attests no
// workload. Three surfaces are already the exception (SCIM, the SPIRE Server
// API, the admin console) and each has its argument written down. This is the
// FOURTH, and its argument is different from all three of theirs.
//
// Those three REFUSE a caller in order to make a client exercise a refusal.
// This one refuses because THERE IS NO PERMISSIVE ANSWER AVAILABLE. "Accept
// any SAML Response" does not mean "be generous", it means "let anybody who
// can reach this port POST a document naming themselves as anybody and get a
// session for it" — and the session is the one this service's OAuth2, SAML,
// WS-Federation and console surfaces all read. The permissive version of this
// feature is not a mock of federation; it is a hole underneath every other
// protocol here.
//
// So the shape of the exception is: **a relationship must be configured, and
// what it configures is a KEY** — AND, SINCE #109 (2026-09-22), WHICH PEOPLE
// THAT KEY MAY SIGN IN. A verified assertion signs in only the person its
// subject is LINKED to (`federationLink`, `federation_links.ts`), and what
// happens to a subject nobody linked is `fedSubjectPolicy`'s: a local sign-in
// as the person it names before the link is made (the default), a refusal, a
// new namespaced entry, or — development only — the old name match. The gate
// was on the SIGNER alone until then, which let any partner whose signature
// verified sign in any local account it could name, `admin` included.
//
// ---------------------------------------------------------------------------
// ONE RELATIONSHIP IS ONE DIRECTION, AND THAT IS A DECISION.
//
// A partner this service both consumes from and asserts to is TWO
// relationships, not one record with two halves. Everything that configures a
// relationship differs by direction — the endpoints are theirs or ours, the
// certificate is theirs or ours, the attribute mapping runs inbound or the
// release list runs outbound — so a single record would need two of each field
// and every page and every form would have to say which half it meant. Two
// records with two ids says it once, in the `fedRole` attribute, and the
// console lists them side by side.
//
// ---------------------------------------------------------------------------
// THE STORE IS THE DIRECTORY, exactly as `../common/applications.js`'s is.
//
// `ou=federations,<base>` IS the register. There is no Map in this file
// shadowing it; every function below is a directory read or write. That gives
// an `ldapmodify` for free — changing `fedSigningCertificate` on an entry
// changes which signer the next assertion is verified against — and it is the
// same one-store rule that keeps the RFC 7591 registrations in
// `ou=applications` rather than in a second map inside `oauth2.js`.
//
// **WHAT IT DELIBERATELY DOES NOT HOLD is anything the applications registry
// already holds.** An identity-provider-side relationship names an application
// by its identifier (`fedApplication`) and stops. That partner's entityID, its
// assertion consumer service, its redirect URIs and its signing certificate
// are on the `ou=applications` entry, where every protocol module already reads
// them — copying them here would be the two-stores failure this whole
// repository is arranged to avoid, and the copy would be the one an operator
// edited.
//
// The service-provider side is the opposite case and holds everything, because
// there is nothing on the other side to hold it: the partner is a foreign
// identity provider, and a foreign identity provider is not an application.
// `ou=applications` is "what this service has been ASKED ABOUT" — a party that
// asks this service for nothing has no business being in it.
//
// ---------------------------------------------------------------------------
// THE RELEASE FILTER, AND WHY IT IS NARROW ON PURPOSE.
//
// `releaseFilterFor(context)` is consulted by `admin_stats.js` at its two
// existing funnels — `jwtClaims()` and `samlAttributes()` — and by nothing
// else. What it can remove is exactly what those two functions ADD: the typed
// claims, the directory-attribute claims and the groups claim. It cannot
// remove `sub`, `iss`, `exp`, a NameID or anything else a protocol module puts
// in a token itself, and that is not a limitation to fix later:
//
//   * those are the protocol's own, not attributes about a person, and a
//     partner-specific `exp` is a lifetime rather than a release rule;
//   * every one of them is what makes the artifact verifiable at all, so a
//     release list that could drop `iss` would be a form producing assertions
//     that fail to verify with nothing pointing back at the page — which is the
//     exact argument `setClaimSet()` already makes for refusing the reserved
//     names on the way IN.
//
// A relationship with NO release list declared filters nothing. That is the
// difference between "release nothing to this partner" and "this partner has
// no release policy", and they must not be the same state: the second is what
// every partner is on the day it is created, and treating it as the first
// would mean registering a partner silently stopped it receiving the
// attributes it received the day before.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND ITS DIRECTORY HALF IS INVERTED (rule 6).
//
// It registers no route. It requires `helpers.js`, `config.js`, `realms.js`,
// `audit.js`, `error_codes.js` and `applications.js` (below) and nothing else
// in this repository — none of which registers a route or reaches back here —
// which is what lets `admin_stats.js`, `authn/authn.ts`, `admin-ui/admin.ts`,
// `admin-core/`, `ldap_server.js`, `federation_graph.js` and
// `federation_sp.js` all require it in the ordinary direction with no cycle
// and no route moved. Do not let it grow a require of anything that registers
// a route.
//
// The DIRECTORY half is inverted for `applications.js`'s reason:
// `ldap_server.js` is near the end of the require order because requiring it
// pulls every `/ldap` route into the router at that point, and a module the
// sign-in screen reads cannot drag those routes to the front. So this file
// offers `setDirectory()` and that module fills it at ITS require time.
//
// The division of labour is the same one and worth keeping: THIS module owns
// the SCHEMA and both conversions, and that module owns the directory
// mechanics — where the container is, how an entry is created, what the cap is.
//
// ---------------------------------------------------------------------------
// THE CLIENT SECRET AND THE CERTIFICATE ARE STORED, AND THEY ARE NOT THE SAME
// KIND OF THING.
//
// `fedClientSecret` is OUR credential AT THE PARTNER — a real secret at a real
// foreign service, which is a stronger statement than anything else in this
// directory: `oauthClientSecret` is a secret this service minted for a mock
// client and can mint again, and this one is not ours to regenerate. It is
// held in the clear for the reason that attribute's header gives, it is marked
// `sensitive` so no page prints it and no audit row carries it, and the honest
// consequence is stated here rather than buried: anybody who can read this
// directory can authenticate as this service at that partner. A deployment
// that federates with something real should say so out loud.
//
// `fedSigningCertificate` is the opposite — the partner's PUBLIC key, worth
// nothing to whoever reads it, and it is the single most important attribute
// on a service-provider-side entry because it is the ONE thing standing
// between this service and the hole described at the top of this file.
// ===========================================================================

const crypto = require('crypto');
const config = require('./../common/config');
const { log, nowSec, randomId } = require('./../common/helpers');
// The release index below is per trust realm. A LEAF requiring only `config`,
// so rule 3o's "requires nothing heavier" stays true.
const realms = require('./../common/realms');
const audit = require('./../common/audit');
// The error-code registry, a leaf. See actionRefused() below for why a refused
// change to the register carries its code on an audit row and not on its
// result.
const errorCodes = require('./../common/error_codes');
const cacheRegistry = require('./../common/cache_registry');
// ---------------------------------------------------------------------------
// THE APPLICATIONS REGISTRY, AND WHY THIS MODULE MAY REQUIRE IT (rule 3o, read
// the other way round).
//
// Rule 3o is about who may require THIS file. This is the one require going the
// other way, and it is a plain one in the ordinary direction rather than a
// slot: `applications.js` registers no route, and none of what it requires
// (`config.js`, `helpers.js`, `realms.js`, `audit.js`, `roles.js`,
// `keystore.js` and leaves) reaches back here — so nothing about requiring it
// can close a cycle or move a route. Rule 3e's test is not
// reached, and a slot would have cost a reader an indirection for nothing. It
// is the same argument `admin_stats.js` makes above its own require of that
// file.
//
// WHAT IT IS FOR IS ONE QUESTION AND ONLY ONE: *is this application actually
// configured to authenticate through this relationship, right now?* — asked at
// the moment a use is recorded, so that `fedApplicationUse` below cannot be
// grown by anybody who can reach `/federation/login/{id}` with an `application`
// of their choosing. See applicationConfiguredFor().
// ---------------------------------------------------------------------------
const applications = require('./../common/applications');
// `any-existing` is refused in product (#109): a relationship may not be SET to
// it there. A leaf over config.js; it requires nothing here back.
const mode = require('./../common/mode');

// ---------------------------------------------------------------------------
// THE TWO ROLES. Which end of the relationship THIS SERVICE is.
//
// Named for what this service does rather than for what the partner does,
// because every page and every log line here is written from this service's
// point of view and "identity provider" meaning "them" on one screen and "us"
// on the next is the ambiguity this vocabulary exists to remove.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE PATHS, HERE RATHER THAN IN `federation_sp.js` WHERE THEY ARE SERVED.
//
// Three things need them and only one of them may require that module.
// `federation_sp.js` registers routes, so `admin-ui/admin.ts` must not require
// it — `common/protocol_stack.ts` loads that module BEFORE the console, and a
// require in the other direction would be the reason a route moved the day
// somebody reorders the two (the line already drawn around
// `spiffe_server.js`). But the console page's whole job is to tell an operator
// WHICH URL to configure at the partner, so it has to know.
//
// So the strings live in the library both sides may reach, and neither writes
// them out. A console printing `/federation/acs/x` while the router serves
// `/federation/callback/x` is the single most expensive mistake this feature
// could make: the person configures the wrong URL at the partner, signs in
// successfully somewhere else, and lands on a 404 with nothing to point at.
// ---------------------------------------------------------------------------
const PATHS = {
  base: '/federation',
  login: '/federation/login',
  acs: '/federation/acs',
  metadata: '/federation/metadata',
  // Where the local sign-in of `link-at-first-sign-in` returns to (#109).
  link: '/federation/link',
  // A PARTNER'S SIGN-OUT (#167). `slo` is the one path every browser-borne
  // sign-out arrives at — a SAML LogoutRequest or LogoutResponse, a
  // WS-Federation wsignoutcleanup1.0, and the browser coming back from an
  // OpenID Provider's end_session_endpoint — for the ACS's reason (decision 2
  // in federation_sp.ts): one URL to configure at the partner rather than
  // four. The two OpenID Connect paths are separate because each is a
  // registration member of its own at the partner and each is answered in a
  // shape of its own (a JSON-free 200/400 to a server; a page in an iframe).
  slo: '/federation/slo',
  backchannelLogout: '/federation/backchannel-logout',
  frontchannelLogout: '/federation/frontchannel-logout',
  // An OpenID Connect relationship's encryption key as a JWKS (#168), what
  // the partner registers to encrypt its ID Token to.
  jwks: '/federation/jwks'
};

const ROLES = [
  { role: 'service-provider', label: 'This service is the service provider',
    short: 'Service provider',
    what: 'A FOREIGN identity provider authenticates the person and this ' +
          'service consumes what it issues. This is the direction that ' +
          'creates directory entries for people this service has never seen, ' +
          'and the direction that cannot be permissive: an assertion is ' +
          'refused unless it verifies against the key on this relationship.' },
  { role: 'identity-provider', label: 'This service is the identity provider',
    short: 'Identity provider',
    what: 'This service authenticates the person and a FOREIGN service ' +
          'provider consumes what it issues. Every protocol endpoint here ' +
          'already does that for any caller — what the relationship adds is ' +
          'the partner being marked as a federation partner rather than a ' +
          'test client, and a list of which attributes are released to it.' }
];

const ROLE_IDS = ROLES.map(function (one) { return one.role; });

// ---------------------------------------------------------------------------
// THE FIVE PROTOCOLS. Closed on purpose, for the reason applications.js's KINDS
// list is closed: a typo that silently became a sixth protocol is how a page
// comes to offer `oidc` and `openid-connect` as two things.
//
// `consumes` and `asserts` say which ROLES a protocol can take here. All five
// can do both, which is worth stating rather than leaving to be inferred — it
// is the reason the form is one form with a role select rather than two forms.
//
// `needs` is what a relationship of this protocol in the SERVICE PROVIDER role
// must carry before it can be enabled. It is read by `readyFor()` below and by
// nothing else, so the rule a form enforces and the rule the endpoint enforces
// are one list rather than two.
//
// **`fedPeer` IS IN EVERY ROW SINCE 2026-09-12, AND IT WAS IN NONE.** It is the
// partner's own identifier — the issuer an assertion or an ID Token must name —
// and `federation_sp.js` skipped the issuer check whenever it was empty, with a
// warning. So a relationship with no peer accepted an assertion from ANY issuer
// its configured key had signed for: one certificate shared by two identity
// providers, or one identity provider hosting several tenants under one key,
// and either could assert for the other here. That is the surface this
// directory says cannot be made permissive, so it is fixed in every mode by
// making the relationship NOT FULLY CONFIGURED without it — refused at the read
// and named by readinessOf() like every other missing field — rather than by a
// check that quietly lapses.
// ---------------------------------------------------------------------------
const PROTOCOLS = [
  { protocol: 'saml2', label: 'SAML 2.0', family: 'SAML 2.0',
    what: 'The Web Browser SSO profile. This service sends an <AuthnRequest> ' +
          'to the partner and consumes the <Response> at its assertion ' +
          'consumer service, or issues one to the partner from /saml2.',
    needs: ['fedSsoUrl', 'fedSigningCertificate', 'fedPeer'],
    spec: 'saml-profiles-2.0-os section 4.1' },
  { protocol: 'saml11', label: 'SAML 1.1', family: 'SAML 1.1',
    what: 'The Browser/POST profile. THERE IS NO REQUEST MESSAGE — a SAML ' +
          '1.1 flow is identity-provider-initiated, so what this service ' +
          'sends the browser to is an inter-site transfer URL carrying a ' +
          'TARGET, and what comes back is a <Response> with no InResponseTo ' +
          'to match. See the note about replay on fedNonce below.',
    needs: ['fedSsoUrl', 'fedSigningCertificate', 'fedPeer'],
    spec: 'saml-profiles-1.1 section 4.1' },
  { protocol: 'wsfed', label: 'WS-Federation 1.2', family: 'WS-Federation',
    what: 'The passive requestor profile. This service sends wa=wsignin1.0 ' +
          'with its own wtrealm and consumes the wresult, which carries a ' +
          'SAML 1.1 or SAML 2.0 assertion inside an RSTR.',
    needs: ['fedSsoUrl', 'fedSigningCertificate', 'fedPeer'],
    spec: 'WS-Federation 1.2 section 13' },
  { protocol: 'oidc', label: 'OpenID Connect', family: 'OAuth 2.0 / OIDC',
    what: 'The authorization code flow by default, and ' +
          'response_type=id_token with response_mode=form_post where there ' +
          'is to be no back channel at all. The attributes come off the ID ' +
          'Token, and off UserInfo where one is configured.',
    needs: ['fedSsoUrl', 'fedClientId', 'fedPeer'],
    spec: 'OpenID Connect Core 1.0 section 3' },
  { protocol: 'oauth2', label: 'OAuth 2.0', family: 'OAuth 2.0 / OIDC',
    what: 'The authorization code flow with NO ID Token — the attributes ' +
          'come off the access token where it is a JWT, and off a configured ' +
          'userinfo-shaped endpoint otherwise. It is a distinct protocol ' +
          'here rather than OIDC with a flag because what identifies the ' +
          'person is a different artifact, and getting that wrong is the ' +
          'whole of what goes wrong when people use OAuth 2.0 for ' +
          'authentication.',
    needs: ['fedSsoUrl', 'fedTokenUrl', 'fedClientId', 'fedPeer'],
    spec: 'RFC 6749 section 4.1' }
];

const PROTOCOL_IDS = PROTOCOLS.map(function (one) { return one.protocol; });

function protocolRow(id) {
  log.debug("Entering protocolRow().");
  const wanted = String(id || '');
  for (let i = 0; i < PROTOCOLS.length; i++) {
    if (PROTOCOLS[i].protocol === wanted) {
      log.debug("Leaving protocolRow().");
      return PROTOCOLS[i];
    }
  }
  log.debug("Leaving protocolRow().");
  return null;
}

function roleRow(id) {
  log.debug("Entering roleRow().");
  const wanted = String(id || '');
  for (let i = 0; i < ROLES.length; i++) {
    if (ROLES[i].role === wanted) {
      log.debug("Leaving roleRow().");
      return ROLES[i];
    }
  }
  log.debug("Leaving roleRow().");
  return null;
}

// ---------------------------------------------------------------------------
// HOW A PERSON PROVES WHO THEY ARE WHEN THIS SERVICE IS THE IDENTITY PROVIDER.
//
// `fedAuthnMechanism` on an identity-provider-side relationship, and it is the
// attribute that makes this service an identity BROKER rather than an identity
// provider with partners: the fourth value sends the person on to ANOTHER
// relationship — one where this service is the service provider — so a
// SAML 2.0 partner can be authenticated over WS-Federation by somebody else
// again, and that partner over something else again, to any depth.
//
// WHY IT IS HERE AND NOT ON THE APPLICATION ENTRY, which is where
// `appFederationRelationship` lives and is a fair question. That attribute
// answers "where do THIS APPLICATION's people sign in" — a fact about a
// relying party, set by whoever registered it. This one answers "what does
// this service DO when that partner asks it to authenticate somebody", which
// is a fact about the RELATIONSHIP: the same directory entry may be a partner
// of one federation and an ordinary OAuth client besides, and the two answers
// need not agree. So the register carries it and the application entry keeps
// what it had.
//
// The cost of that choice is stated rather than hidden: there are now TWO
// places a sign-in can be redirected from, and `authn.js`'s resolver reads
// them in ONE order, written down at `mechanismFor()` — the relationship
// first, because it is the more specific statement, and the application entry
// only when no enabled relationship names that application. Nothing that
// worked before this attribute existed changes: a relationship that declares
// no mechanism falls through to exactly the path it always took.
//
// AN EMPTY VALUE IS NOT `password`. It is "this relationship says nothing",
// which is what every relationship created before this attribute existed
// holds, and it has to fall through to the application entry rather than
// overriding it — otherwise adding this feature would have silently switched
// off every `appFederationRelationship` in the field.
// ---------------------------------------------------------------------------
const MECHANISMS = [
  { mechanism: 'password', label: 'Username and password',
    what: 'This service\'s own sign-in screen, which checks no password. The ' +
          'ordinary case, and what an unset mechanism falls through to once ' +
          'nothing else has an opinion.' },
  { mechanism: 'password-mfa', label: 'Username and password, with MFA',
    what: 'The same screen with the second-factor box ticked and locked, so ' +
          'the WebAuthn ceremony runs after the password step and the ' +
          'session records amr ["pwd","hwk"] and acr "mfa". It is the same ' +
          'demand a RequestedAuthnContext can make; a protocol asking for it ' +
          'and a relationship configuring it produce one screen, not two.' },
  { mechanism: 'webauthn', label: 'WebAuthn, passwordless',
    what: 'A security key ALONE — no password is presented, so the session ' +
          'records amr ["hwk"] and ONE factor. That is why it cannot satisfy ' +
          'a caller that demanded a second factor: see forceMfa in authn.js, ' +
          'which wins over this and says so in the log.' },
  { mechanism: 'federation', label: 'Another federation relationship',
    what: 'THE BROKER CASE. `fedAuthnRelationship` names a ' +
          'SERVICE-PROVIDER-side relationship in this same realm and the ' +
          'person is sent there, so this service consumes somebody else\'s ' +
          'assertion and then issues its own to the partner that asked. The ' +
          'two protocols need not match and usually do not — that is the ' +
          'whole of what an identity bridge is.' },
  // THE FIFTH, ADDED 2026-08-26, AND IT IS THE FIRST ONE THAT IS NEITHER THIS
  // SERVICE'S SCREEN NOR SOMEBODY ELSE'S. The other four are a page here or a
  // redirect to a partner; this one is a CREDENTIAL THE BROWSER ALREADY HOLDS,
  // which is what "integrated authentication" has always meant. It is also the
  // only value in this table that can be switched off service-wide — see
  // authn.js's declaredMechanismFor(), which reports a relationship or an
  // application naming it while krb5.spnegoAuthentication is false rather than
  // letting somebody meet a 403 halfway through a sign-in.
  { mechanism: 'spnego', label: 'Kerberos ticket (SPNEGO)',
    what: 'INTEGRATED AUTHENTICATION. The person is sent to /authn/spnego, ' +
          'which answers 401 with WWW-Authenticate: Negotiate and signs them ' +
          'in on the service ticket their client sends back (RFC 4559 over ' +
          'RFC 4178 over RFC 4121). Nothing is typed and no screen is drawn. ' +
          'It is the one mechanism here that rests on a credential this ' +
          'service genuinely verifies — every other sign-in takes the name ' +
          'it is given — and what the session then claims is read off the ' +
          'TICKET\'s own flags: amr ["pwd"] for pre-authent, ["hwk"] for ' +
          'hw-authent, both for both, and NOTHING at all for a ticket that ' +
          'claims neither. A client that cannot get a ticket meets a page ' +
          'with the sign-in screen linked from it, because a bare 401 ' +
          'Negotiate is a dead end in every browser that is not configured ' +
          'for this host.' },
  // THE SIXTH, ADDED 2026-09-17 (#38's follow-ups): a WALLET. Like `spnego`
  // it is a credential the person already holds rather than a screen, and
  // like `spnego` it can be switched off service-wide — `oid4vp.signIn` —
  // which authn.ts's declaredMechanismFor() reports rather than sending
  // somebody to a door that is shut.
  { mechanism: 'wallet', label: 'Wallet (OpenID4VP)',
    what: 'The person is sent to /authn/wallet, which asks their wallet — ' +
          'through the Digital Credentials API, or on this device by link — ' +
          'for a credential this realm issued them, and signs them in as the ' +
          'directory entry it was issued for once a fresh holder proof ' +
          'verifies. amr ["pop"] and acr "1" for one factor; a caller that ' +
          'demanded two is asked for a second factor afterwards (or has one ' +
          'already, where the credential\'s key attestation says so), so this ' +
          'mechanism does not lose to forceMfa the way spnego does.' }
];

const MECHANISM_IDS = MECHANISMS.map(function (one) {
  return one.mechanism;
});

// ---------------------------------------------------------------------------
// WHICH PEOPLE A PARTNER MAY ASSERT (#109, 2026-09-22): `fedSubjectPolicy`'s
// four values, the order they are offered in, and the two readers of the
// three rules. The decision itself is `federation_sp.ts`'s
// `subjectDecision()`; this is the vocabulary it and the console share.
//
// **AN EMPTY VALUE IS THE DEFAULT, AND AN UNKNOWN ONE IS THE STRICTEST.**
// Empty is what every relationship created before the attribute holds and
// what a console clearing the field writes, so it means
// `link-at-first-sign-in`. A value that is none of the four can only have
// arrived by `ldapmodify` (update() refuses it), and reading it as anything
// but `pre-linked` would let a typo widen who the partner may sign in.
// ---------------------------------------------------------------------------
const SUBJECT_POLICIES = [
  { policy: 'link-at-first-sign-in', label: 'Link at first sign-in (default)',
    what: 'A linked subject signs in. An unlinked one naming an existing ' +
          'person signs in HERE as that person first, and is then linked.' },
  { policy: 'pre-linked', label: 'Pre-linked only',
    what: 'Only a link made beforehand — on the console, through ' +
          '/admin-api or SCIM — signs anybody in.' },
  { policy: 'jit-namespaced', label: 'Just-in-time, namespaced',
    what: 'An unlinked subject gets a new entry named ' +
          '<relationship>~<name>, linked at creation, never an existing ' +
          'person.' },
  { policy: 'any-existing', label: 'Any existing person, by name ' +
                                    '(development only)',
    what: 'The name the partner sends is matched onto a local person. ' +
          'Refused in product mode.' }
];

const SUBJECT_POLICY_IDS = SUBJECT_POLICIES.map(function (one) {
  return one.policy;
});

const DEFAULT_SUBJECT_POLICY = 'link-at-first-sign-in';

function subjectPolicyRow(id) {
  log.debug("Entering subjectPolicyRow().");
  const wanted = String(id || '');
  const found = SUBJECT_POLICIES.filter(function (one) {
    return one.policy === wanted;
  })[0] || null;
  log.debug("Leaving subjectPolicyRow().");
  return found;
}

// The policy a relationship is under. See the header above SUBJECT_POLICIES.
function subjectPolicyOf(record) {
  log.debug("Entering subjectPolicyOf().");
  const text = String((record && record.fedSubjectPolicy) || '').trim();
  if (!text) {
    log.debug("Leaving subjectPolicyOf(). The default.");
    return DEFAULT_SUBJECT_POLICY;
  }
  if (SUBJECT_POLICY_IDS.indexOf(text) < 0) {
    log.warn('federation: the relationship ' + (record && record.fedId) +
             ' carries fedSubjectPolicy "' + text + '", which is none of ' +
             SUBJECT_POLICY_IDS.join(', ') + '; it is read as pre-linked, ' +
             'the strictest.');
    log.debug("Leaving subjectPolicyOf(). Unknown, so pre-linked.");
    return 'pre-linked';
  }
  log.debug("Leaving subjectPolicyOf(). " + text);
  return text;
}

// ---------------------------------------------------------------------------
// `fedSubjectPattern`: AN ADMINISTRATOR'S REGULAR EXPRESSION, BOUNDED.
//
// JavaScript's engine backtracks and node offers no timeout on a match, so
// the bound is on what may be written rather than on how long a match runs:
// at most PATTERN_MAX characters, no backreference, and no quantifier on a
// group that itself contains one — `(a+)+`, `(a|aa)*`, the shapes that make a
// backtracking engine exponential — and the value tested is cut off at
// PATTERN_INPUT_MAX characters. It is ANCHORED here (`^(?:…)$`), so an
// administrator writing `ou=partners` gets a whole-DN match rather than a
// substring one, which is XACML's regexp-match lesson (xacml_functions.js)
// read again: an unanchored pattern admits far more than it names.
// ---------------------------------------------------------------------------
const PATTERN_MAX = 256;
const PATTERN_INPUT_MAX = 1024;

// Whether a group that holds a quantifier or an alternation (at any depth) is
// itself followed by a quantifier. A scan rather than a regex over the
// pattern, because the groups nest and a regex cannot count them. Escapes and
// character classes are stepped over: `[+]` is a plus sign, not a quantifier.
function nestedQuantifier(pattern) {
  log.debug("Entering nestedQuantifier().");
  const stack = [];
  let i = 0;
  let found = false;
  // No Entering/Leaving pair in quantifierAt(): it runs for every character
  // of the pattern, and a pair per character would drown the log.
  const quantifierAt = function (at, withOptional) {
    const c = pattern.charAt(at);
    return c === '+' || c === '*' || c === '{' || (withOptional && c === '?');
  };
  while (i < pattern.length && !found) {
    const c = pattern.charAt(i);
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (c === '[') {
      let j = i + 1;
      while (j < pattern.length && pattern.charAt(j) !== ']') {
        j += pattern.charAt(j) === '\\' ? 2 : 1;
      }
      i = j + 1;
      if (quantifierAt(i, false) && stack.length) {
        stack[stack.length - 1].risky = true;
      }
      continue;
    }
    if (c === '(') {
      stack.push({ risky: false });
      i += 1;
      continue;
    }
    if (c === ')') {
      const group = stack.pop() || { risky: false };
      i += 1;
      const quantified = quantifierAt(i, true);
      if (group.risky && quantified) {
        found = true;
      }
      if (stack.length && (group.risky || quantifierAt(i, false))) {
        stack[stack.length - 1].risky = true;
      }
      continue;
    }
    if (stack.length && (c === '|' || quantifierAt(i, false) ||
                         (c === '?' && i > 0 &&
                          pattern.charAt(i - 1) !== '('))) {
      stack[stack.length - 1].risky = true;
    }
    i += 1;
  }
  log.debug("Leaving nestedQuantifier(). " + found);
  return found;
}

function subjectPatternProblem(text) {
  log.debug("Entering subjectPatternProblem().");
  const pattern = String(text == null ? '' : text);
  if (!pattern) {
    log.debug("Leaving subjectPatternProblem(). Empty is no pattern.");
    return '';
  }
  if (pattern.length > PATTERN_MAX) {
    log.debug("Leaving subjectPatternProblem(). Too long.");
    return 'it is ' + pattern.length + ' characters long, and at most ' +
           PATTERN_MAX + ' are accepted';
  }
  if (/\\[1-9]|\\k</.test(pattern)) {
    log.debug("Leaving subjectPatternProblem(). A backreference.");
    return 'it uses a backreference, which a pattern here may not';
  }
  // A group whose body carries a quantifier or an alternation, followed by a
  // quantifier — at any depth. Read on the source text by nestedQuantifier(),
  // so it errs towards refusing: `([a-z]+)?` is refused too, and `[a-z]+`
  // does the same job without the group.
  if (nestedQuantifier(pattern)) {
    log.debug("Leaving subjectPatternProblem(). A nested quantifier.");
    return 'it applies a quantifier to a group that is itself quantified ' +
           'or an alternation, the shape that makes a match take ' +
           'exponential time; write the repetition once';
  }
  try {
    new RegExp('^(?:' + pattern + ')$');
  } catch (e) {
    log.debug("Caught in subjectPatternProblem(): " + ((e && e.message) || e));
    log.debug("Leaving subjectPatternProblem(). It does not compile.");
    return 'it does not compile: ' + e.message;
  }
  log.debug("Leaving subjectPatternProblem(). Usable.");
  return '';
}

// Whether `value` matches the relationship's pattern, WHOLE. A pattern that
// would be refused today (written by `ldapmodify`) matches NOTHING — a rule
// that cannot be read must not fall open.
function subjectPatternMatches(text, value) {
  log.debug("Entering subjectPatternMatches().");
  const pattern = String(text == null ? '' : text);
  if (subjectPatternProblem(pattern)) {
    log.debug("Leaving subjectPatternMatches(). An unusable pattern.");
    return false;
  }
  const subject = String(value == null ? '' : value);
  if (subject.length > PATTERN_INPUT_MAX) {
    log.debug("Leaving subjectPatternMatches(). The value is too long.");
    return false;
  }
  const matched = new RegExp('^(?:' + pattern + ')$', 'i').test(subject);
  log.debug("Leaving subjectPatternMatches(). " + matched);
  return matched;
}

function mechanismRow(id) {
  log.debug("Entering mechanismRow().");
  const wanted = String(id || '');
  for (let i = 0; i < MECHANISMS.length; i++) {
    if (MECHANISMS[i].mechanism === wanted) {
      log.debug("Leaving mechanismRow().");
      return MECHANISMS[i];
    }
  }
  log.debug("Leaving mechanismRow().");
  return null;
}

// Which protocol family a relationship belongs to, for the audit log and for
// the application record an identity-provider-side relationship points at. One
// function so the four spellings cannot drift.
function familyOf(protocolId) {
  log.debug("Entering familyOf().");
  const row = protocolRow(protocolId);
  log.debug("Leaving familyOf().");
  return row ? row.family : String(protocolId || 'unstated');
}

// ---------------------------------------------------------------------------
// THE SCHEMA.
//
// One row per attribute and the row is the whole definition, exactly as
// `applications.js`'s is: `GET /admin/ldap/federations` publishes this table,
// the console builds its forms from it, `ldap_server.js` writes the entry from
// it, and there is no second list anywhere. An attribute that is not here is
// not written.
//
// `single` vs `multi` is load-bearing rather than descriptive — a multi-valued
// attribute ACCUMULATES and a single-valued one is ASSIGNED — and getting it
// backwards on a counter produces an entry with fifty `fedAuthentications`
// values, which is the visible symptom of a bug nobody can locate.
//
// `role` on a row says which direction the attribute is FOR. It is what stops
// the console offering a token endpoint on a relationship where this service
// is the one issuing the token, and it is read by `fieldsForRole()` rather
// than by any form directly.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ENCRYPTION TO THIS SERVICE AS A SERVICE PROVIDER (#168): the vocabulary of
// the four relationship fields below, owned here because the register owns
// the schema. `federation_encryption.ts` owns what is DONE with them.
//
// Two families, because a SAML 2.0 or WS-Federation assertion is XML
// Encryption and an OpenID Connect ID Token is JWE, and they name the same
// ideas differently. Refused in every mode, by name: AES-CBC in either
// (XML's is the Jager-Somorovsky padding oracle; JOSE's composite is
// authenticated but there is no partner that has CBC and not GCM), and
// RSAES-PKCS1-v1_5 in either (Bleichenbacher).
// ---------------------------------------------------------------------------
const ENCRYPTING_PROTOCOLS = ['saml2', 'wsfed', 'oidc'];
const ENCRYPTION_KEY_TYPES = ['rsa-3072', 'ec-p256'];
const XML_KEY_MANAGEMENT = ['rsa-oaep', 'ecdh-es'];
const JOSE_KEY_MANAGEMENT = ['RSA-OAEP-256', 'RSA-OAEP', 'ECDH-ES',
                             'ECDH-ES+A128KW', 'ECDH-ES+A256KW'];
const XML_CONTENT_ENCRYPTION = ['aes256-gcm', 'aes128-gcm'];
const JOSE_CONTENT_ENCRYPTION = ['A256GCM', 'A128GCM'];
const REFUSED_ALGORITHMS = ['aes128-cbc', 'aes192-cbc', 'aes256-cbc',
                            'rsa-1_5', 'RSA1_5', 'A128CBC-HS256',
                            'A192CBC-HS384', 'A256CBC-HS512'];
// Which management algorithms a key of each type can do.
const MANAGEMENT_FOR_KEY = {
  'rsa-3072': ['rsa-oaep', 'RSA-OAEP-256', 'RSA-OAEP'],
  'ec-p256': ['ecdh-es', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW']
};

const SCHEMA = {
  objectClasses: [
    { name: 'top', where: 'RFC 4512', standard: true,
      what: 'The abstract class every entry carries.' },
    { name: 'applicationProcess', where: 'RFC 4519 section 3.3', standard: true,
      what: 'The same registered class ou=applications uses, and for the ' +
            'same reason: it is the one that fits a party in a protocol at ' +
            'all, and it brings cn, description, seeAlso, ou and l with it.' },
    { name: 'stsFederation', where: 'this service', standard: false,
      what: 'INVENTED. No registered LDAP schema has a federation partner, ' +
            'because every product that stores one (AD FS, Shibboleth, ' +
            'Keycloak, Ping) keeps it in its own database. These are this ' +
            'service\'s own names in the way stsApplication\'s already are.' }
  ],
  attributes: [
    // --- identity ---------------------------------------------------------
    { name: 'fedId', kind: 'single', role: 'both', from: 'this register',
      what: 'THE KEY: a short name an operator chose, unique across both ' +
            'roles. It is the RDN as well, unlike an application\'s, because ' +
            'this register is CONFIGURED rather than observed — nobody has ' +
            'to accept whatever a protocol presented, so the id can simply ' +
            'be required to be RDN-safe and short.' },
    { name: 'cn', kind: 'single', role: 'both', standard: true,
      from: 'this register',
      what: 'The RDN value, equal to fedId. Unlike an application entry ' +
            'there is no digest case here: an id that would not fit is ' +
            'refused at creation rather than hashed.' },
    { name: 'fedName', kind: 'single', role: 'both', from: 'this register',
      what: 'What to call the partner on a page. The id is the name when ' +
            'none is given, because inventing a friendly name would be ' +
            'inventing a fact.' },
    { name: 'fedRole', kind: 'single', role: 'both', from: 'this register',
      what: 'WHICH END THIS SERVICE IS: service-provider (it consumes) or ' +
            'identity-provider (it asserts). One relationship is one ' +
            'direction — see the header.' },
    { name: 'fedProtocol', kind: 'single', role: 'both', from: 'this register',
      what: 'One of saml2, saml11, wsfed, oidc, oauth2.' },
    { name: 'fedPeer', kind: 'single', role: 'both', from: 'this register',
      what: 'THE PARTNER\'S OWN IDENTIFIER, in whatever its protocol calls ' +
            'it: a SAML entityID, an OpenID Connect issuer, a WS-Federation ' +
            'wtrealm. On a service-provider-side relationship it is CHECKED ' +
            '— an assertion whose Issuer is not this string is refused — ' +
            'which is why it is not merely documentation, and since ' +
            '2026-09-12 it is REQUIRED there: a relationship without it is ' +
            'not fully configured.' },
    { name: 'fedLocalEntityId', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'WHAT THIS SERVICE IS CALLED TO THIS PARTNER, when that is not ' +
            'the name this service derives. Empty — the default — derives it ' +
            'from the base URL the browser reached this service at ' +
            '(<base>/federation/acs/<id>, which global.publicBaseUrl pins). ' +
            'Set it to the entityID the partner was configured with: it ' +
            'becomes the Issuer of the outbound AuthnRequest, the ' +
            'WS-Federation wtrealm, the SAML 1.1 providerId, this ' +
            'relationship\'s SP metadata entityID, and the audience an ' +
            'inbound assertion must name — which is a REFUSAL since ' +
            '2026-09-12, so a partner that knows this service by another ' +
            'name needs this set. The assertion consumer URL stays derived, ' +
            'because it is an address a browser must be able to reach.' },
    { name: 'fedEnabled', kind: 'single', role: 'both', from: 'this register',
      what: 'TRUE/FALSE. A relationship is created DISABLED and nothing ' +
            'about it does anything until it is turned on: a half-configured ' +
            'partner that silently accepted assertions would be the failure ' +
            'this whole register exists to prevent.' },
    { name: 'description', kind: 'multi', role: 'both', standard: true,
      from: 'this register',
      what: 'One line per thing that has happened to this relationship.' },

    // --- the service provider half: what this service CONSUMES ------------
    { name: 'fedSsoUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'WHERE THE BROWSER IS SENT. The partner\'s SAML Single Sign-On ' +
            'service, its SAML 1.1 inter-site transfer service, its ' +
            'WS-Federation passive endpoint, or its OAuth 2.0 authorization ' +
            'endpoint. Required in every protocol, because a relationship ' +
            'with nowhere to send anybody cannot begin.' },
    { name: 'fedTokenUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s token endpoint, for the authorization code flow. ' +
            'THIS IS ONE OF THE TWO URLS THIS SERVICE WILL ACTUALLY DIAL — ' +
            'see federation_http.js, which is the only outbound request in ' +
            'this repository and argues why a configured URL is a different ' +
            'thing from a registered one.' },
    { name: 'fedUserinfoUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s UserInfo endpoint, or any endpoint that answers ' +
            'JSON about the bearer of an access token. OPTIONAL for OIDC, ' +
            'where the ID Token usually carries enough, and the ONLY source ' +
            'of attributes for a plain OAuth 2.0 partner whose access token ' +
            'is opaque. The second URL this service will dial.' },
    { name: 'fedJwksUri', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s JWKS. FETCHED — which is the exact opposite of ' +
            'what oauthJwksUri on an application entry does, and the ' +
            'difference is the whole argument in federation_http.js: that ' +
            'one is a URL an unauthenticated caller REGISTERED, this one is ' +
            'a URL an administrator CONFIGURED. Leave it empty and paste the ' +
            'keys into fedJwks instead if this service is not to make the ' +
            'call.' },
    { name: 'fedJwks', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The partner\'s public keys as a JWKS document, verbatim. Read ' +
            'BEFORE fedJwksUri and never refreshed, so a relationship ' +
            'carrying this makes no outbound request for keys at all.' },
    // OPENID FEDERATION (#134, 2026-09-23): an `oidc` relationship whose OP
    // is DISCOVERED through its Trust Chain rather than configured by hand.
    // See oidfed/oidfed_rp.ts, and federation/CLAUDE.md for why this is
    // still a relationship whose trust is a configured key.
    { name: 'fedTrustAnchor', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'OPENID CONNECT ONLY. The Entity Identifier of one of this ' +
            'realm\'s Trust Anchors (/admin/oidfed). Set, the OP named by ' +
            'fedPeer is resolved through its Trust Chain to that anchor, ' +
            'its endpoints and keys are the openid_provider metadata the ' +
            'chain vouches for, and this service registers with it ' +
            'AUTOMATICALLY under its own Entity Identifier, signing its ' +
            'requests and token-endpoint authentication with its ES256 ' +
            'key — so fedSsoUrl, fedTokenUrl, fedJwks, fedJwksUri, ' +
            'fedClientId and fedClientSecret are not read. Empty, the ' +
            'relationship is configured by hand as always.' },
    { name: 'fedSigningCertificate', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'THE PARTNER\'S SIGNING CERTIFICATE, base64 DER — the same ' +
            'spelling a ds:X509Certificate carries and the same one ' +
            'samlSigningCertificate uses on an application entry, so one ' +
            'certificate has one spelling across this service. It is what ' +
            'every SAML and WS-Federation assertion is verified against, and ' +
            'it is the single attribute standing between this service and an ' +
            'endpoint anybody could assert anything at.' },
    { name: 'fedClientId', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'THIS SERVICE\'S client_id AT THE PARTNER. Ours, issued by them ' +
            '— not to be confused with an oauthClientId on an application ' +
            'entry, which is a mock client\'s id here.' },
    { name: 'fedClientSecret', kind: 'single', role: 'service-provider',
      sensitive: true, from: 'this register',
      what: 'THIS SERVICE\'S SECRET AT THE PARTNER, in the clear, in a ' +
            'directory where every bind succeeds. It is a REAL credential at ' +
            'a REAL foreign service, which is a stronger statement than ' +
            'anything else in this directory — see the header. Never written ' +
            'to the audit log and never printed on a page.' },
    { name: 'fedScope', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'The scope asked of the partner. `openid profile email` is the ' +
            'default for an OIDC relationship and there is no default for an ' +
            'OAuth 2.0 one, because what an OAuth 2.0 authorization server ' +
            'will give you is entirely local to it.' },
    { name: 'fedResponseType', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'code (the default) or id_token. `id_token` with form_post is ' +
            'the shape that needs NO back channel and therefore no token ' +
            'endpoint, no client secret and no outbound request — which is ' +
            'the only way to federate with an OIDC partner from a deployment ' +
            'that has no egress at all.' },
    { name: 'fedBinding', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'Which binding the outbound SAML AuthnRequest goes on: ' +
            'HTTP-Redirect (the default, and what every identity provider ' +
            'supports) or HTTP-POST. It says nothing about the response, ' +
            'which arrives on whatever binding the partner sends it on and ' +
            'is accepted on all of them.' },
    { name: 'fedSignRequest', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'Sign the outbound AuthnRequest with THIS service\'s key. OFF by ' +
            'default: most identity providers do not require it, and a ' +
            'partner that does will refuse the request in a way that names ' +
            'the problem. When it is on, the certificate to configure at the ' +
            'partner is the one on this service\'s own SAML metadata.' },
    { name: 'fedUsernameSource', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'WHICH INCOMING VALUE BECOMES THE LOCAL USERNAME — a claim name ' +
            'for OIDC/OAuth 2.0, a SAML Attribute Name for the others. Empty ' +
            'means the subject itself: the NameID, or `sub`. This is the one ' +
            'mapping decision that cannot be got wrong quietly, because it ' +
            'decides which directory entry a person lands on.' },
    { name: 'fedAttributeMap', kind: 'multi', role: 'service-provider',
      from: 'this register',
      what: 'ONE VALUE PER MAPPING, written `<incoming name>=<LDAP ' +
            'attribute>`. What is NOT listed here still arrives — ' +
            'federation_map.js has a default table covering the ordinary ' +
            'OIDC claims, the SAML urn:oid: names and the WS-Federation ' +
            'claim URIs — so this is for the partner\'s own inventions ' +
            'rather than for the names everybody uses.' },
    { name: 'fedAutocreateUsers', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'DYNAMIC PROVISIONING: create a directory entry the first time ' +
            'this partner signs somebody in. ON by default. OFF means the ' +
            'person must ALREADY have an entry here — provisioned ahead of ' +
            'time, by SCIM or by hand — and a sign-in for somebody who does ' +
            'not is refused, because a session needs an entry to be the ' +
            'subject of. (Until 2026-09-14 OFF gave a session and no entry; ' +
            'a stable subject made that state impossible.)' },
    { name: 'fedUpdateUserAttributes', kind: 'single',
      role: 'service-provider', from: 'this register',
      what: 'Update the person\'s directory attributes on EVERY sign-in from ' +
            'the latest assertion or token. ON by default, which is what ' +
            'this service always did. OFF writes the partner\'s attributes ' +
            'only when this sign-in CREATED the entry, so a pre-provisioned ' +
            'person — or one somebody has since edited — keeps what the ' +
            'directory says. Which relationship and issuer a person came ' +
            'through is recorded either way.' },
    // --- WHICH PEOPLE THE PARTNER MAY ASSERT (#109, 2026-09-22) ----------
    // The gate used to be on the SIGNER only: any person a verified assertion
    // named was signed in, matched onto a local entry by NAME. These five say
    // which local person a partner's subject may become — see
    // federation/CLAUDE.md, *WHICH PEOPLE A PARTNER MAY ASSERT*.
    { name: 'fedSubjectPolicy', kind: 'single', role: 'service-provider',
      from: 'this register', enum: SUBJECT_POLICY_IDS,
      what: 'HOW THE PARTNER\'S SUBJECT BECOMES A LOCAL PERSON. The subject ' +
            'is the partner\'s own stable identifier — iss + sub, a ' +
            'persistent NameID and the partner\'s entity ID — and a person ' +
            'carries it as a federationLink. link-at-first-sign-in (the ' +
            'default; empty means it): a linked subject signs in; an ' +
            'unlinked one naming an existing person must first sign in HERE ' +
            'as that person — password, and a second factor where one is ' +
            'held or required — and only then is the link recorded and the ' +
            'partner\'s attributes written; one naming nobody gets a new ' +
            'entry namespaced to this relationship where provisioning is on. ' +
            'pre-linked: only a link signs anybody in. jit-namespaced: an ' +
            'unlinked subject always gets a NEW entry, ' +
            '<relationship>~<name>, ' +
            'never an existing person. any-existing: the name the partner ' +
            'sent is matched straight onto a local person, as this service ' +
            'did before #109 — DEVELOPMENT ONLY, refused in product, and it ' +
            'lets this partner sign in any account it can name.' },
    { name: 'fedSubjectGroup', kind: 'multi', role: 'service-provider',
      from: 'this register',
      what: 'A RULE ON TOP OF THE POLICY: the person must be a member of one ' +
            'of these groups, each a cn or a DN. An entry this sign-in would ' +
            'CREATE is in no group, so with this set nobody is created. ' +
            'Empty: no group rule.' },
    { name: 'fedSubjectDomain', kind: 'multi', role: 'service-provider',
      from: 'this register',
      what: 'A RULE ON TOP OF THE POLICY: the mail domain the partner SENT ' +
            '(the mapped mail, or the mapped username where it is an ' +
            'address) must be one of these, and so must the local entry\'s ' +
            'mail where it has one. Compared case-insensitively and ' +
            'exactly: example.com does not admit sub.example.com. Empty: no ' +
            'domain rule.' },
    { name: 'fedSubjectPattern', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'A RULE ON TOP OF THE POLICY: a regular expression the local ' +
            'entry\'s DN must match WHOLE (it is anchored for you), such as ' +
            'uid=[^,]+,ou=users,.* — for an entry this sign-in would create, ' +
            'the DN it would be created at. At most 256 characters, no ' +
            'backreference and no quantifier applied to a group that is ' +
            'itself quantified, and it is tested against at most 1024 ' +
            'characters, so a pattern cannot be made to backtrack for ' +
            'minutes. Empty: no pattern.' },
    { name: 'fedMayAssertAdministrators', kind: 'single',
      role: 'service-provider', from: 'this register',
      what: 'LET THIS PARTNER SIGN IN A CONSOLE ADMINISTRATOR. OFF by ' +
            'default, and off means a person in the Admin Read or Admin ' +
            'Write roster — or holding REMOTE_PEPS — is refused whatever ' +
            'else is true, a valid link included (STS-FED-0093). Turning it ' +
            'on makes this partner\'s signing key a key to the console for ' +
            'every administrator linked to it.' },
    // --- A PARTNER'S SIGN-OUT (#167) ---------------------------------------
    // federation/federation_slo.ts is what reads these, in both directions:
    // the partner telling this service a session ended, and this service
    // telling the partner. federation/CLAUDE.md, *A PARTNER'S SIGN-OUT*.
    { name: 'fedSloUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'THE PARTNER\'S SAML 2.0 SingleLogoutService — where this ' +
            'service sends a signed <LogoutRequest> when a person signs out ' +
            'HERE (/logout), and where the <LogoutResponse> to the ' +
            'partner\'s own LogoutRequest goes. From the partner\'s ' +
            'metadata. Empty: the partner is never told of a sign-out here, ' +
            'and a LogoutRequest from it is still honoured but answered with ' +
            'nothing, because there is nowhere to send the answer. SAML 2.0 ' +
            'only: SAML 1.1 defines no logout at all.' },
    { name: 'fedSloBinding', kind: 'single', role: 'service-provider',
      from: 'this register', enum: ['HTTP-Redirect', 'HTTP-POST'],
      what: 'Which binding a LogoutRequest or LogoutResponse this service ' +
            'sends the partner goes on: HTTP-Redirect (the default; the ' +
            'signature is over the query string) or HTTP-POST (an enveloped ' +
            'signature, on a real form with a real button — no script). A ' +
            'message FROM the partner is accepted on either.' },
    { name: 'fedEndSessionUrl', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'THE PARTNER\'S OpenID Connect end_session_endpoint ' +
            '(RP-Initiated Logout 1.0), from its discovery document. When a ' +
            'person signs out HERE, the sign-out page offers to send them ' +
            'there with the partner\'s own ID Token as id_token_hint, this ' +
            'relationship\'s client_id, and this relationship\'s single ' +
            'logout endpoint as post_logout_redirect_uri — which the partner ' +
            'must have registered. The ID Token is kept on the session only ' +
            'while this is set. Empty: the partner is not told.' },
    { name: 'fedAcceptSignout', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'HONOUR THE PARTNER\'S SIGN-OUT: a SAML LogoutRequest, an ' +
            'OpenID Connect Back-Channel or Front-Channel logout, a ' +
            'WS-Federation cleanup. ON by default — the partner is the ' +
            'authority on the person\'s sign-on, and when it ends a session ' +
            'or disables an account there, this is the only signal that ' +
            'reaches here. Off, every one of them is refused ' +
            '(STS-FED-0123) and the session here lives its whole lifetime.' },
    { name: 'fedRequireSignedLogout', kind: 'single',
      role: 'service-provider', from: 'this register',
      what: 'REQUIRE THE PARTNER\'S SAML LogoutRequest AND LogoutResponse TO ' +
            'BE SIGNED, as saml-profiles-2.0-os section 4.4.4.1 says they ' +
            'MUST be. ON by default and ALWAYS on in product mode, where ' +
            'turning it off is refused (STS-FED-0132). Off — development ' +
            'only — accepts an UNSIGNED logout message, which lets anybody ' +
            'who can name a person\'s partner session end it: a partner ' +
            'under test that cannot sign yet is the only reason to. A ' +
            'signature that IS present is verified either way.' },
    // --- WHAT A PARTNER ENCRYPTS TO (#168) ------------------------------
    // federation/federation_encryption.ts issues, rotates, publishes and
    // decrypts with the key; federation/CLAUDE.md, *A PARTNER'S ENCRYPTED
    // ASSERTION*. SAML 2.0, WS-Federation and OpenID Connect only: SAML 1.1
    // has no encryption construct and a plain OAuth 2.0 relationship reads
    // no ID Token.
    { name: 'fedEncryptionKeyType', kind: 'single', role: 'service-provider',
      from: 'this register', enum: ENCRYPTION_KEY_TYPES,
      what: 'THE KIND OF KEY A PARTNER ENCRYPTS TO: rsa-3072 (the default ' +
            'for SAML 2.0 and WS-Federation) or ec-p256 (the default for ' +
            'OpenID Connect). Changing it issues a new key of that kind at ' +
            'once and keeps the old one for federation.encryptionKeyGraceS, ' +
            'as a rotation does.' },
    { name: 'fedKeyManagementAlgorithm', kind: 'single',
      role: 'service-provider', from: 'this register',
      enum: XML_KEY_MANAGEMENT.concat(JOSE_KEY_MANAGEMENT),
      what: 'HOW THE PARTNER WRAPS OR AGREES THE CONTENT KEY, and the only ' +
            'one accepted. XML (SAML 2.0, WS-Federation): rsa-oaep — XML ' +
            'Encryption 1.1\'s RSA-OAEP with SHA-256 and MGF1-SHA-256 — for ' +
            'an RSA key, ecdh-es (ConcatKDF, kw-aes256) for an EC one. JOSE ' +
            '(an OpenID Connect ID Token): RSA-OAEP-256 or RSA-OAEP for an ' +
            'RSA key, ECDH-ES, ECDH-ES+A128KW or ECDH-ES+A256KW for an EC ' +
            'one. WARNING: RSA-OAEP is OAEP over SHA-1, offered for a ' +
            'partner that has nothing newer; RSA-OAEP-256 is the one to ' +
            'use. rsa-1_5 and ' +
            'RSA1_5 are refused in every mode (Bleichenbacher). Empty means ' +
            'the default for the key type.' },
    { name: 'fedContentEncryptionAlgorithm', kind: 'single',
      role: 'service-provider', from: 'this register',
      enum: XML_CONTENT_ENCRYPTION.concat(JOSE_CONTENT_ENCRYPTION),
      what: 'THE CIPHER OVER THE ASSERTION OR THE ID TOKEN, and the only one ' +
            'accepted: aes256-gcm (the default) or aes128-gcm for XML, ' +
            'A256GCM (the default) or A128GCM for JOSE. AES-CBC — XML ' +
            'Encryption\'s aes*-cbc and JOSE\'s A*CBC-HS* — is refused in ' +
            'every mode: the XML form is the padding oracle of Jager and ' +
            'Somorovsky (2011), and a partner that can do GCM in one can in ' +
            'the other.' },
    { name: 'fedAllowUnencrypted', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'ACCEPT A PLAINTEXT ASSERTION IN PRODUCT MODE. OFF by default, ' +
            'and off means a SAML 2.0 or WS-Federation assertion, or an ' +
            'OpenID Connect id_token by form_post, that is NOT encrypted to ' +
            'this relationship\'s key is refused (STS-FED-0140). WARNING: ' +
            'turning it on lets the partner send the person\'s NameID, mail, ' +
            'groups and every other attribute IN CLEAR through their ' +
            'browser — its history, its extensions and every TLS-terminating ' +
            'proxy on the way. Turn it on only for a partner that cannot ' +
            'encrypt, and prefer asking it to. Development mode accepts ' +
            'plaintext whatever this says.' },
    { name: 'fedEncryptionKey', kind: 'multi', role: 'service-provider',
      from: 'this register', sensitive: true,
      what: 'THE KEY TABLE: one JSON row per key this relationship decrypts ' +
            'with — its kid, its key type, `current` or `previous`, its ' +
            'certificate and chain under this realm\'s Intermediate, and the ' +
            'private key, SEALED under the key-encryption key wherever keys ' +
            'persist. A `previous` row is kept until its retiresAt and then ' +
            'removed by the scheduler job federation.encryption-key-retire. ' +
            'Written only by create, rotate and that job; WITHHELD from ' +
            'every LDAP search in product and from every page and ' +
            '/admin-api reply, which publish the public half. The key type ' +
            'is a column so a ' +
            'hybrid post-quantum key can be a row beside the classical one ' +
            'once one is registered.' },
    { name: 'fedAllowUnsolicited', kind: 'single', role: 'service-provider',
      from: 'this register',
      what: 'Accept a response this service did not ask for — SAML 2.0\'s ' +
            'unsolicited Response, and SAML 1.1\'s ONLY mode of operation. ' +
            'OFF by default for SAML 2.0 and forced ON for SAML 1.1, because ' +
            'that profile has no request to be in response to. Turning it on ' +
            'for SAML 2.0 removes the InResponseTo check, which is worth ' +
            'knowing rather than worth hiding.' },

    // --- the identity provider half: what this service ASSERTS ------------
    { name: 'fedApplication', kind: 'single', role: 'identity-provider',
      from: 'this register',
      what: 'THE POINTER, and the whole of what this side stores about the ' +
            'partner: the identifier of its entry in ou=applications. Its ' +
            'entityID, its assertion consumer service, its redirect URIs and ' +
            'its certificate live THERE, where every protocol module already ' +
            'reads them. Copying any of them here would be the two-stores ' +
            'failure this repository is arranged to avoid.' },
    { name: 'fedAuthnMechanism', kind: 'single', role: 'identity-provider',
      from: 'this register', enum: MECHANISM_IDS,
      what: 'HOW THIS SERVICE AUTHENTICATES THE PERSON when this partner ' +
            'asks it to: password, password-mfa, webauthn, spnego — a ' +
            'Kerberos ticket the browser already holds, with no screen at ' +
            'all — wallet — a credential this realm issued, presented from ' +
            'the person\'s wallet — or federation, ' +
            'which sends them on to another relationship and is what makes ' +
            'this service an identity BRIDGE between two protocols. EMPTY ' +
            'MEANS THIS RELATIONSHIP SAYS NOTHING, which is not the same as ' +
            'password: it falls through to appFederationRelationship on the ' +
            'application entry and then to the sign-in screen, which is ' +
            'exactly what every relationship did before this attribute ' +
            'existed.' },
    { name: 'fedAuthnRelationship', kind: 'single',
      role: 'identity-provider', from: 'this register',
      what: 'WHICH RELATIONSHIP THE PERSON IS SENT TO, when the mechanism is ' +
            '`federation`. It names a SERVICE-PROVIDER-side relationship in ' +
            'THIS realm — the register is per realm, so an id from another ' +
            'one names nothing here — and it is checked when it is USED ' +
            'rather than when it is written, because the relationship it ' +
            'names can be disabled or deleted afterwards by somebody who ' +
            'never looked at this entry. Ignored by every other mechanism, ' +
            'and required by this one: readinessOf() names it.' },
    { name: 'fedRelease', kind: 'multi', role: 'identity-provider',
      from: 'this register',
      what: 'WHICH ATTRIBUTES ARE RELEASED TO THIS PARTNER, by claim or ' +
            'attribute name. It FILTERS what /admin/claims, ' +
            '/admin/saml-attributes and the groups claim would otherwise put ' +
            'in an artifact for this audience, and it can touch nothing else ' +
            '— not sub, not iss, not exp, not a NameID. NO VALUES HERE MEANS ' +
            'NO POLICY, not release nothing; see the header, where the ' +
            'difference is argued.' },

    // --- what has happened ------------------------------------------------
    { name: 'fedFirstSeen', kind: 'single', role: 'both', from: 'this register',
      what: 'GeneralizedTime: when this relationship was first USED, which ' +
            'is not when it was created.' },
    { name: 'fedLastSeen', kind: 'single', role: 'both', from: 'this register',
      what: 'GeneralizedTime, the most recent use.' },
    { name: 'fedAuthentications', kind: 'single', role: 'both',
      from: 'this register',
      what: 'How many credentials have crossed this relationship. ASSIGNED ' +
            'on every change — a counter that accumulated values would be ' +
            'nonsense — and it is a live number in a directory entry, which ' +
            'a real directory would not hold.' },
    { name: 'fedUsers', kind: 'single', role: 'both', from: 'this register',
      what: 'How many distinct identities have crossed it. Counted against ' +
            'fedLastUser, so it counts a CHANGE of user rather than a set: ' +
            'right for the ordinary case and an undercount for somebody ' +
            'alternating between two partners. Stated here because it is a ' +
            'number on a page.' },
    { name: 'fedLastUser', kind: 'single', role: 'both', from: 'this register',
      what: 'The most recent identity. On the entry rather than in memory ' +
            'because the entry is the store.' },
    { name: 'fedApplicationUse', kind: 'multi', role: 'service-provider',
      from: 'this register',
      what: 'THE SAME TWO COUNTS, SPLIT BY THE APPLICATION THE SIGN-IN WAS ' +
            'FOR — one value per application, packed as ' +
            '`application|authentications|users|lastUser|lastSeen`. It ' +
            'exists because fedAuthentications answers "how much has crossed ' +
            'this relationship" and the map at /admin/federation/map has to ' +
            'answer "how much has crossed it FOR EACH of the applications ' +
            'configured to use it", which is a different question the moment ' +
            'a second application names the same partner.\n\nIT IS ' +
            'SERVICE-PROVIDER SIDE ONLY, and that is not an omission. An ' +
            'identity-provider-side relationship names exactly ONE ' +
            'application (fedApplication), so its per-application count IS ' +
            'fedAuthentications and a second attribute holding the same ' +
            'number under another name is the copy that comes to ' +
            'disagree.\n\nA VALUE IS WRITTEN ONLY FOR A PAIR THIS SERVICE IS ' +
            'CONFIGURED FOR, checked against the live configuration at the ' +
            'moment of the write rather than trusted from the request — see ' +
            'applicationConfiguredFor(). Without that check this attribute ' +
            'would be an unbounded list of strings anybody who can reach ' +
            '/federation/login/{id} chose, on the one entry in this ' +
            'directory whose contents decide whether an assertion is ' +
            'refused.\n\n`|` IN EITHER FREE-TEXT FIELD IS REPLACED BY `~` ON ' +
            'THE WAY IN, which is the trade this format makes and it is ' +
            'stated rather than discovered: this is a packed counter drawn ' +
            'on a picture, not an identifier anything joins on. The ' +
            'application a row is FILED under is compared in the same packed ' +
            'spelling throughout, so a pair round-trips to itself whatever ' +
            'it is called.' },
    { name: 'fedLastError', kind: 'single', role: 'both', from: 'this register',
      what: 'WHY THE LAST ATTEMPT FAILED, in this service\'s own words. It ' +
            'is the most useful attribute here and it is why refusals are ' +
            'recorded rather than only logged: a federation that does not ' +
            'work fails at somebody else\'s service, and "the signature did ' +
            'not verify against the configured certificate" is the sentence ' +
            'that ends the argument about whose end is broken.' },
    { name: 'fedLastErrorAt', kind: 'single', role: 'both', from: 'this ' +
        'register',
      what: 'GeneralizedTime for the line above. Separate, so that an old ' +
            'error beside a recent success reads as history rather than as ' +
            'the current state.' }
  ]
};

// ---------------------------------------------------------------------------
// WHAT A CONSOLE MAY CHANGE, which is a different question from what an entry
// carries — the same DERIVED-versus-DECLARED split `applications.js` draws, and
// it lands differently here because almost everything on these entries is
// declared.
//
// Everything a relationship is CONFIGURED with is editable. The six counters
// and the two error fields are not: a form that could rewrite them would make
// this page lie about what actually happened, and the lie would be
// indistinguishable from a bug in the recording.
//
// `fedId`, `fedRole` and `fedProtocol` are NOT editable either, and that is a
// third category rather than an oversight. They are the entry's identity: the
// id is the RDN, and the role and the protocol decide which of the fields
// above even apply. Changing one of them on an existing entry would leave a
// SAML relationship carrying a token endpoint, which no form could then draw.
// Delete it and make another; there is no state to lose but the counters.
//
// LDAP can still change every one of them, exactly as it can on an application
// entry, and that is the same line: an operator with an ldapmodify is doing
// something deliberate.
// ---------------------------------------------------------------------------
const EDITABLE = {
  fedName: 'set',
  fedPeer: 'set',
  fedLocalEntityId: 'set',
  fedEnabled: 'set',
  fedSsoUrl: 'set',
  fedTokenUrl: 'set',
  fedUserinfoUrl: 'set',
  fedJwksUri: 'set',
  fedJwks: 'set',
  fedTrustAnchor: 'set',
  fedSigningCertificate: 'set',
  fedClientId: 'set',
  fedClientSecret: 'set',
  fedScope: 'set',
  fedResponseType: 'set',
  fedBinding: 'set',
  fedSignRequest: 'set',
  fedUsernameSource: 'set',
  fedAutocreateUsers: 'set',
  fedUpdateUserAttributes: 'set',
  fedSubjectPolicy: 'set',
  fedSubjectPattern: 'set',
  fedMayAssertAdministrators: 'set',
  fedAllowUnsolicited: 'set',
  fedEncryptionKeyType: 'set',
  fedKeyManagementAlgorithm: 'set',
  fedContentEncryptionAlgorithm: 'set',
  fedAllowUnencrypted: 'set',
  fedSloUrl: 'set',
  fedSloBinding: 'set',
  fedEndSessionUrl: 'set',
  fedAcceptSignout: 'set',
  fedRequireSignedLogout: 'set',
  fedApplication: 'set',
  fedAuthnMechanism: 'set',
  fedAuthnRelationship: 'set',
  fedAttributeMap: 'multi',
  fedSubjectGroup: 'multi',
  fedSubjectDomain: 'multi',
  fedRelease: 'multi',
  description: 'multi'
};

SCHEMA.attributes.forEach(function (row) {
  row.editable = EDITABLE[row.name] || false;
});

const ATTRIBUTE_BY_NAME = {};
SCHEMA.attributes.forEach(function (row) {
  ATTRIBUTE_BY_NAME[row.name] = row;
});

// Every attribute that applies to a relationship in this role, in schema order.
// The console draws its form from this and the action validates against the
// same call, which is what stops a form offering a field the action refuses.
function fieldsForRole(role, mode) {
  log.debug('Entering fieldsForRole(). role=' + role + ', mode=' +
            (mode || 'any'));
  const wanted = String(role || '');
  const rows = SCHEMA.attributes.filter(function (row) {
    if (row.role !== 'both' && row.role !== wanted) return false;
    if (mode) return row.editable === mode;
    return !!row.editable;
  });
  log.debug('Leaving fieldsForRole(). ' + rows.length + ' field(s).');
  return rows;
}

function editableFields(mode) {
  log.debug("Entering editableFields().");
  log.debug("Leaving editableFields().");
  return SCHEMA.attributes.filter(function (row) {
    return mode ? row.editable === mode : !!row.editable;
  });
}

// ---------------------------------------------------------------------------
// THE STORE IS THE DIRECTORY. These are the only ways in and out of it.
//
// `ldap_server.js` fills this at its require time with the same five functions
// the applications registry takes, and the two directions are DELIBERATELY NOT
// SYMMETRICAL for the reason stated there: a WRITE speaks in attribute objects
// because that is all a record has to say, and a READ hands back the whole
// ENTRY because THE DN IS NOT AN ATTRIBUTE.
//
// Without the directory there is no register. It does NOT fall back to a Map:
// a fallback store is a second store, and it would be the one that silently
// disagreed. It says so once in the log and every function below answers empty
// — which means a deployment that never required ldap_server.js has no
// federation, and the sign-in screen simply shows no partners.
// ---------------------------------------------------------------------------
let directory = null;
let warnedAboutNoDirectory = false;

function setDirectory(fns) {
  log.debug('Entering setDirectory().');
  directory = fns || null;
  log.debug('Leaving setDirectory(). The register ' +
            (directory ? 'has its container.' : 'has none.'));
}

function haveDirectory() {
  log.debug('Entering haveDirectory().');
  if (directory) {
    log.debug('Leaving haveDirectory().');
    return true;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('federation: the embedded directory was never loaded, so there ' +
             'is no ou=federations to hold a relationship. Every federation ' +
             'function answers empty and no partner appears on the sign-in ' +
             'screen. This is the ordinary state of an in-process test that ' +
             'requires only app.js and one protocol module; it is not a ' +
             'failure and there is no fallback store, deliberately.');
  }
  log.debug('Leaving haveDirectory().');
  return false;
}

// ---------------------------------------------------------------------------
// A RECORD, AND THE TWO CONVERSIONS THIS MODULE OWNS.
//
// The record is the shape everything above the directory speaks in: a plain
// object with the schema's attribute names as members, single-valued ones
// holding a string and multi-valued ones holding an array. `attributesFor()`
// turns one into what the directory writes and `recordFromAttributes()` turns
// an entry back into one.
//
// EMPTY IS NOT WRITTEN. An attribute with no value is left off the entry
// rather than written as an empty string, because `ldapsearch` shows an empty
// attribute and a reader cannot tell it from a configured blank — and on
// `fedSigningCertificate` those two states are "not configured" and
// "configured to trust nothing", which must not look alike.
// ---------------------------------------------------------------------------
function attributesFor(record) {
  log.debug('Entering attributesFor(). id=' + (record && record.fedId));
  const out = {
    objectClass: ['top', 'applicationProcess', 'stsFederation']
  };
  SCHEMA.attributes.forEach(function (row) {
    if (row.name === 'objectClass') return;
    const value = record[row.name];
    if (value == null) return;
    if (row.kind === 'multi') {
      const values = (Array.isArray(value) ? value : [value])
        .map(function (one) { return String(one); })
        .filter(function (one) { return one !== ''; });
      if (values.length) out[row.name] = values;
      return;
    }
    const single = String(value);
    if (single !== '') out[row.name] = [single];
  });
  log.debug('Leaving attributesFor(). ' + Object.keys(out).length + ' ' +
      'attribute(s).');
  return out;
}

// LDAP attribute names are case-insensitive and the directory hands them back
// canonically spelled, but a caller that has been through an `ldapmodify` may
// have any casing at all. One lookup function, so that a record read back
// through the console and one read back through the register are the same
// record.
function byLowerName(attributes, name) {
  log.debug("Entering byLowerName().");
  const wanted = String(name).toLowerCase();
  const keys = Object.keys(attributes || {});
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === wanted) {
      log.debug("Leaving byLowerName().");
      return attributes[keys[i]];
    }
  }
  log.debug("Leaving byLowerName().");
  return undefined;
}

function recordFromAttributes(attributes) {
  log.debug('Entering recordFromAttributes().');
  const record = {};
  SCHEMA.attributes.forEach(function (row) {
    const values = byLowerName(attributes, row.name);
    if (values === undefined) {
      record[row.name] = row.kind === 'multi' ? [] : '';
      return;
    }
    const list = (Array.isArray(values) ? values : [values])
      .map(function (one) { return String(one); });
    record[row.name] = row.kind === 'multi' ? list : (list[0] || '');
  });
  log.debug('Leaving recordFromAttributes().');
  return record;
}

// TRUE/FALSE on an entry, read the way every other boolean attribute in this
// directory is read. It is a STRING in LDAP, so `'FALSE'` is truthy in
// JavaScript and a naive read makes every relationship enabled — which is the
// one bug in this file that would be silent and would matter.
function boolOf(value, dflt) {
  log.debug("Entering boolOf().");
  const text = String(value == null ? '' : value).trim().toUpperCase();
  if (text === 'TRUE' || text === 'YES' || text === '1' || text === 'ON') {
    log.debug("Leaving boolOf().");
    return true;
  }
  if (text === 'FALSE' || text === 'NO' || text === '0' || text === 'OFF') {
    log.debug("Leaving boolOf().");
    return false;
  }
  log.debug("Leaving boolOf().");
  return !!dflt;
}

function boolText(value) {
  log.debug("Entering boolText().");
  log.debug("Leaving boolText().");
  return value ? 'TRUE' : 'FALSE';
}

function generalizedTime(ms) {
  log.debug("Entering generalizedTime().");
  const d = ms ? new Date(ms) : new Date();
  const pad = function (n, w) {
    log.debug("Entering pad().");
    log.debug("Leaving pad().");
    return String(n).padStart(w || 2, '0');
  };
  log.debug("Leaving generalizedTime().");
  return d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate()) +
    pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + pad(d.getUTCSeconds()) +
    'Z';
}

// ---------------------------------------------------------------------------
// THE ID.
//
// It is the RDN, so it has to be safe in one; it appears in a URL
// (`/federation/login/<id>`), so it has to be safe in one of those too; and it
// is short because it is a label on a button. All three are enforced HERE
// rather than at the three doors, so the console, the management API and an
// `ldapadd` cannot disagree about what an id is.
//
// An `ldapadd` can still create `cn=a+b,ou=federations` with the escaping
// written out by hand, which is the same line `applications.js` draws between
// what a door offers and what it merely does not prevent. Such an entry is
// listed and is never matched by `get()`, which is the honest outcome: the
// register found something it cannot address.
// ---------------------------------------------------------------------------
const ID_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

function idProblem(id) {
  log.debug("Entering idProblem().");
  const text = String(id == null ? '' : id).trim();
  if (!text) {
    log.debug("Leaving idProblem().");
    return 'Name the relationship. An id is required — it is the key, the ' +
           'RDN and the URL segment.';
  }
  if (!ID_SHAPE.test(text)) {
    log.debug("Leaving idProblem().");
    return 'The id "' + text + '" will not do. It has to start with a letter ' +
           'or a digit and hold only letters, digits, dot, dash and ' +
           'underscore, up to 63 characters — it is an RDN and a URL segment ' +
           'as well as a key.';
  }
  log.debug("Leaving idProblem().");
  return '';
}

// ---------------------------------------------------------------------------
// READING THE REGISTER.
// ---------------------------------------------------------------------------
function list() {
  log.debug('Entering list().');
  if (!haveDirectory()) {
    log.debug('Leaving list(). There is no directory.');
    return [];
  }
  const rows = directory.allFederations().map(function (entry) {
    const record = recordFromAttributes(entry.attributes);
    record.dn = entry.dn;
    record.createdAt = entry.createdAt || '';
    record.modifiedAt = entry.modifiedAt || '';
    record.entry = entry;
    return record;
  });
  // By id, so the console's list, the management API's list and an ldapsearch
  // in tree order are three views of one order rather than three orders.
  rows.sort(function (a, b) {
    return String(a.fedId).localeCompare(String(b.fedId));
  });
  log.debug('Leaving list(). ' + rows.length + ' relationship(s).');
  return rows;
}

function get(id) {
  log.debug('Entering get(). id=' + id);
  if (!haveDirectory()) {
    log.debug('Leaving get(). There is no directory.');
    return null;
  }
  const entry = directory.readFederation(String(id || ''));
  if (!entry) {
    log.debug('Leaving get(). Not here.');
    return null;
  }
  const record = recordFromAttributes(entry.attributes);
  record.dn = entry.dn;
  record.createdAt = entry.createdAt || '';
  record.modifiedAt = entry.modifiedAt || '';
  record.entry = entry;
  log.debug('Leaving get(). Found ' + record.dn + '.');
  return record;
}

function count() {
  log.debug("Entering count().");
  log.debug("Leaving count().");
  return haveDirectory() ? directory.countFederations() : 0;
}

function containerDn() {
  log.debug("Entering containerDn().");
  log.debug("Leaving containerDn().");
  return haveDirectory() ? directory.containerDn() : '';
}

// ---------------------------------------------------------------------------
// THE PEOPLE A PARTNER'S SUBJECTS ARE LINKED TO (#109), through the same slot.
//
// These five are PERSON questions asked of a register that is otherwise about
// relationships, and they are here rather than behind a slot of their own
// because the object `ldap_server.js` hands `setDirectory()` already IS this
// module's door into the directory: a second slot would be a second door for
// one caller, which is rule 3e's test failed rather than passed. What a link
// IS lives in `federation_links.ts`; what these answer is where the values are.
//
//   federatedPerson(name)      the entry a name finds — its DN, mail, links
//                              and groups — or null
//   peopleLinkedBy(value)      every person carrying that federationLink
//   linkedThrough(fedId)       every link made through one relationship
//   plannedPersonDn(name)      the DN an entry created for `name` would get
//   writeFederationLink(...)   add or remove one value on one person
// ---------------------------------------------------------------------------
function directoryHas(fn) {
  log.debug("Entering directoryHas().");
  log.debug("Leaving directoryHas().");
  return haveDirectory() && typeof directory[fn] === 'function';
}

function federatedPerson(name) {
  log.debug("Entering federatedPerson().");
  log.debug("Leaving federatedPerson().");
  return directoryHas('federationPerson')
    ? directory.federationPerson(String(name || '')) : null;
}

function peopleLinkedBy(value) {
  log.debug("Entering peopleLinkedBy().");
  log.debug("Leaving peopleLinkedBy().");
  return directoryHas('peopleByFederationLink')
    ? directory.peopleByFederationLink(String(value || '')) : [];
}

function linkedThrough(fedId) {
  log.debug("Entering linkedThrough().");
  log.debug("Leaving linkedThrough().");
  return directoryHas('federationLinksThrough')
    ? directory.federationLinksThrough(String(fedId || '')) : [];
}

function plannedPersonDn(name) {
  log.debug("Entering plannedPersonDn().");
  log.debug("Leaving plannedPersonDn().");
  return directoryHas('plannedPersonDn')
    ? directory.plannedPersonDn(String(name || '')) : '';
}

function writeFederationLink(name, value, add, options) {
  log.debug("Entering writeFederationLink(). add=" + !!add);
  if (!directoryHas('writeFederationLink')) {
    log.debug("Leaving writeFederationLink(). No directory.");
    return errorCodes.mark({ ok: false, errors: ['There is no embedded ' +
      'directory loaded, so there is nobody to link.'] }, 'STS-FED-0109');
  }
  log.debug("Leaving writeFederationLink().");
  return directory.writeFederationLink(String(name || ''), String(value || ''),
                                       !!add, options || {});
}

function maxRelationships() {
  log.debug("Entering maxRelationships().");
  log.debug("Leaving maxRelationships().");
  return haveDirectory() ? directory.maxFederations() : 0;
}

// ---------------------------------------------------------------------------
// IS THIS RELATIONSHIP USABLE?
//
// Two different questions and both of them are asked, which is why this
// returns a list of reasons rather than a boolean:
//
//   * ENABLED is what an operator decided.
//   * READY is whether the fields the protocol needs are actually filled in,
//     read off `PROTOCOLS[].needs` so the form's rule and the endpoint's rule
//     are one list.
//
// A relationship that is enabled and not ready is the interesting state and it
// is REPORTED rather than silently skipped: it is what somebody who has just
// half-configured a partner is looking at, and "nothing happened" is the worst
// possible answer for them.
// ---------------------------------------------------------------------------
function readinessOf(record) {
  log.debug('Entering readinessOf(). id=' + (record && record.fedId));
  const missing = [];
  if (!record) {
    log.debug('Leaving readinessOf(). There is no relationship.');
    return { ready: false, missing: ['the relationship does not exist'] };
  }
  if (record.fedRole === 'service-provider' &&
      record.fedProtocol === 'oidc' &&
      String(record.fedTrustAnchor || '').trim()) {
    // DISCOVERED THROUGH THE FEDERATION (#134): the OP and the anchor are
    // the whole configuration; what the chain does not vouch for is refused
    // at the sign-in, by name (oidfed/oidfed_rp.ts). The authorization code
    // flow only — automatic registration signs the request, and an ID Token
    // on the front channel would carry no client authentication at all.
    if (!String(record.fedPeer || '').trim()) {
      missing.push('fedPeer');
    }
    if (String(record.fedResponseType || 'code') !== 'code') {
      missing.push('fedResponseType=code (an OP discovered through a Trust ' +
                   'Chain is used with the authorization code flow)');
    }
  } else if (record.fedRole === 'service-provider') {
    const row = protocolRow(record.fedProtocol);
    const needs = row ? row.needs : [];
    needs.forEach(function (name) {
      if (!String(record[name] || '').trim()) missing.push(name);
    });
    // The two OIDC shapes need different things and the difference is exactly
    // what fedResponseType selects, so it cannot be a static list on the
    // protocol row. `code` needs somewhere to redeem the code; `id_token`
    // needs a key to verify it with and needs no back channel at all.
    if (record.fedProtocol === 'oidc') {
      if (String(record.fedResponseType || 'code') === 'code') {
        if (!String(record.fedTokenUrl || '').trim()) missing.push(
            'fedTokenUrl');
      } else if (!String(record.fedJwks || '').trim() &&
                 !String(record.fedJwksUri || '').trim()) {
        missing.push('fedJwks or fedJwksUri');
      }
    }
    // A JWT from an OAuth 2.0 partner is verified against a key like any
    // other, and an OPAQUE one cannot be read at all — so a plain OAuth 2.0
    // relationship needs either keys or a userinfo endpoint, and the message
    // says which two rather than naming one and leaving the other to be found.
    if (record.fedProtocol === 'oauth2' &&
        !String(record.fedJwks || '').trim() &&
        !String(record.fedJwksUri || '').trim() &&
        !String(record.fedUserinfoUrl || '').trim()) {
      missing.push('fedUserinfoUrl (or fedJwks / fedJwksUri, if the access ' +
                   'token is a JWT)');
    }
  }
  // THE KEY A PARTNER HAS TO ENCRYPT TO (#168), where plaintext would be
  // refused: without one nothing could be accepted, which is a relationship
  // that half-works — refused by name like any other missing field.
  if (encryptionRequired(record) && !currentEncryptionKeyOf(record)) {
    missing.push('fedEncryptionKey (rotate the encryption key to issue one)');
  }
  if (record.fedRole === 'identity-provider') {
    if (!String(record.fedApplication || '').trim()) {
      missing.push('fedApplication');
    }
    // The mechanism is OPTIONAL — an empty one means this relationship says
    // nothing and the sign-in falls through exactly as it always did — but a
    // mechanism of `federation` with nowhere to send anybody is the
    // half-configured state this register refuses on principle, so it is
    // named here rather than discovered at the sign-in screen.
    const mechanism = String(record.fedAuthnMechanism || '').trim();
    if (mechanism && !mechanismRow(mechanism)) {
      missing.push('fedAuthnMechanism ("' + mechanism + '" is not one of ' +
                   MECHANISM_IDS.join(', ') + ')');
    }
    if (mechanism === 'federation' &&
        !String(record.fedAuthnRelationship || '').trim()) {
      missing.push('fedAuthnRelationship');
    }
  }
  log.debug('Leaving readinessOf(). ' + (missing.length ? missing.length + ' ' +
      'field(s) missing.'
                                                        : 'Ready.'));
  return { ready: missing.length === 0, missing: missing };
}

// ---------------------------------------------------------------------------
// ENCRYPTION (#168): what a relationship's four fields MEAN, read in one
// place so that the console, the metadata, the decryption and the readiness
// check cannot disagree about the default.
// ---------------------------------------------------------------------------
function encrypts(record) {
  log.debug("Entering encrypts().");
  log.debug("Leaving encrypts().");
  return !!record && record.fedRole === 'service-provider' &&
         ENCRYPTING_PROTOCOLS.indexOf(record.fedProtocol) >= 0;
}

// `xml` for SAML 2.0 and WS-Federation, `jose` for OpenID Connect.
function encryptionFamilyOf(record) {
  log.debug("Entering encryptionFamilyOf().");
  log.debug("Leaving encryptionFamilyOf().");
  return record && record.fedProtocol === 'oidc' ? 'jose' : 'xml';
}

function defaultKeyTypeFor(protocol) {
  log.debug("Entering defaultKeyTypeFor().");
  log.debug("Leaving defaultKeyTypeFor().");
  return protocol === 'oidc' ? 'ec-p256' : 'rsa-3072';
}

function defaultManagementFor(family, keyType) {
  log.debug("Entering defaultManagementFor().");
  const ec = keyType === 'ec-p256';
  log.debug("Leaving defaultManagementFor().");
  return family === 'jose' ? (ec ? 'ECDH-ES' : 'RSA-OAEP-256')
                           : (ec ? 'ecdh-es' : 'rsa-oaep');
}

// `{ family, keyType, management, content }`, each the field or its default.
// A stored value the vocabulary no longer holds (only an ldapmodify writes
// one) reads as the DEFAULT — the strictest reading there is, since every
// default is also the strongest choice.
function encryptionPolicyOf(record) {
  log.debug("Entering encryptionPolicyOf().");
  const family = encryptionFamilyOf(record);
  const typed = String((record && record.fedEncryptionKeyType) || '').trim();
  const keyType = ENCRYPTION_KEY_TYPES.indexOf(typed) >= 0 ? typed
    : defaultKeyTypeFor(record && record.fedProtocol);
  const managed = String((record && record.fedKeyManagementAlgorithm) || '')
    .trim();
  const managementList = family === 'jose' ? JOSE_KEY_MANAGEMENT
                                           : XML_KEY_MANAGEMENT;
  const management = managementList.indexOf(managed) >= 0 &&
      MANAGEMENT_FOR_KEY[keyType].indexOf(managed) >= 0
    ? managed : defaultManagementFor(family, keyType);
  const contentList = family === 'jose' ? JOSE_CONTENT_ENCRYPTION
                                        : XML_CONTENT_ENCRYPTION;
  const contentTyped = String((record &&
                               record.fedContentEncryptionAlgorithm) || '')
    .trim();
  const content = contentList.indexOf(contentTyped) >= 0 ? contentTyped
                                                         : contentList[0];
  log.debug("Leaving encryptionPolicyOf(). " + family + " " + keyType + " " +
            management + " " + content);
  return { family: family, keyType: keyType, management: management,
           content: content };
}

// THE KEY TABLE, parsed. A row that does not parse is dropped with a line in
// the log: it decrypts nothing and publishes nothing either way.
function encryptionKeysOf(record) {
  log.debug("Entering encryptionKeysOf().");
  const rows = [];
  ((record && record.fedEncryptionKey) || []).forEach(function (value) {
    try {
      const row = JSON.parse(String(value));
      if (row && row.kid && row.certificate) {
        rows.push(row);
      }
    } catch (e) {
      log.warn('federation: ' + ((record && record.fedId) || '') + ' holds ' +
               'a fedEncryptionKey value that is not JSON, and it is ' +
               'ignored: ' + ((e && e.message) || e));
    }
  });
  log.debug("Leaving encryptionKeysOf(). " + rows.length + " row(s).");
  return rows;
}

// The same rows WITHOUT the private key — what any page, API reply or log may
// carry.
function encryptionKeyView(record) {
  log.debug("Entering encryptionKeyView().");
  const out = encryptionKeysOf(record).map(function (row) {
    const view = Object.assign({}, row);
    delete view.privateKey;
    return view;
  });
  log.debug("Leaving encryptionKeyView().");
  return out;
}

function currentEncryptionKeyOf(record) {
  log.debug("Entering currentEncryptionKeyOf().");
  log.debug("Leaving currentEncryptionKeyOf().");
  return encryptionKeysOf(record).filter(function (row) {
    return row.state === 'current';
  })[0] || null;
}

// Does THIS response have to be encrypted? Only where it crosses the browser
// — a SAML 2.0 Response, a WS-Federation wresult, an id_token by form_post —
// and only in product, where `fedAllowUnencrypted` is the one way out. An ID
// Token redeemed at the partner's token endpoint comes over TLS from the
// partner and is not the exposure this closes. See mode.js.
function encryptionRequired(record) {
  log.debug("Entering encryptionRequired().");
  if (!encrypts(record)) {
    log.debug("Leaving encryptionRequired(). Not an encrypting protocol.");
    return false;
  }
  const frontChannel = record.fedProtocol !== 'oidc' ||
    String(record.fedResponseType || 'code') !== 'code';
  log.debug("Leaving encryptionRequired().");
  return frontChannel && !mode.acceptsUnencryptedFederatedAssertions() &&
         !boolOf(record.fedAllowUnencrypted, false);
}

// The four fields' values a write may NOT hold, or null.
function encryptionFieldProblem(record, field, value) {
  log.debug("Entering encryptionFieldProblem(). field=" + field);
  const fields = ['fedEncryptionKeyType', 'fedKeyManagementAlgorithm',
                  'fedContentEncryptionAlgorithm', 'fedAllowUnencrypted'];
  if (fields.indexOf(field) < 0) {
    log.debug("Leaving encryptionFieldProblem(). Not an encryption field.");
    return null;
  }
  if (!encrypts(record)) {
    log.debug("Leaving encryptionFieldProblem(). Not an encrypting protocol.");
    return { code: 'STS-FED-0143',
             why: field + ' applies to SAML 2.0, WS-Federation and OpenID ' +
                  'Connect only',
             message: field + ' applies to a SAML 2.0, WS-Federation or ' +
                      'OpenID Connect relationship. SAML 1.1 has no ' +
                      'encryption construct and a plain OAuth 2.0 ' +
                      'relationship reads no ID Token.' };
  }
  if (value === '' || field === 'fedAllowUnencrypted') {
    log.debug("Leaving encryptionFieldProblem(). Empty or a switch.");
    return null;
  }
  if (REFUSED_ALGORITHMS.indexOf(value) >= 0) {
    log.debug("Leaving encryptionFieldProblem(). A refused algorithm.");
    return { code: 'STS-FED-0139',
             why: value + ' is refused in every mode',
             message: value + ' is refused in every mode: ' +
                      (/cbc/i.test(value)
                        ? 'AES-CBC in XML Encryption is a padding oracle ' +
                          '(Jager and Somorovsky, 2011), and every partner ' +
                          'that has it has GCM'
                        : 'RSAES-PKCS1-v1_5 is Bleichenbacher\'s ' +
                          'decryption oracle (XML Encryption 1.1 section ' +
                          '6.1.2, RFC 8017)') + '.' };
  }
  const family = encryptionFamilyOf(record);
  const allowed = field === 'fedEncryptionKeyType' ? ENCRYPTION_KEY_TYPES
    : field === 'fedKeyManagementAlgorithm'
      ? (family === 'jose' ? JOSE_KEY_MANAGEMENT : XML_KEY_MANAGEMENT)
      : (family === 'jose' ? JOSE_CONTENT_ENCRYPTION
                           : XML_CONTENT_ENCRYPTION);
  if (allowed.indexOf(value) < 0) {
    log.debug("Leaving encryptionFieldProblem(). Not in the vocabulary.");
    return { code: 'STS-FED-0143',
             why: '"' + value + '" is not a ' + field + ' for this protocol',
             message: '"' + value + '" is not a ' + field + ' for ' +
                      (family === 'jose' ? 'an OpenID Connect' :
                       'a SAML 2.0 or WS-Federation') + ' relationship. It ' +
                      'is one of ' + allowed.join(', ') + '.' };
  }
  if (field === 'fedKeyManagementAlgorithm' &&
      MANAGEMENT_FOR_KEY[encryptionPolicyOf(record).keyType]
        .indexOf(value) < 0) {
    log.debug("Leaving encryptionFieldProblem(). The wrong key type.");
    return { code: 'STS-FED-0143',
             why: value + ' does not fit a ' +
                  encryptionPolicyOf(record).keyType + ' key',
             message: value + ' cannot be done with this relationship\'s ' +
                      encryptionPolicyOf(record).keyType + ' key. Set ' +
                      'fedEncryptionKeyType first; it is one of ' +
                      MANAGEMENT_FOR_KEY[encryptionPolicyOf(record).keyType]
                        .join(', ') + ' for this key.' };
  }
  log.debug("Leaving encryptionFieldProblem(). Nothing wrong.");
  return null;
}

// THE ONE WRITER OF THE KEY TABLE, for `federation_encryption.ts`: rotate,
// issue and retire. `rows` are whole rows, private keys included, as they are
// to be stored; `why` is the audit sentence.
function writeEncryptionKeys(id, rows, why) {
  log.debug("Entering writeEncryptionKeys(). id=" + id);
  const record = get(id);
  if (!record) {
    log.debug("Leaving writeEncryptionKeys(). No such relationship.");
    return false;
  }
  record.fedEncryptionKey = rows.map(function (row) {
    return JSON.stringify(row);
  });
  if (!persist(record)) {
    log.debug("Leaving writeEncryptionKeys(). The directory refused it.");
    return false;
  }
  recordChange('federation.encryption-key', record,
               why + ' on the federation relationship ' + id,
               { keys: rows.map(function (row) {
                   return row.kid + ':' + row.state;
                 }).join(', ') });
  log.debug("Leaving writeEncryptionKeys().");
  return true;
}

function isEnabled(record) {
  log.debug("Entering isEnabled().");
  log.debug("Leaving isEnabled().");
  return !!record && boolOf(record.fedEnabled, false);
}

function isUsable(record) {
  log.debug("Entering isUsable().");
  log.debug("Leaving isUsable().");
  return isEnabled(record) && readinessOf(record).ready;
}

// Every relationship in one role, usable or not. The callers want different
// halves of that — the sign-in screen wants the usable ones and the console
// wants all of them — so the filter is the caller's rather than being baked in
// here, and there is one list function rather than two that could drift.
function inRole(role) {
  log.debug("Entering inRole().");
  const wanted = String(role || '');
  log.debug("Leaving inRole().");
  return list().filter(function (record) { return record.fedRole === wanted; });
}

// HOW A RELATIONSHIP IS DESCRIBED ON A PAGE SOMEBODY CHOOSES FROM, in one
// place. Three pages draw a partner now — the buttons at the foot of the
// sign-in screen, the same buttons narrowed to one application's own partners,
// and the chooser at /authn/select-idp — and the fields they show are the same
// three because they are the three a person picking between two partners needs:
// what it is called, which protocol it speaks (a SAML 2.0 partner and an
// OpenID Connect one are the ordinary pair, and they look identical without
// it), and who is at the far end.
//
// It is HERE and not in authn.js because the register owns what a relationship
// IS. A second description assembled in the sign-in path would be the copy that
// stopped matching the day fedName gained a fallback.
function optionOf(record) {
  log.debug("Entering optionOf().");
  log.debug("Leaving optionOf().");
  return {
    id: record.fedId,
    label: record.fedName || record.fedId,
    protocol: record.fedProtocol,
    protocolLabel: (protocolRow(record.fedProtocol) ||
                    {}).label || record.fedProtocol,
    peer: record.fedPeer
  };
}

// What the sign-in screen offers: the service-provider-side relationships that
// would actually work if somebody clicked them. A button that led to a refusal
// would be worse than no button, which is why this is `isUsable` and not
// `isEnabled`.
function signInOptions() {
  log.debug('Entering signInOptions().');
  const rows = inRole('service-provider').filter(isUsable).map(optionOf);
  log.debug('Leaving signInOptions(). ' + rows.length +
            ' partner(s) to offer.');
  return rows;
}

// ---------------------------------------------------------------------------
// A SERVICE-PROVIDER-SIDE RELATIONSHIP THAT WOULD ACTUALLY WORK, and the four
// checks that decide it.
//
// TWO CALLERS AND ONE IMPLEMENTATION, which is the whole reason this is here
// rather than in either of them. `usableServiceProviders()` below asks it of
// every id on an APPLICATION entry (`appFederationRelationship`, which holds a
// list) and authenticationFor() asks it of the id on a RELATIONSHIP
// (`fedAuthnRelationship`). Both are a string somebody typed into a directory
// attribute, both name a relationship that can be disabled or deleted
// afterwards by somebody who never looked at the entry pointing at it, and
// both must refuse LOUDLY rather than fall back to a password box — a
// federated application authenticating people locally looks exactly like a
// federated application working.
//
// EVERY CHECK IS MADE HERE RATHER THAN AT THE WRITE, for that reason: a check
// made when the pointer was written would be a check about the past.
//
// `subject` is how the caller says what is doing the naming, because the
// operator reading the message needs to know WHICH entry to go and fix and
// the two callers are looking at different pages. It is interpolated into
// every message and nothing else is.
// ---------------------------------------------------------------------------
function usableServiceProvider(id, subject) {
  log.debug('Entering usableServiceProvider(). id=' + (id || '(none)'));
  const named = String(id || '').trim();
  const who = String(subject || 'Something here');
  if (!named) {
    log.debug('Leaving usableServiceProvider(). Nothing is named.');
    return { id: '', relationship: null, problem: '' };
  }
  const record = get(named);
  if (!record) {
    log.debug('Leaving usableServiceProvider(). No such relationship.');
    return { id: named, relationship: null,
             problem: who + ' is configured to authenticate through the ' +
                      'federation relationship "' + named + '", and there is ' +
                      'no such relationship in this trust realm.' };
  }
  if (record.fedRole !== 'service-provider') {
    log.debug('Leaving usableServiceProvider(). It goes the other way.');
    return { id: named, relationship: null,
             problem: who + ' names the federation relationship "' + named +
                      '", which is identity-provider-side: this service ' +
                      'ASSERTS to that partner rather than consuming from ' +
                      'it, so there is nothing to sign in to there.' };
  }
  if (!isEnabled(record)) {
    log.debug('Leaving usableServiceProvider(). It is disabled.');
    return { id: named, relationship: null,
             problem: who + ' authenticates through the federation ' +
                      'relationship "' + named + '", which is DISABLED. ' +
                      'Every relationship is created disabled deliberately; ' +
                      'enable it on /admin/federation.' };
  }
  const readiness = readinessOf(record);
  if (!readiness.ready) {
    log.debug('Leaving usableServiceProvider(). Not fully configured.');
    return { id: named, relationship: null,
             problem: who + ' authenticates through the federation ' +
                      'relationship "' + named + '", which is enabled and ' +
                      'not fully configured: ' + readiness.missing.join(', ') +
                      ' still to set.' };
  }
  log.debug('Leaving usableServiceProvider(). ' + named + ' is usable.');
  return { id: named, relationship: record, problem: '' };
}

// ---------------------------------------------------------------------------
// THE SAME QUESTION ASKED OF A LIST, and it is a function rather than a loop
// at the call site for one reason: WHAT IT DOES WITH THE UNUSABLE ONES.
//
// An application entry may name several service-provider-side relationships
// (`appFederationRelationship` is multi-valued since 2026-08-26), and the
// tempting shape is `ids.map(usableServiceProvider).filter(usable)`. That
// shape loses the thing an operator needs: a list of three whose middle value
// names a DISABLED relationship then draws two buttons and says nothing, which
// is indistinguishable from a list of two. So every value is resolved and the
// unusable ones are KEPT, each with the sentence usableServiceProvider() wrote
// about it, and the caller decides where to print them.
//
// DUPLICATES ARE COLLAPSED and the order of first appearance is kept. Nothing
// stops `ldapmodify` writing one id twice — the directory's own multi-valued
// semantics deduplicate at the attribute level, but a caller may hand us a
// list from anywhere — and two identical buttons is a page that looks broken.
//
// EMPTY IN, EMPTY OUT, with no problem reported. A relationship id list with
// nothing in it is the state every application in this registry is in, and
// calling that a misconfiguration would put an error banner on every sign-in
// screen in the service.
// ---------------------------------------------------------------------------
function usableServiceProviders(ids, subject) {
  log.debug('Entering usableServiceProviders(). ' +
            (Array.isArray(ids) ? ids.length : (ids ? 1 : 0)) + ' named.');
  const wanted = (Array.isArray(ids) ? ids : [ids])
    .map(function (one) { return String(one == null ? '' : one).trim(); })
    .filter(Boolean);
  const seen = {};
  const rows = [];
  wanted.forEach(function (id) {
    if (seen[id]) {
      log.info('federation: "' + String(subject || 'something here') + '" ' +
               'names the federation relationship ' +
               '"' + id + '" more than once. It ' +
               'is offered once — two identical buttons is a page that looks ' +
               'broken — and the duplicate is a configuration to tidy rather ' +
               'than a rule this service applies.');
      return;
    }
    seen[id] = true;
    const one = usableServiceProvider(id, subject);
    rows.push({ id: one.id, relationship: one.relationship,
                problem: one.problem,
                option: one.relationship ? optionOf(one.relationship) : null });
  });
  const usable = rows.filter(function (one) { return !!one.relationship; });
  log.debug('Leaving usableServiceProviders(). ' + usable.length + ' of ' +
            rows.length + ' usable.');
  return { all: rows, usable: usable,
           problems: rows.filter(function (one) { return !!one.problem; })
                         .map(function (one) { return one.problem; }) };
}

// ---------------------------------------------------------------------------
// THE IDENTITY-PROVIDER-SIDE RELATIONSHIP NAMING AN APPLICATION, or null.
//
// A LINEAR WALK AND NOT AN INDEX, deliberately, and the reason is the one
// releaseIndexNow() gives for rebuilding rather than maintaining: there are
// four doors onto these entries — this module, the console, the management
// API and an ldapmodify — and an index this module kept up to date would be
// wrong exactly when somebody had just edited the entry by hand. This runs
// once per sign-in over a register an operator configured by hand, which is
// tens of rows and not thousands; the release filter is the one that runs per
// TOKEN, and that one is indexed.
//
// FIRST MATCH WINS, and two relationships naming one application is a
// misconfiguration this cannot resolve — so it is LOGGED at warn rather than
// picked over silently. `fedApplication` is one direction of a pointer and
// nothing enforces uniqueness on it: the identity-provider half deliberately
// stores nothing but that string.
//
// A DISABLED RELATIONSHIP IS SKIPPED, which is a change in what a disabled
// identity-provider-side relationship MEANS and is worth saying out loud.
// Until this attribute existed it meant nothing at all — every protocol
// endpoint here answers a partner whether or not a relationship names it, so
// the flag governed only the release list. It now also governs the mechanism,
// and skipping is the safe direction: falling through to the password screen
// is what the service did before anybody configured this.
// ---------------------------------------------------------------------------
function identityProviderFor(applicationId) {
  log.debug('Entering identityProviderFor(). application=' +
            (applicationId || '(none)'));
  const wanted = String(applicationId || '').trim();
  if (!wanted) {
    log.debug('Leaving identityProviderFor(). No application was named.');
    return null;
  }
  const rows = inRole('identity-provider').filter(function (record) {
    return String(record.fedApplication || '').trim() === wanted &&
           isEnabled(record);
  });
  if (!rows.length) {
    log.debug('Leaving identityProviderFor(). Nothing names it.');
    return null;
  }
  if (rows.length > 1) {
    log.warn('federation: ' + rows.length + ' enabled identity-provider-side ' +
             'relationships name the application "' + wanted + '" (' +
             rows.map(function (r) { return r.fedId; }).join(', ') + '). ' +
             'Nothing enforces one, so the FIRST is used and the rest are ' +
             'ignored — which is a configuration to fix rather than a rule ' +
             'this service applies.');
  }
  log.debug('Leaving identityProviderFor(). ' + rows[0].fedId + '.');
  return rows[0];
}

// ---------------------------------------------------------------------------
// WHAT AN IDENTITY-PROVIDER-SIDE RELATIONSHIP SAYS TO DO, resolved.
//
// Returns null when it says nothing, which is the ordinary case and the one
// every relationship created before `fedAuthnMechanism` existed is in. A
// caller that gets null must behave exactly as it did before this function —
// see mechanismFor() in authn.js, which is the only caller.
//
// A PROBLEM IS RETURNED RATHER THAN THROWN AND RATHER THAN SWALLOWED. This
// runs on the way to a sign-in screen, so it must not be able to cost the
// screen; and a relationship configured to broker to a partner that is
// disabled must say so on that screen rather than quietly asking for a
// password, which is the same argument authn.js's federationFor() makes at
// length.
// ---------------------------------------------------------------------------
function authenticationFor(record) {
  log.debug('Entering authenticationFor(). id=' +
            ((record && record.fedId) || '(none)'));
  if (!record) {
    log.debug('Leaving authenticationFor(). There is no relationship.');
    return null;
  }
  const mechanism = String(record.fedAuthnMechanism || '').trim();
  if (!mechanism) {
    log.debug('Leaving authenticationFor(). It declares no mechanism.');
    return null;
  }
  const row = mechanismRow(mechanism);
  if (!row) {
    log.debug('Leaving authenticationFor(). The mechanism is not one of ours.');
    return { via: record.fedId, mechanism: '', label: '', relationship: null,
             problem: 'The federation relationship "' + record.fedId +
                      '" configures the authentication mechanism "' +
                      mechanism + '", which is not one this service has: ' +
                      'they are ' + MECHANISM_IDS.join(', ') + '.' };
  }
  if (mechanism !== 'federation') {
    log.debug('Leaving authenticationFor(). ' + mechanism + '.');
    return { via: record.fedId, mechanism: mechanism, label: row.label,
             relationship: null, problem: '' };
  }
  const onward = usableServiceProvider(
    record.fedAuthnRelationship,
    'The federation relationship "' + record.fedId + '"');
  if (!onward.id) {
    log.debug('Leaving authenticationFor(). No onward relationship is named.');
    return { via: record.fedId, mechanism: mechanism, label: row.label,
             relationship: null,
             problem: 'The federation relationship "' + record.fedId +
                      '" authenticates through another federation ' +
                      'relationship and names none. Set ' +
                      'fedAuthnRelationship on it.' };
  }
  log.debug('Leaving authenticationFor(). federation via ' + onward.id + '.');
  return { via: record.fedId, mechanism: mechanism, label: row.label,
           onward: onward.id, relationship: onward.relationship,
           problem: onward.problem };
}

// ---------------------------------------------------------------------------
// THE RELEASE FILTER — the identity-provider half, and the only thing in this
// module anything outside `federation/` calls on the ISSUING path.
//
// `admin_stats.js` asks it, at `jwtClaims()` and `samlAttributes()`, with the
// context those two already build. It answers `null` for "no policy, change
// nothing" and a Set for "these names and no others".
//
// It looks the partner up by `client_id` FIRST and by `audience` second, and
// the order matters: an ID Token carries both, and the client_id is the exact
// identifier an application entry is filed under while the audience may be a
// space-joined list. A SAML context has only the audience, which is the
// entityID, and that is the application identifier for a service provider.
//
// IT MUST NOT THROW AND MUST NOT BE SLOW. It runs on every token and every
// assertion this service issues, so the early return for an empty register is
// the ordinary path and is deliberately the first line.
// ---------------------------------------------------------------------------
//
// **PER TRUST REALM SINCE 2026-09-12.** It was two `let`s for the process, and
// the register it indexes is not: `inRole()` reads the AMBIENT realm's
// `ou=federations`, so the index was built out of whichever realm issued the
// first token in a five-second window and then applied to every token in every
// realm for the rest of it — a partner's release list in `acme` filtering the
// claims of an unrelated application in the default realm, or a default-realm
// partner's list not being applied at all because acme had built the index.
// `realms.keyed()` is one index per realm, built out of that realm's register.
//
// Invalidation clears EVERY realm's, which is broader than it needs to be and
// is the right trade: the four writers below are inside a request whose realm
// they could name, and `recordUse()` is too, but an index that is rebuilt a
// little early costs one walk of a small register while one that is not
// invalidated is a release policy that lags an edit.
const releaseIndexes = realms.keyed(function () {
  return { index: null, at: 0 };
});

function forgetReleaseIndexes() {
  log.debug("Entering forgetReleaseIndexes().");
  releaseIndexes.existing().forEach(function (held) {
    held.index = null;
  });
  log.debug("Leaving forgetReleaseIndexes().");
}

// The index is rebuilt rather than kept up to date, on a short timer, and both
// halves of that are deliberate. Rebuilt, because there are four doors onto
// these entries — the console, the management API, an ldapmodify and an
// ldapadd — and only two of them come through this module, so an index this
// module maintained would be wrong exactly when somebody had just edited the
// entry by hand. On a timer, because the alternative is walking the register on
// every token issued. Five seconds is short enough that nobody testing a
// release list notices and long enough that a load test does not walk a
// directory per token.
//
// `federation.releaseIndexTtlMs` since 2026-09-12; it was the constant 5000.
// Read per call, so 0 — rebuild on every token — is a value somebody can set
// while watching a release list take effect.
function releaseIndexTtlMs() {
  log.debug("Entering releaseIndexTtlMs().");
  log.debug("Leaving releaseIndexTtlMs().");
  return Number(config.value('federation.releaseIndexTtlMs'));
}

// Described to `/admin/caches` (#74, rule 3ap): one row per realm holding an
// index, which is the whole cache for that realm.
const releaseIndexCount = cacheRegistry.register({
  name: 'federation.release-index',
  title: 'Federation attribute-release index',
  description: 'Which partner\'s release list applies to which ' +
    'application, built from ou=federations so a token issue does not walk ' +
    'the register. One index per realm.',
  owner: 'federation/federation.js',
  scope: 'realm',
  settings: ['federation.releaseIndexTtlMs'],
  maxEntries: function () {
    return 1;
  },
  bound: 'Structural: one index per realm, holding one entry per ' +
    'application with a release list.',
  lifetime: function () {
    return 'federation.releaseIndexTtlMs (' + releaseIndexTtlMs() +
      ' ms) after it was built, or at once when a federation ' +
      'relationship is written through this service.';
  },
  // A realm's index past its lifetime, which `releaseIndexNow()` would
  // rebuild: dropped, and rebuilt at the next use (#49 P5).
  eject: function (now) {
    let dropped = 0;
    const ttl = releaseIndexTtlMs();
    releaseIndexes.existing().forEach(function (held) {
      if (held && held.index && now - held.at >= ttl) {
        held.index = null;
        dropped += 1;
      }
    });
    return dropped;
  },
  entries: function () {
    const out = [];
    releaseIndexes.existing().forEach(function (held, id) {
      if (!held.index) {
        return;
      }
      out.push({ realm: id,
                 key: held.index.size + ' application(s) with a release list',
                 validUntil: held.at + releaseIndexTtlMs() });
    });
    return out;
  }
});

function releaseIndexNow() {
  log.debug('Entering releaseIndexNow().');
  const now = Date.now();
  const held = releaseIndexes();
  if (held.index && now - held.at < releaseIndexTtlMs()) {
    releaseIndexCount.hit();
    log.debug('Leaving releaseIndexNow().');
    return held.index;
  }
  releaseIndexCount.miss();
  const index = new Map();
  inRole('identity-provider').forEach(function (record) {
    if (!isEnabled(record)) return;
    const application = String(record.fedApplication || '').trim();
    const names = (record.fedRelease || []).map(function (
        one) { return String(one).trim(); })
      .filter(function (one) { return one !== ''; });
    // NO VALUES MEANS NO POLICY. See the header: a partner registered with no
    // release list must receive exactly what it received the day before.
    if (!application || !names.length) return;
    index.set(application, { id: record.fedId, names: new Set(names) });
  });
  held.index = index;
  held.at = now;
  log.debug('Leaving releaseIndexNow().');
  return index;
}

function releaseFilterFor(context) {
  log.debug('Entering releaseFilterFor().');
  const index = releaseIndexNow();
  if (!index.size) {
    log.debug('Leaving releaseFilterFor().');
    return null;
  }
  const info = context || {};
  const clientId = String(info.client_id || '').trim();
  if (clientId && index.has(clientId)) {
    log.debug('Leaving releaseFilterFor().');
    return index.get(clientId);
  }
  const audience = String(info.audience || '').trim();
  if (!audience) {
    log.debug('Leaving releaseFilterFor().');
    return null;
  }
  if (index.has(audience)) {
    log.debug('Leaving releaseFilterFor().');
    return index.get(audience);
  }
  // A JWT `aud` may be a list, joined with spaces by the context builder. Each
  // member is tried, and the FIRST match wins rather than the union of them —
  // a token for two audiences with two release policies is a state nothing here
  // can resolve correctly, so it resolves it predictably and says so in the log
  // rather than quietly intersecting two lists.
  const parts = audience.split(/\s+/)
                        .filter(function (one) { return one !== ''; });
  if (parts.length < 2) {
    log.debug('Leaving releaseFilterFor().');
    return null;
  }
  for (let i = 0; i < parts.length; i++) {
    if (index.has(parts[i])) {
      log.debug('releaseFilterFor(): the audience names ' + parts.length + ' ' +
          'parties and ' +
                parts[i] + ' has a release policy; it is the one applied.');
      log.debug('Leaving releaseFilterFor().');
      return index.get(parts[i]);
    }
  }
  log.debug('Leaving releaseFilterFor().');
  return null;
}

// ---------------------------------------------------------------------------
// WRITING.
// ---------------------------------------------------------------------------
function persist(record, why) {
  log.debug('Entering persist(). id=' + record.fedId);
  const ok = directory.writeFederation(record.fedId, attributesFor(record));
  log.debug('Leaving persist(). ' + (ok ? 'Written.' : 'Refused by the ' +
                                                       'directory.'));
  return ok;
}

// The audit row for a change to a relationship. ONE function, because there are
// three doors (the console, the management API, this module's own counters) and
// three copies of this would be three rows that came to disagree about what a
// federation change is.
//
// NO VALUES ARE NAMED, only field names — the same rule every LDAP row here
// follows, and it matters more on these entries than on any other:
// `fedClientSecret` is a real credential at a real foreign service.
function recordChange(action, record, summary, detail) {
  log.debug('Entering recordChange().');
  audit.audit({
    action: action,
    actor: '',
    protocol: familyOf(record.fedProtocol),
    channel: 'internal',
    target: record.fedId,
    summary: summary,
    detail: Object.assign({
      id: record.fedId,
      role: record.fedRole,
      protocol: record.fedProtocol,
      peer: record.fedPeer || ''
    }, detail || {})
  });
  log.debug('Leaving recordChange().');
}

// A REFUSED CHANGE TO THE REGISTER, as an audit row carrying its error code.
//
// The result of create(), update() and remove() is what the console and the
// management API send back as it is — `/admin-api` serialises it whole — so a
// code on that object would reach the caller, which no code may. The row names
// the relationship and the reason, and never a value: fedClientSecret is among
// the fields an update names.
function actionRefused(code, id, why) {
  log.debug("Entering actionRefused().");
  audit.failure(code, {
    protocol: 'Federation', channel: 'internal',
    target: String(id || ''),
    summary: 'a change to the federation relationship ' +
             String(id || '(unnamed)') +
             ' was refused: ' + why,
    // error-code: none — the helper's own row; every caller passes its code
    outcome: 'refused'
  });
  log.debug("Leaving actionRefused().");
}

// ---------------------------------------------------------------------------
// CREATE.
//
// Everything a relationship needs to EXIST is checked here; everything it needs
// to WORK is checked by readinessOf() and reported rather than refused. The
// split is deliberate and it is the same one `/admin/token-lifetimes` makes
// about a legal-but-surprising combination: a half-configured partner is a
// state somebody is passing through, and refusing to save it would mean
// configuring the whole thing in one form submission with no way to come back
// to it.
//
// WHAT IS REFUSED: a bad id, a duplicate id, an unknown role, an unknown
// protocol, and a full container. Nothing else.
//
// IT IS CREATED DISABLED whatever the caller asked for, and that is the one
// place this function overrides its input. See the header: the failure this
// register exists to prevent is a partner that half-exists and silently
// accepts. Enabling is a second, deliberate act.
// ---------------------------------------------------------------------------
function create(spec) {
  log.debug('Entering create(). id=' + (spec && spec.fedId));
  const info = spec || {};
  const errors = [];
  const id = String(info.fedId || info.id || '').trim();
  const problem = idProblem(id);
  if (problem) errors.push(problem);
  const role = String(info.fedRole || info.role || '').trim();
  if (ROLE_IDS.indexOf(role) === -1) {
    errors.push('Unknown role "' + role + '". The two are: ' +
                ROLE_IDS.join(', ') + '.');
  }
  const protocol = String(info.fedProtocol || info.protocol || '').trim();
  if (PROTOCOL_IDS.indexOf(protocol) === -1) {
    errors.push('Unknown protocol "' + protocol + '". The five are: ' +
                PROTOCOL_IDS.join(', ') + '.');
  }
  if (errors.length) {
    log.debug('Leaving create(). Refused: ' + errors.join(' '));
    actionRefused('STS-FED-0061', id, 'the id, role or protocol is not valid');
    log.debug("Leaving create().");
    return { ok: false, errors: errors };
  }
  if (!haveDirectory()) {
    log.debug('Leaving create(). There is no directory to write into.');
    actionRefused('STS-FED-0062', id, 'there is no embedded directory to ' +
                                      'hold it');
    log.debug("Leaving create().");
    return { ok: false,
             errors: ['There is no embedded directory loaded, so there is no ' +
                      'ou=federations to hold a relationship.'] };
  }
  if (get(id)) {
    log.debug('Leaving create(). It is already here.');
    actionRefused('STS-FED-0063', id, 'a relationship with that id already ' +
                                      'exists');
    log.debug("Leaving create().");
    return { ok: false,
             errors: ['A relationship called "' + id + '" is already ' +
                      'registered. An id names ONE relationship here, so the ' +
                      'answer to "it is already there" is to change what it ' +
                      'holds rather than to create it twice.'] };
  }
  const record = recordFromAttributes({});
  record.fedId = id;
  record.cn = id;
  record.fedRole = role;
  record.fedProtocol = protocol;
  record.fedName = String(info.fedName || info.name || '').trim() || id;
  record.fedPeer = String(info.fedPeer || info.peer || '').trim();
  // See the header: DISABLED, whatever was asked for.
  record.fedEnabled = boolText(false);
  record.fedAuthentications = '0';
  record.fedUsers = '0';
  // The defaults that are a protocol's convention rather than this service's
  // preference, written onto the entry rather than applied at read time — so
  // that `ldapsearch` shows what will actually happen instead of showing
  // nothing and leaving the behaviour in this file.
  if (role === 'service-provider') {
    record.fedAutocreateUsers = boolText(true);
    record.fedUpdateUserAttributes = boolText(true);
    // WHICH PEOPLE THE PARTNER MAY ASSERT (#109): the most secure default a
    // federation still works with, written onto the entry for the reason the
    // two above are.
    record.fedSubjectPolicy = DEFAULT_SUBJECT_POLICY;
    record.fedMayAssertAdministrators = boolText(false);
    record.fedSignRequest = boolText(false);
    // A PARTNER'S SIGN-OUT (#167): honoured, and signed — the most secure
    // default, and the one a partner that follows its specification meets.
    record.fedAcceptSignout = boolText(true);
    record.fedRequireSignedLogout = boolText(true);
    if (protocol === 'saml2') {
      record.fedSloBinding = 'HTTP-Redirect';
    }
    if (protocol === 'saml2' || protocol === 'saml11') {
      record.fedBinding = 'HTTP-Redirect';
      // SAML 1.1 has no request, so there is nothing for a response to be in
      // response to and every response is unsolicited by definition. Written
      // onto the entry rather than special-cased at the endpoint, because a
      // reader of the entry should not have to know that.
      record.fedAllowUnsolicited = boolText(protocol === 'saml11');
    }
    if (protocol === 'oidc') {
      record.fedResponseType = 'code';
      record.fedScope = 'openid profile email';
    }
    if (protocol === 'oauth2') {
      record.fedResponseType = 'code';
    }
    // WHAT A PARTNER ENCRYPTS TO (#168), the defaults written down. The key
    // itself is issued by `federation_encryption.ts` right after this, which
    // the console and /admin-api both do; this function is synchronous and
    // issuing is not.
    if (ENCRYPTING_PROTOCOLS.indexOf(protocol) >= 0) {
      const family = protocol === 'oidc' ? 'jose' : 'xml';
      record.fedEncryptionKeyType = defaultKeyTypeFor(protocol);
      record.fedKeyManagementAlgorithm =
        defaultManagementFor(family, record.fedEncryptionKeyType);
      record.fedContentEncryptionAlgorithm = family === 'jose'
        ? JOSE_CONTENT_ENCRYPTION[0] : XML_CONTENT_ENCRYPTION[0];
      record.fedAllowUnencrypted = boolText(false);
    }
  }
  if (role === 'identity-provider') {
    record.fedApplication = String(info.fedApplication || info.application ||
                                   '').trim();
  }
  // Phrased to need no indefinite article. "a OpenID Connect" and "an SAML
  // 2.0" are both wrong, and the usual a/an-by-first-letter rule produces
  // exactly those two — the article follows the SOUND, and three of these five
  // labels are initialisms.
  const note = 'registered as a federation relationship: ' +
    (protocolRow(protocol) || {}).label + ', with this service as the ' +
    String((roleRow(role) || {}).short || role).toLowerCase();
  record.description = [note];
  if (!persist(record)) {
    log.debug('Leaving create(). The directory refused it.');
    actionRefused('STS-FED-0064', id, 'the directory would not hold another ' +
                                      'relationship');
    log.debug("Leaving create().");
    return { ok: false,
             errors: ['The directory would not hold another relationship: ' +
                      'ou=federations is at its maximum of ' +
                      maxRelationships() +
                      ' (federation.max), or the directory itself is full.'] };
  }
  forgetReleaseIndexes();
  recordChange('federation.create', record,
               'the federation relationship ' + id + ' was registered (' +
               note + ')',
               { enabled: false,
                 note: 'created disabled; a relationship does nothing until ' +
                       'it is enabled deliberately' });
  log.info('federation: registered ' + id + ' — ' + note + '. It is DISABLED ' +
           'and will do nothing until it is enabled.');
  const stored = get(id);
  log.debug('Leaving create(). ' + id + ' is registered.');
  return { ok: true, relationship: stored, readiness: readinessOf(stored) };
}

// ---------------------------------------------------------------------------
// UPDATE — one field at a time, in the mode the SCHEMA says.
//
// The mode is read from the attribute row and never from the caller, exactly as
// `applications.updateApplication()` reads it, and for the same reason: a `set`
// on a multi-valued attribute leaves the entry with one value where the schema
// promises a list, and the console and an `ldapmodify` then disagree about what
// the attribute holds.
// ---------------------------------------------------------------------------
// The fields a value can be WRONG for: the three subject fields (#109), and
// the sign-out binding and signature switch (#167). Answers null, or the code,
// the audit sentence and the message for the caller.
function subjectFieldProblem(field, value) {
  log.debug("Entering subjectFieldProblem(). field=" + field);
  if (field === 'fedSubjectPolicy' && value !== '') {
    if (SUBJECT_POLICY_IDS.indexOf(value) < 0) {
      log.debug("Leaving subjectFieldProblem(). Not a policy.");
      return { code: 'STS-FED-0102',
               why: '"' + value + '" is not a subject policy',
               message: '"' + value + '" is not a fedSubjectPolicy. It is ' +
                        'one of ' + SUBJECT_POLICY_IDS.join(', ') + ', or ' +
                        'empty for ' + DEFAULT_SUBJECT_POLICY + '.' };
    }
    if (value === 'any-existing' && !mode.matchesFederatedNames()) {
      log.debug("Leaving subjectFieldProblem(). any-existing in product.");
      return { code: 'STS-FED-0095',
               why: 'any-existing is refused in product mode',
               message: 'any-existing is refused in product mode: it ' +
                        'matches the name a partner sends onto any local ' +
                        'person, which OpenID Connect Core section 5.7 ' +
                        'says a relying party must not rely on. Use ' +
                        'link-at-first-sign-in, pre-linked or ' +
                        'jit-namespaced.' };
    }
  }
  if (field === 'fedSubjectPattern') {
    const problem = subjectPatternProblem(value);
    if (problem) {
      log.debug("Leaving subjectFieldProblem(). An unusable pattern.");
      return { code: 'STS-FED-0103',
               why: 'fedSubjectPattern is unusable: ' + problem,
               message: 'fedSubjectPattern was not changed: ' + problem +
                        '.' };
    }
  }
  // A PARTNER'S SIGN-OUT (#167): the binding is one of two, and product
  // mode never accepts an unsigned logout message — so it refuses the switch
  // that would, rather than holding a value it will ignore.
  if (field === 'fedSloBinding' && value !== '' &&
      ['HTTP-Redirect', 'HTTP-POST'].indexOf(value) < 0) {
    log.debug("Leaving subjectFieldProblem(). Not a binding.");
    return { code: 'STS-FED-0133',
             why: '"' + value + '" is not a single logout binding',
             message: '"' + value + '" is not a fedSloBinding. It is ' +
                      'HTTP-Redirect or HTTP-POST, or empty for ' +
                      'HTTP-Redirect.' };
  }
  if (field === 'fedRequireSignedLogout' && !boolOf(value, true) &&
      !mode.acceptsUnsignedFederatedLogout()) {
    log.debug("Leaving subjectFieldProblem(). Unsigned logout in product.");
    return { code: 'STS-FED-0132',
             why: 'fedRequireSignedLogout off is refused in product mode',
             message: 'fedRequireSignedLogout cannot be turned off in ' +
                      'product mode: saml-profiles-2.0-os section 4.4.4.1 ' +
                      'says a logout message MUST be signed, and an ' +
                      'unsigned one is anybody signing anybody out.' };
  }
  log.debug("Leaving subjectFieldProblem(). Nothing wrong.");
  return null;
}

function update(id, change) {
  log.debug('Entering update(). id=' + id + ', field=' +
            (change && change.field));
  const record = get(id);
  if (!record) {
    log.debug('Leaving update(). No such relationship.');
    actionRefused('STS-FED-0065', id,
                  'there is no such relationship to update');
    log.debug("Leaving update().");
    return { ok: false,
             errors: ['There is no federation relationship called "' + id +
                      '".'] };
  }
  const info = change || {};
  const field = String(info.field || info.attribute || '').trim();
  const row = ATTRIBUTE_BY_NAME[field];
  if (!row) {
    log.debug('Leaving update(). Unknown field.');
    actionRefused('STS-FED-0066', id, '"' + field + '" is not an attribute ' +
                                                    'of a relationship');
    log.debug("Leaving update().");
    return { ok: false,
             errors: ['"' + field + '" is not an attribute of a federation ' +
                      'relationship. GET /admin/ldap/federations publishes ' +
                      'the whole schema.'] };
  }
  if (!row.editable) {
    log.debug('Leaving update(). Not editable.');
    actionRefused('STS-FED-0067', id, '"' + field + '" is not editable');
    log.debug("Leaving update().");
    return { ok: false,
             errors: ['"' + field + '" is not editable here. ' +
                      (row.name === 'fedId' || row.name === 'fedRole' ||
                       row.name === 'fedProtocol'
                        ? 'It is part of the relationship\'s identity — ' +
                          'delete it and make another; there is no state to ' +
                          'lose but the counters.'
                        : 'It records what HAPPENED, and a form that could ' +
                          'rewrite it would make this page lie about the ' +
                          'service\'s own behaviour.') +
                      ' An ldapmodify can still change it.'] };
  }
  if (row.role !== 'both' && row.role !== record.fedRole) {
    log.debug('Leaving update(). Wrong role for this field.');
    actionRefused('STS-FED-0068', id, '"' + field + '" belongs to the other ' +
                                                    'direction');
    log.debug("Leaving update().");
    return { ok: false,
             errors: ['"' + field + '" applies to a ' + row.role + '-side ' +
                 'relationship, and ' +
                      id + ' is ' + record.fedRole + '-side. Nothing was ' +
                                                     'changed.'] };
  }
  let value = String(info.value == null ? '' : info.value);
  // A DOMAIN IS COMPARED CASE-INSENSITIVELY, so it is stored lower-cased and
  // without the `@` somebody pasting an address would bring (#109).
  if (field === 'fedSubjectDomain') {
    value = value.trim().replace(/^@+/, '').toLowerCase();
  }
  const refusal = subjectFieldProblem(field, value) ||
                  encryptionFieldProblem(record, field, value);
  if (refusal) {
    log.debug('Leaving update(). ' + refusal.code);
    // error-code: none — subjectFieldProblem() names the code at each return
    actionRefused(refusal.code, id, refusal.why);
    log.debug("Leaving update().");
    return { ok: false, errors: [refusal.message] };
  }
  const before = row.kind === 'multi' ? (record[field] || []).slice() :
                 record[field];
  if (row.editable === 'multi') {
    const mode = String(info.mode || 'add');
    const values = (record[field] || []).slice();
    if (mode === 'remove') {
      const at = values.indexOf(value);
      if (at === -1) {
        log.debug('Leaving update(). There was no such value to remove.');
        actionRefused('STS-FED-0069', id,
                      'the value to remove from ' + field + ' ' +
            'is not there');
        log.debug("Leaving update().");
        return { ok: false,
                 errors: ['"' + value + '" is not one of ' + field + '\'s ' +
            'values.'] };
      }
      values.splice(at, 1);
    } else {
      if (!value) {
        log.debug('Leaving update(). Nothing to add.');
        actionRefused('STS-FED-0070', id,
                      'no value was given to add to ' + field);
        log.debug("Leaving update().");
        return { ok: false, errors: ['Give a value to add to ' + field + '.'] };
      }
      if (values.indexOf(value) !== -1) {
        log.debug('Leaving update(). It is already a value.');
        actionRefused('STS-FED-0071', id,
                      field + ' already carries that value');
        log.debug("Leaving update().");
        return { ok: false,
                 errors: [field + ' already carries "' + value + '".'] };
      }
      values.push(value);
    }
    record[field] = values;
  } else {
    record[field] = value;
  }
  // The one field whose value is normalised rather than stored as typed, and
  // the reason is `saml2Action()`'s: what the schema holds is base64 DER, which
  // is what a ds:X509Certificate carries. A PEM pasted in here would be stored
  // as something no reader of the attribute expects, and nothing would say so
  // until the day an assertion failed to verify.
  if (field === 'fedSigningCertificate') {
    record[field] = String(record[field]).replace(/-----[^-]+-----/g, '')
                                         .replace(/\s+/g, '');
  }
  // And the two booleans, so that `on`, `true`, `1` and a ticked checkbox all
  // reach the entry as the same string. Without this the entry holds whatever
  // the form posted and `boolOf()` has to guess.
  if (row.name === 'fedEnabled' || row.name === 'fedAutocreateUsers' ||
      row.name === 'fedUpdateUserAttributes' ||
      row.name === 'fedMayAssertAdministrators' ||
      row.name === 'fedSignRequest' || row.name === 'fedAllowUnsolicited' ||
      row.name === 'fedAllowUnencrypted') {
    record[field] = boolText(boolOf(record[field], false));
  }
  // A NEW KEY TYPE TAKES ITS OWN DEFAULT KEY MANAGEMENT (#168): the old
  // value may be one the new key cannot do, and a relationship whose
  // algorithm and key disagree accepts nothing. The key itself is issued by
  // the action that called this — see admin-core's federationAction().
  if (row.name === 'fedEncryptionKeyType' && value !== '' &&
      value !== before) {
    record.fedKeyManagementAlgorithm =
      defaultManagementFor(encryptionFamilyOf(record), value);
  }
  // The two sign-out switches default ON (#167), so an empty value is TRUE.
  if (row.name === 'fedAcceptSignout' ||
      row.name === 'fedRequireSignedLogout') {
    record[field] = boolText(boolOf(record[field], true));
  }
  if (!persist(record)) {
    log.debug('Leaving update(). The directory refused the write.');
    actionRefused('STS-FED-0072', id,
                  'the directory refused the write to ' + field);
    log.debug("Leaving update().");
    return { ok: false, errors: ['The directory refused the write.'] };
  }
  forgetReleaseIndexes();
  const stored = get(id);
  const readiness = readinessOf(stored);
  recordChange('federation.update', stored,
               field + ' was changed on the federation relationship ' + id,
               { field: field,
                 mode: row.editable === 'multi' ? String(info.mode || 'add') :
                       'set',
                 // NO VALUE. See recordChange(): fedClientSecret is among the
                 // fields that reach here.
                 sensitive: !!row.sensitive,
                 ready: readiness.ready,
                 missing: readiness.missing.join(', ') });
  log.info('federation: ' + field + ' changed on ' + id + '. It is ' +
           (isEnabled(stored) ? 'ENABLED' : 'disabled') + ' and ' +
           (readiness.ready ? 'ready.' :
            'NOT ready — ' + readiness.missing.join(', ') +
            ' still to configure.'));
  log.debug('Leaving update(). ' + field + ' changed.');
  return { ok: true, relationship: stored, readiness: readiness,
           message: field + ' changed. ' +
             (isEnabled(stored)
               ? (readiness.ready
                   ? 'The relationship is enabled and ready.'
                   : 'The relationship is ENABLED but NOT READY: ' +
                     readiness.missing.join(', ') + ' still to configure. It ' +
                     'will refuse rather than half-work.')
               : 'The relationship is still disabled.') };
}

function remove(id) {
  log.debug('Entering remove(). id=' + id);
  const record = get(id);
  if (!record) {
    log.debug('Leaving remove(). No such relationship.');
    actionRefused('STS-FED-0065', id,
                  'there is no such relationship to delete');
    log.debug("Leaving remove().");
    return { ok: false,
             errors: ['There is no federation relationship called "' + id +
                      '".'] };
  }
  if (!directory.deleteFederation(record.fedId)) {
    log.debug('Leaving remove(). The directory would not delete it.');
    actionRefused('STS-FED-0073', id, 'the directory would not delete it');
    log.debug("Leaving remove().");
    return { ok: false,
             errors: ['The directory would not delete ' + record.dn + '.'] };
  }
  forgetReleaseIndexes();
  recordChange('federation.delete', record,
               'the federation relationship ' + id + ' was deleted',
               { dn: record.dn,
                 note: 'nothing else was deleted: the people this partner ' +
                       'authenticated keep their entries under ou=users, ' +
                       'which is the rule everywhere in this directory' });
  log.info('federation: deleted ' + id + '. The people it authenticated keep ' +
           'their entries — nothing here is ever deleted from ou=users.');
  log.debug('Leaving remove(). Gone.');
  return { ok: true,
           message: 'Deleted. The people this partner authenticated keep ' +
                    'their entries under ou=users — nothing is ever deleted ' +
                    'from there — and any session they hold is unaffected ' +
                    'until it expires or is ended.' };
}

// ---------------------------------------------------------------------------
// THE PER-APPLICATION COUNTS, AND THE CHECK THAT BOUNDS THEM.
//
// `fedAuthentications` says how much has crossed a relationship;
// `/admin/federation/map` has to say how much has crossed it FOR EACH
// application configured to use it, which is a different number the moment a
// second application names the same partner. Hence one packed value per
// application under `fedApplicationUse`.
//
// **THE APPLICATION IS NOT TRUSTED FROM THE REQUEST, AND THIS IS THE WHOLE
// REASON THE CHECK IS A FUNCTION.** The id reaches `recordUse()` from a query
// parameter on `/federation/login/{id}`, which — unlike the rest of the feature
// — needs no configuration at all to reach. So an unchecked write would let
// anybody who can reach this port put a string of their choosing onto the entry
// whose contents decide whether an assertion is refused, as many times as they
// liked. What bounds it is that a value is written ONLY for a pair this service
// is genuinely configured for, and "configured" is read from the live register
// at the moment of the write rather than from whatever asked.
//
// THERE ARE EXACTLY TWO WAYS TO BE CONFIGURED FOR ONE, and they are
// `authn.js`'s `mechanismFor()`'s two sources rather than a third opinion about
// them:
//
//   1. THE APPLICATION ENTRY NAMES IT. `appFederationRelationship` holds a list
//      of service-provider-side relationship ids, and this is the ordinary case
//      — the application's users are authenticated at that partner.
//   2. AN IDENTITY-PROVIDER-SIDE RELATIONSHIP BROKERS TO IT. The broker case:
//      an enabled relationship names this application in `fedApplication`,
//      declares `fedAuthnMechanism: federation`, and points
//      `fedAuthnRelationship` at this one. The application entry says nothing
//      at all in that arrangement, which is why checking only (1) would
//      silently record nothing for every brokered sign-in — the case the
//      identity broker exists for.
//
// It answers WHICH of the two rather than a boolean, because the map draws them
// as different lines and the log line is worth the distinction.
// ---------------------------------------------------------------------------
function applicationConfiguredFor(applicationId, relationshipId) {
  log.debug('Entering applicationConfiguredFor(). application=' +
            (applicationId || '(none)') + ', relationship=' +
            (relationshipId || '(none)'));
  const wantedApp = String(applicationId || '').trim();
  const wantedFed = String(relationshipId || '').trim();
  if (!wantedApp || !wantedFed) {
    log.debug('Leaving applicationConfiguredFor(). Nothing was named.');
    return { configured: false, source: '' };
  }
  // 1. THE APPLICATION ENTRY. Wrapped, and swallowed with a reason: this runs
  // on the way out of a sign-in that has already succeeded, so a registry that
  // throws must cost the counter and never the session.
  try {
    const entry = applications.get(wantedApp);
    const named = ((entry || {}).fields || {}).appFederationRelationship;
    const ids = (Array.isArray(named) ? named : (named ? [named] : []))
      .map(function (one) { return String(one).trim(); });
    if (ids.indexOf(wantedFed) >= 0) {
      log.debug('Leaving applicationConfiguredFor(). The application entry ' +
                'names it.');
      return { configured: true, source: 'application' };
    }
  } catch (e) {
    log.error(errorCodes.tag('STS-FED-0057') + 'federation: the applications ' +
                                               'registry threw while ' +
                                               'checking whether "' +
              wantedApp + '" is configured for "' + wantedFed + '"; the ' +
              'per-application count is skipped and the sign-in itself ' +
              'stands: ' + e.message);
    log.debug('Leaving applicationConfiguredFor(). The registry threw.');
    return { configured: false, source: '' };
  }
  // 2. THE BROKER. An enabled identity-provider-side relationship naming this
  // application and pointing at this one. `identityProviderFor()` already
  // applies the enabled-and-first-match rule and warns about a second, so it is
  // asked rather than the register being walked again here.
  const broker = identityProviderFor(wantedApp);
  if (broker &&
      String(broker.fedAuthnMechanism || '').trim() === 'federation' &&
      String(broker.fedAuthnRelationship || '').trim() === wantedFed) {
    log.debug('Leaving applicationConfiguredFor(). ' + broker.fedId + ' ' +
        'brokers it.');
    return { configured: true, source: 'broker', via: broker.fedId };
  }
  log.debug('Leaving applicationConfiguredFor(). Not configured for that ' +
            'pair.');
  return { configured: false, source: '' };
}

// The delimiter, and the one character neither free-text field may contain. See
// the schema row: a packed counter drawn on a picture is not an identifier
// anything joins on, so the substitution is stated rather than refused — a pair
// whose application id carries a pipe still gets counted, under a name spelled
// with a tilde, which is a better answer than a number that is quietly wrong.
const USE_SEPARATOR = '|';

function packField(value) {
  log.debug("Entering packField().");
  log.debug("Leaving packField().");
  return String(value == null ? '' : value).split(USE_SEPARATOR).join('~');
}

// One packed value -> the row it means, or null. A value this cannot read is
// DROPPED rather than guessed at: `ldapmodify` is a door onto this entry like
// any other, and half-parsing somebody's hand-written value would put a
// nonsense count on a page that is meant to be read.
function parseApplicationUse(value) {
  log.debug("Entering parseApplicationUse().");
  const parts = String(value == null ? '' : value).split(USE_SEPARATOR);
  if (parts.length < 2) {
    log.debug("Leaving parseApplicationUse().");
    return null;
  }
  const application = parts[0].trim();
  if (!application) {
    log.debug("Leaving parseApplicationUse().");
    return null;
  }
  log.debug("Leaving parseApplicationUse().");
  return {
    application: application,
    authentications: parseInt(parts[1], 10) || 0,
    users: parseInt(parts[2], 10) || 0,
    lastUser: (parts[3] || '').trim(),
    lastSeen: (parts[4] || '').trim()
  };
}

function packApplicationUse(row) {
  log.debug("Entering packApplicationUse().");
  log.debug("Leaving packApplicationUse().");
  return [packField(row.application), String(row.authentications || 0),
          String(row.users || 0), packField(row.lastUser),
          packField(row.lastSeen)].join(USE_SEPARATOR);
}

// EVERY PER-APPLICATION ROW ON A RELATIONSHIP, parsed, busiest first. The
// console and the map both read it, so the ordering is decided here rather than
// twice: a picture whose boxes moved because two applications drew level would
// be a picture nobody could compare with itself.
function applicationUse(record) {
  log.debug('Entering applicationUse(). id=' +
            ((record && record.fedId) || '(none)'));
  const rows = ((record || {}).fedApplicationUse || [])
    .map(parseApplicationUse)
    .filter(function (one) { return !!one; });
  rows.sort(function (a, b) {
    if (b.authentications !== a.authentications) {
      return b.authentications - a.authentications;
    }
    return a.application < b.application ? -1 :
           a.application > b.application ? 1 : 0;
  });
  log.debug('Leaving applicationUse(). ' + rows.length + ' application(s).');
  return rows;
}

// THE CAP, and it is here for the reason MAX_CONTEXTS is there. The check above
// already means only a CONFIGURED pair is ever written, so this cannot be
// reached by anybody but an operator — but `appFederationRelationship` is a
// list somebody can put five hundred values in through four different doors,
// and an entry carrying five hundred packed counters is one nothing can draw
// and `ldapsearch` cannot read. Past it the busiest rows are kept and the rest
// are dropped, which is stated on the page rather than left to be inferred from
// a number that stopped moving.
//
// `federation.maxApplicationUse` since 2026-09-12; it was the constant 64, and
// the export is the function now (nothing outside this file read the constant),
// so a reader sees the value in force rather than the number it once was.
function maxApplicationUse() {
  log.debug("Entering maxApplicationUse().");
  log.debug("Leaving maxApplicationUse().");
  return Number(config.value('federation.maxApplicationUse'));
}

// WHICH APPLICATIONS ARE CONFIGURED TO USE THIS RELATIONSHIP, which is a
// question about CONFIGURATION and not about what has happened — so it is
// answered from the two registers rather than from the counters above. An
// application that names a partner and has never been used is exactly the state
// the map has to be able to show: it is what "configured and never exercised"
// looks like, and reading it off `fedApplicationUse` would draw nothing at all.
//
// A LINEAR WALK, for identityProviderFor()'s reason: there are four doors onto
// these entries and an index this module kept would be wrong exactly when
// somebody had just edited one by hand. It runs when a page is drawn, over a
// register an operator configured, and not on any issuing path.
function applicationsUsing(relationshipId) {
  log.debug('Entering applicationsUsing(). id=' + (relationshipId || '(none)'));
  const wanted = String(relationshipId || '').trim();
  const out = [];
  const seen = Object.create(null);
  const add = function (id, source, via) {
    log.debug("Entering add().");
    const name = String(id || '').trim();
    if (!name || seen[name]) {
      log.debug("Leaving add().");
      return;
    }
    seen[name] = true;
    out.push({ application: name, source: source, via: via || '' });
    log.debug("Leaving add().");
  };
  if (!wanted) {
    log.debug('Leaving applicationsUsing(). Nothing was named.');
    return out;
  }
  try {
    applications.list().forEach(function (entry) {
      const named = ((entry || {}).fields || {}).appFederationRelationship;
      const ids = (Array.isArray(named) ? named : (named ? [named] : []))
        .map(function (one) { return String(one).trim(); });
      if (ids.indexOf(wanted) >= 0) {
        add(entry.identifier, 'application');
      }
    });
  } catch (e) {
    // Swallowed with a reason: this builds a picture on a console page, and a
    // registry that throws must cost the picture's completeness rather than the
    // page. The brokered half below is still worth having.
    log.error(errorCodes.tag('STS-FED-0058') + 'federation: the applications ' +
                                               'registry threw while listing ' +
                                               'what uses "' +
              wanted + '"; the map is drawn without that half: ' + e.message);
  }
  inRole('identity-provider').forEach(function (record) {
    if (!isEnabled(record)) return;
    if (String(record.fedAuthnMechanism || '').trim() !== 'federation') return;
    if (String(record.fedAuthnRelationship || '').trim() !== wanted) return;
    add(record.fedApplication, 'broker', record.fedId);
  });
  log.debug('Leaving applicationsUsing(). ' + out.length + ' application(s).');
  return out;
}

// ONE PAIR'S COUNTS, MOVED. It mutates the record the caller is about to
// persist rather than persisting itself, so that a federated sign-in is ONE
// write to the directory and not two — and so that a failure to write leaves
// the relationship's own counts and the per-application ones agreeing, rather
// than one of them ahead.
//
// `users` is counted against the row's OWN lastUser and not the
// relationship's, which is the whole reason the field is repeated per row: two
// applications used alternately by one person would otherwise each see a
// "change of user" on every arrival and count them as many people. It is the
// same approximation `appLastUser` makes and it is stated in the same place —
// a change of user rather than a distinct set, right for the ordinary case and
// an undercount for somebody alternating between two partners.
function recordApplicationUse(record, application, user, now, how) {
  log.debug('Entering recordApplicationUse(). application=' + application);
  const key = packField(application);
  const rows = applicationUse(record);
  let row = null;
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].application === key) { row = rows[i]; break; }
  }
  if (!row) {
    if (rows.length >= maxApplicationUse()) {
      // The busiest are kept. See maxApplicationUse(): past the cap this stops
      // being a picture and becomes an entry nothing can read, and dropping the
      // quietest row is the one choice that leaves the picture saying the same
      // thing it said before.
      log.warn('federation: ' + record.fedId + ' already carries ' +
               rows.length +
               ' per-application counts, which is the cap ' +
               '(federation.maxApplicationUse, ' +
               maxApplicationUse() +
               '), so "' + application + '" is not being counted separately. ' +
               'The relationship\'s own totals still include it.');
      log.debug('Leaving recordApplicationUse(). At the cap.');
      return;
    }
    row = { application: key, authentications: 0, users: 0, lastUser: '',
            lastSeen: '' };
    rows.push(row);
    log.info('federation: "' + application + '" signed somebody in through ' +
             record.fedId + ' for the first time' +
             (how && how.source === 'broker'
                ? ', brokered by the identity-provider-side relationship "' +
                  how.via + '"'
                : ', which its own entry names') + '.');
  }
  row.authentications++;
  const packedUser = packField(user);
  if (packedUser && packedUser !== row.lastUser) {
    row.users++;
    row.lastUser = packedUser;
  }
  row.lastSeen = now;
  // ASSIGNED WHOLE. `fedApplicationUse` is multi-valued, and a multi-valued
  // attribute ACCUMULATES — see the schema's own note about getting single and
  // multi backwards on a counter. Writing the changed row alone would leave the
  // entry carrying every generation of every count.
  record.fedApplicationUse = rows.map(packApplicationUse);
  log.debug('Leaving recordApplicationUse(). ' + row.authentications +
            ' for that pair, ' + rows.length + ' application(s) on the entry.');
}

// ---------------------------------------------------------------------------
// THE COUNTERS.
//
// Called from `federation_sp.js` when a credential is ACCEPTED, and from
// nowhere else. It is the same rule `recordAuthentication()` follows and for
// the same reason: a row that meant "an assertion arrived" rather than "an
// assertion was believed" would make the number on the page meaningless.
//
// It cannot throw. A federation that worked must not be failed by a counter,
// which is the argument the JWT recorder and the user observer both make.
// ---------------------------------------------------------------------------
function recordUse(id, detail) {
  log.debug('Entering recordUse(). id=' + id);
  try {
    const record = get(id);
    if (!record) {
      log.debug('Leaving recordUse(). No such relationship.');
      return null;
    }
    const info = detail || {};
    const now = generalizedTime();
    record.fedFirstSeen = record.fedFirstSeen || now;
    record.fedLastSeen = now;
    record.fedAuthentications = String((parseInt(record.fedAuthentications,
                                                 10) || 0) + 1);
    const user = String(info.user || '').trim();
    if (user && user !== record.fedLastUser) {
      record.fedUsers = String((parseInt(record.fedUsers, 10) || 0) + 1);
      record.fedLastUser = user;
    }
    // ---------------------------------------------------------------------
    // AND THE SAME PAIR OF COUNTS FOR THE APPLICATION THIS SIGN-IN WAS FOR.
    //
    // Only when the caller named one, only on the SERVICE-PROVIDER side (see
    // the schema row — an identity-provider-side relationship names one
    // application, so its per-application count is the one above), and only
    // when this service is actually configured for the pair. The check is not a
    // formality: `application` arrives from a query parameter on an endpoint
    // that needs no configuration to reach.
    //
    // A NAMED-BUT-UNCONFIGURED PAIR IS LOGGED RATHER THAN COUNTED OR IGNORED.
    // It is the shape a mistake takes — an application whose
    // appFederationRelationship was edited after the flow began, a
    // hand-composed login URL — and a count that silently did not move is
    // exactly the thing nobody can find afterwards.
    // ---------------------------------------------------------------------
    const application = String(info.application || '').trim();
    if (application && record.fedRole === 'service-provider') {
      const how = applicationConfiguredFor(application, record.fedId);
      if (how.configured) {
        recordApplicationUse(record, application, user, now, how);
      } else {
        log.warn('federation: a sign-in through ' + record.fedId + ' named ' +
                 'the application ' +
                 '"' + application + '", which is NOT configured ' +
                 'to authenticate through it — neither its entry\'s ' +
                 'appFederationRelationship nor any enabled ' +
                 'identity-provider-side relationship brokering to this one ' +
                 'names the pair. The sign-in stands and the relationship\'s ' +
                 'own counts moved; no per-application count was recorded, ' +
                 'because this attribute is not a list of whatever asked.');
      }
    }
    // A success CLEARS the last error, and that is worth the line: an error
    // left standing beside a rising success count is the state that sends
    // somebody to debug a problem they already fixed.
    record.fedLastError = '';
    record.fedLastErrorAt = '';
    persist(record);
    forgetReleaseIndexes();
    log.debug('Leaving recordUse(). ' + record.fedAuthentications + ' so far.');
    return get(id);
  } catch (e) {
    log.error(errorCodes.tag('STS-FED-0059') + 'federation: the register ' +
                                               'threw while recording a use ' +
                                               'of ' + id +
              ' and was ignored; the sign-in itself stands: ' + e.message);
    log.debug('Leaving recordUse(). It threw.');
    return null;
  }
}

// And the other half, which is the more useful one. See fedLastError's schema
// row: a federation that does not work fails at somebody else's service, and
// this is where this service writes down what it thought was wrong.
function recordFailure(id, why) {
  log.debug('Entering recordFailure(). id=' + id);
  try {
    const record = get(id);
    if (!record) {
      log.debug('Leaving recordFailure(). No such relationship.');
      return null;
    }
    record.fedLastError = String(why || 'refused, with no reason recorded');
    record.fedLastErrorAt = generalizedTime();
    persist(record);
    forgetReleaseIndexes();
    // An audit row as well as the attribute, because the attribute holds ONE
    // failure and somebody debugging a partner that intermittently fails needs
    // the sequence. The audit log is the only place here that answers "when,
    // and how many times".
    recordChange('federation.refused', record,
                 'a federated sign-in through ' + id + ' was refused: ' +
                 record.fedLastError,
                 { why: record.fedLastError });
    log.warn('federation: ' + id + ' refused a sign-in — ' +
             record.fedLastError);
    log.debug('Leaving recordFailure(). Recorded.');
    return get(id);
  } catch (e) {
    log.error(errorCodes.tag('STS-FED-0060') + 'federation: the register ' +
                                               'threw while recording a ' +
                                               'failure of ' + id +
              ' and was ignored: ' + e.message);
    log.debug('Leaving recordFailure(). It threw.');
    return null;
  }
}

module.exports = {
  PATHS: PATHS,
  ROLES: ROLES,
  ROLE_IDS: ROLE_IDS,
  PROTOCOLS: PROTOCOLS,
  PROTOCOL_IDS: PROTOCOL_IDS,
  MECHANISMS: MECHANISMS,
  MECHANISM_IDS: MECHANISM_IDS,
  // WHICH PEOPLE A PARTNER MAY ASSERT (#109).
  SUBJECT_POLICIES: SUBJECT_POLICIES,
  SUBJECT_POLICY_IDS: SUBJECT_POLICY_IDS,
  DEFAULT_SUBJECT_POLICY: DEFAULT_SUBJECT_POLICY,
  subjectPolicyRow: subjectPolicyRow,
  subjectPolicyOf: subjectPolicyOf,
  subjectPatternProblem: subjectPatternProblem,
  subjectPatternMatches: subjectPatternMatches,
  SCHEMA: SCHEMA,
  protocolRow: protocolRow,
  mechanismRow: mechanismRow,
  roleRow: roleRow,
  familyOf: familyOf,
  setDirectory: setDirectory,
  // The people a partner's subjects are linked to (#109); see their header.
  federatedPerson: federatedPerson,
  peopleLinkedBy: peopleLinkedBy,
  linkedThrough: linkedThrough,
  plannedPersonDn: plannedPersonDn,
  writeFederationLink: writeFederationLink,
  attributesFor: attributesFor,
  recordFromAttributes: recordFromAttributes,
  idProblem: idProblem,
  boolOf: boolOf,
  boolText: boolText,
  list: list,
  get: get,
  count: count,
  inRole: inRole,
  containerDn: containerDn,
  maxRelationships: maxRelationships,
  fieldsForRole: fieldsForRole,
  editableFields: editableFields,
  readinessOf: readinessOf,
  isEnabled: isEnabled,
  isUsable: isUsable,
  signInOptions: signInOptions,
  // How one relationship is described on a page somebody chooses from. Read by
  // authn.js's broker branch as well as by signInOptions(), so the broker's
  // one button and the chooser's describe a relationship the same way.
  optionOf: optionOf,
  // THE BROKER HALF. `identityProviderFor()` finds the relationship a partner
  // asking this service to authenticate somebody is registered under,
  // `authenticationFor()` says what that relationship wants done about it, and
  // `usableServiceProvider()` is the four checks both this module and
  // authn.js's federationFor() make on a relationship id somebody typed. All
  // three are read by authn.js's mechanismFor() and by nothing else.
  usableServiceProvider: usableServiceProvider,
  // The same four checks over a LIST, keeping the unusable ones so the caller
  // can print what is wrong with each. See its header for why that is not a
  // map-and-filter at the call site.
  usableServiceProviders: usableServiceProviders,
  identityProviderFor: identityProviderFor,
  authenticationFor: authenticationFor,
  // The identity-provider half, and the one function on the ISSUING path. See
  // the header: it is consulted by admin_stats.js at its two existing funnels
  // and by nothing else.
  releaseFilterFor: releaseFilterFor,
  create: create,
  update: update,
  // ENCRYPTION TO THIS SERVICE (#168): the vocabulary, the policy a record's
  // four fields mean, and the key table's one writer.
  ENCRYPTING_PROTOCOLS: ENCRYPTING_PROTOCOLS,
  ENCRYPTION_KEY_TYPES: ENCRYPTION_KEY_TYPES,
  XML_KEY_MANAGEMENT: XML_KEY_MANAGEMENT,
  JOSE_KEY_MANAGEMENT: JOSE_KEY_MANAGEMENT,
  XML_CONTENT_ENCRYPTION: XML_CONTENT_ENCRYPTION,
  JOSE_CONTENT_ENCRYPTION: JOSE_CONTENT_ENCRYPTION,
  REFUSED_ALGORITHMS: REFUSED_ALGORITHMS,
  encrypts: encrypts,
  encryptionFamilyOf: encryptionFamilyOf,
  encryptionPolicyOf: encryptionPolicyOf,
  encryptionKeysOf: encryptionKeysOf,
  encryptionKeyView: encryptionKeyView,
  currentEncryptionKeyOf: currentEncryptionKeyOf,
  encryptionRequired: encryptionRequired,
  writeEncryptionKeys: writeEncryptionKeys,
  remove: remove,
  recordUse: recordUse,
  recordFailure: recordFailure,
  // THE PER-APPLICATION HALF, read by `/admin/federation` and by the map beside
  // it. `applicationUse()` is what HAS happened, parsed off the entry;
  // `applicationsUsing()` is what is CONFIGURED to happen, read off the two
  // registers — and the map needs both, because an application configured for a
  // partner and never used is a state only the second one can show.
  applicationUse: applicationUse,
  applicationsUsing: applicationsUsing,
  // Exported for the same reason `usableServiceProvider()` is: `authn.js`
  // decides the pair and this decides whether it may be recorded, and a second
  // implementation of "is this application configured for that relationship"
  // would be the one that disagreed on the broker case.
  applicationConfiguredFor: applicationConfiguredFor,
  maxApplicationUse: maxApplicationUse
};
