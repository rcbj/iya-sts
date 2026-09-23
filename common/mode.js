// @ts-check
'use strict';
//
// File: mode.js
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE IS: A MOCK, OR AN IDENTITY PROVIDER.
//
// **THE ONE PLACE EITHER ANSWER IS GIVEN.** Every surface that used to decide
// for itself whether a credential was required asks here instead, and the three
// settings that used to decide separately — `admin.authRequired`,
// `scim.authRequired`, `spiffe.authRequired` — are gone. They were not "partial
// security"; they were one question with four answers, and a deployment that
// required a credential at SCIM and not at the console was unsecured with a
// longer configuration file.
//
// ---------------------------------------------------------------------------
// THE TWO MODES, AND WHAT ACTUALLY DIFFERS.
//
// **`development` IS EVERY RELEASE OF THIS SERVICE BEFORE 2026-09-06** and is
// the default, so an unedited process behaves exactly as it always did. That is
// not a legacy compatibility shim — it is the mode that makes this thing
// USEFUL: a client is exercised by a server that says yes, and a test suite
// that had to provision a credential for every one of seventeen protocol
// families before it could assert anything about a protocol would spend its
// life on setup.
//
// **`product` runs THE SAME PROTOCOL IMPLEMENTATIONS with the permissiveness
// taken out.** Not a different code path per protocol, and that distinction is
// the whole architecture: what changes is the answer to a handful of policy
// questions, all of them asked here. If a future change adds a behaviour that
// exists in one mode and not the other, it belongs behind a predicate in this
// file rather than behind an `if` at the call site — otherwise "what does
// product mode do" becomes a question you answer by reading the whole service.
//
// ---------------------------------------------------------------------------
// THE FOUR THINGS PRODUCT MODE REQUIRES, which are the four rcbj named.
//
//   1. REAL AUTHENTICATION. A presented password is verified against the hashed
//      `userPassword` on the person's directory entry, at every door that takes
//      one: the sign-in screen, an LDAP bind, a WS-Security UsernameToken, SCIM
//      Basic. `common/credentials.ts` performs it; this file decides whether it
//      is asked.
//   2. EVERY REFERENCED OBJECT EXISTS ALREADY. Nothing is created because it
//      was named — not a user, not an application, not a service principal, not
//      an authorization server. An unknown name is a refusal, which is what
//      makes the register a statement about the deployment rather than a log of
//      what has been tried.
//   3. EVERY OAUTH 2.0 / OIDC APPLICATION THAT DECLARED A CONFIDENTIAL METHOD
//      AUTHENTICATES WITH IT — and a PUBLIC client is allowed (2026-09-17).
//      It said *there are no public clients in product mode* until then, which
//      made this service unable to exercise the single commonest kind of OAuth
//      client there is: a browser or native application that cannot keep a
//      secret. What replaced the refusal is the compliance the specifications
//      ask for instead of a secret — product mode now ENFORCES THE OAUTH 2.0
//      SECURITY BCP (RFC 9700), so a public client is held to PKCE with S256,
//      exact redirect-URI matching, a transaction-specific challenge, refresh
//      tokens that rotate, and no response type that issues a token from the
//      authorization endpoint. A public client may use the authorization code
//      and refresh grants and NOT the client credentials or resource owner
//      password grants, which the specifications define for confidential
//      clients (RFC 6749 section 4.4) and deprecate outright (RFC 9700
//      section 2.4).
//   4. `/admin-api` IS GATED. It was ungated in development on purpose — it
//      is what the tests drive and the way back in when nobody holds a role —
//      and that is a total authentication bypass which cannot survive into a
//      product. Since 2026-09-09 an OAuth 2.0 access token is required in BOTH
//      modes (`adminApi.authRequired`, on by default); what this file decides
//      is what happens with that setting OFF — open in development, the
//      console's session and roles in product. See `gatesManagementApi()`.
//
// ---------------------------------------------------------------------------
// IT IS PER TRUST REALM, and that is worth stating because it is unusual.
//
// `global.mode` is an ordinary RUNTIME row, so a realm may carry one of its
// own — and it is NOT `realmRuntime`, which `config.js` argues at the row:
// nothing about the mode is a property of a listener, so one process can serve
// a development realm and a product realm at once. A client can then be
// exercised against both without a second service — which is the same
// argument that made RFC 9700 mode a realm rather than a second instance.
//
// **WHAT IS NOT PER REALM IS ISOLATION**, and the two must not be confused. A
// trust realm is fully isolated from every other in BOTH modes; the mode says
// how hard the doors are, not whose doors they are.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, so its position in the require
// order is not a position. It requires only `config`, which requires only two
// leaves here, and `error_codes`, which requires nothing (since #104, for the
// code of an ignored value), so it is a LEAF and must stay one: everything
// above it may require it and it may never require any of them back. Every
// predicate takes no argument and reads the AMBIENT realm, exactly as
// `config.value()` does.
// ---------------------------------------------------------------------------

const config = require('./config');
// A leaf that requires nothing here, for the code of an ignored value.
const errorCodes = require('./error_codes');

// This module's own logger rather than the shared one in helpers.js, which
// requires this module: a require back would close a cycle. So the level is
// read the way the vendored modules read theirs: STS_LOG_LEVEL, then
// CONFIG_FILE's logLevel, then info.
let logLevelProblem = null;
const log = require('bunyan').createLogger({
  name: 'sts-mode',
  level: (function () {
    if (process.env.STS_LOG_LEVEL) {
      return process.env.STS_LOG_LEVEL;
    }
    try {
      return require(process.env.CONFIG_FILE).logLevel || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('No log level from CONFIG_FILE, so info: ' +
            logLevelProblem.message);
}

const DEVELOPMENT = 'development';
const PRODUCT = 'product';

// The mode of the realm this request is in. Read through `config.value()` and
// never cached, because it is runtime-settable and per realm — a cached answer
// would be the mode of whichever realm happened to ask first.
function current() {
  log.debug("Entering current().");
  const value = String(config.value('global.mode') || DEVELOPMENT);
  log.debug("Leaving current().");
  return value === PRODUCT ? PRODUCT : DEVELOPMENT;
}

function isProduct() {
  log.debug("Entering isProduct().");
  log.debug("Leaving isProduct().");
  return current() === PRODUCT;
}

function isDevelopment() {
  log.debug("Entering isDevelopment().");
  log.debug("Leaving isDevelopment().");
  return current() === DEVELOPMENT;
}

// ---------------------------------------------------------------------------
// THE PREDICATES. One per policy question, named for the QUESTION and not for
// the mode, so that a call site reads as what it is checking rather than as
// which mode it is in — `if (mode.verifiesCredentials())` says why the branch
// exists where `if (mode.isProduct())` says only when.
//
// They are all `isProduct()` today and that is not a reason to collapse them.
// The moment one of them wants a setting of its own, or a third mode arrives,
// the call sites do not move.
// ---------------------------------------------------------------------------

// Is a presented password actually checked? Development checks none, in any
// protocol — the one exception being Kerberos, which cannot be permissive that
// way because the password IS the key, and whose permissiveness therefore lives
// in the KDC's account policy instead. See kerberos/CLAUDE.md.
function verifiesCredentials() {
  log.debug("Entering verifiesCredentials().");
  log.debug("Leaving verifiesCredentials().");
  return isProduct();
}

// May a SPIFFE Workload API caller's OWN claims about itself be matched as
// selectors (`spiffe.acceptAssertedSelectors`, the `x-sts-workload-selector`
// header)? (#40, 2026-09-21.) Development says yes when that setting is on:
// it is how a client's "these selectors matched" path is exercised without a
// real attestor. Product says no whatever the setting says — a selector the
// caller wrote is a claim nothing checked, and a registration entry written
// for `unix:uid:0` must not be had by typing it into a header.
function believesAssertedSelectors() {
  log.debug("Entering believesAssertedSelectors().");
  log.debug("Leaving believesAssertedSelectors().");
  return !isProduct();
}

// Must the SPIFFE Workload API's Unix socket be ATTESTED to be served at all?
// (#40, 2026-09-21.) Product says yes: without the native module that reads a
// caller's credentials, every process that can reach the socket would get
// whatever the transport selectors match, so the socket is not served.
// Development serves it and says, on GET /spiffe, that nothing is attested.
function requiresWorkloadAttestation() {
  log.debug("Entering requiresWorkloadAttestation().");
  log.debug("Leaving requiresWorkloadAttestation().");
  return isProduct();
}

// May the SPIFFE Workload API be served over TCP to callers nothing attests
// (#166, 2026-09-23)? The Workload Endpoint specification section 3: "TCP
// transport MUST NOT be used unless the underlying network allows the
// Workload Endpoint server to strongly authenticate the workload based on
// source IP address". A TCP connection has no peer process to ask, so the
// source address is the only identity it can carry, and whether the network
// guarantees it is something this service cannot observe. Development says
// yes: the port is how a client in another container reaches it, and GET
// /spiffe says nothing on it is attested. Product says no — the port is not
// bound (STS-SPIFFE-0120) — unless the operator DECLARES the section 3
// condition with `spiffe.workloadTcpSourceAuthenticated`, and then only on a
// named address, never the wildcard (STS-SPIFFE-0121).
// `spiffe/spiffe_auth.ts`'s `workloadTcpPosture()` asks it.
function servesUnattestedWorkloadTcp() {
  log.debug("Entering servesUnattestedWorkloadTcp().");
  log.debug("Leaving servesUnattestedWorkloadTcp().");
  return !isProduct();
}

// May a SPIFFE registration entry select its workload on NOTHING THAT
// IDENTIFIES ONE (#166, 2026-09-23) — no selector at all, or only the
// `transport:` and `endpoint:` a caller reached? Such an entry matches every
// caller of a transport, which is the unattested identity #40 closed for the
// socket, arriving through the registry instead. Development says yes: it is
// how a client reaches an SVID with no attestor, and what an invented entry
// carries. Product says no: it is refused at every door that creates or
// updates an entry (STS-SPIFFE-0122) — as SPIRE refuses an entry with an
// empty selector list — and one already in the registry (written while the
// realm was in development) answers nobody (STS-SPIFFE-0123).
// `spiffe/spiffe_registry.ts` asks it.
function registersUnidentifyingEntries() {
  log.debug("Entering registersUnidentifyingEntries().");
  log.debug("Leaving registersUnidentifyingEntries().");
  return !isProduct();
}

// May `spiffe.attestWorkloads` OFF answer a Workload API caller with entries
// its selectors do not match (#104, 2026-09-23)? Development says yes: off is
// the answer this service gave before selectors decided anything, and a
// client's "I was handed every identity" path is exercised with it. Product
// says no whatever the setting says — every caller would be handed every
// registration entry, which makes #40's attestation meaningless — so the
// Workload API narrows on selectors there always.
function servesUnattestedEntries() {
  log.debug("Entering servesUnattestedEntries().");
  log.debug("Leaving servesUnattestedEntries().");
  return !isProduct();
}

// May the OpenID4VP Verifier accept a credential of THIS realm that carries
// no status reference, or an `ldp_vc` whose presentation withheld its
// `credentialStatus` (#165, 2026-09-23)? `oid4vp.requireStatusReference`
// `off` is the setting that says so, and only development honours it: a
// credential with no reference is one that can never be shown to have been
// revoked, and for a credential this realm issued — every one of which
// carries a reference — its absence means the holder hid it. Product reads
// `off` as the default, `all` (`valueInForce()`, logged once, STS-CORE-0106),
// and refuses to write it (the `onlyWhile` marker, STS-CORE-0103).
// `own-only`, which relaxes the rule for FOREIGN credentials alone, is allowed
// in both modes, with the warning its description carries.
function acceptsCredentialsWithoutStatus() {
  log.debug("Entering acceptsCredentialsWithoutStatus().");
  log.debug("Leaving acceptsCredentialsWithoutStatus().");
  return !isProduct();
}

// May a caller on the SPIRE Server API's Unix socket be the `local` entity
// with nothing verified but the socket's existence (#104, 2026-09-23)?
// `spiffe.trustLocalSocket` (on by default) is SPIRE's own model — the local
// caller is trusted and the socket's filesystem permissions are the boundary.
// Development trusts the socket as it always did. Product VERIFIES the
// boundary instead of assuming it: the socket must have been made 0600 and
// must sit in a directory other users cannot reach, and the peer's kernel uid
// (SO_PEERCRED, `spiffe/spiffe_peer.ts`) must be this service's own. A caller
// failing either is not `local`, and needs an administrator's X509-SVID on
// the TCP port like anybody else. `spiffe/spiffe_auth.ts` asks it.
function trustsUnverifiedLocalSocket() {
  log.debug("Entering trustsUnverifiedLocalSocket().");
  log.debug("Leaving trustsUnverifiedLocalSocket().");
  return !isProduct();
}

// May a DELIBERATE DEFECT make a response wrong (#104, 2026-09-23)? Three
// settings exist to spoil something on purpose, so that a client's handling of
// a wrong answer can be exercised against a server that is otherwise right:
// `oauth2.breakIdTokenNonce` (a wrong nonce in every ID Token),
// `ssf.breakSetSignature` (one character of every SET's signature changed) and
// `ssf.legacySubClaim` (the `sub` claim RFC 8417 discourages, beside
// `sub_id`). Development honours them. Product does not: each is IGNORED
// where it is read — the mode can be flipped at runtime, so the read is the
// guard — said once per process (STS-CORE-0106, `valueInForce()` below), and
// refused on write (the `onlyWhile` marker, STS-CORE-0103).
//
// TWO MORE SINCE #181 (2026-09-23), each already called a deliberate defect
// by its own description: `risc.googleSubjectType`, which writes the
// `subject_type` member RISC 1.0 section 3.1 says new services MUST NOT use,
// and `krb5.clockOffset`, which moves the KDC's clock so that a skew failure
// can be produced on purpose. A product KDC's clock is the machine's.
function spoilsOnPurpose() {
  log.debug("Entering spoilsOnPurpose().");
  log.debug("Leaving spoilsOnPurpose().");
  return !isProduct();
}

// May a BROKEN ALGORITHM be used (#181, 2026-09-23)? Two are offered here
// because deployed peers still demand them and a client library is entitled
// to be tested against one: SHA-1 in a signature, and RSAES-PKCS1-v1_5 key
// transport, which Bleichenbacher's adaptive chosen-ciphertext attack is
// against — XML Encryption 1.1 section 5.1 lists it with no requirement
// level and a security note, and section 6.1.2 recommends RSA-OAEP instead.
// Development uses them where a setting says to. Product never does:
//
//   * `saml.signatureAlgorithm` `rsa-sha1` — what this service SIGNS XML with;
//   * `saml2.keyTransportAlgorithm` `rsa-1_5` — how it wraps a content key,
//     and the same value on an application's `saml2KeyTransportAlgorithm`;
//   * `saml.allowSha1Signatures` on — accepting SHA-1 in a signature it
//     VERIFIES, on every XML path (SAML, WS-Trust, WS-Federation, RFC 7522);
//   * `pki.signatureAlgorithm` `sha1-rsa` / `sha1-ecdsa` — a certificate
//     authority signing with SHA-1, and a build form naming either;
//   * an XML element encrypted TO this service with `rsa-1_5` — the unwrap
//     that is the decryption oracle — which no setting governs.
//
// Each value is IGNORED where it is read (STS-CORE-0106) and refused on
// write (STS-CORE-0103); the stronger values of each setting stay allowed.
// JOSE's `RSA1_5` is refused in both modes already (`common/crypto.js`).
//
// TWO MORE SINCE #182 (2026-09-23):
//
//   * `scim.digestMd5` on — MD5 in SCIM's HTTP Digest. RFC 7616 section 3.3
//     keeps MD5 for backward compatibility only, and it is collision-broken.
//     Product offers no Digest at all (`scim/scim_auth.ts`, STS-SCIM-0056),
//     so the value is moot there; it is marked so that it cannot be stored
//     meaning something it does not do, and its default is now OFF in
//     development too.
//   * the `23` (rc4-hmac) in `krb5.enctypes`, beside the RFC 8429 and RFC
//     6649 numbers the codec does not implement (1, 2, 3, 16, 24), which the
//     marker names for the day it does. RFC 8429 deprecates RC4-HMAC: its
//     key is the unsalted NT hash, and RC4 is broken. The marker is on the
//     ELEMENT, not the list (`allowsValue()` below), because the default
//     keeps `23` so a development KDC exercises an RC4 client out of the box:
//     a product KDC reads the list without it, derives and stores no RC4 key,
//     opens nothing sealed under one, and answers a request that offers
//     nothing else KDC_ERR_ETYPE_NOSUPP (`kerberos/krb5_principals.js`).
function usesBrokenAlgorithms() {
  log.debug("Entering usesBrokenAlgorithms().");
  log.debug("Leaving usesBrokenAlgorithms().");
  return !isProduct();
}

// May a SAML assertion or a SAML 1.1 Response go out UNSIGNED (#181,
// 2026-09-23)? Development says yes where `saml2.signAssertion`,
// `saml11.signAssertion` or `saml11.signResponse` is off, or an application
// overrides one of them off: a relying party that accepts an unsigned
// assertion has a hole, and this is how it is found.
//
// Product signs all three, and the decision is the specifications':
//
//   * SAML 2.0 (saml-profiles-2.0-os sections 4.1.3.5 and 4.1.4.5): the
//     assertions in a Response delivered by the HTTP POST binding MUST be
//     signed; over the Artifact binding they MAY be. The approved errata let
//     a signature over the Response stand in for the assertion's. Product
//     signs the ASSERTION whatever the binding: that satisfies both texts,
//     and an assertion that leaves its Response — resolved by artifact, held
//     for AssertionIDReference, presented as an RFC 7522 grant — carries the
//     only signature it will ever have. `saml2.signResponse` off stays
//     allowed, because with the assertion signed the profile asks for no
//     more.
//   * SAML 1.1 (oasis-sstc-saml-bindings-1.1 section 4.1.2.4): in the
//     Browser/POST profile "the SAML response MUST be digitally signed" and
//     the assertions in it MAY be. So `saml11.signResponse` off is a
//     non-conforming Browser/POST response and is development's; and the
//     assertion is signed too, for the reason the 2.0 one is.
function issuesUnsignedAssertions() {
  log.debug("Entering issuesUnsignedAssertions().");
  log.debug("Leaving issuesUnsignedAssertions().");
  return !isProduct();
}

// May the SPIFFE Workload API serve a call that does not carry the
// `workload.spiffe.io: true` metadata header (#181, 2026-09-23)? The
// SPIFFE Workload Endpoint specification section 3 says a server MUST
// refuse one. Development honours `spiffe.requireSecurityHeader` off, which
// is how something other than the header is tested with a client that does
// not send it; product always refuses.
function servesWithoutSecurityHeader() {
  log.debug("Entering servesWithoutSecurityHeader().");
  log.debug("Leaving servesWithoutSecurityHeader().");
  return !isProduct();
}

// May a user, application, service principal or authorization server be created
// because something NAMED it? Development says yes and that is most of what
// makes it a mock: a client can point at this service with any client_id and
// get a working exchange.
function autoCreates() {
  log.debug("Entering autoCreates().");
  log.debug("Leaving autoCreates().");
  return !isProduct();
}

// Must an OAuth 2.0 / OpenID Connect application that DECLARED A CONFIDENTIAL
// METHOD present its credential and have it verify? (2026-09-17.)
//
// **THIS IS NOT "MUST EVERY CLIENT HOLD A SECRET" ANY MORE, AND THE RENAME IS
// THE CHANGE.** It was `requiresClientSecret()` and it answered a question
// about every client; product mode refused a client registered
// `token_endpoint_auth_method=none` at the token endpoint and at PAR, so this
// service could not exercise a browser or native application at all in the
// mode a deployment runs in. A PUBLIC CLIENT IS NOW ALLOWED. What product mode
// requires of it is not a secret it cannot keep — it is the compliance the
// specifications ask for INSTEAD of one, which is
// `enforcesOauthSecurityBcp()` below.
//
// What is unchanged is the other half, and it is the half that was doing the
// security work: a client whose registration declares a confidential method —
// which is every method but `none`, RFC 7591 section 2's default applying
// where a registration omitted it — must present that credential and it must
// verify. `oauth-oidc/oauth2_bcp.js`'s `isConfidential()` is the one test for
// which kind a client is, and its header says why it must stay one function.
function requiresConfidentialClientAuthentication() {
  log.debug("Entering requiresConfidentialClientAuthentication().");
  log.debug("Leaving requiresConfidentialClientAuthentication().");
  return isProduct();
}

// Does this service enforce the OAuth 2.0 Security Best Current Practice
// (RFC 9700) whatever `oauth2.rfc9700` says? (2026-09-17.)
//
// **PRODUCT MODE IMPLIES THE BCP, AND THAT IS WHAT MAKES A PUBLIC CLIENT SAFE
// TO ALLOW.** The two go together and were decided together: what a
// confidential client proves with a credential, a public client proves with
// PKCE, an exactly-matched redirect URI, a challenge that cannot be replayed
// and a refresh token that rotates. Allowing the one without the other would
// have made product mode LESS compliant than `oauth2.rfc9700` mode, which is
// the opposite of what product mode is for.
//
// **A REALM CANNOT TURN IT OFF.** `oauth2.rfc9700` is `realmRuntime`, so a
// realm may turn the mode ON while the process is not in it; product mode is
// the process's and is a FLOOR under every realm. A realm that could opt out
// of the BCP in product mode would be a realm that could opt out of the only
// thing holding its public clients together.
//
// It is read by `oauth2_bcp.js`'s `enabled()` and by
// `sender_constraints.js`'s `rotationRequired()`, which reads the same
// sources directly rather than calling `enabled()` (it is required BY that
// module). `tests/public_clients_product.js` sections 0a and 0d assert both
// answer yes in product mode, which is what catches this predicate reaching
// one of them and not the other.
function enforcesOauthSecurityBcp() {
  log.debug("Entering enforcesOauthSecurityBcp().");
  log.debug("Leaving enforcesOauthSecurityBcp().");
  return isProduct();
}

// ---------------------------------------------------------------------------
// FIVE MORE QUESTIONS, ADDED 2026-09-12 BY AN AUDIT FOR WHAT WAS HARD-CODED.
//
// Every one of them was a development-mode behaviour written as a LITERAL at a
// call site — a fixture password, a persona surname, an ungated switch — with
// no mode check, so product mode shipped it unchanged. The rule at the top of
// this file is that a behaviour existing in one mode and not the other belongs
// behind a predicate here; these are the ones that had not been put here.
// ---------------------------------------------------------------------------

// Is a service created with DEMONSTRATION DATA in it? The directory's three
// people and their groups, the Kerberos fixture accounts and their literal
// long-term keys, the SPIFFE registry's sample entries, and the credential
// attributes generated onto every person. A product deployment starts empty
// apart from what it was configured with, because a fixture account with a
// password printed in this repository is an account anybody can use.
function seedsDemoData() {
  log.debug("Entering seedsDemoData().");
  log.debug("Leaving seedsDemoData().");
  return !isProduct();
}

// Does this service ROTATE its signing keys on a schedule? (2026-09-22, #42.)
// Product keeps a key set for as long as the store does, so a key that is
// never replaced is a key whose compromise never ends; each unit gets a
// `next` key, published before it signs anything, promoted by `signing.rotate`
// and kept verifying through its grace after. Development makes its keys anew
// at every start and has nothing to rotate — a rotation there would only
// churn the documents a client is being pointed at.
function rotatesSigningKeys() {
  log.debug("Entering rotatesSigningKeys().");
  log.debug("Leaving rotatesSigningKeys().");
  return isProduct();
}

// Is an EXPIRED client secret refused? (2026-09-22, #49 P5.) Product refuses
// it at the token endpoint wherever a secret is checked; development accepts
// it and says so, because a test fixture registered with a short
// oauth2.registeredSecretLifetimeS must not stop working half-way through a
// run nobody meant to be about secrets.
function refusesExpiredClientSecrets() {
  log.debug("Entering refusesExpiredClientSecrets().");
  log.debug("Leaving refusesExpiredClientSecrets().");
  return isProduct();
}

// Does the realm chooser in front of `/admin` and `/portal` LIST the realms?
// (2026-09-14, #32.) A person arriving at either surface with no session, on a
// service with realms defined, chooses which realm to sign in through.
// Development draws every realm in a list, because the list is what somebody
// exercising the service wants; product asks for the realm's id in a text box,
// because a list drawn to anybody who can reach the page publishes every
// tenant this deployment serves.
function listsRealmsBeforeSignIn() {
  log.debug("Entering listsRealmsBeforeSignIn().");
  log.debug("Leaving listsRealmsBeforeSignIn().");
  return !isProduct();
}

// May a claim VALUE be invented where the store holds none? A persona surname,
// an address at a domain nobody owns with `email_verified: true`, a generated
// birthdate in a signed credential, an `@example.com` subject in a security
// event sent to a real receiver. Development invents them so a client has
// something to parse; product OMITS what it does not know, because an invented
// fact a relying party believes is worse than an absent one it can handle.
function inventsClaimValues() {
  log.debug("Entering inventsClaimValues().");
  log.debug("Leaving inventsClaimValues().");
  return !isProduct();
}

// May a response be delivered to an address the REQUEST named and no
// registration did? A SAML AssertionConsumerServiceURL, a SAML 1.1 `shire`, a
// WS-Federation `wreply`, a wallet URL on a query string. Development accepts
// any absolute URL on purpose — it is how a client under test is pointed at
// this service without registering first. Product delivers only to an address
// on the application's own entry, which is the difference between an identity
// provider and a signed-assertion forwarding service.
function acceptsUnregisteredAddresses() {
  log.debug("Entering acceptsUnregisteredAddresses().");
  log.debug("Leaving acceptsUnregisteredAddresses().");
  return !isProduct();
}

// Are the TEST CONTROLS open to anybody who can reach the port? Adding a trust
// anchor at POST /tls/trust, switching DPoP nonces, reading the Kerberos
// fixture passwords off /krb5/principals, signing somebody ELSE out with
// ?username=, registering an OAuth client with no initial credential, asking a
// SAML 1.1 attribute authority about any named person. Each exists so a test
// can drive a state; in product each is either refused or behind the credential
// the equivalent administrative operation already requires.
function opensTestControls() {
  log.debug("Entering opensTestControls().");
  log.debug("Leaving opensTestControls().");
  return !isProduct();
}

// Does the console's BOOTSTRAP WINDOW open the console to anybody who signs in
// (2026-09-22, #103)? Until a realm's bootstrap administrator first signs in
// to `/admin` — or, where none was seeded, while its roster is empty — the
// window grants BOTH console roles to every signed-in person while
// `admin.openWhenEmpty` is on. Development answers yes: a new stack must be
// drivable by whoever signs in first, and every job signs in under a random
// name. Product answers no, and there is no setting that says otherwise: the
// window made anybody who could sign in BY ANY METHOD — a federation partner's
// assertion, a trusted certificate, a wallet, a Kerberos ticket — an
// administrator of the whole service until the operator arrived. So in
// product only the roster decides, the bootstrap account's roles are honoured
// from a PASSWORD sign-in alone until it has claimed the console, and a
// realm with nobody on its roster is closed, reachable again through
// `POST /admin-api/rbac/grant`. Read in the realm whose window it is, which
// `admin-ui/admin_rbac.ts` binds. See `admin-ui/CLAUDE.md` 8a.
function opensConsoleToAnyone() {
  log.debug("Entering opensConsoleToAnyone().");
  log.debug("Leaving opensConsoleToAnyone().");
  return !isProduct();
}

// Is a write over the DIRECTORY'S OWN SOCKET authorized against the identity
// that bound? Product mode: an anonymous connection writes nothing, an
// administrator (Admin Write, in the default realm) writes anything, and a
// person may modify only the attributes `ldap.selfWritableAttributes` names on
// their own entry. Development binds any DN with any password, so the bound DN
// proves nothing and a check keyed on it would refuse the suite while
// protecting nothing. `ldap/ldap_server.js`'s `directoryWriteRefusal()` argues
// the rule.
function authorizesDirectoryWrites() {
  log.debug("Entering authorizesDirectoryWrites().");
  log.debug("Leaving authorizesDirectoryWrites().");
  return isProduct();
}

// ---------------------------------------------------------------------------
// THE DIRECTORY'S OWN SOCKET, READ SIDE AND BIND SIDE (2026-09-12).
//
// node-ldapjs is a protocol library and decides nothing: it records the DN a
// bind named on the connection and leaves every question about what that
// connection may then do to the handlers. `authorizesDirectoryWrites()` above
// answers the write half. These five answer the rest, and they are five rather
// than one because each is a different question an operator reading
// /admin/mode asks, and each is refused with a different LDAP result code.
// `ldap/ldap_server.js`'s *THE DIRECTORY'S READ AND BIND SECURITY* block argues
// all of them. Development answers no to every one: every bind succeeds there,
// so a bound DN proves nothing and a check keyed on it protects nothing.
// ---------------------------------------------------------------------------

// Must a connection BIND AS SOMEBODY before it may read? Product: an anonymous
// or unauthenticated simple bind is refused (RFC 4513 sections 5.1.1 and 5.1.2
// both permit a server to), and a search or compare on a connection that never
// bound is refused — the root DSE excepted, because a client reads it to find
// out where to bind.
function requiresDirectoryBind() {
  log.debug("Entering requiresDirectoryBind().");
  log.debug("Leaving requiresDirectoryBind().");
  return isProduct();
}

// Are CREDENTIAL ATTRIBUTES withheld from every reader of the socket? Product:
// a password hash, a client secret, a private key, a TOTP secret, a recovery
// code, an activation token and a Kerberos key never leave in a search, a
// filter cannot see them (or it would be an oracle, one character at a time),
// and a compare against one is refused. An administrator is not excepted: the
// console and the management API read them through this module's functions,
// and nothing needs them on the wire.
function withholdsDirectorySecrets() {
  log.debug("Entering withholdsDirectorySecrets().");
  log.debug("Leaving withholdsDirectorySecrets().");
  return isProduct();
}

// May a client WRITE an attribute the directory maintains itself —
// createTimestamp, modifyTimestamp, entryDN? Product: no, not even an
// administrator, because a timestamp anybody can set is not evidence of when
// anything happened.
function protectsOperationalAttributes() {
  log.debug("Entering protectsOperationalAttributes().");
  log.debug("Leaving protectsOperationalAttributes().");
  return isProduct();
}

// Must a bind that carries a password arrive over TLS? Product: a simple bind
// on the plain listener is answered confidentialityRequired before the password
// is looked at, since by then it has already crossed the network in the clear.
function requiresConfidentialDirectoryBinds() {
  log.debug("Entering requiresConfidentialDirectoryBinds().");
  log.debug("Leaving requiresConfidentialDirectoryBinds().");
  return isProduct();
}

// Are FAILED binds rate limited? Product: failures are counted per bind DN and
// per address in `common/websecurity.ts`'s buckets, and a caller over either
// limit is refused before its password is checked — so a correct guess during a
// lockout is refused like a wrong one and teaches nothing. A SUCCESSFUL bind is
// never counted, because a connection pool binds on every connection it opens.
function limitsDirectoryBindFailures() {
  log.debug("Entering limitsDirectoryBindFailures().");
  log.debug("Leaving limitsDirectoryBindFailures().");
  return isProduct();
}

// May a response go out WEAKER than the caller or the registration asked for?
// An assertion an application is configured to have encrypted, or a WS-Trust
// token requested with an encryption certificate, that cannot be encrypted —
// development sends it in the clear and says so loudly, because refusing to
// issue would hide the defect a client author is trying to see. Product
// refuses: a document the deployment said must be confidential and was not is a
// leak, however loudly it is logged. Not `opensTestControls()`, which the first
// version used for want of this: that one is about who may DRIVE a switch, and
// this one is about what a response is allowed to lose on the way out.
function sendsWeakerThanAsked() {
  log.debug("Entering sendsWeakerThanAsked().");
  log.debug("Leaving sendsWeakerThanAsked().");
  return !isProduct();
}

// When a presented certificate's REVOCATION STATUS cannot be established — a
// foreign CRL that cannot be fetched, does not verify or is stale — is the
// certificate refused? This is what `pki.revocationCheck=auto` resolves to:
// product answers yes (hard-fail), development answers no (soft-fail).
//
// **SOFT-FAIL IS THE WEAKNESS AN ATTACKER USES**: somebody holding a revoked
// certificate who can block the fetch turns "revoked" into "unknown", and
// soft-fail waves "unknown" through. A product closes that. Development keeps
// soft-fail because what it refuses is then exactly what somebody REVOKED —
// both modes consult this service's own register, which has no network in it
// and cannot make a good certificate fail. `common/revocation_status.js`
// argues all of it.
function refusesUnknownRevocationStatus() {
  log.debug("Entering refusesUnknownRevocationStatus().");
  log.debug("Leaving refusesUnknownRevocationStatus().");
  return isProduct();
}

// Is a certificate NOBODY CAN REVOKE refused (#174, 2026-09-23)? One issued by
// an authority this service does not hold — by a CA, not self-signed, and
// without RFC 9608's noRevAvail — that names no CRL distribution point and no
// OCSP responder. This is what `pki.revocationRequireDistributionPoint=auto`
// resolves to: product answers yes, development answers no.
//
// **IT IS NOT `refusesUnknownRevocationStatus()` AGAIN**, and the difference is
// the argument. That one is about a status that could not be FETCHED, where an
// attacker who blocks the fetch is the threat. This one is about a certificate
// with nothing to fetch at all, where no attacker is needed: a stolen key under
// such an authority is good until the certificate expires, whatever its issuer
// or this service does. RFC 5280 section 4.2.1.13 only RECOMMENDS the
// extension, which is the cost — a private CA that publishes nothing is
// refused in product until it does, or until an operator sets the setting to
// `off`, whose description carries the warning. Development accepts it because
// what a client author points a stack here to watch is their own flow, and a
// test CA with no list is the usual first thing they build.
function refusesUnrevocableCertificates() {
  log.debug("Entering refusesUnrevocableCertificates().");
  log.debug("Leaving refusesUnrevocableCertificates().");
  return isProduct();
}

// Does a GNAP key proved by MUTUAL TLS need a certificate a trusted authority
// issued, rather than one merely registered (#107, 2026-09-23)? This is what
// `gnap.mtlsTrust=auto` resolves to: product answers yes (`pki`), development
// answers no (`pinned`).
//
// RFC 9635 section 7.3.2 allows both: the verifier compares the certificate
// with the key it expected, and "in many instances ... will not do a full
// certificate chain validation", the trust coming from "a static registration
// or trust-on-first-use". Section 11.4 is why product takes the other one: "an
// AS using PKI to validate the MTLS connection would need to ensure that the
// presented certificate was issued by a trusted certificate authority", and
// only that model lets a key be "revoked and rotated through management at the
// certificate authority without requiring additional registration or
// management at the AS". A pinned self-signed certificate can be withdrawn
// only by editing the entry that pins it. Development keeps `pinned` because a
// client under test brings the self-signed certificate it generated a minute
// ago. REVOCATION IS CONSULTED IN BOTH, whatever this answers:
// `gnap/gnap_proof.ts` argues it.
function requiresPkiForGnapMtls() {
  log.debug("Entering requiresPkiForGnapMtls().");
  log.debug("Leaving requiresPkiForGnapMtls().");
  return isProduct();
}

// Must an ACME or EST request arrive over TLS (2026-09-13)? RFC 8555 section
// 6.1 says ACME MUST be HTTPS and RFC 7030 section 3.2 puts EST on TLS by
// definition, so product answers yes and refuses a request that reached the
// main port as plain HTTP. Development answers, logs that it did, and is how a
// client under test reaches a service started with STS_HTTPS=false. SCEP is
// not asked: its messages are signed and encrypted CMS and RFC 8894 section
// 2.1 runs it over plain HTTP on purpose.
function requiresEnrollmentTls() {
  log.debug("Entering requiresEnrollmentTls().");
  log.debug("Leaving requiresEnrollmentTls().");
  return isProduct();
}

// May a caller that does not authenticate introspect a token at
// /oauth2/introspect (2026-09-13)? RFC 7662 section 2.1 says the endpoint MUST
// require some form of authorization, and development answers yes anyway: the
// suites and every client under test introspect with nothing but the token,
// and a refusal there removes the case they run. Product answers no — an open
// introspection endpoint tells anybody holding a token string who it belongs
// to and what it may do.
//
// **AN RFC 9701 JWT RESPONSE IS NOT ASKED THIS**, and must not be: that
// response names the resource server that asked in its `aud`, so it needs an
// authenticated caller in every mode, and section 5 says to refuse one that is
// not. `oauth-oidc/oauth2.ts`'s `introspectEndpoint()` makes both decisions.
function opensIntrospection() {
  log.debug("Entering opensIntrospection().");
  log.debug("Leaving opensIntrospection().");
  return !isProduct();
}

// May a caller that does not authenticate revoke a token at /oauth2/revoke
// (#102, 2026-09-22)? RFC 7009 section 2.1 has the server first validate "the
// client credentials (in case of a confidential client)" and then whether the
// token "was issued to the client making the revocation request" — and
// development answers yes anyway, for `opensIntrospection()`'s reason: the
// suites and every client under test revoke with nothing but the token, and a
// refusal there removes the case they run. Product answers no: a confidential
// client must present a credential that verifies, a public one must name a
// registered `client_id`, and either may revoke only its own token. A token
// issued to somebody else is refused `invalid_grant` there.
//
// **A CREDENTIAL THAT IS PRESENTED IS VERIFIED IN BOTH MODES**, which is where
// this differs from introspection: a client under test that authenticates at
// the revocation endpoint should meet section 2.1's refusals, the wrong-secret
// 401 and another client's token, rather than a quiet 200.
// `oauth-oidc/oauth2.ts`'s `revokeRequest()` makes both decisions.
function opensRevocation() {
  log.debug("Entering opensRevocation().");
  log.debug("Leaving opensRevocation().");
  return !isProduct();
}

// Does an OpenID4VCI endpoint — the credential, deferred credential and
// notification endpoints — accept an access token this realm CANNOT VERIFY
// (2026-09-18)? OID4VCI lets the authorization server be somebody else, so
// development reads such a token's claims unverified and issues what it can,
// which is what lets a wallet under test point at this issuer with a token from
// anywhere. Product refuses it (`invalid_token`), and refuses a token this
// realm revoked: a credential is a signed statement about somebody, and
// signing one for whoever can reach the port — with nothing verified about who
// asked — is issuing to strangers.
function acceptsUnverifiedIssuerTokens() {
  log.debug("Entering acceptsUnverifiedIssuerTokens().");
  log.debug("Leaving acceptsUnverifiedIssuerTokens().");
  return !isProduct();
}

// Does the RFC 8693 token exchange accept a `subject_token` or `actor_token`
// this realm CANNOT VERIFY (2026-09-21)? Development says yes: it reads the
// name out of a token from anywhere and exchanges it, which is what lets a
// client under test drive the grant with a token some other issuer minted.
// Product says no. The subject_token is the WHOLE of what the grant asks for —
// there is no browser, password or consent anywhere in it — so an unverified
// one is a token for whoever the caller wrote into a JWT it signed itself, or
// did not sign at all. Until this predicate existed product exchanged exactly
// that, and the page saying every door verifies its tokens was wrong about
// this one. `oauth-oidc/oauth2.ts`'s token-exchange branch asks it.
function exchangesUnverifiedTokens() {
  log.debug("Entering exchangesUnverifiedTokens().");
  log.debug("Leaving exchangesUnverifiedTokens().");
  return !isProduct();
}

// Does THIS SERVICE DECIDE who may act for whom at the two delegating doors
// that had no policy — WS-Trust `OnBehalfOf` / `ActAs` and the RFC 8693 token
// exchange (#108, 2026-09-23)? Product says yes: `common/delegation_policy.ts`
// is asked with the intermediary, the subject and the targets, and a refusal
// is a refusal — `wst:RequestFailed`, `invalid_request` or `invalid_target`.
// Development says no, and still ASKS: the answer is written on the act's row
// on `/admin/delegation` as "would have been refused", which is Kerberos's
// development fixtures' arrangement and `exchangesUnverifiedTokens()`'s. The
// same predicate refuses an exchange that WIDENS the verified subject_token's
// scope, because that is the same question — what may a middle tier obtain in
// somebody else's name — asked about the scope rather than the party.
// `may_act` is NOT behind it: a subject_token naming its authorized actor is
// honoured in every mode, because the token itself asks for it.
function authorizesDelegation() {
  log.debug("Entering authorizesDelegation().");
  log.debug("Leaving authorizesDelegation().");
  return isProduct();
}

// Does the authorization server issue a scope the client never DECLARED
// (#110, 2026-09-22)? Development says yes: a client under test asks for
// whatever word it likes and is given it, which is what lets it be driven with
// no registration at all. Product says no. RFC 6749 section 3.3 lets an
// authorization server hold a request to its own policy, and RFC 7591 section
// 2 names the policy — `scope` is the list "that the client can use when
// requesting access tokens" — so a client is issued only what its
// `oauthAllowedScope` lists, or, where it lists nothing, the documented
// default set (OpenID Connect's six and this realm's OpenID4VCI scopes). A
// scope naming an application or a delegated permission keeps its own rules.
// **This service's own protected scopes are NOT behind this predicate**:
// `admin:*`, the SCIM and Shared Signals scopes and the debugger permission
// are held to the declaration in both modes (`common/scope_policy.ts`).
function grantsUndeclaredScopes() {
  log.debug("Entering grantsUndeclaredScopes().");
  log.debug("Leaving grantsUndeclaredScopes().");
  return !isProduct();
}

// Is a delegated permission the client has NOT been granted honoured anyway
// (#110, 2026-09-22)? Development says yes unless
// `oauth2.delegatedPermissionsEnforced` is set, because a client is exercised
// by both answers. Product says no whatever the setting says: a permission is
// a statement that one application may act on another's API, and issuing it to
// a client nobody granted it makes the grant decorative. The setting now only
// turns enforcement ON in development.
function honoursUngrantedPermissions() {
  log.debug("Entering honoursUngrantedPermissions().");
  log.debug("Leaving honoursUngrantedPermissions().");
  return !isProduct();
}

// Does the sign-in screen ENROL a security key for a passwordless sign-in that
// names somebody holding none (2026-09-21)? Development says yes — "enrol on
// first use", so a tester can reach a passkey sign-in with no set-up — and the
// first person to claim a name gets it, which the screen says. Product says
// no. Nothing on that path proves who is asking: no password is read, and the
// only other check was that the name EXISTS, so anybody who knew a username
// could register their own authenticator as that person's primary credential
// and be signed in as them, for good. In product a primary key is added only
// where the person has already proved who they are — `/portal/keys` behind a
// session, an activation link, or an operator. `authn/authn.ts` asks it.
function enrolsKeysOnFirstUse() {
  log.debug("Entering enrolsKeysOnFirstUse().");
  log.debug("Leaving enrolsKeysOnFirstUse().");
  return !isProduct();
}

// May a password alone open a PASSWORD-ONLY DOOR for a person who holds, or
// is required to hold, a second factor (#101, 2026-09-22)? An LDAP simple
// bind, a WS-Security UsernameToken, SCIM and SSF HTTP Basic and EST Basic
// each authenticate with a password and have nowhere to ask for anything
// more (RFC 4513 section 5.1.3, the UsernameToken Profile, RFC 7617, RFC 7030
// section 3.2.3). So the rule comes from the ACCOUNT: NIST SP 800-63B section
// 4.2 puts an account bound to two factors at AAL2, and a verifier that takes
// one of them alone brings it down to AAL1. Development accepts the password
// there, as it accepts every password. Product refuses the person's own
// password at those doors — answered exactly as a wrong one — and accepts an
// APP PASSWORD scoped to the door instead (`common/app_passwords.ts`).
// `common/credentials.ts` asks it, in `secondFactorRefusal()`.
function acceptsPasswordAloneFromSecondFactorAccounts() {
  log.debug("Entering acceptsPasswordAloneFromSecondFactorAccounts().");
  log.debug("Leaving acceptsPasswordAloneFromSecondFactorAccounts().");
  return !isProduct();
}

// May the KDC issue a ticket-granting ticket on a PASSWORD ALONE to a person
// who holds, or is required to hold, a second factor (#173, 2026-09-22)? The
// AS exchange is the sixth password door #101 found, and the one that CAN ask
// for more: RFC 6113 FAST carries RFC 6560 OTP pre-authentication, so a
// person proves their password AND their authenticator app's code in one AS
// exchange. Development says yes, as it accepts every password. Product says
// no: an AS-REQ pre-authenticated with the password alone (PA-ENC-TIMESTAMP,
// or FAST's PA-ENCRYPTED-CHALLENGE) is refused KDC_ERR_POLICY — AFTER the
// password verified, so a wrong one is still KDC_ERR_PREAUTH_FAILED and the
// refusal tells nobody without the password anything. `kerberos/krb5_kdc.js`
// asks it, through the key source (`kerberos/krb5_person_keys.ts`).
function issuesTicketsOnPasswordAlone() {
  log.debug("Entering issuesTicketsOnPasswordAlone().");
  log.debug("Leaving issuesTicketsOnPasswordAlone().");
  return !isProduct();
}

// May a federation partner's asserted NAME be matched straight onto an
// existing local person, which is `fedSubjectPolicy: any-existing` (#109,
// 2026-09-22)? Development says yes — it is what this service did before the
// policy existed, and a client whose partner sends only a name can still be
// exercised. Product says no, whatever the relationship says: OpenID Connect
// Core section 5.7 makes `iss` and `sub` the only claims a relying party may
// rely on as a stable identifier, and a name match lets any partner whose
// signature verifies sign in any local account it can name — `admin`
// included. `federation/federation_sp.ts` refuses such a sign-in
// (STS-FED-0094) and `federation/federation.js` refuses setting the value
// (STS-FED-0095).
function matchesFederatedNames() {
  log.debug("Entering matchesFederatedNames().");
  log.debug("Leaving matchesFederatedNames().");
  return !isProduct();
}

// May a federation partner's SAML LogoutRequest or LogoutResponse arrive
// UNSIGNED (#167)? saml-profiles-2.0-os section 4.4.4.1 says a logout message
// on the HTTP-Redirect or HTTP-POST binding MUST be signed, and a signature
// that is present is verified in every mode. What development may relax is
// ABSENCE, and only on a relationship whose `fedRequireSignedLogout` is set
// off: a partner under test that cannot sign yet is otherwise impossible to
// point at this service. Product refuses the unsigned message whatever the
// relationship says — an unsigned LogoutRequest is anybody signing anybody
// out — and refuses the setting too (STS-FED-0132).
function acceptsUnsignedFederatedLogout() {
  log.debug("Entering acceptsUnsignedFederatedLogout().");
  log.debug("Leaving acceptsUnsignedFederatedLogout().");
  return !isProduct();
}

// May a request object be UNSIGNED — `alg: none` — at the authorization
// endpoint (2026-09-13)? RFC 9101 section 4 says a request object is signed, or
// signed and then encrypted, and nothing else; OpenID Connect Core section 6.1
// still allows `none`, and a great many clients send one. Development accepts
// it — unless `oauth2.requireSignedRequestObject`, the client's
// `oauthRequireSignedRequestObject` or the authorization server's profile says a
// signed one is required, which RFC 9101 section 10.5 says turns `none` away —
// because a client under test that has only met a strict server has never run
// the code it is trying to debug. Product refuses it: an unsigned request
// object is query parameters with extra steps, and anybody can write one.
function acceptsUnsignedRequestObjects() {
  log.debug("Entering acceptsUnsignedRequestObjects().");
  log.debug("Leaving acceptsUnsignedRequestObjects().");
  return !isProduct();
}

// May a registered `request_uri` be dialled over plain HTTP, or answer with a
// media type other than `application/oauth-authz-req+jwt` or `application/jwt`
// (2026-09-13)? RFC 9101 section 5.2 makes a request_uri HTTPS and section 10.4
// asks the server to check what comes back. Development allows both, logged,
// because a client under test commonly serves its request object from a local
// listener with no certificate; product refuses both. What is fetched is ONLY
// ever a URI the client REGISTERED — `oauth-oidc/request_object.ts` argues that
// half, and no mode changes it.
function acceptsLooseRequestUris() {
  log.debug("Entering acceptsLooseRequestUris().");
  log.debug("Leaving acceptsLooseRequestUris().");
  return !isProduct();
}

// May a SAML 2.0 service provider's AuthnRequest — or LogoutRequest — arrive
// UNSIGNED (2026-09-17, #37)? This is what `saml2.requireSignedAuthnRequests`'s
// default, `auto`, resolves to. Development answers yes: most service
// providers under test send unsigned requests, and a refusal there removes the
// case they run. Product answers no — an unsigned request is an
// AssertionConsumerServiceURL, a NameIDPolicy and a RelayState anybody can
// write, and saml-profiles-2.0-os section 4.4.3.1 asks for a logout message to
// be authenticated. A signature that is PRESENT is verified against the
// service provider's registered certificate in BOTH modes, whatever this
// answers; `saml/request_signature.ts` argues why that half is not a mode.
function acceptsUnsignedSamlRequests() {
  log.debug("Entering acceptsUnsignedSamlRequests().");
  log.debug("Leaving acceptsUnsignedSamlRequests().");
  return !isProduct();
}

// May an assertion be ENCRYPTED to a certificate nobody confirmed (2026-09-17,
// #37)? The certificate off a signed AuthnRequest's `ds:KeyInfo` is recorded
// as OBSERVED (`samlObservedSigningCertificate`) and is never a trust anchor
// for a signature in either mode. Development still encrypts to it when the
// entry holds no other certificate, which is the zero-configuration behaviour
// SAML 2.0 encryption has had since 2026-08-27. Product does not: the key in a
// request anybody can send is a key anybody can hold, and encrypting an
// assertion to it hands the assertion to whoever sent the request.
function encryptsToObservedCertificates() {
  log.debug("Entering encryptsToObservedCertificates().");
  log.debug("Leaving encryptsToObservedCertificates().");
  return !isProduct();
}

// May a Metadata Query (MDQ) lookup REGISTER a SAML 2.0 service provider
// nobody registered, on an answer no trust anchor verified (2026-09-23, #112)?
// A request from an unknown entityID starts a lookup (`saml/sp_metadata.ts`'s
// `queueMdqLookup()`), so what the answer may do is decided by whoever sends
// an AuthnRequest — anybody. Development answers yes: a service provider under
// test is registered by the responder the moment it asks, which is the
// zero-configuration behaviour MDQ has had since the #37 follow-up. Product
// answers no. A lookup a REQUEST started is not made at all for an unknown
// entityID unless the realm has `saml2.metadataTrustAnchors`, and then the
// answer registers the entity only when its signature verifies against one of
// them (draft-young-md-query-25 section 6.1 and draft-young-md-query-saml-25
// section 4.1 put a response's integrity in a signature the requester checks
// against a key it already holds). An OPERATOR's import is refused too with no
// anchor, unless `saml2.mdqImportWithoutAnchors` says otherwise. An entry that
// already exists is refreshed from MDQ as before in both modes.
function registersFromMetadataQuery() {
  log.debug("Entering registersFromMetadataQuery().");
  log.debug("Leaving registersFromMetadataQuery().");
  return !isProduct();
}

// Does this identity provider PUBLISH itself to a service provider nobody
// registered (2026-09-23, #112)? `/saml2/metadata/{sp}` and
// `/saml11/metadata/{rp}` mint a signed document naming an identity provider
// of its own for the segment, and the SSO, SLO and artifact endpoints under
// that segment answer for it. Development answers yes — a service provider
// can be pointed here before anything is provisioned, which is the mock's
// decision 1 in both profiles. Product answers no: every one of those paths
// is a 404 for a name that is not a registered service provider (SAML 2.0) or
// relying party (SAML 1.1), so this service signs no document about a party
// an operator never agreed to serve. The unscoped `/saml2/metadata` and
// `/saml11/metadata` are unchanged. A per-SP document is this service's own
// extension (SAML Metadata 2.0 section 4.1 defines one document per entity),
// so the 404 breaks no specification.
function publishesMetadataForUnregisteredProviders() {
  log.debug("Entering publishesMetadataForUnregisteredProviders().");
  log.debug("Leaving publishesMetadataForUnregisteredProviders().");
  return !isProduct();
}

// Does this process embed the identity protocol debugger (2026-09-13)?
// `debugger.enabled` decides where it says `on` or `off`; its default, `auto`,
// is this predicate's own answer: yes in development, where the debugger is
// the other half of what this service is for, and no in product, where an
// operator should turn on a network relay deliberately rather than find one.
// Read against the DEFAULT realm's mode, because the listener and the child
// process belong to the process and not to a realm. See debugger/CLAUDE.md.
function embedsProtocolDebugger() {
  log.debug("Entering embedsProtocolDebugger().");
  const asked = String(config.value('debugger.enabled') || 'auto');
  if (asked === 'on' || asked === 'off') {
    log.debug("Leaving embedsProtocolDebugger(). debugger.enabled=" + asked);
    return asked === 'on';
  }
  log.debug("Leaving embedsProtocolDebugger(). auto.");
  return isDevelopment();
}

// May the embedded debugger's api dial anything other than this service
// (2026-09-13)? Development answers yes — the debugger's own address guard
// still applies, with private networks allowed, which is how it reaches a
// Keycloak or a KDC beside this stack. Product answers no: the api child is
// handed an ALLOW-LIST of this service's own addresses plus
// `debugger.allowedDestinations`, because a relay that dials a caller's URL
// from inside an identity provider's network is the thing to not ship.
function limitsDebuggerDestinations() {
  log.debug("Entering limitsDebuggerDestinations().");
  log.debug("Leaving limitsDebuggerDestinations().");
  return isProduct();
}

// May a URL an ADMINISTRATOR names reach an address inside this service's own
// network (2026-09-13)? The one caller is the RFC 9728 import on
// /admin/applications/new, which fetches a protected resource's metadata
// document. Development answers yes: a resource on localhost is the ordinary
// thing to import there. Product answers no — the name is resolved once, every
// address is checked against loopback, the private ranges, link-local and the
// reserved blocks, and the connection is pinned to the address that was
// checked. `oauth-oidc/protected_resource_metadata.ts` argues it.
function dialsInternalAddresses() {
  log.debug("Entering dialsInternalAddresses().");
  log.debug("Leaving dialsInternalAddresses().");
  return !isProduct();
}

// May an outbound request go out over TLS WITHOUT verifying the certificate
// of whoever answers (#171, 2026-09-23)? Four families send something across
// the network to an address somebody configured or registered — GNAP's push
// finish, SSF push delivery, federation's back channels and the XACML PEP
// nudge — and each has a `…SkipTlsVerification` setting for the one case it
// exists for: a listener on a developer's machine with a certificate nothing
// trusts. Development answers yes and the setting is honoured, with a warning
// on every request. Product answers no: the setting is IGNORED (logged once
// with the family's code) and refused on write, because RFC 9635 section
// 11.1, RFC 8935 and BCP 195 (RFC 9325) all require the peer to be
// authenticated, and an unverified session gives none of that protection. A
// private CA is reached with the family's `…CaFile` instead, with
// verification on. SPIRE's `skip_kubelet_verification`
// (`spiffe.k8sSkipKubeletVerification`) asks this too. `common/outbound_tls.ts`
// is the one place it is asked.
function skipsOutboundTlsVerification() {
  log.debug("Entering skipsOutboundTlsVerification().");
  log.debug("Leaving skipsOutboundTlsVerification().");
  return !isProduct();
}

// May an outbound request go out over PLAIN HTTP to an address that is not
// this host (#171)? The same four families, each with a `…AllowHttp` setting.
// Development answers yes where that setting is on. Product answers no, and
// the one exception is decided by the family, not here: GNAP's push finish may
// still go to a loopback address, because RFC 9635 section 2.5.2.1 (and RFC
// 8252 for native clients) names loopback as a legitimate place for a client
// instance to listen — `STS-GNAP-0103`'s rule, unchanged. SSF, federation and
// XACML have no such text and refuse plain http outright in product.
function dialsPlainHttpOutbound() {
  log.debug("Entering dialsPlainHttpOutbound().");
  log.debug("Leaving dialsPlainHttpOutbound().");
  return !isProduct();
}

// Is an RFC 9728 protected resource metadata document that fails a MUST a
// client applies accepted with a warning (2026-09-13)? Two of them: section
// 3.3's `resource` matching the well-known URL the document was fetched from,
// and section 2's https scheme for a resource identifier. Development warns
// and imports; product refuses. A document that is MALFORMED — the wrong JSON
// types, no `resource` — is refused in both, because shape is not a mode.
function acceptsNonconformingResourceMetadata() {
  log.debug("Entering acceptsNonconformingResourceMetadata().");
  log.debug("Leaving acceptsNonconformingResourceMetadata().");
  return !isProduct();
}

// Is the management API gated by the console's session and roles WHEN
// `adminApi.authRequired` IS OFF? Since 2026-09-09 that setting — on by
// default, in both modes — puts an access token in front of `/admin-api`
// first, and `mgmt-api/admin_api.ts` asks this only below it. See the note
// above on why it is open in development. **THIS IS THE ONLY GATE THE MODE
// TURNS ON**, because it is the only one that was ever off.
function gatesManagementApi() {
  log.debug("Entering gatesManagementApi().");
  log.debug("Leaving gatesManagementApi().");
  return isProduct();
}

// ---------------------------------------------------------------------------
// THE FOUR GATES THAT WERE ALREADY ON, AND WHY THE MODE DOES NOT MOVE THEM.
//
// **`admin.authRequired`, `scim.authRequired`, `spiffe.authRequired` and
// `ssf.authRequired` ALL DEFAULTED TO `true`.** They existed so that an
// operator could turn a gate OFF, which is a thing a mock wants and a product
// must not offer — so what "moving them to the mode" means is that the gate is
// now UNCONDITIONAL and the setting that could disable it is gone.
//
// **THEY RETURN `true` IN BOTH MODES, AND THAT IS THE POINT RATHER THAN AN
// OVERSIGHT.** A first draft had them answer `isProduct()`, which turned four
// gates OFF in development and was caught within the hour by the console suite
// — a reader's form POST answered 303 where it must answer 403, because with
// the gate off everybody may do everything. Development mode is what this
// service always did, and what it always did was require a sign-in at all four.
//
// **WHAT THE MODE ACTUALLY CHANGES AT THESE DOORS IS `verifiesCredentials()`.**
// The gate asks who you are in both modes; only in product mode is the answer
// checked. That is the distinction the whole file exists to keep: a turnstile
// and a lock are different, and this service has always had the turnstile.
// ---------------------------------------------------------------------------

// Is a sign-on session and a role required at the console? Was
// `admin.authRequired`, which defaulted to on.
function gatesConsole() {
  log.debug("Entering gatesConsole().");
  log.debug("Leaving gatesConsole().");
  return true;
}

// Is a credential required at /scim/v2? Was `scim.authRequired`, on by default,
// because those endpoints create and DELETE accounts.
function gatesScim() {
  log.debug("Entering gatesScim().");
  log.debug("Leaving gatesScim().");
  return true;
}

// Is a credential required at the Shared Signals endpoints? Was
// `ssf.authRequired`, on by default. A stream is an agreement to be SENT
// security events about people, so an ungated one is a subscription anybody can
// take out.
function gatesSharedSignals() {
  log.debug("Entering gatesSharedSignals().");
  log.debug("Leaving gatesSharedSignals().");
  return true;
}

// Is an X509-SVID over mutual TLS required at the SPIRE Server API? Was
// `spiffe.authRequired`, on by default, because what comes out of that surface
// is a credential another service will believe.
//
// **The Workload API is deliberately NOT on this list and must never be**: its
// specification says it MUST NOT authenticate a caller, because a workload has
// no root of trust until that call gives it one. What it lacks there is
// ATTESTATION, not authentication, and no mode changes that.
function gatesSpireServerApi() {
  log.debug("Entering gatesSpireServerApi().");
  log.debug("Leaving gatesSpireServerApi().");
  return true;
}

// Does a risk decision only OBSERVE (#62 P3, 2026-09-22)? Development says
// yes unless `risk.enforceInDevelopment` is set: the issuance policy is asked
// with the risk facts and what it decides is recorded, and the roles alone
// decide the issuance — a client under test from a fresh container, a new
// address and an unfamiliar TLS stack would otherwise be asked for a second
// factor it has never heard of. Product says no: a Deny the policy's risk
// obligation carries is kept. The RULES are policy (`ou=policies`); this is
// only whether their risk Deny is kept. `risk/risk_engine.ts` asks it.
function observesRiskOnly() {
  log.debug("Entering observesRiskOnly().");
  log.debug("Leaving observesRiskOnly().");
  return !isProduct();
}

// Does a surface's reaction to a RECEIVED signal only OBSERVE (#62,
// 2026-09-22)? This service's own console and portal receive the CAEP and
// RISC events it transmits, and the `signal-response` policy decides which
// of them end the surface's own sessions for the person named. Development
// records what the policy permitted and ends nothing, unless
// `ssf.actOnSignalsInDevelopment` is on — a suite driving the console emits
// events about the very people it is signed in as. Product takes them.
// `ssf/ssf_receivers.ts` asks it.
function observesSignalsOnly() {
  log.debug("Entering observesSignalsOnly().");
  log.debug("Leaving observesSignalsOnly().");
  return !isProduct() &&
         config.value('ssf.actOnSignalsInDevelopment') !== true;
}

// ---------------------------------------------------------------------------
// WHAT THE MODE CHANGES, as data rather than as prose — so that /admin/mode,
// GET /admin-api/mode and this file cannot come to disagree about what product
// mode does. The page renders this; nothing writes the list twice.
// ---------------------------------------------------------------------------
const REQUIREMENTS = [
  { id: 'credentials',
    what: 'A presented password is verified',
    development: 'No password is checked in any protocol. The sign-in screen ' +
                 'accepts anything, an LDAP bind accepts any DN with any ' +
                 'password, a WS-Security UsernameToken is read for its name ' +
                 'and not its secret, SCIM Basic passes on any pair, and ' +
                 'WS-Trust issues to a caller that presented nothing or an ' +
                 'unsigned SAML assertion.',
    product: 'Verified against the hashed `userPassword` on the person\'s ' +
             'directory entry, at every one of those doors. A person with no ' +
             '`userPassword` set cannot sign in at all. The OAuth 2.0 ' +
             'password grant does not exist in product mode, which implies ' +
             'RFC 9700 mode (section 2.4). ' +
             'WS-Trust requires a credential, and accepts an assertion only ' +
             'when this realm signed it and it is inside its Conditions.',
    where: 'common/credentials.ts, ws-trust/wstrust.ts, oauth-oidc/oauth2.ts' },
  { id: 'credential-issuer-tokens',
    what: 'An OpenID4VCI endpoint accepts only an access token this realm ' +
          'can verify',
    development: 'The credential, deferred credential and notification ' +
                 'endpoints accept any access token and read its claims ' +
                 'unverified — OpenID4VCI lets the authorization server be ' +
                 'somebody else — so a wallet can be pointed at this issuer ' +
                 'with a token from anywhere.',
    product: 'A token that does not verify against this realm\'s signing ' +
             'key, or that this realm revoked, is refused invalid_token ' +
             '(HTTP 401) before anything is issued.',
    where: 'oid4vc/vc_issuer.ts, oauth-oidc/dpop.ts' },
  { id: 'signal-reactions',
    what: 'What this service\'s own console and portal do with a CAEP or ' +
          'RISC event they receive is done',
    development: 'A verified event is recorded on the surface\'s signal ' +
                 'inbox with what the signal-response policy permitted, and ' +
                 'nothing is ended, unless ssf.actOnSignalsInDevelopment is ' +
                 'on.',
    product: 'A verified event the signal-response policy permits — ' +
             'session-revoked, credential-change, a RISC account or ' +
             'credential event, a risk-level-change to HIGH, by default — ' +
             'ends the receiving surface\'s own sessions for the person it ' +
             'names. An unverified event is never acted on in either mode.' },
  { id: 'risk-decisions',
    what: 'The issuance policy\'s decisions on the RISK of an ' +
          'authentication are enforced',
    development: 'Every sign-in is assessed and the issuance policy is ' +
                 'asked with its risk facts, and what it decides is recorded ' +
                 'on the assessment — but a risk Deny is set aside and the ' +
                 'roles alone decide, unless risk.enforceInDevelopment is on.',
    product: 'A risk Deny is kept: an authentication the policy refuses on ' +
             'risk (HIGH, by default) is refused, and one it asks a step-up ' +
             'of (MEDIUM) is asked for a second factor or a security key ' +
             'where the door can ask, and refused where it cannot. When a ' +
             'person\'s risk changes, the reactions the risk-response ' +
             'policy permits are taken — ending everything at HIGH, RISC ' +
             'credential-compromise; development announces the change and ' +
             'records the rest as observed.',
    where: 'risk/risk_engine.ts, xacml/xacml_role_pep.ts, ' +
           'common/issuance_gate.js, authn/authn.ts' },
  { id: 'token-exchange-tokens',
    what: 'An RFC 8693 token exchange accepts only a subject_token and ' +
          'actor_token this realm can verify',
    development: 'A subject_token this realm cannot verify is read for its ' +
                 'name and exchanged anyway, and an actor_token is read and ' +
                 'never verified, so a client can drive the grant with a ' +
                 'token from any issuer.',
    product: 'Both must verify against this realm\'s signing key, be ' +
             'unexpired and not revoked, or the exchange is refused ' +
             'invalid_request (HTTP 400, RFC 8693 section 2.2.2).',
    where: 'oauth-oidc/oauth2.ts' },
  // #108 (2026-09-23). `may_act` is not a row: it is honoured in both modes.
  { id: 'delegation-policy',
    what: 'Who may act for whom is decided at WS-Trust OnBehalfOf / ActAs ' +
          'and the RFC 8693 token exchange',
    development: 'Every delegation is issued. The policy is still asked and ' +
                 'its answer is recorded on the act on /admin/delegation as ' +
                 '"would have been refused: ...", and an exchange may ask ' +
                 'for a scope wider than its subject_token\'s.',
    product: 'The delegation attributes decide (appAllowedToDelegateTo, ' +
             'appAllowedToActOnBehalfOf, appDelegationSubjectGroup, ' +
             'appTrustedToImpersonate on application entries; ' +
             'stsNotDelegated and the console roster on people), then the ' +
             'issuance policy may Deny action-id `delegate`. A refusal is ' +
             'invalid_request or invalid_target (RFC 8693 section 2.2.2) or ' +
             'a wst:RequestFailed SOAP Fault (WS-Trust 1.4 section 11). Only ' +
             'an application entry may delegate as a WS-Trust requester, and ' +
             'an exchange may not widen its subject_token\'s scope ' +
             '(invalid_scope).',
    where: 'common/delegation_policy.ts, oauth-oidc/oauth2.ts, ' +
           'ws-trust/wstrust.ts' },
  // #110 (2026-09-22). The protected scopes are not a row: they are held to
  // the declaration in both modes, which is what a mode does not change.
  { id: 'declared-scopes',
    what: 'A client is issued only the scopes it declared',
    development: 'Any scope a client asks for is issued, whatever its ' +
                 '`oauthAllowedScope` lists. In BOTH modes admin:read, ' +
                 'admin:write, the SCIM and Shared Signals scopes and the ' +
                 'debugger permission are issued only to a client whose ' +
                 '`oauthAllowedScope` lists them.',
    product: 'A scope outside the client\'s `oauthAllowedScope` is refused ' +
             'invalid_scope at the authorization, pushed authorization and ' +
             'token endpoints (STS-OAUTH-0578) and taken off a refresh or an ' +
             'exchange. A client that lists nothing gets the documented ' +
             'default: openid, profile, email, address, phone, ' +
             'offline_access and this realm\'s OpenID4VCI scopes. A scope ' +
             'naming an application or a delegated permission keeps its own ' +
             'rules.',
    where: 'common/scope_policy.ts, oauth-oidc/oauth2.ts, ' +
           'gnap/gnap_grants.ts' },
  { id: 'delegated-permissions',
    what: 'A delegated permission is issued only to a client granted it',
    development: 'An ungranted permission is honoured and recorded as ' +
                 'ungranted, unless oauth2.delegatedPermissionsEnforced is ' +
                 'on.',
    product: 'Refused invalid_scope (STS-OAUTH-0155) whatever ' +
             'oauth2.delegatedPermissionsEnforced says: the grant is ' +
             '`oauthDelegatedPermission` on the client\'s entry.',
    where: 'oauth-oidc/oauth2.ts, common/app_permissions.ts' },
  { id: 'federated-name-match',
    what: 'A federation partner signs in only the person its subject is ' +
          'linked to',
    development: 'A relationship may set fedSubjectPolicy to any-existing, ' +
                 'which matches the name the partner asserted straight onto ' +
                 'a local person — any person, an administrator included ' +
                 'unless fedMayAssertAdministrators is off (the default). ' +
                 'Every other policy behaves as it does in product.',
    product: 'any-existing is refused, at the relationship (STS-FED-0095) ' +
             'and at the sign-in (STS-FED-0094). A partner signs in the ' +
             'entry its (issuer, subject) is linked to; an unlinked subject ' +
             'naming an existing person must first sign in here as that ' +
             'person (link-at-first-sign-in, the default), or is refused ' +
             '(pre-linked). Development and product both keep the rules and ' +
             'the console-administrator refusal.',
    where: 'federation/federation_sp.ts, federation/federation_links.ts, ' +
           'federation/federation.js' },
  { id: 'federated-logout-signature',
    what: 'A federation partner\'s SAML sign-out is signed by that partner',
    development: 'A relationship whose fedRequireSignedLogout is set off ' +
                 'accepts an UNSIGNED LogoutRequest or LogoutResponse from ' +
                 'its partner. A signature that is present is verified ' +
                 'against fedSigningCertificate exactly as in product, and ' +
                 'the setting is on for every relationship unless somebody ' +
                 'turns it off.',
    product: 'Every SAML logout message from a partner must be signed and ' +
             'verify against the relationship\'s certificate ' +
             '(saml-profiles-2.0-os section 4.4.4.1): an unsigned one is ' +
             'refused (STS-FED-0115) whatever fedRequireSignedLogout says, ' +
             'and turning the setting off is refused (STS-FED-0132).',
    where: 'federation/federation_slo.ts, federation/federation.js' },
  { id: 'passkey-first-use',
    what: 'The sign-in screen does not enrol a security key for somebody ' +
          'who has not proved who they are',
    development: 'A passwordless sign-in naming somebody who holds no ' +
                 'primary key enrols one on the spot, with no password read ' +
                 '— the first person to claim a name gets it.',
    product: 'It is refused. A primary key is added on /portal/keys behind ' +
             'a session, by an activation link, or by an operator.',
    where: 'authn/authn.ts' },
  // #101 (2026-09-22).
  { id: 'second-factor-doors',
    what: 'A person who holds or must hold a second factor is refused their ' +
          'password alone at the password-only doors',
    development: 'An LDAP simple bind, a WS-Security UsernameToken, SCIM and ' +
                 'SSF HTTP Basic and EST Basic accept the password as they ' +
                 'accept every password; the sign-in screen still asks for ' +
                 'the second factor.',
    product: 'At those five doors the person\'s own password is refused — ' +
             'answered exactly as a wrong password, and counted against the ' +
             'rate limit as one (STS-AUTHN-0213 on the audit row and in the ' +
             'log only) — whenever they hold an authenticator app or a ' +
             'security key in the mfa role, or a second factor is required ' +
             'of them (stsMfaRequired, authn.mfaRequired). An APP PASSWORD ' +
             'they made on /portal/app-passwords, scoped to the door, is ' +
             'accepted instead. authn.passwordAloneDoors names doors that ' +
             'accept the password anyway, which lowers every such person to ' +
             'one factor there.',
    where: 'common/credentials.ts, common/app_passwords.ts' },
  { id: 'kerberos-second-factor',
    what: 'A person who holds or must hold a second factor gets no Kerberos ' +
          'ticket on a password alone',
    development: 'The KDC issues a TGT to an AS-REQ pre-authenticated with ' +
                 'the password alone (PA-ENC-TIMESTAMP, or FAST\'s ' +
                 'PA-ENCRYPTED-CHALLENGE), as it takes every password.',
    product: 'That AS-REQ is refused KDC_ERR_POLICY (12), STS-KRB-0135, ' +
             'after the password verified (a wrong one is still ' +
             'KDC_ERR_PREAUTH_FAILED), whenever the person holds an ' +
             'authenticator app or a security key in the mfa role, or a ' +
             'second factor is required of them. A person with an ' +
             'authenticator app gets a ticket through RFC 6113 FAST armor ' +
             'with RFC 6560 OTP pre-authentication — password and code in ' +
             'one exchange — and it carries the RFC 8129 indicator `otp`. An ' +
             'app password is never a Kerberos key.',
    where: 'kerberos/krb5_kdc.js, kerberos/krb5_fast.ts' },
  { id: 'resource-metadata-import',
    what: 'An RFC 9728 protected resource metadata import is held to the ' +
          'rules a client of the document follows',
    development: 'A document fetched from a URL is imported with a warning ' +
                 'when its `resource` does not match the well-known URL it ' +
                 'came from (section 3.3) or is not https, and the URL may ' +
                 'resolve to loopback or a private address.',
    product: 'Both are refused, and a URL resolving to a loopback, private, ' +
             'link-local or reserved address is not dialled — the name is ' +
             'resolved once and the connection pinned to the address that ' +
             'was checked. A malformed document is refused in both modes.',
    where: 'oauth-oidc/protected_resource_metadata.ts' },
  { id: 'outbound-tls',
    what: 'An outbound request verifies the certificate of whoever answers, ' +
          'and does not go out over plain http',
    development: 'GNAP push finishes, SSF push deliveries, federation\'s ' +
                 'back channels and XACML PEP nudges honour their ' +
                 '…SkipTlsVerification settings (verification off, warned on ' +
                 'every request) and their …AllowHttp settings (plain http to ' +
                 'any host). SPIRE\'s spiffe.k8sSkipKubeletVerification is ' +
                 'honoured too.',
    product: 'Every …SkipTlsVerification setting, and ' +
             'spiffe.k8sSkipKubeletVerification, is IGNORED — logged once ' +
             'with its code — and refused on write through /admin and ' +
             '/admin-api (STS-CORE-0103); a private CA is reached through ' +
             'the family\'s …CaFile with verification on. Plain http is ' +
             'refused for SSF, federation and XACML whatever …AllowHttp ' +
             'says, and allowed for a GNAP push finish only to a loopback ' +
             'address (RFC 9635 section 2.5.2.1).',
    where: 'common/outbound_tls.ts, gnap/gnap_http.ts, ssf/ssf_http.ts, ' +
           'federation/federation_http.ts, xacml/xacml_pep_http.ts, ' +
           'spiffe/spiffe_workload_attestor_k8s.ts' },
  // #104 (2026-09-23).
  { id: 'deliberate-defects',
    what: 'A deliberate defect does not make a response wrong',
    development: 'oauth2.breakIdTokenNonce puts a wrong nonce in every ID ' +
                 'Token that should carry one, ssf.breakSetSignature changes ' +
                 'one character of every SET\'s signature, ' +
                 'ssf.legacySubClaim adds the `sub` claim RFC 8417 ' +
                 'discourages beside `sub_id`, risc.googleSubjectType writes ' +
                 'the `subject_type` member RISC 1.0 section 3.1 says new ' +
                 'services MUST NOT use, and krb5.clockOffset moves the ' +
                 'KDC\'s clock — each while it is set, so that a client\'s ' +
                 'handling of a wrong answer can be exercised.',
    product: 'All five are IGNORED where they are read — a realm switched ' +
             'to product with one still stored answers correctly, on the ' +
             'machine\'s clock — logged once per process (STS-CORE-0106), ' +
             'and refused on write through /admin, /admin-api and a ' +
             'realm\'s settings (STS-CORE-0103).',
    where: 'common/mode.js, oauth-oidc/oauth2.ts, ssf/ssf_events.js, ' +
           'ssf/risc.ts, kerberos/krb5_kdc.js, kerberos/krb5_principals.js, ' +
           'kerberos/krb5_fast.ts' },
  // #181 (2026-09-23).
  { id: 'broken-algorithms',
    what: 'No broken algorithm is used: SHA-1 in a signature, or RSA ' +
          'PKCS#1 v1.5 key transport',
    development: 'saml.signatureAlgorithm rsa-sha1 signs every XML ' +
                 'signature with SHA-1, saml2.keyTransportAlgorithm rsa-1_5 ' +
                 '(or an application\'s saml2KeyTransportAlgorithm) wraps ' +
                 'an encrypted assertion\'s key with RSAES-PKCS1-v1_5, ' +
                 'saml.allowSha1Signatures on accepts SHA-1 in a signature ' +
                 'this service verifies, pki.signatureAlgorithm sha1-rsa or ' +
                 'sha1-ecdsa (or a build form naming either) makes a ' +
                 'certificate authority sign with SHA-1, and an XML element ' +
                 'encrypted to this service with rsa-1_5 is unwrapped, and ' +
                 'scim.digestMd5 on offers and accepts MD5 in SCIM\'s HTTP ' +
                 'Digest. Every one is off unless set.',
    product: 'Each weak value is IGNORED where it is read (logged once, ' +
             'STS-CORE-0106) and refused on write (STS-CORE-0103, and ' +
             'STS-REG-0193 on an application): XML is signed with the ' +
             'default rsa-sha256, keys are wrapped with rsa-oaep-mgf1p, a ' +
             'SHA-1 signature is refused, a CA build or key pair naming ' +
             'SHA-1 is refused (STS-PKI-0191) and one inherited from a ' +
             'branch built in development is replaced by the key\'s ' +
             'default, and an rsa-1_5 EncryptedKey is ' +
             'refused before it is unwrapped (STS-KEYS-0070) — XML ' +
             'Encryption 1.1 section 6.1.2. scim.digestMd5 is moot, product ' +
             'offering no Digest at all (STS-SCIM-0056). The stronger ' +
             'values of every setting stay available. JOSE RSA1_5 is ' +
             'refused in both modes.',
    where: 'saml/document_settings.ts, saml/saml2_sso.ts, common/crypto.js, ' +
           'common/pki.js, common/applications.js, scim/scim_auth.ts' },
  // #182 (2026-09-23).
  { id: 'kerberos-deprecated-enctypes',
    what: 'No Kerberos key, ticket or exchange uses an enctype RFC 8429 ' +
          'deprecates (rc4-hmac)',
    development: 'krb5.enctypes is 18,17,20,19,23 by default: every account ' +
                 'has an rc4-hmac key beside its AES keys, the rc4only ' +
                 'fixture has nothing else, and a client offering only 23 ' +
                 'gets a ticket — so an RC4 client can be exercised.',
    product: 'The list is read WITHOUT 23 (logged once, STS-CORE-0106) and ' +
             'a write naming it is refused (STS-CORE-0103). No RC4 key is ' +
             'derived, stored or put in a keytab for krbtgt, a service or a ' +
             'person; a key or a ticket of that enctype is never used; an ' +
             'AS-REQ or TGS-REQ offering nothing else is refused ' +
             'KDC_ERR_ETYPE_NOSUPP (STS-KRB-0156); an RC4 session key or ' +
             'subkey in a TGS-REQ, an AP-REQ or FAST armor is refused ' +
             '(STS-KRB-0157, 0158, 0159). AES (17, 18, 19, 20) is what is ' +
             'left.',
    where: 'kerberos/krb5_principals.js, kerberos/krb5_kdc.js, ' +
           'kerberos/krb5_service.js, kerberos/krb5_fast.ts' },
  { id: 'signed-assertions',
    what: 'Every SAML assertion is signed, and every SAML 1.1 Response',
    development: 'saml2.signAssertion, saml11.signAssertion and ' +
                 'saml11.signResponse off — service-wide or on one ' +
                 'application — send an unsigned assertion or an unsigned ' +
                 'SAML 1.1 Response, which is how a relying party that ' +
                 'accepts one is found.',
    product: 'All three are IGNORED where they are read (STS-CORE-0106) ' +
             'and refused on write (STS-CORE-0103; STS-REG-0193 on an ' +
             'application). A SAML 2.0 assertion is signed whatever the ' +
             'binding (saml-profiles-2.0-os 4.1.3.5 and 4.1.4.5 require it ' +
             'over POST), and a SAML 1.1 Response is signed ' +
             '(oasis-sstc-saml-bindings-1.1 4.1.2.4 requires it in ' +
             'Browser/POST), with its assertion. saml2.signResponse off ' +
             'stays allowed: with the assertion signed, the profile asks ' +
             'for no more.',
    where: 'saml/saml2_sso.ts, saml/saml11_sso.ts, common/applications.js' },
  { id: 'workload-security-header',
    what: 'A Workload API call without the workload.spiffe.io header is ' +
          'refused',
    development: 'spiffe.requireSecurityHeader is on by default, as in ' +
                 'product; off serves a call without the header.',
    product: 'Always refused (the SPIFFE Workload Endpoint specification ' +
             'section 3, an SSRF hardening measure): off is IGNORED where ' +
             'it is read (STS-CORE-0106) and refused on write ' +
             '(STS-CORE-0103).',
    where: 'spiffe/spiffe_grpc.ts' },
  { id: 'credential-status-reference',
    what: 'A presented credential must carry a status reference',
    development: 'oid4vp.requireStatusReference is all by default, as in ' +
                 'product: every credential presented to the OpenID4VP ' +
                 'Verifier must name a status that resolves VALID, unless ' +
                 'its trusted issuer is listed in ' +
                 'oid4vp.statusOptionalIssuers. own-only exempts foreign ' +
                 'credentials, and off — development only — accepts one of ' +
                 'this realm\'s own with no reference, and an ldp_vc whose ' +
                 'presentation withheld its credentialStatus.',
    product: 'off is IGNORED where it is read (logged once, STS-CORE-0106) ' +
             'and refused on write (STS-CORE-0103): a credential of this ' +
             'realm with no status reference, or an ldp_vc that did not ' +
             'disclose its credentialStatus, is always refused. own-only ' +
             'and the per-issuer exemption are allowed.',
    where: 'oid4vc/vc_verifier.ts, oid4vc/vc_status.ts' },
  { id: 'realm-chooser',
    what: 'The realm chooser before sign-in lists every realm',
    development: 'A browser with no session at /admin or /portal, on a ' +
                 'service with trust realms defined, is shown a list of every ' +
                 'realm to sign in through.',
    product: 'The same page asks for the realm\'s id in a text box, so the ' +
             'deployment\'s realms are not published to anybody who can ' +
             'reach it.',
    where: 'common/realm_chooser.ts' },
  { id: 'weaker-responses',
    what: 'A response may go out weaker than asked',
    development: 'An assertion or token that should have been encrypted and ' +
                 'could not be is sent in the clear, with a warning.',
    product: 'Refused.',
    where: 'saml/saml2_sso.ts, ws-trust/wstrust.ts' },
  { id: 'objects',
    what: 'A referenced object must already exist',
    development: 'A user, application, service principal or authorization ' +
                 'server is created the first time something names it, which ' +
                 'is what lets a client point at this service with any ' +
                 'identifier and get a working exchange.',
    product: 'An unknown name is REFUSED. Everything must be created ahead ' +
             'of time, through the console, /admin-api, SCIM or an LDAP add.',
    where: 'ldap/ldap_server.js, kerberos/krb5_principals.js, ' +
           'common/applications.js, oauth-oidc/authorization_servers.ts, ' +
           'spiffe/spiffe_workload.ts, scim/scim_auth.ts' },
  { id: 'key-material',
    what: 'Signing keys survive a restart',
    development: 'A new signing key is generated on every start and held in ' +
                 'memory. A token does not survive a restart — which is what ' +
                 'makes this service disposable, and the `kid` is derived ' +
                 'from the key material so two instances can never publish ' +
                 'one name over two keys.',
    product: 'Generated ONCE and read back from the persistence store — ' +
             'which product mode therefore requires — encrypted with ' +
             'AES-256-GCM under a key this service never generates and never ' +
             'stores, read from a mounted file, AWS Secrets Manager, GCP ' +
             'Secret Manager, Azure Key Vault or HashiCorp Vault.',
    where: 'common/keystore.js, common/secrets.js' },
  { id: 'client-secret',
    what: 'An OAuth 2.0 / OIDC application authenticates as what it ' +
          'registered as',
    development: 'Nothing is required of anybody: a client may send nothing ' +
                 'but a client_id, whatever its registration declares.',
    product: 'A CONFIDENTIAL client — one whose registration declares any ' +
             'token_endpoint_auth_method but "none", which includes a ' +
             'registration that declared none at all (RFC 7591 section 2 ' +
             'defaults it to client_secret_basic) — must present that ' +
             'credential and it must verify. A PUBLIC client (an explicit ' +
             'token_endpoint_auth_method=none) is ALLOWED and presents ' +
             'nothing, which is correct; what it is held to instead is the ' +
             'row below. It was "there are no public clients" until ' +
             '2026-09-17.',
    where: 'oauth-oidc/oauth2.ts, oauth-oidc/oauth2_bcp.js, ' +
           'oauth-oidc/client_auth.js' },
  { id: 'oauth-security-bcp',
    what: 'The OAuth 2.0 Security BCP (RFC 9700) is enforced',
    development: 'Only where oauth2.rfc9700 or oauth2.oauth21 is set, per ' +
                 'process or per realm. Off, this service answers a request ' +
                 'the BCP would refuse — which is how a client is exercised ' +
                 'against both answers.',
    product: 'ALWAYS, whatever those settings say, and a realm cannot turn ' +
             'it off. PKCE with S256 required of a public client, exact ' +
             'redirect-URI matching, no open redirect, no http redirect URI ' +
             'off the loopback, a challenge or nonce that cannot be ' +
             'replayed, a nonce with any id_token, no response type that ' +
             'issues an access token from the authorization endpoint, and ' +
             'refresh tokens that rotate with reuse detection. It is what a ' +
             'public client is held to INSTEAD of a credential, and it is ' +
             'why one can be allowed at all (2026-09-17).',
    where: 'common/mode.js, oauth-oidc/oauth2_bcp.js, ' +
           'oauth-oidc/sender_constraints.js' },
  { id: 'public-client-grants',
    what: 'Which grants a public client may use',
    development: 'Every grant this service offers, to anybody.',
    product: 'The authorization code and refresh grants, and not the client ' +
             'credentials grant (RFC 6749 section 4.4 defines it for ' +
             'confidential clients; OAuth 2.1 section 4.2 says so outright) ' +
             'or the resource owner password grant (RFC 9700 section 2.4: ' +
             'it MUST NOT be used). A confidential client is unaffected.',
    where: 'oauth-oidc/oauth2.ts' },
  { id: 'introspection',
    what: 'A caller of /oauth2/introspect authenticates',
    development: 'An RFC 7662 JSON introspection answers anybody who holds ' +
                 'the token string, with no client credential. An RFC 9701 ' +
                 'JWT response (Accept: application/token-introspection+jwt) ' +
                 'is the exception in both modes: its aud names the resource ' +
                 'server that asked, so that caller must authenticate as a ' +
                 'client with a credential on file, and is refused 400 ' +
                 'invalid_client otherwise.',
    product: 'Every introspection request must authenticate as a client ' +
             'with a credential that verifies — client_secret_basic or post, ' +
             'a client assertion, or an RFC 8705 certificate — and is ' +
             'refused ' +
             '401 invalid_client otherwise (400 for a JWT request, RFC 9701 ' +
             'section 5).',
    where: 'oauth-oidc/oauth2.ts, oauth-oidc/introspection_jwt.ts' },
  { id: 'revocation',
    what: 'A caller of /oauth2/revoke authenticates, and revokes only its ' +
          'own token',
    development: 'An RFC 7009 revocation with no client credential revokes ' +
                 'any access or refresh token this realm issued, for anybody ' +
                 'who holds the token string. A caller that DOES present a ' +
                 'credential is held to what product holds it to: a ' +
                 'credential that does not verify is refused 401 ' +
                 'invalid_client, and a token issued to another client ' +
                 'is refused invalid_grant.',
    product: 'Every revocation request must come from a client: a ' +
             'confidential one presents a credential that verifies (the ' +
             'token endpoint\'s methods), a public one names its registered ' +
             'client_id, and anything else is refused 401 invalid_client ' +
             '(RFC 7009 section 2.1). A token issued to another client is ' +
             'refused 400 invalid_grant and nothing is revoked.',
    where: 'oauth-oidc/oauth2.ts' },
  { id: 'request-objects',
    what: 'A JWT-secured authorization request is signed, and a request_uri ' +
          'is HTTPS',
    development: 'A request object signed with `none` (OpenID Connect Core ' +
                 '6.1) is accepted unless a signed one is required — by ' +
                 'oauth2.requireSignedRequestObject, the client\'s entry or ' +
                 'the authorization server\'s profile. A registered ' +
                 'request_uri may be plain http and may answer with any ' +
                 'media type; both are logged.',
    product: 'A request object must be signed (RFC 9101 section 4) and is ' +
             'refused invalid_request_object otherwise. A registered ' +
             'request_uri must be https and must answer ' +
             'application/oauth-authz-req+jwt or application/jwt, or the ' +
             'request is refused invalid_request_uri. In both modes a ' +
             'request_uri is fetched only when the client registered it.',
    where: 'oauth-oidc/request_object.ts' },
  // 2026-09-09: `adminApi.authRequired` (on by default, both modes) put an
  // access token in front of this surface, so the two columns below are what
  // happens with that setting OFF. Both columns say so.
  { id: 'management-api',
    what: '/admin-api requires a sign-in and a role',
    development: 'An OAuth 2.0 access token carrying admin:read or ' +
                 'admin:write, while adminApi.authRequired is on (the ' +
                 'default). With it off: open. It is what the tests drive ' +
                 'and the way back in when nobody holds a role — which also ' +
                 'means anybody who can reach this port can grant themselves ' +
                 'both roles through it.',
    product: 'The same access token while adminApi.authRequired is on. With ' +
             'it off: gated exactly as /admin is — the same session, the ' +
             'same two roles.',
    where: 'mgmt-api/admin_api.ts' },
  { id: 'console',
    what: '/admin requires a sign-in and a role',
    development: 'Required — and it always was; the setting that could turn ' +
                 'it off is gone. The sign-in behind it checks no password, ' +
                 'so what the gate proves is that somebody typed a name that ' +
                 'holds a role.',
    product: 'Required, and the sign-in behind it verifies the credential.',
    where: 'admin-ui/admin.ts' },
  // #103 (2026-09-22). The row the `console` row above cannot state: WHO may
  // use the console before anybody has taken charge of it.
  { id: 'console-bootstrap-window',
    what: 'The console is not opened to everybody before its bootstrap ' +
          'administrator arrives',
    development: 'Until a realm\'s bootstrap administrator first signs in ' +
                 'to /admin — or, where none was seeded, while the roster ' +
                 'is empty — every signed-in person holds both console ' +
                 'roles in that realm, while admin.openWhenEmpty is on. Any ' +
                 'sign-in by that account closes the window.',
    product: 'Nobody holds a role because of the window, whatever ' +
             'admin.openWhenEmpty says: only the roster decides. Until the ' +
             'bootstrap administrator has claimed the console, its roles are ' +
             'honoured only from a PASSWORD sign-in through its own realm ' +
             '(amr pwd, verified here, not a federation partner, a ' +
             'certificate, a wallet or a Kerberos ticket), and only that ' +
             'sign-in claims it (STS-ADMIN-0796); the debugger and a ' +
             'session\'s certificate-enrollment authority wait for the ' +
             'claim. A realm with no bootstrap administrator and an empty ' +
             'roster is closed and logged at startup (STS-ADMIN-0798); ' +
             'POST /admin-api/rbac/grant is the way in.',
    where: 'admin-ui/admin_rbac.ts, admin-core/admin_views.ts, ' +
           'admin-ui/admin.ts, debugger/debugger_access.ts, ' +
           'common/cert_enrollment.ts' },
  { id: 'certificate-enrollment',
    what: 'ACME and EST require TLS; an enrollment credential is verified',
    development: 'ACME (/enroll/acme) and EST (/.well-known/est) answer over ' +
                 'plain HTTP as well and log that they did. An EST password ' +
                 'is not checked (the credentials row) and an application\'s ' +
                 'client secret is not required. An ACME External Account ' +
                 'Binding MAC and a SCEP challenge password ARE verified, and ' +
                 'who a certificate may be issued for is enforced exactly as ' +
                 'in product: yourself, or anybody in the realm if you hold ' +
                 'Admin Write.',
    product: 'A request that did not arrive over TLS is refused ' +
             '(STS-ENROLL-0060). EST verifies the directory password and ' +
             'requires the client secret. Everything else is as in ' +
             'development.',
    where: 'common/cert_enrollment.ts, acme/, est/, scep/' },
  { id: 'scim',
    what: '/scim/v2 requires a credential',
    development: 'Required in one of RFC 7644 section 2\'s six schemes — and ' +
                 'it always was — with none of them verified beyond its shape.',
    product: 'Required and verified. HTTP Digest is not offered, because RFC ' +
             '7616 needs the password or its hash and a scrypt hash can ' +
             'check neither; a HOBA key may be registered only by the ' +
             'signed-in owner of an existing account, and registering one ' +
             'never creates an account.',
    where: 'scim/scim_auth.ts' },
  { id: 'shared-signals',
    what: '/ssf requires a credential',
    development: 'Required in one of the schemes the endpoints accept — and ' +
                 'it always was — none verified beyond its shape.',
    product: 'Required and verified: a Basic credential is checked against ' +
             'the person\'s userPassword, and ssf.authBasic removes the ' +
             'scheme.',
    where: 'ssf/ssf_auth.ts' },
  { id: 'demo-data',
    what: 'A new service contains demonstration data',
    development: 'The directory is seeded with three people, two groups, a ' +
                 'bind account, and the remote-pep-1 and xacml-user-1 ' +
                 'identities in the two XACML role groups; the KDC with ' +
                 'fixture accounts, delegation rules and a trusted realm ' +
                 'whose passwords are written in its source; the SPIFFE ' +
                 'registry with sample entries; and every person is given ' +
                 'generated credential attributes.',
    product: 'None of it. The directory, the principal database and the ' +
             'registry hold what was configured or provisioned, and nothing ' +
             'else — the two XACML role groups exist and are empty, and the ' +
             'KDC refuses to build krbtgt or its service account on the ' +
             'passwords published in this repository.',
    where: 'ldap/ldap_server.js, kerberos/krb5_principals.js, ' +
           'spiffe/spiffe_registry.ts' },
  { id: 'claim-values',
    what: 'A claim value may be invented',
    development: 'A token names a persona — family name `Mock`, an address ' +
                 'at sts.example with email_verified true — a credential ' +
                 'fills an absent attribute with a generated value, and a ' +
                 'security event names an @example.com subject.',
    product: 'A value comes from the person\'s directory entry or is omitted.',
    where: 'common/helpers.js, oauth-oidc/oauth2.ts, oid4vc/vc_claims.ts, ' +
           'ssf/ssf_subjects.js, ssf/risc.ts' },
  { id: 'saml-request-signatures',
    what: 'A SAML 2.0 service provider\'s request is signed',
    development: 'An unsigned AuthnRequest or LogoutRequest is accepted ' +
                 '(saml2.requireSignedAuthnRequests=auto) unless the service ' +
                 'provider\'s consumed metadata says AuthnRequestsSigned. A ' +
                 'signature that IS present is verified against the service ' +
                 'provider\'s registered certificate and refused if it does ' +
                 'not verify; with no registered certificate it is recorded ' +
                 'as not verified. The certificate a request carries in its ' +
                 'KeyInfo is recorded as OBSERVED — never a trust anchor — ' +
                 'and an assertion may still be encrypted to it when the ' +
                 'entry holds no other certificate.',
    product: 'An unsigned AuthnRequest or LogoutRequest is refused ' +
             '(STS-SAML-0063). A signature is verified exactly as in ' +
             'development, and one with no registered certificate to check ' +
             'it against is refused as unsigned. An OBSERVED certificate is ' +
             'not encrypted to until an operator confirms it on the SAML 2.0 ' +
             'page or with POST /admin-api/saml2/confirm-signing-certificate.',
    where: 'saml/request_signature.ts, saml/saml2_sso.ts' },
  { id: 'saml-metadata-query',
    what: 'A Metadata Query lookup registers only a service provider an ' +
          'operator or a trust anchor vouched for',
    development: 'A request from an unknown entityID starts an MDQ lookup ' +
                 '(saml2.mdqBaseUrl), and an answer that describes that ' +
                 'entity creates the application entry, held to ' +
                 'saml2.metadataTrustAnchors only when any are set. The ' +
                 'Import from MDQ action does the same with or without ' +
                 'anchors.',
    product: 'A lookup started by a request is not made for an unknown ' +
             'entityID when the realm has no saml2.metadataTrustAnchors ' +
             '(STS-SAML-0080); with anchors the answer creates the entry ' +
             'only when its signature verifies against one of them ' +
             '(STS-SAML-0081). An operator\'s Import from MDQ with no anchor ' +
             'is refused (STS-SAML-0084) unless ' +
             'saml2.mdqImportWithoutAnchors is on. The refused entityIDs ' +
             'are listed on the SAML 2.0 page and GET /admin-api/saml2 ' +
             '(mdqRefused).',
    where: 'saml/sp_metadata.ts, saml/saml2_sso.ts' },
  { id: 'saml-unregistered-providers',
    what: 'Per-provider SAML metadata and endpoints answer only for a ' +
          'registered provider',
    development: 'GET /saml2/metadata/{sp} and /saml11/metadata/{rp} mint a ' +
                 'signed document for any name, and the SSO, SLO, artifact ' +
                 'and responder endpoints under {sp} or {rp} answer for it.',
    product: 'Each of those paths answers 404 for a name that is not a ' +
             'registered SAML 2.0 service provider (STS-SAML-0082) or SAML ' +
             '1.1 relying party (STS-SAML-0083). The unscoped documents are ' +
             'unchanged.',
    where: 'saml/saml2_sso.ts, saml/saml11_sso.ts' },
  { id: 'return-addresses',
    what: 'A response goes where the request says',
    development: 'Any absolute URL a SAML AuthnRequest, a SAML 1.1 shire, a ' +
                 'WS-Federation wreply or a wallet link names is used, ' +
                 'registered or not — and an address a sighting writes onto ' +
                 'an application entry (or a callback the console or portal ' +
                 'learns from a Host header) is MARKED as observed on ' +
                 'appReturnAddressObserved.',
    product: 'Only an address registered on the application\'s own entry — ' +
             'and a sighting never adds one. An address still marked as ' +
             'observed is NOT registered: development put it there and it is ' +
             'refused until an operator confirms it on the application\'s ' +
             'page or with POST /admin-api/applications/confirm-address ' +
             '(STS-REG-0049). Addresses recorded before sightings were ' +
             'marked carry no mark and still need reviewing before a realm ' +
             'is switched. The console\'s and the portal\'s own callbacks ' +
             'are not learnt from a request\'s Host header (set ' +
             'global.publicBaseUrl), and a WebAuthn RP ID that does not fit ' +
             'the host refuses the ceremony instead of falling back to it.',
    where: 'saml/saml2_sso.ts, saml/saml11_sso.ts, ws-federation/wsfed.ts, ' +
           'oid4vc/vc_offers.ts, oid4vc/vc_verifier.ts, ' +
           'common/applications.js, common/oidc_rp.ts, authn/authn.ts' },
  { id: 'test-controls',
    what: 'Test controls are open',
    development: 'POST /tls/trust and /tls/trust/clear, POST ' +
                 '/dpop/nonce-mode, the passwords on ' +
                 '/krb5/principals, signing another person out with ' +
                 '?username=, open dynamic client registration, the SAML ' +
                 '1.1 attribute authority and HOBA key registration all ' +
                 'answer anybody, a refused SCIM Digest challenge prints ' +
                 'the shared password, and the console\'s restore-kerberos ' +
                 'clears a Kerberos sign-out instant.',
    product: 'Each is refused, or requires the credential its administrative ' +
             'equivalent already requires. A sign-out naming anybody but the ' +
             'signed-in caller is refused whatever logout.anyUser says. ' +
             'restore-kerberos is refused on the console and on ' +
             '/admin-api alike, so a Kerberos sign-out stands until the ' +
             'latest a ticket from before it could be valid. ' +
             'Dynamic client registration is refused unless ' +
             'oauth2.openRegistration is on — or the registration carries a ' +
             'software statement this realm trusts (it issued it, or an ' +
             'application declares its issuer) and ' +
             'oauth2.softwareStatementOpensRegistration is on, which is the ' +
             'operator deciding who may register by deciding whose ' +
             'statements to trust.',
    where: 'tls/tls_server.js, oauth-oidc/oauth2.ts, kerberos/krb5_kdc.js, ' +
           'logout/logout.ts, saml/saml11_sso.ts, scim/scim_auth.ts, ' +
           'admin-core/admin_actions.ts' },
  { id: 'directory-writes',
    what: 'A write to the directory over LDAP is authorized',
    development: 'Any connection may add, modify, rename or delete any entry ' +
                 'in any realm, anonymous ones included — which is what lets ' +
                 'a test drive the raw socket with no setup.',
    product: 'An anonymous connection writes nothing. A connection bound as ' +
             'somebody holding Admin Write — in the default realm\'s ' +
             'directory, and not merely because no role has a member yet — ' +
             'writes anything. Anybody else may modify only their OWN entry, ' +
             'and only the attributes ldap.selfWritableAttributes names; a ' +
             'userPassword among them still meets the password policy. The ' +
             'refusal is LDAP result code 50, insufficientAccessRights. What ' +
             'this does not cover is READING: see directory-reads.',
    where: 'ldap/ldap_server.js' },
  { id: 'directory-reads',
    what: 'A read of the directory over LDAP requires a bind, and never ' +
          'returns a credential',
    development: 'Any connection, anonymous or never bound, may search and ' +
                 'compare every entry and read every attribute but a ' +
                 'Kerberos key, and may write createTimestamp, ' +
                 'modifyTimestamp and entryDN like any other attribute.',
    product: 'A search or compare on a connection that has not bound as ' +
             'somebody is refused with result code 50, ' +
             'insufficientAccessRights — the root DSE excepted, which a ' +
             'client reads to find out where to bind. Credential attributes ' +
             '(userPassword, pwdHistory, client secrets, registration access ' +
             'tokens, private keys, TOTP secrets, recovery codes, activation ' +
             'tokens and Kerberos keys) are never returned by a search, are ' +
             'invisible to a search FILTER so that it cannot be used as an ' +
             'oracle, and cannot be compared against; an administrator is ' +
             'not excepted. createTimestamp, modifyTimestamp and entryDN ' +
             'cannot be written by anybody, with result code 19, ' +
             'constraintViolation.',
    where: 'ldap/ldap_server.js' },
  { id: 'directory-binds',
    what: 'An LDAP bind is confidential, authenticated and rate limited',
    development: 'Every bind succeeds but one with the password "invalid", ' +
                 'on 389 and 636 alike, anonymous and unauthenticated ones ' +
                 'included, with no limit on how many fail.',
    product: 'An anonymous bind is refused with result code 48, ' +
             'inappropriateAuthentication, and a DN with an empty password ' +
             'with 53, unwillingToPerform (RFC 4513 sections 5.1.1 and ' +
             '5.1.2). A bind carrying a password on the plain listener is ' +
             'refused with 13, confidentialityRequired, before the password ' +
             'is read — use LDAPS, or turn ldap.plainListener off. FAILED ' +
             'binds are counted per bind DN and per address against ' +
             'security.rateLimitPerIdentity and security.rateLimitPerAddress ' +
             'within security.rateLimitWindowS, and a caller over either is ' +
             'refused with 53 before its password is checked; a successful ' +
             'bind clears its own DN\'s counter, never its address\'s, and ' +
             'is never counted.',
    where: 'ldap/ldap_server.js, common/websecurity.ts' },
  { id: 'spire',
    what: 'The SPIRE Server API requires an X509-SVID',
    development: 'Required over mutual TLS and authorized against SPIRE\'s ' +
                 'own per-method table; anybody may ask the local socket to ' +
                 'mint the SVID that gets them in.',
    product: 'The same, over a registry that no longer mints an entry for ' +
             'whoever asks.',
    where: 'spiffe/spiffe_auth.ts' },
  // #104 (2026-09-23): SPIRE's model, with the boundary verified.
  { id: 'spire-local-socket',
    what: 'A caller on the SPIRE Server API\'s Unix socket is the trusted ' +
          '`local` entity only where the socket\'s boundary holds',
    development: 'Every caller on the socket is `local` while ' +
                 'spiffe.trustLocalSocket is on (the default): the socket\'s ' +
                 'filesystem permissions are assumed to be the boundary, as ' +
                 'a real spire-server assumes.',
    product: 'The boundary is VERIFIED per connection: the socket must have ' +
             'been made 0600 and sit in a directory with no group or other ' +
             'bits (STS-SPIFFE-0117), and the peer\'s kernel uid, read with ' +
             'SO_PEERCRED through the native module, must be this ' +
             'service\'s own (STS-SPIFFE-0118; unreadable, STS-SPIFFE-0119). ' +
             'A caller failing either is not `local` and needs an ' +
             'administrator\'s X509-SVID on the TCP port.',
    where: 'spiffe/spiffe_auth.ts, spiffe/spiffe_grpc.ts, ' +
           'spiffe/spiffe_server.ts' },
  // #40 (2026-09-21): what node and workload attestation check, by mode.
  { id: 'spiffe-node-attestation',
    what: 'SPIFFE node attestation (AttestAgent)',
    development: 'Every type is VERIFIED by its attestor or refused — ' +
                 'join_token, x509pop, sshpop, tpm_devid, k8s_psat, ' +
                 'http_challenge, aws_iid, gcp_iit, azure_imds — as the ' +
                 'realm lists in spiffe.nodeAttestors.',
    product: 'The same; nothing about node attestation differs by mode.',
    where: 'spiffe/spiffe_node_attestation.ts' },
  { id: 'spiffe-workload-attestation',
    what: 'SPIFFE workload attestation (the Workload API Unix socket)',
    development: 'A caller\'s kernel credentials and process are read at ' +
                 'connect (spiffe.workloadAttestors: unix, docker, k8s) where ' +
                 'the native module is built; without it the socket is served ' +
                 'on transport selectors alone and says so. Asserted ' +
                 'selectors are believed when spiffe.acceptAssertedSelectors ' +
                 'is on, and spiffe.attestWorkloads off answers every caller ' +
                 'with every entry.',
    product: 'Without the native module the Workload API socket is NOT ' +
             'served. Asserted selectors are never believed, and a caller ' +
             'is answered only with the entries its selectors match, ' +
             'whatever spiffe.attestWorkloads says; both settings are ' +
             'ignored where they are read (logged once, STS-CORE-0106) and ' +
             'refused on write (STS-CORE-0103).',
    where: 'spiffe/spiffe_peer.ts, spiffe/spiffe_auth.ts, ' +
           'spiffe/spiffe_workload.ts' },
  // #166 (2026-09-23): the Workload API over TCP, and what an entry must
  // select.
  { id: 'spiffe-workload-tcp',
    what: 'The SPIFFE Workload API over TCP (spiffe.workloadPort)',
    development: 'Served on spiffe.grpcHost, the wildcard included. A TCP ' +
                 'caller is not attested — there is no peer process to ask — ' +
                 'and is identified by its transport, the endpoint it ' +
                 'reached and its source address.',
    product: 'NOT SERVED (STS-SPIFFE-0120) unless ' +
             'spiffe.workloadTcpSourceAuthenticated declares that the ' +
             'network authenticates source addresses (Workload Endpoint ' +
             'section 3), and then only on a named address: a wildcard ' +
             'spiffe.grpcHost is refused (STS-SPIFFE-0121). A realm switched ' +
             'to product with the port already bound refuses every call on ' +
             'it with the same codes.',
    where: 'spiffe/spiffe_auth.ts, spiffe/spiffe_server.ts, ' +
           'spiffe/spiffe_grpc.ts' },
  { id: 'spiffe-entry-selectors',
    what: 'A SPIFFE registration entry selects something that identifies a ' +
          'workload',
    development: 'Any selectors, none included: an entry on transport:tcp ' +
                 'alone is issued to every TCP caller, and an invented entry ' +
                 'carries exactly that.',
    product: 'An entry with no selector, or only transport: and endpoint: ' +
             'ones, is refused at the console, /admin-api and the SPIRE ' +
             'Server API (STS-SPIFFE-0122; INVALID_ARGUMENT per item there), ' +
             'and one already in the registry answers no caller ' +
             '(STS-SPIFFE-0123). A peer: selector matches the source address ' +
             'exactly — no prefixes, as in SPIRE.',
    where: 'spiffe/spiffe_registry.ts, spiffe/spiffe_workload.ts' },
  // 2026-09-12. The one row here whose two columns differ in what is REFUSED
  // for a reason that is not "development checks nothing": both modes consult
  // the register, and the difference is what an UNREACHABLE foreign CRL costs.
  { id: 'revocation-check',
    what: 'A presented certificate is checked for revocation',
    development: 'SOFT-FAIL (pki.revocationCheck=auto). A certificate this ' +
                 'service issued is looked up in its own register, the whole ' +
                 'chain, and a revoked one is refused; one from another ' +
                 'authority is checked with the OCSP responder and the CRL ' +
                 'it names, and a status that cannot be fetched or verified ' +
                 'is accepted and reported.',
    product: 'HARD-FAIL (pki.revocationCheck=auto). The same lookups, and a ' +
             'foreign certificate whose status cannot be fetched, verified ' +
             'or trusted as fresh — or that its issuer\'s responder does not ' +
             'know — is REFUSED too: an attacker who can block a fetch ' +
             'cannot turn "revoked" into "accepted". So is one whose only ' +
             'list or responder is at an address this service is ' +
             'configured not to dial (plain ldap: under pki.revocationLdap' +
             '=ldaps, any ldap with it off, a relative name without ' +
             'pki.revocationLdapDirectory; STS-PKI-0188): the issuer ' +
             'published a list and this service\'s own policy is what ' +
             'stopped it being read.',
    where: 'common/revocation_status.js, tls/tls_server.js, ' +
           'oauth-oidc/mtls.js, oauth-oidc/client_auth.js, ' +
           'scim/scim_auth.ts, spiffe/spiffe_auth.ts, common/pki.js' },
  // #174, 2026-09-23. A row of its own rather than a sentence on the one
  // above, because it is a different predicate answering a different question:
  // not "what if the status could not be fetched" but "what if there is
  // nothing to fetch at all".
  { id: 'revocation-unrevocable',
    what: 'A foreign certificate whose issuer names no CRL and no OCSP ' +
          'responder',
    development: 'ACCEPTED (pki.revocationRequireDistributionPoint=auto), ' +
                 'and the verdict says it could not be checked: there is ' +
                 'no fetch an attacker could block, and a client author\'s ' +
                 'test CA with no list is the usual first thing they build.',
    product: 'REFUSED under hard-fail (pki.revocationRequireDistributionPoint' +
             '=auto, STS-PKI-0190): a certificate issued by a CA — not ' +
             'self-signed — that names no distribution point and no ' +
             'responder can never be revoked, so a stolen key under it is ' +
             'good until it expires. One carrying RFC 9608 noRevAvail is ' +
             'accepted, because its issuer declared that no revocation ' +
             'information exists (section 4 skips the check). Setting ' +
             'the setting to off accepts the rest, with a warning.',
    where: 'common/revocation_status.js' },
  // 2026-09-13. The embedded protocol debugger. Its GATE is not on this page
  // because it does not move: an access token carrying the debugger
  // permission, issued only to a console administrator, in both modes.
  { id: 'gnap-mtls-trust',
    what: 'A GNAP key proved by mutual TLS is a certificate a trusted ' +
          'authority issued to the client',
    development: 'PINNED (gnap.mtlsTrust=auto): the TLS client certificate ' +
                 'must be the one the key names — by thumbprint, or the ' +
                 'same public key — and a self-signed one is accepted (RFC ' +
                 '9635 section 7.3.2). No chain is built. A certificate this ' +
                 'service or another authority REVOKED is refused all the ' +
                 'same (pki.revocationCheck).',
    product: 'PKI (gnap.mtlsTrust=auto, RFC 9635 section 11.4): the ' +
             'certificate must build a chain to the client truststore, pass ' +
             'the revocation check, and be BOUND to the client\'s ' +
             'application entry — issued to it by this realm\'s TLS client ' +
             'authority, or carrying the one RFC 8705 subject parameter the ' +
             'entry registers (oauthTlsClientAuth*). A new certificate from ' +
             'the authority is accepted without re-registration, and its ' +
             'thumbprint is recorded on the entry. gnap.mtlsTrust=pinned ' +
             'turns this off for a realm; an entry may ask for pki where the ' +
             'realm does not, never the reverse.',
    where: 'gnap/gnap_proof.ts, gnap/gnap_grants.ts, common/applications.js' },
  { id: 'protocol-debugger',
    what: 'The identity protocol debugger is embedded, and what its api may ' +
          'dial',
    development: 'ON (debugger.enabled=auto): its own listener ' +
                 '(debugger.port) serves the debugger UI and forwards /api to ' +
                 'a child process. The api dials whatever a signed-in ' +
                 'administrator asks it to, including private networks.',
    product: 'OFF unless debugger.enabled=on. When on, the api child is ' +
             'handed an ALLOW-LIST — this service\'s own addresses and ' +
             'debugger.allowedDestinations — and refuses every other ' +
             'destination, raw sockets included.',
    where: 'debugger/debugger_server.ts, debugger/debugger_api_process.ts' },
  // 2026-09-22 (#49 P5).
  { id: 'client-secret-expiry',
    what: 'An expired client secret',
    development: 'ACCEPTED where a secret is checked, with an audit row ' +
                 'saying it had expired.',
    product: 'REFUSED at the token endpoint (invalid_client, ' +
             'STS-OAUTH-0558) once oauthClientSecretExpiresAt — or the ' +
             'registration\'s client_secret_expires_at — has passed. A ' +
             'rotated secret\'s predecessor is accepted in both modes until ' +
             'oauth2.clientSecretOverlapS has passed.',
    where: 'oauth-oidc/client_auth.js, common/applications.js' },
  // 2026-09-22 (#42). It was NOT_YET's `key-overlap` — "a rotation has NO
  // OVERLAP" — until key GENERATIONS gave every unit a next key published
  // before it signs and retired keys that verify through their grace.
  { id: 'signing-key-rotation',
    what: 'Signing keys are rotated, with an overlap',
    development: 'NOT ROTATED: the keys are made anew at every start. Every ' +
                 'unit still carries its generations, so a next or retired ' +
                 'key made by hand is published and verifies as in product.',
    product: 'Every unit (realm, use case, algorithm) holds a NEXT key, ' +
             'published in the JWKS, the SAML and WS-Federation metadata ' +
             'and /crypto/metadata before it signs anything, promoted every ' +
             'signing.rotationIntervalDays by the signing.rotate job; the key ' +
             'it replaces goes on verifying for signing.retiredKeyGraceDays ' +
             'or the longest token lifetime, whichever is longer.',
    where: 'common/helpers.js, common/keystore.js, common/pki.js, ' +
           'pki/crypto_metadata_document.ts' }
];

// WHAT PRODUCT MODE STILL DOES NOT DO. Named here rather than left to be
// discovered, because a mode called `product` invites the assumption that
// everything in it is production-grade, and three things were not — all three
// narrowed or paid since, and NOT_YET below is the current list:
//
//   * ~~NO REVOCATION IS CHECKED ON A CLIENT CERTIFICATE~~ — **PAID ON
//     2026-09-12.** It read "there is no OCSP responder and no CRL fetch, in
//     either mode". The responder arrived on 2026-09-11 and the check on
//     2026-09-12 (`common/revocation_status.js`), with OCSP for a FOREIGN
//     certificate and delta and indirect CRLs the same day; what remains is
//     in NOT_YET below.
//   * ~~NOTHING THIS SERVICE MINTS SURVIVES A RESTART~~ — **PAID ON
//     2026-09-06 and left here as the record of it.** It read "in either
//     mode, because the signing key is regenerated on every start; a product
//     deployment needs key persistence and rotation, and that is a feature
//     rather than a mode". Both halves arrived that day: `keystore.js`
//     persists the keys in product mode, and with the premise gone
//     `persistence_minted.js` persists the sessions, tokens, codes,
//     artifacts, tickets, counters and audit log beside them. DEVELOPMENT
//     MODE IS UNCHANGED and the sentence is still true of it, which is why
//     it is qualified here rather than deleted.
//   * ~~A KERBEROS ACCOUNT POLICY IS STILL PERMISSIVE~~ — **REWRITTEN ON
//     2026-09-12.** It read "every seeded principal shares one password;
//     product mode does not give the existing ones distinct long-term keys".
//     Product mode now seeds no fixture principals at all; what is left is
//     the `kerberos-keys` row in NOT_YET below.
const NOT_YET = [
  // **THIS ROW NARROWED ON 2026-09-11 AND DID NOT GO AWAY.** It read *there
  // is no OCSP responder and no CRL fetch*; the first half stopped being true
  // that day — every authority in `/admin/pki` signs a CRL and answers OCSP —
  // and the SECOND half is what this row was always about and is unchanged.
  // Publishing revocation and consulting it are different pieces of work, and
  // a row deleted because half of it was done would have quietly removed the
  // half that is still outstanding.
  // **AND IT NARROWED AGAIN ON 2026-09-12, AND AGAIN DID NOT GO AWAY.** It
  // read *revocation is PUBLISHED and never CONSULTED*: a certificate revoked
  // on /admin/pki still authenticated here. `common/revocation_status.js`
  // consults it now at every door that accepts a presented certificate, and
  // the REQUIREMENTS row above says what each mode refuses. What is left is
  // the three things that file does not do, which are what this row is about.
  // **AND A THIRD TIME THE SAME DAY.** It named three things outstanding: OCSP
  // for a foreign certificate, indirect and delta CRLs, and a registered key.
  // The first two are consulted now — the responder a certificate names, with
  // delegated-responder validation, and delta and indirect lists with their
  // issuing distribution point — and what is left is narrower than either.
  { id: 'certificate-revocation',
    what: 'Revocation is CONSULTED for a presented certificate (see the ' +
          'requirement above) and for a REGISTERED one when it verifies ' +
          'something — the register, the OCSP responder (a delegated ' +
          'responder\'s own status included) and the CRL a foreign ' +
          'certificate names, over http, https and ldaps, delta CRLs merged, ' +
          'indirect CRLs read per issuer with their signer fetched from the ' +
          'list\'s caIssuers address where nothing here holds it. What ' +
          'remains is limits rather than work: a BARE key registered with no ' +
          'certificate (a JWK without x5c) names no issuer and no list, so ' +
          'only taking it off the entry stops it verifying; plain ldap: is ' +
          'dialled only when pki.revocationLdap allows it; a distribution ' +
          'point named relative to its CRL issuer is used only with ' +
          'pki.revocationLdapDirectory set and every RDN single-valued; and ' +
          'LDAPS 636 asks for no client certificate, so nothing there is ' +
          'consulted.' },
  // **THE SPIFFE HALF OF THIS ROW NARROWED ON 2026-09-11.** It said "the TLS
  // server certificate and the SPIFFE authorities, which belong to their own
  // modules and are shared across realms" — and the SPIFFE X.509 authority is
  // `common/pki.js`'s SPIFFE Issuing CA now, per realm, in the same sealed
  // `pki:` row family as the rest of the hierarchy, so in product mode it
  // survives a restart. The JWT authority does not: it has no certificate and
  // no hierarchy to hang from, so there is nothing for the keystore to keep it
  // beside.
  //
  // **AND THE POST-QUANTUM HALF CAME OFF IT ON 2026-09-12**, though the row
  // kept its id: `helpers.js`'s `pqKeysForAsync()` writes a realm's eleven
  // post-quantum keys into its stored key set (`keystore.remember()`), and a
  // restore puts them back — see common/CLAUDE.md, *THE POST-QUANTUM HALF WAS
  // WRITTEN AND NEVER READ BACK*. The id is an identifier a client may match
  // on, so it was not renamed.
  { id: 'post-quantum-keys',
    what: 'The TLS server certificate and the SPIFFE JWT authority are NOT ' +
          'persisted, in either mode: they belong to their own modules and ' +
          'are made again at every start (unless tls.certificateFile ' +
          'supplies the certificate). A realm\'s eleven post-quantum ' +
          'keys came off this row on 2026-09-12 — in product mode they are ' +
          'written with the realm\'s key set and restored with it — and the ' +
          'SPIFFE X.509 authority on 2026-09-11: it is this realm\'s SPIFFE ' +
          'Issuing CA under the service Root, so it persists in product mode ' +
          'exactly as the rest of the certificate authority does.' },
  { id: 'key-never-in-memory',
    what: 'A private key is DECRYPTED IN THIS PROCESS while it signs. Since ' +
          '2026-09-06 what is resident between signatures is the ciphertext, ' +
          'and `keys.plaintextRetention` decides how long the plaintext ' +
          'lives — but the key-encryption key is resident too, so this ' +
          'narrows the value of a SNAPSHOT (a core dump, a swapped page, a ' +
          'debugger attached for a moment) and defends against nothing that ' +
          'can read this memory at a moment of its choosing and wait for the ' +
          'next signature. A key that this process genuinely cannot read is ' +
          'an HSM, or a KMS that signs on your behalf, and is a different ' +
          'design rather than a setting. A JavaScript string also cannot be ' +
          'wiped: the decrypt buffer is zeroed and everything made out of it ' +
          'is released rather than erased.' },
  // **REWRITTEN 2026-09-12.** It read *product mode stops the KDC creating
  // principals on demand; it does not give the seeded ones distinct long-term
  // keys — they still share `krb5.userPassword`*. Product mode now seeds no
  // fixture principals at all, so there are no shared keys left to describe —
  // and what that exposed is the larger gap, which is this row now.
  { id: 'kerberos-keys',
    what: 'Product mode creates no fixture principals, no trusted realm and ' +
          'nothing on demand, and refuses the published krbtgt and service ' +
          'passwords. Directory people authenticate to the product KDC with ' +
          'keys derived from their own password when it is set or verified, ' +
          'sealed on their entry (`stsKrb5Keys`); service principals get ' +
          'random keys and a keytab shown once at ' +
          '/admin/kerberos/principals. A person\'s keytab (#59) is derived ' +
          'from a password in hand — their own on /portal/kerberos, or one ' +
          'an administrator sets with "Reset password and download keytab" ' +
          '— and never read out of storage. A password change or a ' +
          'rotation keeps ' +
          'the version it replaced — at most krb5.retainedKeyVersions, each ' +
          'for krb5.retainedKeyTtlS — so a ticket issued under it is still ' +
          'accepted until it could have expired, while pre-authentication ' +
          'and issuance use the current key only; "Drop previous versions" ' +
          'ends that window. Not yet: the krbtgt key has no rotation and so ' +
          'no previous version (a TGT under an older krb5.krbtgtPassword is ' +
          'refused). Since 2026-09-15 each trust realm whose krb5.enabled ' +
          'is on has a KDC, a Kerberos realm and keys of its own, on the ' +
          'shared port.' },
  // `vci-request-encryption-key` WAS HERE AND WAS PAID ON 2026-09-12. The
  // OpenID4VCI request-encryption key is a member of each realm's key set now
  // (`helpers.js`'s `makeStsKeys()`), so it is per realm, travels to request
  // workers over the key channel with the rest of the set, and persists
  // wherever the signing keys do. What is left is the race every key-set
  // enrichment already has: two separate service instances on one store adding
  // a key to an OLD stored set at the same moment.
  // `truststore-door` WAS HERE AND WAS PAID IN TWO STEPS ON 2026-09-12: first
  // the gated door (/admin/tls/trust, POST /admin-api/tls/trust/{add,remove}),
  // then persistence — a runtime anchor is written to ou=trustAnchors in the
  // default realm's directory, restored before any listener binds, and
  // re-applied when another process changes the container. What is left is
  // narrower and is the directory's: any LDAP client allowed to write
  // ou=trustAnchors can add an anchor, which the directory authorization gap
  // below covers.
  // `directory-authorization` WAS HERE AND ITS WRITE HALF WAS PAID ON
  // 2026-09-12 — see the `directory-writes` requirement above. It read *a bound
  // LDAP client may add, modify or delete any entry*. What it did not say, and
  // what is left, is that the same client may READ any entry.
  // NARROWED 2026-09-12, when `directory-reads` landed. It read *any
  // connection — anonymous included — may search and compare every entry in
  // every realm and read every attribute, including oauthClientSecret and
  // fedClientSecret in the clear*. An anonymous connection now reads nothing
  // and no connection reads a credential; what is left is the part that is a
  // design question rather than a hole.
  { id: 'directory-read-authorization',
    what: 'The embedded directory has no PER-IDENTITY read authorization. In ' +
          'product mode a read requires a bind and credential attributes are ' +
          'withheld from everybody, but any connection that has bound as ' +
          'somebody may search and compare every entry in the realm its base ' +
          'names and read every other attribute on it — every person\'s ' +
          'mail, telephone number and group memberships, every ' +
          'application\'s redirect URIs. Deciding what a person, an ' +
          'administrator and an application may each read is the outstanding ' +
          'design.' },
];

// ---------------------------------------------------------------------------
// A SETTING THE MODE DOES NOT ALLOW, AS IT IS IN FORCE (#104, 2026-09-23).
//
// A row in `config.js` carrying `onlyWhile: '<predicate>'` may hold a value
// other than its default only while that predicate answers true. The WRITE is
// refused there (`modeWriteProblem()`, STS-CORE-0103); this is the READ, and
// the read is the guard, because `global.mode` is itself a runtime setting and
// a realm can be switched to product with a development-only value still
// stored. So a reader asks `valueInForce(key)` rather than `config.value(key)`
// and gets the row's DEFAULT whenever the predicate says no — with a warning,
// once per process and setting, naming it (STS-CORE-0106). "Once" is a set of
// at most one entry per marked row, bounded by the table, so it is not a cache
// in `common/cache_registry.js`'s sense and not periodic work.
//
// The four `…SkipTlsVerification` rows and SPIRE's kubelet skip carry the
// marker too and are read through `common/outbound_tls.ts`, which says so
// with each family's own code; nothing else reads them.
// ---------------------------------------------------------------------------
const ignoredAnnounced = new Set();
let rowsByKey = null;

// The configuration row for `key`, or null. Indexed on first use: `config.js`
// is loaded before this file, and its table does not change after.
function rowOf(key) {
  log.debug("Entering rowOf(). key=" + key);
  if (!rowsByKey) {
    rowsByKey = {};
    config.SETTINGS.forEach(function (row) {
      rowsByKey[row.key] = row;
    });
  }
  log.debug("Leaving rowOf().");
  return rowsByKey[key] || null;
}

// Does the mode allow `key` to hold `value`? True for a row with no marker,
// for the row's default, and wherever the marker's predicate answers true.
function allowsValue(key, value) {
  log.debug("Entering allowsValue(). key=" + key);
  const row = rowOf(key);
  if (!row || !row.onlyWhile) {
    log.debug("Leaving allowsValue(). Unmarked.");
    return true;
  }
  // A LIST (#182, 2026-09-23): `krb5.enctypes` is a csv row, and what is
  // development-only is an ELEMENT of it — `23`, rc4-hmac — not the list.
  // So a list is allowed when none of its elements is one the marker names,
  // and is judged element by element even when it is the default, because
  // that row's default carries `23` on purpose (development exercises RC4 out
  // of the box) and product must not inherit it. `marked()` below is the one
  // reading of which elements those are, shared with `productValue()`.
  if (Array.isArray(value) && Array.isArray(row.onlyWhileValues)) {
    if (!marked(row, value).length) {
      log.debug("Leaving allowsValue(). No element the marker names.");
      return true;
    }
  } else if (value === row.dflt) {
    log.debug("Leaving allowsValue(). The default.");
    return true;
  } else if (Array.isArray(row.onlyWhileValues) &&
             row.onlyWhileValues.indexOf(value) < 0) {
    // `onlyWhileValues` narrows the marker to the values it names (#165): an
    // enum whose weaker values are not all development-only —
    // `oid4vp.requireStatusReference`'s `own-only` is allowed in product, its
    // `off` is not. A row without it marks every value but the default.
    log.debug("Leaving allowsValue(). A value the marker does not name.");
    return true;
  }
  const predicate = module.exports[row.onlyWhile];
  if (typeof predicate !== 'function') {
    // A marker naming no predicate is a defect in config.js; refusing the
    // value is the direction that cannot loosen anything.
    log.debug("Leaving allowsValue(). The marker names no predicate.");
    return false;
  }
  const allowed = !!predicate();
  log.debug("Leaving allowsValue(). " + allowed);
  return allowed;
}

// The value of `key` as the ambient realm's mode lets it be: the setting's own
// value, or its default where the mode refuses a development-only value.
function valueInForce(key) {
  log.debug("Entering valueInForce(). key=" + key);
  log.debug("Leaving valueInForce().");
  return inForce(key, config.value(key), key);
}

// The same for a value that came from somewhere OTHER than the setting — an
// application entry's override of it (#181: `saml2SignAssertion`,
// `saml2KeyTransportAlgorithm` …, read by `applications.settingFor()`).
// `source` names where it came from in the warning, and is part of what is
// said once, so the setting and each overriding attribute are each said once
// per process: still a set bounded by the table's rows and the schema's
// attributes, never by how many entries carry one.
function inForce(key, value, source) {
  log.debug("Entering inForce(). key=" + key);
  if (allowsValue(key, value)) {
    log.debug("Leaving inForce(). As set.");
    return value;
  }
  const row = rowOf(key);
  const read = productValue(row, value);
  const said = key + '|' + String(source || key);
  if (!ignoredAnnounced.has(said)) {
    ignoredAnnounced.add(said);
    log.warn(errorCodes.tag('STS-CORE-0106') + 'mode: ' +
             (source && source !== key ? source + ' (overriding ' + key +
                                         ')' : key) +
             // A list names the ELEMENTS ignored (#182) — the default of
             // `krb5.enctypes` carries one, and "is set to" would say
             // somebody set it.
             (Array.isArray(value) && Array.isArray(row.onlyWhileValues)
               ? ' names ' + JSON.stringify(marked(row, value)) + ', which ' +
                 'is IGNORED, '
               : ' is set to ' + JSON.stringify(value) + ' and is IGNORED, ') +
             'because this realm is in product mode (global.mode=product): ' +
             writeRefusalReason(row.onlyWhile) + ' It is read as ' +
             JSON.stringify(read) + ' until it is reset. Said once per ' +
             'process.');
  }
  log.debug("Leaving inForce(). The product reading.");
  return read;
}

// The elements of a LIST value that a row's `onlyWhileValues` names (#182),
// compared as text: a csv row's value is an array of strings, and a caller
// asking about one enctype passes a number.
function marked(row, list) {
  log.debug("Entering marked(). key=" + row.key);
  const names = (row.onlyWhileValues || []).map(String);
  log.debug("Leaving marked().");
  return list.filter(function (one) {
    return names.indexOf(String(one)) >= 0;
  });
}

// WHAT A VALUE THE MODE REFUSES IS READ AS. For a single value that is the
// row's default, which is the product value by construction (#104). For a
// LIST (#182) it is the list WITHOUT the elements the marker names, in the
// order it was written — a product realm whose `krb5.enctypes` says
// `18,17,23` uses 18 and 17 — and where nothing would be left, the default
// without them, so a product KDC is never configured into offering nothing.
function productValue(row, value) {
  log.debug("Entering productValue(). key=" + row.key);
  if (!(Array.isArray(value) && Array.isArray(row.onlyWhileValues))) {
    log.debug("Leaving productValue(). The default.");
    return row.dflt;
  }
  const withheld = marked(row, value);
  const kept = value.filter(function (one) {
    return withheld.indexOf(one) < 0;
  });
  if (kept.length) {
    log.debug("Leaving productValue(). " + kept.length + " element(s).");
    return kept;
  }
  const fallback = config.parseAs(row.key, row.dflt);
  const dflt = fallback.ok && Array.isArray(fallback.value) ?
    fallback.value : [];
  log.debug("Leaving productValue(). The default's elements.");
  return dflt.filter(function (one) {
    return marked(row, [one]).length === 0;
  });
}

// WHY a marked row's value is not allowed, by the predicate the row names:
// the sentence the write refusal and the ignored-value warning both end with.
const WRITE_REFUSALS = {
  skipsOutboundTlsVerification:
    'verifying the certificate of whoever answers an outbound request is ' +
    'not optional there. Name a private CA in the matching CA file setting ' +
    'instead.',
  spoilsOnPurpose:
    'a deliberate defect may not make a response wrong there. Exercise a ' +
    'client against it in a development realm.',
  believesAssertedSelectors:
    'a selector a workload asserts about itself is a claim nothing checked, ' +
    'and product never believes one.',
  servesUnattestedEntries:
    'the Workload API answers a caller only with the registration entries ' +
    'its attested selectors match there, never with every entry.',
  acceptsCredentialsWithoutStatus:
    'a credential this realm issued that shows no status reference could ' +
    'be one that was revoked, so the Verifier requires one there. own-only ' +
    'is allowed, and oid4vp.statusOptionalIssuers exempts a trusted issuer ' +
    'that publishes no status.',
  usesBrokenAlgorithms:
    'SHA-1 signatures, RSA PKCS#1 v1.5 key transport, MD5 in HTTP Digest ' +
    'and the Kerberos enctypes RFC 8429 deprecates (rc4-hmac) are broken, ' +
    'and product never uses any of them. The stronger values are allowed.',
  issuesUnsignedAssertions:
    'every SAML assertion, and every SAML 1.1 Response, is signed there ' +
    '(saml-profiles-2.0-os 4.1.4.5, oasis-sstc-saml-bindings-1.1 4.1.2.4). ' +
    'Exercise a relying party against an unsigned one in a development ' +
    'realm.',
  servesWithoutSecurityHeader:
    'the SPIFFE Workload Endpoint specification (section 3) says a call ' +
    'without the workload.spiffe.io header MUST be refused.'
};

function writeRefusalReason(predicate) {
  log.debug("Entering writeRefusalReason(). " + predicate);
  log.debug("Leaving writeRefusalReason().");
  return WRITE_REFUSALS[predicate] ||
    'the setting is for development mode only.';
}

// Every row carrying the `onlyWhile` marker, with the value the ambient realm
// holds and the value IN FORCE — which differ exactly where a development-only
// value is stored in a product realm (#181). Read through `allowsValue()`
// rather than `valueInForce()`, so drawing the page logs nothing.
function developmentOnlySettings() {
  log.debug("Entering developmentOnlySettings().");
  const rows = config.SETTINGS.filter(function (row) {
    return !!row.onlyWhile;
  }).map(function (row) {
    const stored = config.value(row.key);
    const allowed = allowsValue(row.key, stored);
    return { key: row.key, group: row.group, predicate: row.onlyWhile,
             developmentOnlyValues: Array.isArray(row.onlyWhileValues) ?
               row.onlyWhileValues.slice() : null,
             default: row.dflt, value: stored,
             inForce: allowed ? stored : productValue(row, stored),
             ignored: !allowed,
             why: writeRefusalReason(row.onlyWhile) };
  });
  log.debug("Leaving developmentOnlySettings(). " + rows.length + " row(s).");
  return rows;
}

// The whole answer, for the console page (`GET /admin/mode`), the management
// API (`GET /admin-api/mode`) and the metadata report. One function so the
// three cannot disagree; `admin-ui/mode_admin.ts` draws it and adds nothing.
function report() {
  log.debug("Entering report().");
  const product = isProduct();
  log.debug("Leaving report().");
  return {
    mode: current(),
    isProduct: product,
    requirements: REQUIREMENTS.map(function (row) {
      return Object.assign({ inForce: product ? row.product :
                                      row.development },
                           row);
    }),
    developmentOnlySettings: developmentOnlySettings(),
    notYet: NOT_YET
  };
}

module.exports = {
  DEVELOPMENT: DEVELOPMENT,
  PRODUCT: PRODUCT,
  current: current,
  isProduct: isProduct,
  isDevelopment: isDevelopment,
  verifiesCredentials: verifiesCredentials,
  autoCreates: autoCreates,
  believesAssertedSelectors: believesAssertedSelectors,
  requiresWorkloadAttestation: requiresWorkloadAttestation,
  servesUnattestedEntries: servesUnattestedEntries,
  acceptsCredentialsWithoutStatus: acceptsCredentialsWithoutStatus,
  servesUnattestedWorkloadTcp: servesUnattestedWorkloadTcp,
  registersUnidentifyingEntries: registersUnidentifyingEntries,
  trustsUnverifiedLocalSocket: trustsUnverifiedLocalSocket,
  spoilsOnPurpose: spoilsOnPurpose,
  requiresConfidentialClientAuthentication:
    requiresConfidentialClientAuthentication,
  enforcesOauthSecurityBcp: enforcesOauthSecurityBcp,
  gatesManagementApi: gatesManagementApi,
  seedsDemoData: seedsDemoData,
  rotatesSigningKeys: rotatesSigningKeys,
  refusesExpiredClientSecrets: refusesExpiredClientSecrets,
  listsRealmsBeforeSignIn: listsRealmsBeforeSignIn,
  inventsClaimValues: inventsClaimValues,
  acceptsUnregisteredAddresses: acceptsUnregisteredAddresses,
  opensTestControls: opensTestControls,
  opensConsoleToAnyone: opensConsoleToAnyone,
  authorizesDirectoryWrites: authorizesDirectoryWrites,
  requiresDirectoryBind: requiresDirectoryBind,
  withholdsDirectorySecrets: withholdsDirectorySecrets,
  protectsOperationalAttributes: protectsOperationalAttributes,
  requiresConfidentialDirectoryBinds: requiresConfidentialDirectoryBinds,
  limitsDirectoryBindFailures: limitsDirectoryBindFailures,
  sendsWeakerThanAsked: sendsWeakerThanAsked,
  refusesUnknownRevocationStatus: refusesUnknownRevocationStatus,
  refusesUnrevocableCertificates: refusesUnrevocableCertificates,
  requiresPkiForGnapMtls: requiresPkiForGnapMtls,
  requiresEnrollmentTls: requiresEnrollmentTls,
  opensIntrospection: opensIntrospection,
  opensRevocation: opensRevocation,
  acceptsUnverifiedIssuerTokens: acceptsUnverifiedIssuerTokens,
  exchangesUnverifiedTokens: exchangesUnverifiedTokens,
  authorizesDelegation: authorizesDelegation,
  grantsUndeclaredScopes: grantsUndeclaredScopes,
  honoursUngrantedPermissions: honoursUngrantedPermissions,
  enrolsKeysOnFirstUse: enrolsKeysOnFirstUse,
  acceptsPasswordAloneFromSecondFactorAccounts:
    acceptsPasswordAloneFromSecondFactorAccounts,
  issuesTicketsOnPasswordAlone: issuesTicketsOnPasswordAlone,
  matchesFederatedNames: matchesFederatedNames,
  acceptsUnsignedFederatedLogout: acceptsUnsignedFederatedLogout,
  acceptsUnsignedRequestObjects: acceptsUnsignedRequestObjects,
  acceptsLooseRequestUris: acceptsLooseRequestUris,
  acceptsUnsignedSamlRequests: acceptsUnsignedSamlRequests,
  encryptsToObservedCertificates: encryptsToObservedCertificates,
  registersFromMetadataQuery: registersFromMetadataQuery,
  publishesMetadataForUnregisteredProviders:
    publishesMetadataForUnregisteredProviders,
  embedsProtocolDebugger: embedsProtocolDebugger,
  limitsDebuggerDestinations: limitsDebuggerDestinations,
  dialsInternalAddresses: dialsInternalAddresses,
  skipsOutboundTlsVerification: skipsOutboundTlsVerification,
  dialsPlainHttpOutbound: dialsPlainHttpOutbound,
  acceptsNonconformingResourceMetadata: acceptsNonconformingResourceMetadata,
  gatesConsole: gatesConsole,
  gatesScim: gatesScim,
  gatesSharedSignals: gatesSharedSignals,
  gatesSpireServerApi: gatesSpireServerApi,
  observesRiskOnly: observesRiskOnly,
  observesSignalsOnly: observesSignalsOnly,
  usesBrokenAlgorithms: usesBrokenAlgorithms,
  issuesUnsignedAssertions: issuesUnsignedAssertions,
  servesWithoutSecurityHeader: servesWithoutSecurityHeader,
  allowsValue: allowsValue,
  valueInForce: valueInForce,
  inForce: inForce,
  writeRefusalReason: writeRefusalReason,
  REQUIREMENTS: REQUIREMENTS,
  NOT_YET: NOT_YET,
  report: report
};
