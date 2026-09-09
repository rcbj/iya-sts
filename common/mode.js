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
//      Basic. `common/credentials.js` performs it; this file decides whether it
//      is asked.
//   2. EVERY REFERENCED OBJECT EXISTS ALREADY. Nothing is created because it was
//      named — not a user, not an application, not a service principal, not an
//      authorization server. An unknown name is a refusal, which is what makes
//      the register a statement about the deployment rather than a log of what
//      has been tried.
//   3. EVERY OAUTH 2.0 / OIDC APPLICATION HOLDS A SECRET, and authenticates
//      with it. There are no public clients in product mode.
//   4. `/admin-api` IS GATED. It is ungated in development on purpose — it is
//      what the tests drive and the way back in when nobody holds a role — and
//      that is a total authentication bypass which cannot survive into a
//      product.
//
// ---------------------------------------------------------------------------
// IT IS PER TRUST REALM, and that is worth stating because it is unusual.
//
// `global.mode` is `realmRuntime`, following `oauth2.rfc9700` exactly: a realm
// binds no socket, so nothing about the mode is a property of a listener, and
// one process can serve a development realm and a product realm at once. A
// client can then be exercised against both without a second service — which is
// the same argument that made RFC 9700 mode a realm rather than a second
// instance.
//
// **WHAT IS NOT PER REALM IS ISOLATION**, and the two must not be confused. A
// trust realm is fully isolated from every other in BOTH modes; the mode says
// how hard the doors are, not whose doors they are.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, so its position in the require
// order is not a position. It requires only `config`, which requires nothing
// here, so it is a LEAF and must stay one: everything above it may require it
// and it may never require any of them back. Every predicate takes no argument
// and reads the AMBIENT realm, exactly as `config.value()` does.
// ---------------------------------------------------------------------------

const config = require('./config');

const DEVELOPMENT = 'development';
const PRODUCT = 'product';

// The mode of the realm this request is in. Read through `config.value()` and
// never cached, because it is runtime-settable and per realm — a cached answer
// would be the mode of whichever realm happened to ask first.
function current() {
  const value = String(config.value('global.mode') || DEVELOPMENT);
  return value === PRODUCT ? PRODUCT : DEVELOPMENT;
}

function isProduct() {
  return current() === PRODUCT;
}

function isDevelopment() {
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
  return isProduct();
}

// May a user, application, service principal or authorization server be created
// because something NAMED it? Development says yes and that is most of what
// makes it a mock: a client can point at this service with any client_id and
// get a working exchange.
function autoCreates() {
  return !isProduct();
}

// Must an OAuth 2.0 / OpenID Connect application hold a client secret and
// authenticate with it? There are no public clients in product mode — which
// also means no PKCE-only public client, and a deployment that wants one wants
// development mode or a different product.
function requiresClientSecret() {
  return isProduct();
}

// Is the management API gated? See the note above on why it is not, in
// development. **THIS IS THE ONLY GATE THE MODE TURNS ON**, because it is the
// only one that was ever off.
function gatesManagementApi() {
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
  return true;
}

// Is a credential required at /scim/v2? Was `scim.authRequired`, on by default,
// because those endpoints create and DELETE accounts.
function gatesScim() {
  return true;
}

// Is a credential required at the Shared Signals endpoints? Was
// `ssf.authRequired`, on by default. A stream is an agreement to be SENT
// security events about people, so an ungated one is a subscription anybody can
// take out.
function gatesSharedSignals() {
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
  return true;
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
                 'and not its secret, and SCIM Basic passes on any pair.',
    product: 'Verified against the hashed `userPassword` on the person\'s ' +
             'directory entry, at every one of those doors. A person with no ' +
             '`userPassword` set cannot sign in at all.',
    where: 'common/credentials.js' },
  { id: 'objects',
    what: 'A referenced object must already exist',
    development: 'A user, application, service principal or authorization ' +
                 'server is created the first time something names it, which ' +
                 'is what lets a client point at this service with any ' +
                 'identifier and get a working exchange.',
    product: 'An unknown name is REFUSED. Everything must be created ahead of ' +
             'time, through the console, /admin-api, SCIM or an LDAP add.',
    where: 'ldap/ldap_server.js, kerberos/krb5_principals.js, ' +
           'common/applications.js, oauth-oidc/authorization_servers.js' },
  { id: 'key-material',
    what: 'Signing keys survive a restart',
    development: 'A new signing key is generated on every start and held in ' +
                 'memory. A token does not survive a restart — which is what ' +
                 'makes this service disposable, and the `kid` is derived ' +
                 'from the key material so two instances can never publish ' +
                 'one name over two keys.',
    product: 'Generated ONCE and read back from the persistence store — which ' +
             'product mode therefore requires — encrypted with AES-256-GCM ' +
             'under a key this service never generates and never stores, read ' +
             'from a mounted file, AWS Secrets Manager, GCP Secret Manager, ' +
             'Azure Key Vault or HashiCorp Vault.',
    where: 'common/keystore.js, common/secrets.js' },
  { id: 'client-secret',
    what: 'An OAuth 2.0 / OIDC application holds a secret',
    development: 'A client may be public and send nothing but a client_id.',
    product: 'Every application must hold a client secret and authenticate ' +
             'with it. There are no public clients.',
    where: 'oauth-oidc/client_auth.js' },
  { id: 'management-api',
    what: '/admin-api requires a sign-in and a role',
    development: 'Open. It is what the tests drive and the way back in when ' +
                 'nobody holds a role — which also means anybody who can ' +
                 'reach this port can grant themselves both roles through it.',
    product: 'Gated exactly as /admin is: the same session, the same two ' +
             'roles.',
    where: 'mgmt-api/admin_api.js' },
  { id: 'console',
    what: '/admin requires a sign-in and a role',
    development: 'Required — and it always was; the setting that could turn ' +
                 'it off is gone. The sign-in behind it checks no password, ' +
                 'so what the gate proves is that somebody typed a name that ' +
                 'holds a role.',
    product: 'Required, and the sign-in behind it verifies the credential.',
    where: 'admin-ui/admin.js' },
  { id: 'scim',
    what: '/scim/v2 requires a credential',
    development: 'Required in one of RFC 7644 section 2\'s six schemes — and ' +
                 'it always was — with none of them verified beyond its shape.',
    product: 'Required and verified.',
    where: 'scim/scim_auth.js' },
  { id: 'shared-signals',
    what: '/ssf requires a credential',
    development: 'Required in one of the schemes the endpoints accept — and ' +
                 'it always was — none verified beyond its shape.',
    product: 'Required and verified.',
    where: 'ssf/ssf_auth.js' },
  { id: 'spire',
    what: 'The SPIRE Server API requires an X509-SVID',
    development: 'Required over mutual TLS and authorized against SPIRE\'s ' +
                 'own per-method table; anybody may ask the local socket to ' +
                 'mint the SVID that gets them in.',
    product: 'The same, over a registry that no longer mints an entry for ' +
             'whoever asks.',
    where: 'spiffe/spiffe_auth.js' }
];

// WHAT PRODUCT MODE STILL DOES NOT DO. Named here rather than left to be
// discovered, because a mode called `product` invites the assumption that
// everything in it is production-grade, and three things are not:
//
//   * NO REVOCATION IS CHECKED ON A CLIENT CERTIFICATE. There is no OCSP
//     responder and no CRL fetch, in either mode. A revoked certificate
//     verifies here and would not verify anywhere that matters.
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
//   * A KERBEROS ACCOUNT POLICY IS STILL PERMISSIVE in the sense that every
//     seeded principal shares one password. Product mode stops the KDC creating
//     principals on demand; it does not give the existing ones distinct
//     long-term keys.
const NOT_YET = [
  { id: 'certificate-revocation',
    what: 'Revocation is not checked on a client certificate, in either mode. ' +
          'There is no OCSP responder and no CRL fetch, so a revoked ' +
          'certificate verifies here and would not verify anywhere that ' +
          'matters.' },
  { id: 'key-overlap',
    what: 'A rotation has NO OVERLAP. This service publishes one key per realm ' +
          'per algorithm, so everything signed with the old key stops ' +
          'verifying the moment the new one is in use. A product deployment ' +
          'wants both keys in JWKS for a window, which needs the old private ' +
          'key kept — the thing rotation is for getting rid of — so it is a ' +
          'design rather than a setting.' },
  { id: 'post-quantum-keys',
    what: 'The eleven post-quantum keys per realm are NOT persisted, in either ' +
          'mode: they are generated on the worker pool because generating ' +
          'them is expensive, and cached by pq_jose.js. Nor are the TLS server ' +
          'certificate and the SPIFFE authorities, which belong to their own ' +
          'modules and are shared across realms. Only the RSA signing key and ' +
          'the eight EC/Ed keys beside it survive a restart.' },
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
  { id: 'kerberos-keys',
    what: 'Product mode stops the KDC creating principals on demand. It does ' +
          'not give the seeded ones distinct long-term keys — they still ' +
          'share `krb5.userPassword`.' }
];

// The whole answer, for the console page, the management API and the metadata
// report. One function so the three cannot disagree.
function report() {
  return {
    mode: current(),
    isProduct: isProduct(),
    requirements: REQUIREMENTS.map(function (row) {
      return Object.assign({ inForce: isProduct() ? row.product : row.development },
                           row);
    }),
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
  requiresClientSecret: requiresClientSecret,
  gatesManagementApi: gatesManagementApi,
  gatesConsole: gatesConsole,
  gatesScim: gatesScim,
  gatesSharedSignals: gatesSharedSignals,
  gatesSpireServerApi: gatesSpireServerApi,
  REQUIREMENTS: REQUIREMENTS,
  NOT_YET: NOT_YET,
  report: report
};
