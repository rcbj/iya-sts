'use strict';
// File: authn.ts
//
// THE AUTHENTICATION SERVICE — the screen where a person proves who they are,
// and nothing else.
//
// It used to be part of oauth2.js: `GET /oauth2/authorize` with no session
// answered 200 with the login form in the body, at the authorization endpoint's
// own URL. That worked, and it made authentication look like a feature of one
// protocol. It is not: WS-Federation signs people in too, the session is shared
// between them, and everything this service will grow next — a second factor
// somebody else's protocol can ask for, a screen that can say WHY it is asking,
// remembered devices — belongs to the act of authenticating rather than to the
// grant that happened to trigger it. So the screen is its own endpoint, and a
// protocol that needs a user authenticated SENDS them here and gets them back.
//
// The contract, in full:
//
//   1. A protocol module calls beginAuthentication({ returnTo, ... }) and
//      redirects the browser to the path it returns.
//   2. This service shows the screen, takes what the person types, and — on
//      every successful sign-in, which in development mode is all of them,
//      since no password is checked there (product mode verifies it) —
//      establishes the session cookie.
//   3. It redirects the browser to `returnTo`, which the caller built out of
//      its ORIGINAL request, unchanged.
//   4. The caller's endpoint runs again, sees the session cookie this time, and
//      completes its protocol per spec.
//
// Three properties of that are deliberate:
//
// * **`returnTo` is a path on this service and is checked to be one.** It is
//   built by the caller and never read off the query string, but it is checked
//   anyway — an authentication service that will redirect a browser to an
//   arbitrary absolute URL after signing somebody in is an open redirector with
//   a login screen in front of it, which is the exact shape of a credential
//   phishing tool.
//
// * **The service knows nothing about OAuth.** It does not read client_id, it
//   does not know what a redirect_uri is, and it cannot build a protocol error.
//   What the screen SHOWS about the request it interrupted — the client, the
//   scope, the Credential Offer it came from — arrives as `details`, rows the
//   caller wrote, because only the caller knows what those values mean.
//
// * **Cancelling comes back here too.** The person is returned to `returnTo`
//   with `authn_error=access_denied` on it, and the CALLER turns that into
//   whatever its own specification says a refusal looks like. This service must
//   not: OAuth's answer is a redirect to the client's redirect_uri, and in
//   response_mode=form_post it is not a redirect at all but a self-submitting
//   form. Protocol knowledge stays in the protocol module.
//
// It owns the session store because it is the only thing that creates one:
// oauth2.js's note used to say the session lived there "because this module
// owns the login flow the session comes out of", which is exactly the sentence
// that moves it here now that the login flow has.
//
// Nothing in here requires oauth2.js, which is what keeps this a one-way
// dependency and free of the import cycles this service's module split exists
// to avoid: oauth2.js, wsfed.ts and admin.js require THIS.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `Authn` takes every module this file used to require (node's
// `crypto`, the realm, application and federation registers, `helpers` and
// the eight names this file destructured from it, the credential, TOTP and
// WebAuthn libraries, the gate, `mode`, `config`, the audit log and the rest)
// through its constructor, typed as `typeof` each. Its routes — the arrival
// middleware first, then every `/authn/*` page, in the order they always
// were — are registered by `registerRoutes(app)`. Loading the module
// registers NOTHING (#50, R1): the module exports `registerRoutes(app)`, and
// `common/protocol_stack.ts` calls it at the point in the route order where
// requiring this module used to register the routes (rule 1). Since #50's R2
// that root also BUILDS the instance, and the audit actor slot is filled by
// `Authn.wire()` when the instance is installed — right after this module
// finishes loading, as before; a process without the root builds a default,
// and wires it, at load.
//
// What did NOT move into the class, and why:
//
//   * **THE STORES** (`sessions`, `pending`, `pendingMfa`,
//     `pendingPasswordChange`) stay module-level `realms.map()` declarations,
//     because a store becomes per realm at its declaration and nowhere else.
//     `sessions`' `mergeRow` reaches the instance late — through the slot,
//     in a function that is called only once the store is open, long after
//     the instance is installed.
//   * **THE TWO PIECES OF PROCESS STATE** — the session observer
//     `setSessionObserver()` fills (rule 3e) and the sweep timer — stay
//     module-level `let`s beside the stores, one each for the process.
//   * **THE CONSTANTS, THE FORM SCHEMAS AND THE CEREMONY SCRIPT** stay
//     module-level data.
//
// The module still exports every old name, as a FACADE forwarding to that
// instance, for the protocol modules, the console, `ssf/ssf.ts` (which fills
// the observer slot)
// and the tests, several of which replace an export such as `sessionOf` for a
// moment: every caller outside this file reaches these through the module
// object, as before, so the replacement is what they call. `Authn` is exported
// beside them for the composition root.
// ---------------------------------------------------------------------------
import crypto = require('crypto');
// The constant-time comparison a session handle is checked with. A LEAF that
// never requires anything here back (rule 3r).
import stsCrypto = require('../common/crypto');
// CAEP credential-change for a credential set at sign-in (#145). A library
// over `helpers` and `crypto` that sends nothing where Shared Signals is not
// loaded: the require moves no route and closes no cycle.
import accountSignals = require('../ssf/account_signals');
// TRUST REALMS: the stores below are partitioned by realm. It requires only
// config.js and error_codes.js here, so it cannot join a cycle and it
// registers no route, so its position is not a position at all.
import realms = require('../common/realms');
import app = require('../common/app');
// The subject resolver's two questions (2026-09-14), asked by name rather than
// destructured because `sameIdentity()` and the provisioning refusal are the
// only callers and both read better as `helpers.`.
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import stats = require('../common/admin_stats');
// The federation register, for the buttons at the foot of the sign-in screen.
// A plain require in the ordinary direction and it passes rule 3e's test both
// ways round: that module registers no route, so nothing about requiring it
// from here can move one, and it requires only `common/` libraries (config,
// helpers, audit, realms, applications, error_codes) — none of which requires
// this file — so there is no cycle to close.
//
// It is THIS module that requires the register rather than the other way about,
// and that is the arrangement rather than an accident: `federation_sp.ts`
// requires THIS file (it has no sign-in screen of its own and calls
// startSession() directly, which is the same dependency saml2_sso.ts has), so a
// require back from here to that module would be a cycle. The register in the
// middle is what both halves can safely reach.
import federation = require('./../federation/federation');
// The application registry, for the one attribute on an entry that decides
// where that application's people are sent to sign in —
// `appFederationRelationship`. Same shape of dependency as the register above
// and it passes the same test: `common/applications.js` requires only
// libraries (config, helpers, audit, realms, roles, keystore and a few more
// leaves, and `ssf/ssf_events.js`), none of which requires this file, so there
// is no cycle to close, and it registers no route, so requiring it moves
// nothing in the require order.
import applications = require('../common/applications');
// For one thing only: whether the main port is an HTTPS listener, which decides
// the Secure attribute on the session cookie below.
import config = require('../common/config');
// THE ROLE GATE. A LEAF (rule 3): it registers nothing and requires only
// `helpers`, `config` and `error_codes`, so this require cannot move a route
// and cannot close a cycle — which is the whole reason
// `common/issuance_gate.js` exists rather than this module reaching into
// `xacml/`, which is at 23c and would bring seven `/xacml` routes and five
// console pages to position 8. In a process that never loaded the XACML family
// the gate answers "allowed" and this screen behaves exactly as it did.
import gate = require('../common/issuance_gate');
// The credential verifier. A library (rule 3) that registers no route and
// requires nothing that requires this file back — `common/` and `cluster/`
// libraries and this directory's `webauthn.js` and `webauthn_policy.ts` — so
// it can neither move a route nor close a cycle.
// Development mode answers yes to everything but the reserved refusal, so
// requiring it changes nothing about how this screen behaves today.
import credentials = require('../common/credentials');
// CSRF and rate limiting. A library (rule 3): registers nothing, and requires
// only `common/` and `cluster/` libraries, none of which requires this file.
import websecurity = require('../common/websecurity');
import mode = require('../common/mode');
// The input validator. A LEAF (rule 3) — it registers no route and requires
// only `config`, `error_codes`, `bunyan` and zod, so it closes no cycle and
// moves nothing.
// `common/validation.js` argues the shape/existence line every schema below
// rests on: what a value may BE is refused here in both modes, and whether the
// person NAMED exists stays with `mode.js`.
import validation = require('../common/validation');
const vt = validation.types;
const vz = validation.z;
// For one decision: whether ending a session should revoke the refresh tokens
// issued on it (RFC 9700 section 2.2.2). The policy is that module's, with the
// rest of the mode; the session and the token registry are here, which is why
// the act is here. A library that registers no route, so requiring it cannot
// move anything in the require order.
import bcp = require('../oauth-oidc/oauth2_bcp');
// The audit log. Two things happen here that no other module can see: a session
// is created, and a session is ended. Neither is an authentication —
// admin_stats.js records that, at the funnel every protocol family shares — and
// neither is an HTTP call, which app.js records. A sign-in therefore writes
// three audit rows, which is three facts at three layers rather than one fact
// three times; /admin/audit says so where a reader counting rows will see it.
//
// This module also FILLS audit.js's actor slot at the bottom of this file,
// which is what puts a name on every console and management API row.
import audit = require('../common/audit');
// The client's JA4 TLS fingerprint, for the authentication event (#62 P0). A
// LIBRARY (rule 3) with library requires only.
import clientHello = require('../tls/client_hello');
// ONE END PER SESSION IN THE CLUSTER (2026-09-14, #46 section 6). A library:
// it requires `persistence.js` lazily and registers nothing. See
// sessionEndOnce() below.
import clusterClaims = require('../cluster/cluster_claims');
// THE SCHEDULER (#49), for the session-expiry job registered at the foot of
// this file. A LIBRARY (rule 3) that requires nothing of this one.
import scheduler = require('../cluster/scheduler');
// The error codes (common/error_codes.js). A refusal here is marked on the
// RESPONSE before the page or redirect is sent; a verdict from the credential
// libraries arrives carrying its own code non-enumerably, and this module
// marks `codeOf(verdict)` so the specific reason reaches the audit row.
import errorCodes = require('../common/error_codes');
// A DISABLED ACCOUNT (2026-09-17, #36 follow-up). A library that requires
// only `common/` modules loaded before this one, and nothing here: asked by
// startSession() — the one place every session is created, so every door that
// signs somebody in — and by sessionOf(), so a session that was live when the
// account was disabled is not honoured again.
import accountState = require('../common/account_state');

// The path a caller sends the browser to. Exported, because the two callers
// build a URL out of it and a string spelled twice is a string that drifts.
const LOGIN_PATH = '/authn/login';
// WHERE A PERSON PICKS BETWEEN AN APPLICATION'S FEDERATION PARTNERS. A page of
// its own rather than the screen above with its form suppressed — see
// beginAuthentication(), where the choice between the two is argued. It is
// reached only with an `?authn=` id, exactly as the screen is, because what it
// needs is the pending record and not a partner list somebody could compose.
const SELECT_IDP_PATH = '/authn/select-idp';
// THE TWO SECOND-FACTOR SCREENS. `/authn/webauthn` predates this constant and
// is written out in the markup it belongs to; `/authn/totp` (2026-09-10) is
// named here because THREE things build a URL out of it — the form's action,
// the *use a code instead* link on the security-key screen, and the endpoint
// registration — and a path spelled three times is a path that drifts.
const TOTP_PATH = '/authn/totp';
const WEBAUTHN_PATH = '/authn/webauthn';
// **THE THIRD SECOND-FACTOR SCREEN (2026-09-10), AND IT IS NOT A MECHANISM
// SOMEBODY IS CONFIGURED FOR.** `/authn/backup-code` is where a person lands
// who cannot produce the factor their account IS configured for — the phone is
// lost or flat, the security key is at home — and it is reachable only as a
// way OUT of one of the other two screens, never as the factor the sign-in
// asks for first. `credentials.mechanismsFor()` deliberately leaves the
// recovery codes off `secondFactor` for exactly that reason.
const BACKUP_CODE_PATH = '/authn/backup-code';
// THE FORCED PASSWORD CHANGE (2026-09-13): drawn after a password is accepted
// for an entry carrying `pwdReset: TRUE`, before any session exists.
const PASSWORD_CHANGE_PATH = '/authn/password-change';
// A SECOND FACTOR ENROLLED BECAUSE ONE IS REQUIRED (2026-09-13) — see the
// block above `MFA_SETUP_FORM` for why a sign-in may now enrol an authenticator
// app where it never used to.
const MFA_SETUP_PATH = '/authn/mfa-setup';
// ---------------------------------------------------------------------------
// WHERE A PERSON SIGNS IN WITH A KERBEROS TICKET, and the reason the constant
// is HERE while the endpoint is in `kerberos/spnego_authn.ts`.
//
// This module owns `/authn/*` and it is the module that has to point at that
// door: `beginAuthentication()` redirects to it, and the sign-in screen draws a
// button linking to it. The endpoint itself cannot live here — every Kerberos
// module is at #15 and below in the require order, this one is at #8 because
// `oauth2.js` reads the session it owns, and a require in that direction would
// drag the KDC's routes to the front of the router AND close a cycle, since
// that module needs `startSession()`. The first half still holds after #50's
// R1: `spnego_authn.ts` itself would register nothing when required, but it
// requires `kerberos/spnego.js`, which is JavaScript, one of the parent
// project's locked files, and still registers its routes when required.
//
// **AND IT DOES NOT NEED AN INVERTED HOOK EITHER**, which is worth saying
// because rule 3e's list is six slots long and a seventh is the obvious move.
// The only two things this module needs to know are the PATH — a path in the
// space it already owns, so it declares it and the Kerberos module imports it —
// and whether the door is open, which is `krb5.spnegoAuthentication` in
// `config.js` and is read from both files. Rule 3e's test is whether a require
// would close a cycle or move a route; here nothing has to point anywhere at
// all.
// ---------------------------------------------------------------------------
const SPNEGO_PATH = '/authn/spnego';
// ---------------------------------------------------------------------------
// WHERE A PERSON SIGNS IN WITH A WALLET (2026-09-17, #38), and the same
// arrangement as `SPNEGO_PATH` for a smaller reason. The endpoints are
// `oid4vc/vc_signin.ts`'s, because what they drive is the OpenID4VP Verifier
// and that module is required at #11-14; this module is at #8 and reads
// nothing of that family. The two paths are declared here because this module
// owns `/authn/*` and draws the button that links to the first. No slot, for
// SPNEGO's reason: two files read two constants and one setting
// (`oid4vp.signIn`), and nothing has to point anywhere.
// ---------------------------------------------------------------------------
const WALLET_PATH = '/authn/wallet';
const WALLET_WAIT_PATH = '/authn/wallet/wait';
// And, since #38's follow-ups, the Digital Credentials API answer the wait
// page's script posts, and that script. Declared here for the same reason.
const WALLET_DCAPI_PATH = '/authn/wallet/dc-api';
const WALLET_SCRIPT_PATH = '/authn/wallet.js';

// ---------------------------------------------------------------------------
// A PASSWORD AS THE SECOND FACTOR (#38's follow-ups). A wallet presentation is
// one factor — something the person holds — and a request that demands two
// may be answered by a wallet and then something the person knows. This is
// that screen: one password field, checked by `credentials.verify()` exactly
// as the sign-in screen checks one, rate limited on the same bucket, and
// reached only with a pending second-factor step whose FIRST factor was not a
// password. No script.
// ---------------------------------------------------------------------------
const PASSWORD_FACTOR_PATH = '/authn/password-factor';

const SESSION_COOKIE = 'sts_session';

// ---------------------------------------------------------------------------
// THE SESSION CLOCKS ARE SETTINGS SINCE 2026-09-12, AND THESE ARE THEIR
// DEFAULTS.
//
// `SESSION_TTL_MS` was the absolute lifetime of every sign-on, console, portal
// and API session, as a literal, with no idle timeout anywhere — which is the
// first thing a deployment's security review asks to change and the one thing
// here nobody could. `authn.sessionLifetimeS` is the lifetime and
// `authn.sessionIdleTimeoutS` the idle timeout, whose ZERO means none and is
// the default, so an unedited service behaves exactly as it did.
//
// **THE LIFETIME IS STAMPED AT CREATION AND THE IDLE TIMEOUT IS CHECKED AT
// READ**, and the difference is what each setting promises. A lifetime is a
// property a session was issued with, so changing it reaches the next session
// and leaves a live one as it was. An idle timeout is a policy about how long
// this service goes on honouring a session nobody is using, so it is checked
// by `sessionEnded()` — the ONE place the question *is this session over* is
// answered — every time a session is looked up and on every sweep.
// ---------------------------------------------------------------------------
const SESSION_TTL_MS = 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// THE ONE NAME AN UNAUTHENTICATED SESSION EVER CARRIES (2026-09-05).
//
// A STABLE principal rather than one per session, and that is the decision
// somebody is most likely to want to undo. A fresh identity each time would
// keep the sessions apart on /admin/sessions — but it would also seed a
// directory entry per session, put a new row on /admin/users every time
// somebody pressed the button, and leave `anonymous` a name that could never
// be granted a configured role, because the name would be different by the
// time anybody typed it. One entry, many sessions, is the same choice
// `identityKeyOf()` makes for everybody else: the entry is the PERSON and the
// session is one visit.
//
// It is exported because two other modules have to mean the same string by it
// — the console draws the section of unauthenticated sessions and the tests
// ask for this principal by name — and a second spelling of it somewhere else
// would be a second anonymous person that held none of the first one's roles.
// ---------------------------------------------------------------------------
const ANONYMOUS_USERNAME = 'anonymous';

// How long an interrupted request waits at the screen before it has to be
// started again. `authn.pendingTtlS` since 2026-09-12 — this is its default,
// and `common/oidc_rp.ts`'s flow reads the same setting, because the two were
// "deliberately the same" as two literals.
const AUTHN_TTL_MS = 10 * 60 * 1000;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// session id -> the signed-in user
//
// **TOMBSTONED AND MERGED WHEN SEVERAL NODES WRITE IT (2026-09-14, #46).** A
// session ended on one node was written back by another holding an older copy
// — `noteSessionUsed()` and `touchArrivalSession()` re-set the row to stamp a
// time — so a sign-out did not hold; an arrival upgraded to a sign-in on one
// node was written back as the arrival by another; and a relying party added
// to one copy's front-channel list was lost from the row by the other copy's
// write. `tombstone` makes an ended session stay ended in the store, and
// `mergeSessionRows()` below is what two copies of one live session become.
// `persistence/persistence_minted.js` carries the mechanism.
const sessions = realms.map({ persist: 'authn.sessions', tombstone: true,
                              // Late-bound to the instance in the slot at
                              // the bottom: a merge happens only once the
                              // store is open, after the root installed it.
                              mergeRow: function (mine, theirs) {
                                return slot.get().mergeSessionRows(mine,
                                                                   theirs);
                              } });

// The requests waiting at the login screen: what to do with the person once
// they have signed in, and what to tell them they are signing in FOR.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// authn id -> { returnTo, details, ... }
const pending = realms.map({ persist: 'authn.pending', retain: 'age' });

// WebAuthn, IN EITHER OF ITS TWO ROLES. The verifier is ./webauthn — written
// from the specification and sharing no code with the debugger's own decoder,
// which is what makes tests/webauthn_cross_impl.js over there a real check
// rather than an implementation agreeing with itself.
//
// It lives HERE, with the password step it follows or replaces: the two are one
// act of authentication, they share the pending record, and a second factor is
// the first thing a centralized authentication service is asked for.
//
// **The two roles are one ceremony and three consequences, and they are worth
// keeping straight because everything downstream reads them off the session.**
//
//   * SECOND FACTOR (`use_webauthn`): a password step has already happened, so
//     the session records amr ["pwd","hwk"] and acr "mfa". The person is not a
//     new identity — they are the one the password step named — so the
//     directory entry that the funnel seeds is theirs either way, and what the
//     key adds to it is a FLAG saying multi-factor happened. See
//     ldap_server.js's applyAuthenticationFactors().
//   * PRIMARY (`webauthn_only`): no password was presented at all, so the
//     session records amr ["hwk"] and acr "1" — ONE factor, and a
//     phishing-resistant one is still one. This is an authentication in its own
//     right, so it goes through stats.recordAuthentication() like every other
//     accepted credential and the directory grows an entry for the person the
//     same way a password sign-in makes one.
//
// The distinction is refused rather than fudged in one place: a caller that
// demanded a second factor (`forceMfa`) does not get the passwordless path,
// because answering "two factors" with one would be exactly the lie wauth and
// acr_values exist to prevent.
import webauthnVerifier = require('./webauthn');
// The ceremony's OPTIONS and this service's policy about what a key may be, in
// a module of their own beside the verifier. Rule 3: it registers nothing, so
// its position here is not a position, and it requires only `config`, `helpers`
// and the verifier — so it cannot join a cycle. It is not IN the verifier
// because that file is deliberately loadable on its own by the debugger's
// cross-implementation test, and a `require('../common/config')` in there would
// end that silently. See `authn/webauthn_policy.ts`'s header.
import webauthnPolicy = require('./webauthn_policy');
// THE ATTESTATION STATEMENT, VERIFIED (#105). Rule 3 as well: a library that
// requires the policy above, `crypto`, `pki` and `error_codes`, and reaches
// the FIDO metadata and revocation lazily — nothing that reaches back here.
import webauthnAttestation = require('./webauthn_attestation');
// THE AUTHENTICATOR APP'S MECHANISM (2026-09-13), for the enrolment a required
// second factor asks for: the otpauth URI, the QR code and the grouped secret.
// A LEAF requiring `config`, `crypto`, `helpers` and `realms`, none of which
// reaches back here.
import totp = require('../common/totp');
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// ---------------------------------------------------------------------------
// THERE WAS A `webauthnCredentials` MAP HERE AND IT WAS THE WRONG STORE
// (2026-09-10).
//
// `realms.map({ persist: 'authn.webauthnCredentials' })`, keyed by username,
// holding ONE credential each. It survived a restart and it was still wrong,
// because **`common/credentials.ts` already held the security keys** — on the
// person's own directory entry, multi-valued, each with the ROLE it was
// enrolled in (`primary` or `mfa`). That is the store `mechanismsFor()` reads,
// which is the store `/portal/keys`, `/admin/users`, the sign-in screen's
// `mfaRequired` check and `removeKey()`'s last-way-in refusal all read.
//
// **TWO STORES MEANT THE ROLE MODEL WAS CONNECTED TO NOTHING**, and the
// symptoms were worse than a disagreement:
//
//   * `credentials.addKey()` — the only writer of the directory store — had NO
//     CALLER anywhere in this service. So `mechanismsFor()` answered
//     `mfaKeys: 0, primaryKeys: 0` for everybody, for ever.
//   * `mfaRequired` could therefore never become true from a security key, so
//     a key enrolled at this screen was **never demanded again**: the next
//     sign-in had the box unticked and a password alone was accepted.
//   * `GET /authn/webauthn`'s own gate — *does this person hold an `mfa` key?*
//     — refused everybody, so the *use your security key instead* link could
//     never be followed.
//   * `/portal/keys` could list and remove keys that could not exist, and
//     `/portal/activate`'s *a security key instead of a password* spent the
//     activation link, said "your account is ready" and enrolled nothing.
//
// So this module keeps NO credential store of its own. It reads and writes
// `common/credentials.ts`, which is rule 3m applied where it was being broken:
// one answer to *what can this person sign in with*, and the wrong half is no
// longer whichever surface a reader happened to open.
// mfa id -> { authn, username, challenge, passwordless, expires }
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const pendingMfa = realms.map({ persist: 'authn.pendingMfa', retain: 'age' });
// change id -> { authn, username, secondFactor, expires }. A password that must
// be changed before the sign-in it opened goes any further (2026-09-13). A
// store of its own rather than a `factor` on the one above: that register is
// "a sign-in waiting for a SECOND FACTOR", and a new password is not one — the
// person has presented one factor and is being asked to replace it.
const pendingPasswordChange = realms.map({
  persist: 'authn.pendingPasswordChange', retain: 'age' });
// How long a second-factor step waits. `authn.mfaStepTtlS` since 2026-09-12;
// this is its default.
const MFA_TTL_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// WHERE AN ARRIVAL SESSION IS ACTUALLY STARTED: a middleware over the protocol
// front doors, registered HERE and nowhere else.
//
// **THE POSITION IS THE MECHANISM.** Rule 1 in the root CLAUDE.md: express
// applies a middleware only to routes added AFTER it, and this module is 8 in
// the route order — the middleware is registered by `registerRoutes(app)`,
// which `common/protocol_stack.ts` calls at 8 (#50, R1). So a middleware
// registered here covers every browser protocol that follows — the
// authorization endpoint (9), WS-Federation (10), both SAML profiles (10a,
// 10b), federation (10c), OID4VC, the portal and the console — and covers
// nothing registered before it, which is `home`. That is the right set by
// construction rather than by a list somebody keeps up to date. WS-Trust has
// followed this module since 2026-09-05, but it is SOAP with no browser in it
// and names no front door below.
//
// **THE PATHS ARE STILL NAMED, and the list is of FRONT DOORS rather than of
// families.** A protocol has one or two paths a browser ARRIVES at and many it
// only reaches mid-flow, and giving a cookie to a callback or a metadata fetch
// would mint a session for a machine that will never send it back — one row
// per metadata poll, for ever. So the list is the entry points, and anything
// not on it is left alone.
//
// A request that already carries a session cookie is untouched, so this fires
// once per browser and not once per request.
// ---------------------------------------------------------------------------
const ARRIVAL_PATHS = [
  '/oauth2/authorize',
  '/oauth2/device_authorization',
  '/wsfed',
  '/saml2/sso',
  '/saml11/sso',
  '/portal',
  '/admin'
];

// ---------------------------------------------------------------------------
// AND THE TWO PATHS UNDER THOSE PREFIXES THAT ARE NOT A BROWSER ARRIVING
// (2026-09-10).
//
// The list above is FRONT DOORS and is matched by prefix, which is right for
// every path a person can reach. `/admin/signals/receive` and
// `/portal/signals/receive` are not: they are this service's own two Shared
// Signals receivers, and what arrives at them is `ssf/ssf_http.ts` POSTing a
// Security Event Token over the loopback interface.
//
// **THIS IS THE FAILURE THE PARAGRAPH ABOVE NAMES, ARRIVING FROM A DIRECTION
// IT DID NOT ANTICIPATE.** It says giving a cookie to a callback or a metadata
// fetch would "mint a session for a machine that will never send it back — one
// row per metadata poll, for ever", and it prevents that by listing front
// doors rather than families. A prefix match cannot prevent it for a machine
// endpoint registered UNDER a front door, which is what both of these are —
// deliberately, because a receiver hosts its own endpoint and these belong to
// the console and the portal. Measured before this list existed: one arrival
// session per delivered event, so a service telling its own console about
// every sign-in minted a second session for every session.
//
// It is an exclusion HERE rather than two paths moved out of `/admin` and
// `/portal`, because the path is what says WHICH RECEIVER a SET was delivered
// to and a receiver's endpoint living somewhere other than the receiver would
// be the tidier version of a worse design. See `ssf/ssf_receivers.ts`.
//
// **A THIRD ENTRY NEEDS THE SAME TEST**: is this path reached by a BROWSER
// that will hold a cookie? If yes it belongs on neither list and is already
// handled. If no, and it sits under a front door, it belongs here.
// ---------------------------------------------------------------------------
const NOT_ARRIVAL_PATHS = [
  '/admin/signals/receive',
  '/portal/signals/receive'
];

// ---------------------------------------------------------------------------
// `detail` — THE SIXTH ARGUMENT, AND WHY IT EXISTS RATHER THAN A SECOND
// recordAuthentication() CALL AT THE CALLER.
//
// This function is the single funnel for "somebody now holds a session here",
// and it has always recorded the authentication ITSELF — the comment two lines
// into the body says so, and it is what makes a WS-Federation sign-in appear on
// /admin/users without that module knowing the console exists.
//
// FEDERATION BROKE THAT ASSUMPTION IN TWO PLACES AT ONCE and the fix had to be
// here rather than there. A federated sign-in has facts this function cannot
// derive:
//
//   * `methodPhraseFor()` reads `amr` and answers "sign-in screen (password)"
//     for anything it does not recognise, which is exactly wrong for somebody
//     who never saw this screen at all;
//   * the mapped attributes a foreign identity provider asserted have to ride
//     the funnel to the directory, and there is no other way in.
//
// The obvious alternative — the caller calling `stats.recordAuthentication()`
// and then this — was written first and is what this parameter replaced: it
// produced TWO authentication records for one sign-in, so /admin/users counted
// every federated arrival twice and the audit log carried a duplicate of every
// one of them. A caller passing nothing behaves exactly as every existing
// caller did.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE SESSION OBSERVER — AN INVERTED HOOK, AND THE ONLY ONE THIS MODULE
// OFFERS.
//
// `ssf/caep.ts` needs to know when a session starts, is presented and ends,
// because that is what a CAEP event is ABOUT. It cannot be required from here:
// this module is 8 in the require order (`common/protocol_stack.ts`) and
// `ssf/ssf.ts` is 23b, so a require the other way would load the whole SSF
// family HERE — ahead of `oauth2.js`, ahead of the admin console. Until #50's
// R1 that REGISTERED EVERY `/ssf` ROUTE here too, which was rule 1. Since R1
// `ssf/ssf.ts`'s own routes would stay where `common/protocol_stack.ts`
// registers them, but it requires `ldap/ldap_server.js`, which is still
// JavaScript and still registers every `/admin/ldap/*` route when required,
// so the require would still move routes — and it would close a cycle
// besides. So this module holds a function and `ssf/ssf.ts` fills it at its
// own require time, exactly as `admin.setSignalsReporter()` works one layer
// up.
//
// **IT IS ONE FUNCTION AND IT IS ADVISORY.** `notifySession()` swallows
// everything the observer throws, and the reason is the one `audit.js` gives
// about its actor resolver: the observer is a nicety and the sign-in it
// decorates is real work. A Shared Signals transmitter that cannot build an
// event MUST NOT be able to turn a working sign-in into a 500 — and it is
// reachable, because building one signs a JWS and pushing one dials out.
//
// **IT IS ALSO SYNCHRONOUS AND FIRE-AND-FORGET.** The observer may start
// something that finishes later — a push delivery takes as long as somebody
// else's endpoint does — and nothing here waits for it. A sign-out that
// blocked on a receiver's TCP timeout would be a sign-out that hangs, and the
// person signing out has nothing to do with whether a receiver is up.
// ---------------------------------------------------------------------------
let sessionObserver = null;

// ---------------------------------------------------------------------------
// A SESSION THAT RAN OUT — THE FOURTH WAY ONE ENDS, AND UNTIL 2026-09-04 THE
// ONLY ONE THAT SAID NOTHING.
//
// Every sign-out door in this service goes through `dropSession()`:
// /oauth2/logout, WS-Federation's wsignout1.0, SAML 2.0 Single Logout,
// /logout, /admin/logout, /admin/sessions. All of them therefore write the
// `session.end` audit row and emit CAEP's `session-revoked`.
//
// AN EXPIRY DID NEITHER. It was `sessions.delete(id)` in the two lookups, so a
// session that ran out was gone with no audit row and no event — and the
// receiver that had been told the session was ESTABLISHED was told nothing
// when it ended. That is the failure CAEP exists to prevent, arriving through
// the most ordinary cause there is.
//
// **AND IT WAS WORSE THAN LATE, IT WAS CONDITIONAL.** Both deletions were
// lazy: they happen when the session is next LOOKED UP. A person who closes
// the browser is never looked up again, so nothing ever fired at all — while
// the same session sat in the map, live to `/admin/sessions` and to anything
// else counting sessions, hours after it had expired. That is why this needed
// a SWEEP and not just a shared function.
//
// **THE SWEEP IS A SCHEDULER JOB SINCE 2026-09-22 (#49)**, rcbj's directive
// of the day before: `authn.session-expiry`, a CLUSTER job on
// `cluster/scheduler.ts`, every `authn.sessionSweepS` (30, and 0 switches it
// off). It was a `setInterval` of a fixed thirty seconds, armed by the first
// session a process created, in every process that created one — so with
// request workers, every worker swept, and the `authn.session-end` claim
// below was what kept an expiry from being reported once per process. Now
// the scheduler's leader sweeps, once per slot for the whole cluster, and
// each other process holds the same sessions by replication (every
// configuration with more than one process shares the session store: a
// cluster requires `persistence.minted`, and dispatch without coordination is
// refused). A process that signs nobody in still arms nothing: the job
// belongs to the scheduler, which only `server.js` starts.
//
// **WHAT DID NOT MOVE.** The lazy check where a session is looked up — a
// process never honours an expired session, whenever the sweep last ran —
// and the `authn.session-end` claim, because a lookup, a sign-out and the
// job can still meet on one session.
//
// **IT SWEEPS EVERY REALM AND RUNS INSIDE EACH ONE.** The store is
// `realms.map()`, so `sessions.forEach` walks the AMBIENT realm's partition —
// and a timer has no ambient realm, so without `realms.run()` this would sweep
// the default realm's sessions every time and silently leave every other
// realm's to accumulate. Running inside the realm is also what makes the event
// right rather than merely present: the observer builds a subject from the
// realm's own issuer, and an event naming the wrong one is refused at the far
// end and reads as a bad signature.
// The scheduler job's id, and its interval's setting.
const SESSION_EXPIRY_JOB = 'authn.session-expiry';
const SESSION_SWEEP_SETTING = 'authn.sessionSweepS';

// ---------------------------------------------------------------------------
// A SESSION'S END IS REPORTED ONCE, HOWEVER MANY PROCESSES NOTICE IT
// (2026-09-14, #46 section 6).
//
// Every process runs the sweep below over its own copy of the session store,
// and the lazy expiry in `sessionOf()` ends a session wherever it is next
// presented. With several processes against one store — a container's request
// workers, or several containers — two of them find the SAME expired session
// in the same half-minute and each writes a `session.end` audit row and emits
// CAEP's `session-revoked`: a receiver told twice that one session ended, and
// an audit log counting two ends of one session. A sweep led by one elected
// node would fix the timer and not the lazy lookup, and leaves a container's
// own workers sweeping each other's sessions; a CLAIM fixes both.
//
// So the DELETE stays synchronous and local — a process that has noticed an
// expiry must stop honouring the session at once, whatever the store says —
// and the REPORT (the audit row and the event) goes out only once the claim
// `authn.session-end` on the realm and session id is won. An explicit sign-out
// (`dropSession()`) takes the same claim, so a sign-out racing the sweep on
// another node reports one end and not two; the loser records its sign-out as
// refused (`STS-AUTHN-0191`) with no event.
//
// **ON A STORE THAT CANNOT BE SHARED THIS IS SYNCHRONOUS, EXACTLY AS BEFORE.**
// No claim store means one process, and `emit` runs inline, so a single
// process's audit row is written before the function returns, as every test
// and every caller has always seen it.
//
// **A CLAIM THAT CANNOT BE ASKED REPORTS ANYWAY**, which is the opposite of
// `cluster_claims.js`'s fail-closed rule and deliberately so: that rule is for
// a value that must not be ACCEPTED twice, and this is a notice that must not
// be LOST. A duplicate `session-revoked` costs a receiver an idempotent
// repeat; a missing one leaves a receiver trusting a session that ended.
// ---------------------------------------------------------------------------
const SESSION_END_CLAIM_TTL_MS = 60 * 60 * 1000;

// How many events a session keeps. A `max_age=0` client re-authenticates on
// every request and a list that grew without bound would be a persisted row
// that grew without bound. The FIRST event is always kept — it is how the
// session began — and the most recent ones after it; `eventsDropped` says how
// many went, so a reader never mistakes a trimmed list for a whole one.
const MAX_SESSION_EVENTS = 20;

// The screen itself. Unchanged from the one that used to be rendered inside the
// authorization endpoint, in everything a person or a test can see: the same
// element ids (`username`, `password`, `kc-login`, `kc-cancel`), the same
// Keycloak-shaped vocabulary, the same statement that no password is checked.
// What changed is where it lives, what it posts to, and that its footer rows
// are supplied rather than read off an authorization request.
// ---------------------------------------------------------------------------
// THE ONE STYLESHEET BOTH PAGES IN THIS MODULE ARE DRAWN WITH.
//
// It was inline in loginPage() until the chooser at /authn/select-idp needed
// the same card, the same buttons and the same error banner. Copying it would
// have been ten lines nobody would ever have diffed, and the two pages sit one
// redirect apart — a person who picks a partner and comes back to type a name
// sees both in the same second, so a drift between them is visible rather than
// theoretical.
//
// Everything a person meets in this service is still ONE FILE WITH NO ASSETS:
// `script-src 'none'` holds, there is no stylesheet to fetch, and neither page
// runs a line of script. The WebAuthn step is the exception this service
// already argues at length, and it is not one of these two.
// ---------------------------------------------------------------------------
const CARD_CSS =
  'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
  'background:#f4f4f7;margin:0;display:flex;align-items:center;' +
  'justify-content:center;min-height:100vh;color:#222}.card{background:#fff;' +
  'border:1px solid #d5d5dd;border-radius:10px;padding:28px ' +
  '32px;width:380px;box-shadow:0 6px 24px ' +
  'rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 ' +
  '4px}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
  '18px}label{display:block;font-size:.85em;font-weight:600;margin:12px 0 ' +
  '4px}input[type=text],input[type=password]{width:100%;' +
  'box-sizing:border-box;padding:8px 10px;border:1px solid #bbb;' +
  'border-radius:5px;font-size:1em}.row{display:flex;gap:10px;' +
  'margin-top:20px}button{flex:1;padding:9px ' +
  '12px;border-radius:5px;border:1px solid #12107c;background:#12107c;' +
  'color:#fff;font-size:.95em;cursor:pointer}' +
  'button.secondary{background:#fff;color:#12107c}.err{background:#fdecea;' +
  'border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
  'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;padding-top:14px;' +
  'border-top:1px solid ' +
  '#eee;font-size:.75em;color:#777;word-break:break-all}.meta div{margin:2px ' +
  '0}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
  '.fed{margin-top:18px;padding-top:14px;border-top:1px solid #eee}.fed ' +
  'p{font-size:.78em;color:#666;margin:0 0 ' +
  '8px}a.fedbtn{display:block;text-align:center;padding:9px 12px;margin:6px ' +
  '0;border-radius:5px;border:1px solid #12107c;color:#12107c;' +
  'background:#fff;text-decoration:none;font-size:.9em}a.fedbtn ' +
  'span{display:block;font-size:.75em;color:#777}';

const PENDING_ID_QUERY = vz.object({
  authn: vt.opt(vt.base64url)
});

const LOGIN_FORM = vz.object({
  authn_id: vt.opt(vt.base64url),
  // **THE THREE VALUES THE FORM ITSELF DRAWS, AND THE FIRST VERSION OF THIS
  // LINE GOT THEM FROM THE HANDLER INSTEAD.** The handler only ever COMPARES
  // against `cancel` and `anonymous` — everything else falls through to the
  // ordinary sign-in — so reading it bottom-up gives a set that is missing the
  // commonest value there is, and `login` was refused for every sign-in in the
  // service. Eight protocol jobs went red on it and `npm test` could not have
  // seen it, because nothing in process submits this form.
  //
  // The lesson is the general one: a closed set for a control this service
  // draws itself must be read off the MARKUP, which is what a browser will
  // actually send, and not inferred from the branches that happen to test it.
  //
  // It stays a closed set rather than becoming a free string, because this is
  // this service's own form answering to no specification, and `action` decides
  // whether a credential is issued, refused or issued to nobody in particular.
  action: vt.opt(vt.oneOf(['login', 'cancel', 'anonymous'])),
  username: vt.opt(vt.name),
  password: vz.string().max(1024).optional(),
  // THE BROWSER FINGERPRINT (#62 P6), where `risk.fingerprinting` put the
  // script on the page and it ran: FingerprintJS's visitorId, hex. Empty
  // when the script did not run, which is the page working without it.
  device_fp: vz.string().max(64).regex(/^[A-Za-z0-9]*$/).optional(),
  use_webauthn: vt.opt(vt.flag),
  webauthn_only: vt.opt(vt.flag),
  csrf_token: vt.opt(vt.token)
});

// The WebAuthn ceremony's result. `credential` is a JSON document the browser's
// authenticator produced, so it is bounded and parsed downstream rather than
// described here — a schema for it would be a second, worse copy of the
// specification `webauthn.js` already implements.
const WEBAUTHN_FORM = vz.object({
  mode: vt.opt(vt.oneOf(['create', 'get'])),
  mfa_id: vt.opt(vt.base64url),
  credential: vz.string().max(validation.CAP.TEXT).optional(),
  csrf_token: vt.opt(vt.token)
});

const PASSWORD_CHANGE_FORM = vz.object({
  change_id: vt.opt(vt.base64url),
  new_password: vz.string().max(1024).optional(),
  confirm_password: vz.string().max(1024).optional(),
  csrf_token: vt.opt(vt.token)
});

const PASSWORD_CHANGE_QUERY = vz.object({
  change: vt.opt(vt.base64url)
});

const MFA_SETUP_STYLE = '<style>body{font-family:system-ui,-apple-system,' +
  '"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;display:flex;' +
  'align-items:center;justify-content:center;min-height:100vh;color:#222}' +
  '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
  'padding:28px 32px;width:440px;box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
  'h1{font-size:1.25em;margin:0 0 4px}h2{font-size:1em;margin:18px 0 6px}' +
  'p.sub{color:#666;font-size:.85em;margin:0 0 18px}p{font-size:.9em}' +
  'label{display:block;font-size:.8em;color:#444;margin:0 0 4px}' +
  'input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px ' +
  'solid #c8c8d0;border-radius:5px;font-size:1.3em;letter-spacing:.3em;' +
  'text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,' +
  'monospace;margin-bottom:14px}button{padding:9px 12px;border-radius:5px;' +
  'border:1px solid #12107c;background:#12107c;color:#fff;font-size:.95em;' +
  'cursor:pointer;width:100%;margin:4px 0}.err{background:#fdecea;border:' +
  '1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
  'font-size:.85em;margin-bottom:12px}code{font-family:ui-monospace,' +
  'SFMono-Regular,Menlo,monospace}.meta{margin-top:20px;padding-top:14px;' +
  'border-top:1px solid #eee;font-size:.75em;color:#777}</style>';

const MFA_SETUP_FORM = vz.object({
  mfa_id: vt.opt(vt.base64url),
  action: vt.opt(vt.oneOf(['totp', 'webauthn', 'confirm-totp'])),
  code: vz.string().max(32).optional(),
  csrf_token: vt.opt(vt.token)
});

// The security-key screen, and it is ONE screen for both roles. It performs the
// ceremony in the browser against THIS origin — the RP ID is the STS's own
// host, because WebAuthn binds a ceremony to the calling origin and no amount
// of configuration changes that.
//
// Registration on first use, assertion afterwards: a mock authorization server
// that demanded an already-enrolled key would be untestable without a manual
// enrolment step, and the interesting artifacts are the same either way.
//
// What differs between the roles is what the page SAYS, not what it does — the
// ceremony a second factor performs and the one a passwordless sign-in performs
// are the same bytes. It says it anyway, because the difference is what the
// session ends up claiming and a person reading the tokens afterwards has to be
// able to tell which one they did.
// THE CEREMONY SCRIPT'S PATH, NAMED ONCE (2026-09-10). It had one caller and
// was a literal in two places — the route and the `<script src>` on the page.
// `/portal/keys` is the third since it runs a registration of its own against
// the SAME script, and a path written out three times is two chances to move
// one of them.
const WEBAUTHN_SCRIPT_PATH = '/authn/webauthn.js';
// THE BROWSER FINGERPRINT'S SCRIPT (#62 P6): FingerprintJS (MIT, v5 — it
// runs in the browser and sends nothing anywhere; `monitoring: false` turns
// off the one usage ping the library makes, which this service's CSP would
// block regardless) followed by the few lines that put its visitorId in the
// sign-in form. Served only while `risk.fingerprinting` is on.
const FINGERPRINT_SCRIPT_PATH = '/authn/fingerprint.js';
const FINGERPRINT_GLUE = [
  '(function () {',
  '  var field = document.getElementById("device-fp");',
  '  if (!field || typeof FingerprintJS === "undefined") { return; }',
  '  FingerprintJS.load({ monitoring: false })',
  '    .then(function (fp) { return fp.get(); })',
  '    .then(function (result) { field.value = result.visitorId; })',
  '    .catch(function () { field.value = ""; });',
  '})();'
].join('\n');

// The ceremony script, as its own resource. Written with split/join rather than
// regular expressions on purpose: this string passes through a JavaScript
// string literal on the way out, where `\+` collapses to `+` and `\/` to `/`,
// which silently produced `/+/g` and `///g` in the delivered script the first
// time this was written inline. split/join has nothing to escape.
const WEBAUTHN_SCRIPT = [
  '(function () {',
  '  var d = document.getElementById("wa-data");',
  '  var b64u = function (b) {',
  '    var s = btoa(String.fromCharCode.apply(null, new Uint8Array(b)));',
  '    return s.split("+").join("-").split("/").join("_").split("=").join("");',
  '  };',
  '  var bytes = function (s) {',
  '    var t = s.split("-").join("+").split("_").join("/");',
  '    while (t.length % 4) { t += "="; }',
  '    var bin = atob(t), out = new Uint8Array(bin.length);',
  '    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }',
  '    return out;',
  '  };',
  '  var send = function (payload) {',
  '    document.getElementById("wa-credential").value = ' +
  'JSON.stringify(payload);',
  '    document.getElementById("wa-form").submit();',
  '  };',
  '  document.getElementById("wa-go").addEventListener("click", function () {',
  '    var challenge = bytes(d.getAttribute("data-challenge"));',
  '    var rpId = d.getAttribute("data-rpid");',
  '    var user = d.getAttribute("data-user");',
  '    var allow = d.getAttribute("data-allow");',
  '    var exclude = (d.getAttribute("data-exclude") || "").split(",")',
  '      .filter(function (id) { return id; });',
  // EVERY CEREMONY PARAMETER ARRIVES AS ONE PARSED OBJECT (2026-09-10). The
  // RP name, the algorithms, the attestation conveyance, the timeout, the
  // authenticator selection and the extensions were all literals in the lines
  // below until this day; they are `webauthn.*` settings now and this script
  // is served static, so they travel on data-options. The fallback is what
  // this script used to be, so a page served by an older build of the service
  // still performs a ceremony rather than throwing on a missing attribute.
  '    var o = {};',
  '    try { o = JSON.parse(d.getAttribute("data-options") || "{}") || {}; }',
  '    catch (e) { o = {}; }',
  '    var sel = o.authenticatorSelection || { userVerification: "preferred" ' +
  '};',
  '    var algs = (o.algorithms && o.algorithms.length ? o.algorithms : [-7, ' +
  '-257])',
  '      .map(function (a) { return { type: "public-key", alg: a }; });',
  '    var p;',
  '    if (d.getAttribute("data-mode") === "create") {',
  '      p = navigator.credentials.create({ publicKey: {',
  '        rp: o.rp || { name: "Mock authorization server", id: rpId },',
  '        user: { id: new TextEncoder().encode(user), name: user, ' +
  'displayName: user },',
  '        challenge: challenge,',
  '        pubKeyCredParams: algs,',
  '        authenticatorSelection: sel,',
  // WEBAUTHN'S OWN "DO NOT ENROL THIS AUTHENTICATOR TWICE" (2026-09-10). A
  // conforming authenticator that recognises one of these refuses rather than
  // creating a second credential — which is what stops the commonest mistake
  // when adding a BACKUP key: pressing Add and touching the one already
  // plugged in, producing a second credential on the same device and a
  // backup that is lost with the original. `credentials.js` checks it again
  // at the write, because this is a request to the browser like every other
  // option on this page.
  '        excludeCredentials: exclude.map(function (id) {',
  '          return { type: "public-key", id: bytes(id) };',
  '        }),',
  '        extensions: o.credProps ? { credProps: true } : undefined,',
  '        attestation: o.attestation || "direct",',
  '        timeout: o.timeout || 60000 } })',
  '        .then(function (c) {',
  '          var ext = {};',
  '          try { ext = c.getClientExtensionResults ? ' +
  'c.getClientExtensionResults() : {}; }',
  '          catch (e) { ext = {}; }',
  '          return { id: c.id, rawId: b64u(c.rawId), type: c.type,',
  '            authenticatorAttachment: c.authenticatorAttachment || null,',
  '            clientExtensionResults: ext, response: {',
  '            clientDataJSON: b64u(c.response.clientDataJSON),',
  '            attestationObject: b64u(c.response.attestationObject) } }; });',
  '    } else {',
  '      p = navigator.credentials.get({ publicKey: {',
  '        challenge: challenge, rpId: o.rpId || rpId,',
  // A LIST since 2026-09-10: a person may hold several keys of one role and
  // the authenticator picks whichever it has. It was one id, because this
  // module held one credential per person in a map of its own.
  '        allowCredentials: allow ? allow.split(",").map(function (id) {',
  '          return { type: "public-key", id: bytes(id) };',
  '        }) : undefined,',
  '        userVerification: o.userVerification || "preferred",',
  '        timeout: o.timeout || 60000 } })',
  '        .then(function (a) { return { id: a.id, rawId: b64u(a.rawId), ' +
  'type: a.type,',
  '          authenticatorAttachment: a.authenticatorAttachment || null, ' +
  'response: {',
  '          clientDataJSON: b64u(a.response.clientDataJSON),',
  '          authenticatorData: b64u(a.response.authenticatorData),',
  '          signature: b64u(a.response.signature),',
  '          userHandle: a.response.userHandle ? b64u(a.response.userHandle) ' +
  ': null } }; });',
  '    }',
  '    p.then(send).catch(function (e) { send({ error: e.name, message: ' +
  'e.message }); });',
  '  });',
  '})();',
  ''
].join('\n');

const TOTP_FORM = vz.object({
  mfa_id: vt.opt(vt.base64url),
  // A STRING AND NOT AN INTEGER, deliberately. A code is `007123` and a number
  // is 7123; parsing it as an integer here would lose the leading zeros that
  // one code in ten has, and `common/totp.ts` refuses anything that is not
  // exactly the enrolled number of digits — so the shape check belongs where
  // the digit count is known and not in this schema.
  code: vz.string().max(32).optional(),
  csrf_token: vt.opt(vt.token)
});

const PASSWORD_FACTOR_FORM = vz.object({
  mfa_id: vt.opt(vt.base64url),
  password: vz.string().max(1024).optional(),
  csrf_token: vt.opt(vt.token)
});

const MFA_STEP_QUERY = vz.object({
  mfa: vt.opt(vt.base64url)
});

const BACKUP_CODE_FORM = vz.object({
  mfa_id: vt.opt(vt.base64url),
  // A STRING WITH A GENEROUS BOUND, and no shape check here. A recovery code
  // is letters, digits, dashes and whatever spaces somebody typed reading it
  // off paper, and `common/backup_codes.ts` is where the alphabet lives —
  // which is where the refusal belongs, because that is the module that knows
  // what a code is made of. A schema that spelled the alphabet a second time
  // would be the second place to edit when it changes.
  code: vz.string().max(64).optional(),
  csrf_token: vt.opt(vt.token)
});

// The express application the routes are registered on.
type AppModule = typeof app;

// A row of the session store. Its fields are argued where each kind of
// session is made — startSession(), startArrivalSession() and
// startRelyingPartySession() — and a row is extended after it is built.
type SessionRow = Record<string, any>;

interface AuthnDeps {
  accountSignals: typeof accountSignals;
  clientHello: typeof clientHello;
  crypto: typeof crypto;
  stsCrypto: typeof stsCrypto;
  realms: typeof realms;
  app: typeof app;
  log: typeof helpers.log;
  logArtifact: typeof helpers.logArtifact;
  baseUrlOf: typeof helpers.baseUrlOf;
  nowSec: typeof helpers.nowSec;
  randomId: typeof helpers.randomId;
  xmlEscape: typeof helpers.xmlEscape;
  parseBody: typeof helpers.parseBody;
  oauthError: typeof helpers.oauthError;
  userFor: typeof helpers.userFor;
  helpers: typeof helpers;
  stats: typeof stats;
  federation: typeof federation;
  applications: typeof applications;
  config: typeof config;
  gate: typeof gate;
  credentials: typeof credentials;
  websecurity: typeof websecurity;
  mode: typeof mode;
  validation: typeof validation;
  bcp: typeof bcp;
  audit: typeof audit;
  clusterClaims: typeof clusterClaims;
  errorCodes: typeof errorCodes;
  accountState: typeof accountState;
  webauthnVerifier: typeof webauthnVerifier;
  webauthnPolicy: typeof webauthnPolicy;
  webauthnAttestation: typeof webauthnAttestation;
  totp: typeof totp;
}

class Authn {
  constructor(private readonly deps: AuthnDeps) {
    deps.log.debug("Entering Authn.constructor().");
    deps.log.debug("Leaving Authn.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): AuthnDeps {
    helpers.log.debug("Entering Authn.defaultDeps().");
    helpers.log.debug("Leaving Authn.defaultDeps().");
    return {
      accountSignals: accountSignals,
      clientHello: clientHello,
      crypto: crypto,
      stsCrypto: stsCrypto,
      realms: realms,
      app: app,
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      baseUrlOf: helpers.baseUrlOf,
      nowSec: helpers.nowSec,
      randomId: helpers.randomId,
      xmlEscape: helpers.xmlEscape,
      parseBody: helpers.parseBody,
      oauthError: helpers.oauthError,
      userFor: helpers.userFor,
      helpers: helpers,
      stats: stats,
      federation: federation,
      applications: applications,
      config: config,
      gate: gate,
      credentials: credentials,
      websecurity: websecurity,
      mode: mode,
      validation: validation,
      bcp: bcp,
      audit: audit,
      clusterClaims: clusterClaims,
      errorCodes: errorCodes,
      accountState: accountState,
      webauthnVerifier: webauthnVerifier,
      webauthnPolicy: webauthnPolicy,
      webauthnAttestation: webauthnAttestation,
      totp: totp
    };
  }

  // What loading this module did with its instance before #50's R2, now
  // done by the slot for whichever instance is installed: the audit log's
  // actor resolver.
  static wire(instance: Authn): void {
    helpers.log.debug("Entering Authn.wire().");
    audit.setActorResolver(instance.auditActorOf.bind(instance));
    helpers.log.debug("Leaving Authn.wire().");
  }

  private secondsSetting(key, fallbackMs) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.secondsSetting().");
    const n = Number(config.value(key));
    log.debug("Leaving Authn.secondsSetting().");
    return (isFinite(n) && n > 0 ? Math.floor(n) * 1000 : fallbackMs);
  }

  sessionLifetimeMs() {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionLifetimeMs().");
    log.debug("Leaving Authn.sessionLifetimeMs().");
    return this.secondsSetting('authn.sessionLifetimeS', SESSION_TTL_MS);
  }

  // ZERO IS THE DEFAULT AND MEANS NONE, so this is NOT `secondsSetting()`,
  // whose fallback would turn a deliberate zero into an hour.
  sessionIdleTimeoutMs() {
    const { log, config } = this.deps;
    log.debug("Entering Authn.sessionIdleTimeoutMs().");
    const n = Number(config.value('authn.sessionIdleTimeoutS'));
    log.debug("Leaving Authn.sessionIdleTimeoutMs().");
    return isFinite(n) && n > 0 ? Math.floor(n) * 1000 : 0;
  }

  // ---------------------------------------------------------------------------
  // IS THIS SESSION OVER? The one answer, for every reader in this file, for
  // the sweep, and for `logout/logout.ts`'s list of what is live.
  //
  // '' means live. 'expired' means the absolute expiry passed; 'idle' means it
  // has gone unused longer than `authn.sessionIdleTimeoutS`. An ARRIVAL session
  // (`chosen: false`) is exempt from the idle rule: it has an inactivity window
  // of its own — `touchArrivalSession()`, on the sign-in screen's clock — and a
  // short idle timeout applied to it would end a person's flow while they read
  // the screen.
  // ---------------------------------------------------------------------------
  sessionEnded(session, nowMs?) {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionEnded().");
    const now = nowMs || Date.now();
    if (!session) {
      log.debug("Leaving Authn.sessionEnded().");
      return 'expired';
    }
    if (session.expires && session.expires < now) {
      log.debug("Leaving Authn.sessionEnded().");
      return 'expired';
    }
    const idle = this.sessionIdleTimeoutMs();
    if (idle && session.chosen !== false && session.lastSeenAt &&
        now - session.lastSeenAt > idle) {
      log.debug("Leaving Authn.sessionEnded().");
      return 'idle';
    }
    log.debug("Leaving Authn.sessionEnded().");
    return '';
  }

  // A session was USED. Only matters with an idle timeout in force, and only
  // then is anything written — with none, nothing a session carries changes on
  // a read, which is what this service has always done and what keeps a read
  // from being a write to a persisted store. Written back through the store at
  // most once a second, because `sessionOf()` is called several times per
  // request and the store's journal sees `set()` rather than a stamped field.
  private noteSessionUsed(store, id, session) {
    const { log } = this.deps;
    log.debug("Entering Authn.noteSessionUsed().");
    if (!session || !this.sessionIdleTimeoutMs()) {
      log.debug("Leaving Authn.noteSessionUsed().");
      return;
    }
    const now = Date.now();
    if (session.lastSeenAt && now - session.lastSeenAt < 1000) {
      log.debug("Leaving Authn.noteSessionUsed().");
      return;
    }
    session.lastSeenAt = now;
    store.set(id, session);
    log.debug("Leaving Authn.noteSessionUsed().");
  }

  // ---------------------------------------------------------------------------
  // A PROTOCOL EDITED A SESSION IN PLACE, AND THE STORE HAS TO BE TOLD
  // (2026-09-14, #46).
  //
  // Four modules record, ON the session object, the parties it signed into —
  // `saml2_sso.ts`'s `saml2ServiceProviders`, `saml11_sso.ts`'s
  // `saml11RelyingParties`, `wsfed.ts`'s `wsfedRealms`, and
  // `frontchannel_logout.js`'s `oidcClients` — and each did it with a plain
  // assignment. `sessions` journals a `set()`, never an edit to an object it
  // holds (`persistence/CLAUDE.md`, the `touch()` rule), so the list reached
  // the store only if something else re-set the row later, and with no idle
  // timeout nothing does. One node was fine — its own copy had the list. Two
  // were not: a SAML sign-in response issued through node A and `GET
  // /saml2/slo` answered by node B offered NO LogoutRequest for that service
  // provider (`sts_saml_encryption`, the suite's `cluster` mode), because B's
  // copy of the session came from a row written before the list was.
  //
  // **IT DOES NOT BRING BACK A SESSION THAT IS GONE**, and that is why it looks
  // the row up rather than setting blindly: a session another request ended
  // between the caller's read and this write stays ended. Where the store holds
  // a DIFFERENT object for the id — replication replaced it mid-request — the
  // two are merged with `mergeSessionRows()`, the rule the flush applies to two
  // nodes' copies, so neither this edit nor the newer row is lost.
  // ---------------------------------------------------------------------------
  noteSessionChanged(session) {
    const { log } = this.deps;
    log.debug("Entering Authn.noteSessionChanged().");
    if (!session || !session.id) {
      log.debug("Leaving Authn.noteSessionChanged(). No session.");
      return false;
    }
    const held = sessions.get(session.id);
    if (!held) {
      log.debug("Leaving Authn.noteSessionChanged(). The session is gone.");
      return false;
    }
    sessions.set(session.id, held === session
      ? session
      : this.mergeSessionRows(session, held));
    log.debug("Leaving Authn.noteSessionChanged(). Re-set.");
    return true;
  }

  pendingTtlMs() {
    const { log } = this.deps;
    log.debug("Entering Authn.pendingTtlMs().");
    log.debug("Leaving Authn.pendingTtlMs().");
    return this.secondsSetting('authn.pendingTtlS', AUTHN_TTL_MS);
  }

  // ---------------------------------------------------------------------------
  // TWO COPIES OF ONE SESSION, MERGED (2026-09-14, #46 section 3).
  //
  // `mine` is this process's copy and `theirs` the stored one another node
  // wrote. The rule, in three parts, each chosen so that merging the answer
  // with either side again gives the answer (two nodes merging in either order
  // converge):
  //
  //   * **THE COPY FURTHER ALONG IS THE BASE.** An arrival nobody chose
  //     (`chosen: false`) is behind a session somebody signed in to or chose;
  //     then a later sign-in (`authTime`) is ahead of an earlier one — a
  //     re-authentication rotated the handle and changed the methods — then a
  //     later handle rotation, then a later hosted-surface token renewal. A
  //     state only moves forward, so a stale copy can never undo an upgrade.
  //   * **THE CLOCKS TAKE THE LATEST.** `lastSeenAt` always; `expires` only
  //     when both copies are the same sign-in, because an arrival's short
  //     sliding window must not be carried onto the session it became.
  //   * **THE LISTS ARE UNIONS.** The relying parties each protocol records for
  //     its sign-out (`oidcClients`, `wsfedRealms`, `saml2ServiceProviders`,
  //     `saml11RelyingParties`) keep every party either copy saw — a client
  //     missing from the list is a client whose logout iframe is never drawn —
  //     and `relyingParties` and `events` keep every entry either copy holds.
  // ---------------------------------------------------------------------------
  mergeSessionRows(mine, theirs) {
    const { log } = this.deps;
    log.debug("Entering Authn.mergeSessionRows().");
    if (!mine || typeof mine !== 'object') {
      log.debug("Leaving Authn.mergeSessionRows(). Nothing of mine.");
      return theirs;
    }
    if (!theirs || typeof theirs !== 'object') {
      log.debug("Leaving Authn.mergeSessionRows(). Nothing stored.");
      return mine;
    }
    const rank = function (s) {
      return [s.chosen === false ? 0 : 1, Number(s.authTime) || 0,
              Number(s.handleIssuedAt) || 0, Number(s.rpRenewedAt) || 0];
    };
    const a = rank(mine);
    const b = rank(theirs);
    let mineAhead = true;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        mineAhead = a[i] > b[i];
        break;
      }
    }
    const base = mineAhead ? mine : theirs;
    const other = mineAhead ? theirs : mine;
    const out = Object.assign({}, base);
    out.lastSeenAt = Math.max(Number(mine.lastSeenAt) || 0,
                              Number(theirs.lastSeenAt) || 0) ||
                              base.lastSeenAt;
    if (a[0] === b[0] && a[1] === b[1]) {
      out.expires = Math.max(Number(mine.expires) || 0,
                             Number(theirs.expires) || 0) || base.expires;
    }
    ['wsfedRealms', 'saml2ServiceProviders', 'saml11RelyingParties']
      .forEach(function (field) {
        if (other[field] && typeof other[field] === 'object') {
          out[field] = Object.assign({}, other[field], base[field] || {});
        }
      });
    if (other.oidcClients && typeof other.oidcClients === 'object') {
      const clients = Object.assign({}, base.oidcClients || {});
      Object.keys(other.oidcClients).forEach(function (clientId) {
        const there = other.oidcClients[clientId] || {};
        const here = clients[clientId];
        clients[clientId] = !here ? there : {
          first: Math.min.apply(null, [Number(here.first) || 0,
                                       Number(there.first) || 0]
            .filter(Boolean).concat([Date.now()])),
          last: Math.max(Number(here.last) || 0, Number(there.last) || 0),
          count: Math.max(Number(here.count) || 0, Number(there.count) || 0)
        };
      });
      out.oidcClients = clients;
    }
    ['relyingParties', 'events'].forEach(function (field) {
      if (!Array.isArray(other[field]) || !Array.isArray(base[field])) {
        return;
      }
      const seen = new Set(base[field].map(function (one) {
        return JSON.stringify(one);
      }));
      const union = base[field].slice(0);
      other[field].forEach(function (one) {
        const text = JSON.stringify(one);
        if (!seen.has(text)) {
          seen.add(text);
          union.push(one);
        }
      });
      out[field] = union;
    });
    log.debug("Leaving Authn.mergeSessionRows(). " +
              (mineAhead ? "Mine is ahead." : "The stored copy is ahead."));
    return out;
  }

  mfaStepTtlMs() {
    const { log } = this.deps;
    log.debug("Entering Authn.mfaStepTtlMs().");
    log.debug("Leaving Authn.mfaStepTtlMs().");
    return this.secondsSetting('authn.mfaStepTtlS', MFA_TTL_MS);
  }

  // --- the browser session ---------------------------------------------------
  // The cookie, and the three things done with it. This is the store every
  // protocol module reads to answer "is this person already signed in?", and
  // the only place in the service that writes it.
  cookiesOf(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.cookiesOf().");
    const out: Record<string, any> = {};
    String(req.headers.cookie || '').split(';').forEach(function (part) {
      const i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(
          part.slice(i + 1).trim());
    });
    log.debug("Leaving Authn.cookiesOf(). " + Object.keys(out).length +
              " cookie(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // A SESSION COOKIE IS `<sid>.<handle>`, AND ONLY THE HANDLE IS A SECRET
  // (2026-09-14).
  //
  // **ONE VALUE USED TO DO TWO JOBS, AND THE JOBS WANT OPPOSITE THINGS.** The
  // session id was the key in the store, the cookie a browser presented, the
  // `sid` in every ID Token, the SAML `SessionIndex`, the CAEP subject, the
  // join on every token record and the id printed on `/admin/sessions`. A
  // stable identifier wants to NEVER change for the life of the session. A
  // bearer secret wants to CHANGE whenever privilege does — OWASP's rotation
  // rule — and wants never to be printed anywhere. A re-authentication (see
  // `authn/CLAUDE.md`, *What an authenticated identity is here*) is exactly
  // where the two collide:
  // rotating the id would orphan every `sid` a relying party holds, and keeping
  // it would leave a pre-authentication cookie authenticated afterwards.
  //
  // So they are two values now. `session.id` IS the `sid` and does not change,
  // and every reader that wanted a stable identifier — about eighty of them —
  // goes on reading it unchanged. The HANDLE is minted by
  // `mintSessionHandle()`, rotated on every re-authentication and on the
  // arrival session's upgrade, and the store holds only its SHA-256
  // (`handleHash`), so a copy of the store or a row printed on a console page
  // is not a way into anybody's session.
  //
  // **THE SID IS IN THE COOKIE ON PURPOSE**: the store is keyed by it, so a
  // lookup is one `get()` and a hash comparison. The alternative — a handle
  // index beside the store — is a second map to hold in step with the first
  // across realms, processes and persistence, which is the mistake
  // `startSession()`'s keyed-session branch already declines to make one size
  // down.
  //
  // **A COOKIE WITH NO HANDLE IS REFUSED, and so is a row with no
  // `handleHash`.** There is no legacy acceptance of a bare id, and that is a
  // security decision rather than an oversight: relying-party and API rows live
  // in the same store and their ids are printed on `/admin/sessions`, so
  // honouring a bare id would keep every printed id a working credential. A
  // session persisted before this change costs one sign-in.
  // ---------------------------------------------------------------------------
  private handleHashOf(handle) {
    const { crypto, log } = this.deps;
    log.debug("Entering Authn.handleHashOf().");
    log.debug("Leaving Authn.handleHashOf().");
    return crypto.createHash('sha256').update(String(handle), 'utf8')
      .digest('base64url');
  }

  // Mints a fresh handle onto the session and returns the cookie VALUE. The
  // caller writes the session back through its store: this function stamps a
  // field, and a persisted store's journal sees `set()` rather than the field.
  private mintSessionHandle(session) {
    const { log, randomId } = this.deps;
    log.debug("Entering Authn.mintSessionHandle(). sid=" + session.id);
    const handle = randomId(24);
    session.handleHash = this.handleHashOf(handle);
    session.handleIssuedAt = Date.now();
    // OPENID CONNECT SESSION MANAGEMENT's OP BROWSER STATE (#121): minted with
    // the handle, so it changes at a sign-in and at every re-authentication
    // exactly as the handle does, and travels with it through the row merge.
    // Not a secret — script reads it — and it opens nothing.
    session.browserState = randomId(24);
    log.debug("Leaving Authn.mintSessionHandle().");
    return session.id + '.' + handle;
  }

  // The attributes every session cookie is written with. One place, for the
  // reason the header above `methodPhraseFor()` gives: a second copy that
  // disagreed about Path or SameSite would be two sessions that never saw each
  // other.
  private sessionCookieLine(name, value) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.sessionCookieLine(). name=" + name);
    log.debug("Leaving Authn.sessionCookieLine().");
    return String(name) + '=' + value + '; Path=/; HttpOnly; SameSite=Lax' +
           (config.value('global.https') ? '; Secure' : '');
  }

  // The session a request's cookie names, IF the cookie also carries that
  // session's current handle. `{ id, session }` or null. `store` is a realm's
  // partition where the caller is reading a named one; the ambient partition
  // otherwise. It EXPIRES NOTHING: the callers that sweep what they find
  // (`sessionOf()`, `relyingPartySessionOf()`, `consoleSession()`) still do,
  // and an observer that ended sessions while reporting on them would be
  // changing the thing it describes.
  cookieSession(req, cookieName, store?) {
    const { stsCrypto, log } = this.deps;
    log.debug("Entering Authn.cookieSession(). cookie=" + cookieName);
    const value = req ? this.cookiesOf(req)[String(cookieName ||
                                                   SESSION_COOKIE)]
                      : '';
    if (!value) {
      log.debug("Leaving Authn.cookieSession(). No cookie.");
      return null;
    }
    const dot = value.indexOf('.');
    if (dot <= 0 || dot === value.length - 1) {
      log.debug("Leaving Authn.cookieSession(). The cookie carries no handle.");
      return null;
    }
    const id = value.slice(0, dot);
    const handle = value.slice(dot + 1);
    const session = (store || sessions).get(id);
    if (!session || !session.handleHash ||
        !stsCrypto.constantTimeEquals(this.handleHashOf(handle),
                                      session.handleHash)) {
      // A rotated handle lands here, which is the ordinary case after a
      // re-authentication in another browser holding a copied cookie and the
      // whole point of rotating. Not worth a line per request above debug.
      log.debug("Leaving Authn.cookieSession(). No session holds that handle.");
      return null;
    }
    log.debug("Leaving Authn.cookieSession(). sid=" + id);
    return { id: id, session: session };
  }

  sessionOf(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionOf().");
    const found = this.cookieSession(req, SESSION_COOKIE);
    if (!found) {
      log.debug("Leaving Authn.sessionOf(). No session cookie naming a " +
                "session this server holds, with its current handle.");
      return null;
    }
    const id = found.id;
    const session = found.session;
    const ended = this.sessionEnded(session);
    if (ended) {
      // Through expireSession() and not a bare delete: this is a session ENDING
      // and it owes the same audit row and the same CAEP event every other way
      // of ending one writes. See that function's header.
      this.expireSession(sessions.realmMap(), id, session, 'a request that ' +
                                                           'presented it',
                         ended);
      log.debug("Leaving Authn.sessionOf(). The session had " +
                (ended === 'idle' ? "gone idle" : "expired") + " and was " +
                    "discarded.");
      return null;
    }
    // -------------------------------------------------------------------------
    // AN ANONYMOUS SESSION NOBODY HAS CHOSEN YET IS NOT A SIGN-IN, AND THIS IS
    // THE ONE PLACE THAT HAS TO KNOW IT.
    //
    // `startArrivalSession()` below gives every browser its own anonymous
    // unauthenticated session the moment it arrives at a protocol's front door.
    // It is the SAME KIND of session the "Continue without signing in" button
    // makes — the `anonymous` principal, `authenticated: false` — and there is
    // one instance per browser rather than one shared row, so two visitors are
    // two sessions on `/admin/sessions` exactly as two signed-in people are.
    //
    // **WHAT SEPARATES THEM IS `chosen`, AND WITHOUT IT SIGN-IN STOPS
    // WORKING.** `/oauth2/authorize` — and both SAML profiles, and
    // WS-Federation — decide whether to show the sign-in screen by asking this
    // function whether there is a session: `if (session && !forcePrompt)`
    // issues out of it. So a browser handed an anonymous session on arrival
    // would never be prompted again, and this service would issue tokens for
    // `anonymous` to every first-time visitor. That is not a subtle
    // degradation; it is the sign-in screen becoming unreachable.
    //
    // So an arrival session carries `chosen: false` and this funnel declines to
    // hand it out. The moment somebody signs in — or presses the button, which
    // is CHOOSING to be anonymous — the row is upgraded in place and `chosen`
    // becomes true, and every reader sees it from then on.
    //
    // Filtered HERE rather than at the six call sites, because a funnel every
    // reader already goes through is the only place this can be made true by
    // construction rather than by everybody remembering.
    // -------------------------------------------------------------------------
    if (session.chosen === false) {
      log.debug("Leaving Authn.sessionOf(). An anonymous session nobody has " +
                "chosen yet.");
      return null;
    }
    // A SESSION WHOSE ACCOUNT WAS DISABLED IS OVER (2026-09-17). Disabling
    // ends every session at once through `common/account_state.ts`; this is
    // the second half, for a session that act could not reach — a lock
    // written where nothing was listening, another node's copy — and it ends
    // the session through dropSession(), so its consequences (the audit row,
    // CAEP, the back-channel Logout Tokens) are the ones a sign-out has.
    if (this.sessionAccountDisabled(session)) {
      this.dropSession(id, 'the account was disabled by an administrator',
                       false, req);
      log.debug("Leaving Authn.sessionOf(). The account is disabled; the " +
                "session was ended.");
      return null;
    }
    this.noteSessionUsed(sessions.realmMap(), id, session);
    this.noticeRiskDrift(session, req);
    log.debug("Leaving Authn.sessionOf(). Signed in as " +
              session.user.username + ".");
    return session;
  }

  // Whether a signed-in session's person is disabled. The anonymous principal
  // and an unauthenticated session are nobody's account.
  sessionAccountDisabled(session) {
    const { log, accountState } = this.deps;
    log.debug("Entering Authn.sessionAccountDisabled().");
    if (!session || !session.user || session.authenticated === false ||
        session.chosen === false || session.credentialKey) {
      log.debug("Leaving Authn.sessionAccountDisabled(). Not a person's.");
      return false;
    }
    const disabled = accountState.isDisabled(session.user.sub ||
                                             session.user.username);
    log.debug("Leaving Authn.sessionAccountDisabled(). " + disabled);
    return disabled;
  }

  // ---------------------------------------------------------------------------
  // THE TRACKING SESSION: A COOKIE FROM THE FIRST PROTOCOL REQUEST
  // (2026-09-07).
  //
  // Until now the session cookie was written at the END of a sign-in, and
  // everything before that — the authorization request, the trip to the screen,
  // the form post — was correlated by a `pending` record whose id travels in
  // the URL. That works and it means a browser has no identity at all until it
  // has authenticated, which costs two things worth having:
  //
  //   * **The flow cannot be followed.** `/admin/sessions` shows sign-ins; a
  //     person who arrived, was shown the screen and gave up is invisible, and
  //     so is the request that brought them.
  //   * **Nothing about the browser is stable across the hops.** Everything
  //     that wants to recognise the same visitor twice has to be handed an
  //     identifier through the URL by whichever module happens to own that hop.
  //
  // So a browser that arrives at a protocol's front door with no cookie gets
  // one now, naming a row that holds nobody. When they sign in,
  // `startSession()` UPGRADES that row in place — same id, so the cookie the
  // browser already has goes on naming their session and nothing has to be
  // re-issued.
  //
  // **IT HOLDS NO PRINCIPAL, and that is what keeps it honest.** `user` is null
  // and `authenticated` is false, and `sessionOf()` above refuses to hand it to
  // anybody, so no issuance site, no console gate and no role check can mistake
  // it for a party. The only things that see it are the ones that ask for it by
  // name.
  // ---------------------------------------------------------------------------
  startArrivalSession(req, res, via) {
    const { log, nowSec, randomId, userFor } = this.deps;
    log.debug("Entering Authn.startArrivalSession().");
    if (this.cookieSession(req, SESSION_COOKIE)) {
      // Already has one — a live sign-in, or an arrival session from an earlier
      // hop. Either way this browser is already correlated and must not be
      // given a second identity.
      log.debug("Leaving Authn.startArrivalSession(). It already carries one.");
      return null;
    }
    const sessionId = randomId(24);
    const session: SessionRow = {
      id: sessionId,
      // THE ANONYMOUS PRINCIPAL, which is what makes this the same kind of
      // session the button makes rather than a third thing. One directory
      // entry, many sessions — see ANONYMOUS_USERNAME's header.
      user: userFor(ANONYMOUS_USERNAME),
      authenticated: false,
      // NOBODY HAS CHOSEN THIS. See sessionOf() above for what turns on it.
      chosen: false,
      authTime: nowSec(),
      // ---------------------------------------------------------------------
      // THE FLOW'S CLOCK AND NOT THE SESSION'S, which is a correction rather
      // than a preference. It was SESSION_TTL_MS, and the first full suite run
      // showed what that costs: an arrival session is minted for EVERY
      // cookie-less request to a protocol front door, which in a test run — or
      // behind any crawler — is most of them, and at the session TTL they
      // accumulate. `GET /admin-api/sessions?per=200` came back holding its
      // two-hundred-row cap, so a job asserting "the count went up by exactly
      // two" was reading a saturated list.
      //
      // Nobody is in one of these, and the only thing it has to outlive is the
      // sign-in it was created for — which is exactly what AUTHN_TTL_MS is: the
      // time a pending authentication waits at the screen. An arrival session
      // that has not become a sign-in in ten minutes is a browser that went
      // away.
      // ---------------------------------------------------------------------
      expires: Date.now() + this.pendingTtlMs(),
      startedAt: Date.now(),
      lastSeenAt: Date.now(),
      amr: [], acr: '0',
      via: via || 'unknown',
      relyingParties: [],
      events: []
    };
    const cookieValue = this.mintSessionHandle(session);
    sessions.set(sessionId, session);
    this.setCookieHeader(res, this.sessionCookieLine(SESSION_COOKIE,
                                                     cookieValue));
    log.debug("Leaving Authn.startArrivalSession(). " + sessionId + ".");
    return session;
  }

  private isArrivalPath(pathOnly) {
    const { log } = this.deps;
    log.debug("Entering Authn.isArrivalPath().");
    if (NOT_ARRIVAL_PATHS.indexOf(pathOnly) >= 0) {
      log.debug("Leaving Authn.isArrivalPath().");
      return false;
    }
    for (let i = 0; i < ARRIVAL_PATHS.length; i++) {
      const entry = ARRIVAL_PATHS[i];
      if (pathOnly === entry || pathOnly.indexOf(entry + '/') === 0) {
        log.debug("Leaving Authn.isArrivalPath().");
        return true;
      }
    }
    log.debug("Leaving Authn.isArrivalPath().");
    return false;
  }

  // ---------------------------------------------------------------------------
  // TEN MINUTES OF INACTIVITY, NOT TEN MINUTES.
  //
  // The expiry on an arrival session slides: every request that presents one
  // pushes it out again, and it goes when the browser has been quiet for
  // `AUTHN_TTL_MS`. Ten minutes from CREATION — which is what this was first
  // written as — is a different rule and the wrong one: a person reading the
  // sign-in screen, being sent to a home realm and coming back would lose the
  // identity their flow was being correlated by, part way through, for no
  // reason they could see.
  //
  // It is a SLIDE and not a renewal, so it cannot extend a session that has
  // already gone: an expired row is left to `sessionOf()`'s own sweep, which
  // ends it properly rather than quietly reviving it.
  //
  // A SIGNED-IN session is not touched here. Those carry `SESSION_TTL_MS` and
  // their own rules about when they end, and an arrival session's clock has no
  // business being applied to one.
  // ---------------------------------------------------------------------------
  private touchArrivalSession(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.touchArrivalSession().");
    const found = this.cookieSession(req, SESSION_COOKIE);
    const id = found ? found.id : '';
    const session = found ? found.session : null;
    if (!session || session.chosen !== false) {
      log.debug("Leaving Authn.touchArrivalSession().");
      return;
    }
    if (session.expires && session.expires <= Date.now()) {
      log.debug("Leaving Authn.touchArrivalSession().");
      // Already gone. Not revived — see the header.
      return;
    }
    session.expires = Date.now() + this.pendingTtlMs();
    session.lastSeenAt = Date.now();
    // AND WRITTEN BACK THROUGH THE STORE. `sessions` is
    // `realms.map({persist})`, whose journal sees `set()` and not a field
    // stamped on the object it handed out — so an extension made in place
    // reaches this process's memory and nothing else. Another process would go
    // on holding the OLD expiry and refuse a session somebody is actively
    // using.
    sessions.set(id, session);
    log.debug("Leaving Authn.touchArrivalSession().");
  }

  // The arrival session behind the cookie, if that is what it is. It exists for
  // startSession()'s upgrade below and for nothing else — every other reader
  // wants sessionOf(), which is the question they are actually asking, and
  // which deliberately declines to hand one of these out.
  private arrivalSessionOf(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.arrivalSessionOf().");
    const found = this.cookieSession(req, SESSION_COOKIE);
    const session = found ? found.session : null;
    if (!session || session.chosen !== false) {
      log.debug("Leaving Authn.arrivalSessionOf().");
      return null;
    }
    if (session.expires < Date.now()) {
      log.debug("Leaving Authn.arrivalSessionOf().");
      return null;
    }
    log.debug("Leaving Authn.arrivalSessionOf().");
    return session;
  }

  // ===========================================================================
  // RELYING-PARTY SESSIONS: THE ONE THIS SERVICE'S OWN HOSTED SURFACES HOLD
  // (2026-09-06).
  //
  // `/admin` and `/portal` do not read the session above any more. They are
  // RELYING PARTIES of this service's own authorization server: an
  // unauthenticated request is sent through `/oauth2/authorize`, comes back to
  // a registered redirect URI with a code, and the ID Token that code buys is
  // what establishes the session they read. `common/oidc_rp.ts` runs that flow
  // and this is where the session it produces lives.
  //
  // **THERE ARE NOW TWO KINDS OF BROWSER SESSION AND KEEPING THEM APART IS THE
  // WHOLE POINT.** The one above is the SINGLE SIGN-ON session — what a person
  // has with this identity provider, what `/oauth2/authorize` reads to decide
  // whether to draw the sign-in screen, and what every protocol family here
  // shares. The one below is what ONE APPLICATION has with a person who signed
  // in through that provider, which is a different fact with a different
  // lifetime: a real relying party holds its own session and would not be able
  // to read the provider's.
  //
  // **THEY ARE IN ONE STORE, and that is rule 3m rather than a shortcut.** A
  // second register would be a second answer to "is somebody signed in" —
  // `logout/logout.ts` reads this map, `/admin/sessions` draws it, CAEP
  // observes it, and the half a reader happened to look at would be the half
  // that was wrong. This is the same argument the KEYED sessions above make,
  // one shape along: the management API, SCIM and the SPIRE Server API are rows
  // in this map too, told apart by a field rather than by a store of their own.
  //
  // Four things about a derived session:
  //
  //   * **IT IS NOT AN AUTHENTICATION AND NOTHING RECORDS ONE.** The person
  //     authenticated at the authorization endpoint and `startSession()`
  //     counted it there. A second `recordAuthentication()` here would double
  //     every console sign-in on `/admin/users` and in the audit log — which is
  //     exactly the defect `federation_sp.ts` records having shipped once, and
  //     the reason its `completeSignIn()` passes through `startSession()`'s
  //     sixth argument rather than calling the funnel twice.
  //   * **IT CARRIES ITS OWN COOKIE, NAMED BY THE SURFACE.** Two surfaces, two
  //     cookies, so signing in to the portal does not sign anybody in to the
  //     console — which is what makes them two applications rather than one
  //     wearing two paths. Neither is `SESSION_COOKIE`.
  //   * **IT NAMES THE SSO SESSION IT CAME FROM (`derivedFrom`) AND DIES WITH
  //     IT.** Signing out at `/logout` ends the provider session, and a console
  //     session that outlived it would be a sign-out that visibly did nothing
  //     on the one surface an operator is looking at. The cascade is in
  //     `dropSession()`, so every door that ends a session ends the ones
  //     derived from it — the same argument that function's header already
  //     makes about being the single place a session ends.
  //   * **IT IS NOT EXTENDED BY USE.** It expires when the ID Token's own
  //     session would: absolute, like the browser session it descends from.
  // ===========================================================================

  // Every derived session hanging off one SSO session, by id. Used by the
  // cascade below and by nothing else — it is a WALK rather than an index for
  // `startSession()`'s keyed-session reason: an index would be a second map to
  // hold in step with this one, and these maps are already bounded by the
  // sweep.
  //
  // **IT WALKS TWO PARTITIONS SINCE 2026-09-11, AND ONLY EVER TWO.** The admin
  // console AUTHORIZES in the ambient realm — that is what makes single sign-on
  // between `/admin` and `/portal` work inside a realm — and holds its session
  // in the DEFAULT realm's partition, so that one console session is found by
  // the gate from every realm. So a console session reached in `acme` is a
  // child in the default partition whose parent is in acme's, and a cascade
  // that walked only the parent's own partition would find nothing: the sign-on
  // session would end and the console session it issued would go on working.
  //
  // The default realm is the only other partition looked in, because the
  // console is the only surface whose session realm differs from its flow realm
  // — see `common/oidc_rp.ts`'s surface table. A THIRD such surface would have
  // to widen this, and the honest way to do that is another named partition
  // here rather than a walk over every realm: `realms.list()` is unbounded and
  // this runs on every sign-out.
  //
  // A child found in the other partition must SAY it belongs to this parent's
  // realm. Without that check a session id that happened to exist in both
  // partitions with the same `derivedFrom` would be ended by a sign-out it has
  // nothing to do with. An absent `derivedFromRealm` means "my own partition",
  // which is what every session made before this field existed meant.
  derivedFrom(parentId, store?) {
    const { realms, log } = this.deps;
    log.debug("Entering Authn.derivedFrom(). parentId=" + parentId);
    const here = realms.currentId();
    const found = [];
    const seen: Record<string, any> = {};
    function scan(realmId, map) {
      log.debug("Entering scan().");
      map.forEach(function (held, id) {
        if (!held || held.derivedFrom !== parentId || seen[id]) {
          return;
        }
        if (String(held.derivedFromRealm || realmId) !== here) {
          return;
        }
        seen[id] = true;
        found.push({ id: id, session: held, realm: realmId });
      });
      log.debug("Leaving scan().");
    }
    scan(here, store || sessions.realmMap());
    if (here !== realms.DEFAULT_ID) {
      scan(realms.DEFAULT_ID, sessions.realmMap(realms.DEFAULT_ID));
    }
    log.debug("Leaving Authn.derivedFrom(). " + found.length +
              " derived session(s).");
    return found;
  }

  // The session ONE hosted surface holds. `cookie` is that surface's own cookie
  // name — `oidc_rp.js` takes it from the application's row, so the name a
  // browser carries and the name this reads cannot come apart.
  //
  // **IT CHECKS THE PARENT AS WELL AS THE CLOCK.** The cascade in dropSession()
  // is what normally ends these, and it reaches only the sessions in the store
  // it is walking; a derived session whose parent is gone must not be honoured
  // on the strength of its own unexpired cookie, because "the person signed
  // out" is exactly the case that matters. So the parent is looked up on every
  // read. That is a Map lookup on a request that already does several.
  relyingPartySessionOf(req, cookie, realmId) {
    const { realms, log } = this.deps;
    const self = this;
    log.debug("Entering Authn.relyingPartySessionOf(). cookie=" + cookie);
    const store = realmId ? sessions.realmMap(realmId) : sessions.realmMap();
    // THE SAME `<id>.<handle>` SHAPE AS THE SIGN-ON COOKIE (2026-09-14), and
    // for a reason that is sharper here: these ids are printed on
    // /admin/sessions to every holder of Admin Read, and a bare id in
    // `sts_admin` was a console session belonging to whoever held Admin Write.
    const found = this.cookieSession(req, String(cookie || ''), store);
    if (!found) {
      log.debug("Leaving Authn.relyingPartySessionOf(). No cookie naming a " +
                "session with its current handle.");
      return null;
    }
    const id = found.id;
    const session = found.session;
    const ended = this.sessionEnded(session);
    if (ended) {
      this.expireSession(store, id, session, 'a request that presented it',
                         ended);
      log.debug("Leaving Authn.relyingPartySessionOf(). It had " +
                (ended === 'idle' ? "gone idle." : "expired."));
      return null;
    }
    // WHERE THIS SESSION LIVES AND WHERE ITS PARENT LIVES ARE TWO ANSWERS
    // (2026-09-11). The admin console's session is in the default realm's
    // partition and its sign-on session is in whichever realm the code flow ran
    // in — see `common/oidc_rp.ts`'s surface table. Looking the parent up in
    // THIS session's partition would report every console session reached in a
    // realm as an orphan and end it on sight, which is a sign-in that lasts one
    // request. An absent `derivedFromRealm` means the same partition, which is
    // what every session made before this field existed meant.
    const ownRealm = realmId || realms.currentId();
    const parentRealm = String(session.derivedFromRealm || ownRealm);
    const parentStore = parentRealm === ownRealm
      ? store : sessions.realmMap(parentRealm);
    // -------------------------------------------------------------------------
    // A PARENT THAT RAN OUT IS NOT A PARENT THAT SIGNED OUT (2026-09-12).
    //
    // A relying-party session that holds a REFRESH TOKEN renews its own tokens
    // (`common/oidc_rp.ts`'s `renewIfDue()`), so it is not bound to the sign-on
    // session's absolute lifetime any more than a real relying party is bound
    // to its provider's. A SIGN-OUT still ends it: `dropSession()`'s cascade
    // runs while the parent exists and ends every child. What is left for this
    // check to tell apart is WHY a parent is missing, and the clock answers it
    // without a flag anybody has to remember to write: a parent gone after the
    // moment it would have expired (`derivedFromExpires`) ran out; one gone
    // BEFORE that moment was ended, and a child still standing is a cascade
    // that did not reach it — which is ended here exactly as before.
    // -------------------------------------------------------------------------
    const parentRanOut = !!(session.rpTokens && session.rpTokens.refreshToken &&
                            session.derivedFromExpires &&
                            Date.now() >= session.derivedFromExpires);
    if (session.derivedFrom && !parentStore.get(session.derivedFrom) &&
        !parentRanOut) {
      // The provider session is gone and this one is therefore over. It is
      // ENDED rather than merely refused, so that /admin/sessions stops listing
      // it and the audit log carries the row: a session that keeps being
      // refused and keeps being listed is the worst of both answers.
      log.info('authn: the ' + (session.rpSurface || 'relying party') +
               ' session ' + id + ' is being ended because the sign-on ' +
               'session it was derived from (' + session.derivedFrom +
               ', in realm ' +
               parentRealm + ') is gone. A relying party session cannot ' +
               'outlive the provider session it was issued against.');
      // IN THE REALM THE SESSION IS IN, and not in the ambient one.
      // `dropSession()` works on the ambient realm's partition, and this
      // function is reached with an explicit realm — the console reads its
      // default-realm session from inside whatever realm the request is in.
      // Dropping it ambiently deleted nothing and left the orphan to be
      // reported again on the next request.
      if (parentRealm !== ownRealm ||
          (realmId && realmId !== realms.currentId())) {
        realms.run(realms.get(ownRealm), function () {
          self.dropSession(id, 'the sign-on session it came from ended', true,
                           req);
        });
      } else {
        this.dropSession(id, 'the sign-on session it came from ended', true,
                         req);
      }
      log.debug("Leaving Authn.relyingPartySessionOf(). Its parent is gone.");
      return null;
    }
    // USE OF AN APPLICATION IS USE OF THE SIGN-ON SESSION BEHIND IT. With an
    // idle timeout in force, an operator working in the console presents the
    // console's cookie and never the sign-on session's — so without touching
    // the parent here, the sweep would idle the parent out underneath somebody
    // actively using the console, and the cascade would then end the console
    // session too. Inert with no idle timeout, which is the default.
    this.noteSessionUsed(store, id, session);
    if (session.derivedFrom) {
      this.noteSessionUsed(parentStore, session.derivedFrom,
                           parentStore.get(session.derivedFrom));
    }
    log.debug("Leaving Authn.relyingPartySessionOf(). Signed in as " +
              session.user.username + ".");
    return session;
  }

  // Create one. Called only from `common/oidc_rp.ts`, once, after an ID Token
  // has been verified — which is why this takes CLAIMS rather than a username
  // and a password: what it is turning into a session is a statement this
  // service made about somebody, and every field below comes off that statement
  // rather than out of a form.
  startRelyingPartySession(spec) {
    const { realms, log, nowSec, randomId, userFor, audit } = this.deps;
    log.debug("Entering Authn.startRelyingPartySession(). surface=" +
              spec.surface);
    const claims = spec.claims || {};
    const username = String(spec.username || claims.preferred_username ||
                            claims.sub || '');
    const sessionId = randomId(24);
    const store = sessions.realmMap();
    // THE EXPIRY IS THE PARENT'S WHERE THERE IS ONE. A relying party session
    // that outlived the provider session would be refused on the next read
    // anyway (see the parent check above), so making it longer would only mean
    // listing a row that is already dead. Shorter is a legitimate thing for a
    // deployment to want and is not built: one lifetime is what `logout.ts`'s
    // SESSION_EXPIRY_RULES can describe honestly. THE PARENT MAY BE IN ANOTHER
    // PARTITION. `spec.parentRealm` is the realm the code flow ran in, which
    // for the admin console is the ambient realm while this session is being
    // created in the default one. Reading the expiry out of THIS store would
    // find nothing and fall back to a full session lifetime, so a console
    // session would routinely outlive the sign-on session it descends from —
    // which the parent check in relyingPartySessionOf() would then end, at a
    // moment decided by nothing a reader could see.
    const parentRealm = String(spec.parentRealm || realms.currentId());
    const parentStore = parentRealm === realms.currentId()
      ? store : sessions.realmMap(parentRealm);
    const parent = spec.parent ? parentStore.get(spec.parent) : null;
    // WHO VOUCHED FOR THE SIGN-IN THIS SESSION CAME FROM (2026-09-22, #103):
    // the kind of authority on the sign-on session's most recent event —
    // `local` for this service, `federation` or `kerberos` otherwise. The ID
    // Token's `amr` says HOW somebody authenticated and not WHO checked it:
    // SPNEGO puts `pwd` there for a pre-authenticated ticket, and a federation
    // partner's own `pwd` rides behind `federated`. The console's bootstrap
    // claim needs both (`admin-ui/admin_rbac.ts`'s `passwordSignIn()`).
    const signInAuthority = this.latestAuthorityOf(parent);
    // -------------------------------------------------------------------------
    // …UNLESS IT CAN RENEW ITSELF (2026-09-12). A session handed a refresh
    // token is renewed through the refresh token grant when its ID Token and
    // access token run out — see `common/oidc_rp.ts` — so its absolute expiry
    // is the end of the window it may renew in (`spec.renewableUntil`, the
    // refresh token's lifetime from the sign-in), or the tokens' own expiry
    // where that is later. The paragraph above is still the rule for a session
    // with no refresh token, and every session made before this existed is one.
    // -------------------------------------------------------------------------
    const tokens = spec.tokens || null;
    const renewable = !!(tokens && tokens.refreshToken && spec.renewableUntil);
    const session: SessionRow = {
      id: sessionId,
      user: userFor(username),
      authTime: Number(claims.auth_time) || nowSec(),
      expires: renewable
        ? Math.max(Number(spec.renewableUntil), this.tokensExpireAt(tokens))
        : (parent ? parent.expires : Date.now() + this.sessionLifetimeMs()),
      // Off the ID TOKEN and not off the parent, because the token is what this
      // application was actually told. They agree today — the same process
      // issued both — and a relying party that read the provider's own record
      // instead of the statement it was handed would be a relying party in
      // name.
      authenticated: claims.mock_authenticated !== false,
      amr: Array.isArray(claims.amr) ? claims.amr : (spec.amr || []),
      acr: claims.acr || spec.acr || '',
      via: spec.via || 'OAuth 2.0 / OIDC',
      // The sign-on session's authority, above; read with `amr` by the
      // console's bootstrap claim (#103).
      signInAuthority: signInAuthority,
      // WHAT MAKES IT A DERIVED SESSION. `rpSurface` is what /admin/sessions
      // draws in its Kind column and what `logout.ts` reads; `rpClientId` is
      // the application entry it belongs to, so a row can be followed back to
      // the client that holds it.
      derivedFrom: spec.parent || '',
      // WHICH REALM'S PARTITION THAT PARENT IS IN. Empty where there is no
      // parent; otherwise the realm the code flow ran in, which is the ambient
      // realm for both surfaces and is NOT this session's own realm for the
      // admin console. Every reader treats an absent value as "this session's
      // own realm", so a record from a process older than 2026-09-11 behaves as
      // it did.
      derivedFromRealm: spec.parent ? parentRealm : '',
      rpSurface: String(spec.surface || ''),
      rpLabel: String(spec.label || spec.surface || ''),
      rpClientId: String(spec.clientId || ''),
      // The id token's own session identifier where it carried one, so a
      // front-channel logout can name this session the way OpenID Connect
      // Front-Channel Logout section 3 means.
      rpSid: String(claims.sid || ''),
      // THE TOKENS THIS RELYING PARTY WAS ISSUED, and the one place they are
      // kept (2026-09-12). The ID Token, the access token and the refresh
      // token, with the instants the first two run out, the issuer and subject
      // the renewed ID Token must repeat, the realm the code flow ran in and
      // the Host it was asked under. It is ON THE SESSION because that is what
      // it belongs to: a store of its own would be a second record of who is
      // signed in to the console, and it goes when the session does. Never
      // drawn by a view — `logout.ts` builds its rows field by field — and
      // never audited. At rest it is what the whole session row is: sealed
      // wherever minted rows persist (`persistence/persistence_minted.js`).
      rpTokens: tokens,
      rpRenewableUntil: renewable ? Number(spec.renewableUntil) : 0,
      rpRenewals: 0,
      rpRenewedAt: 0,
      // When the sign-on session this one hangs off would have expired, so the
      // reader can tell a parent that RAN OUT from one that was ENDED. See
      // relyingPartySessionOf().
      derivedFromExpires: parent ? Number(parent.expires || 0) : 0,
      credentialKey: null,
      lastSeenAt: Date.now(),
      calls: 1
    };
    const cookieValue = this.mintSessionHandle(session);
    store.set(sessionId, session);
    this.setCookieHeader(spec.res, this.sessionCookieLine(spec.cookie,
                                                          cookieValue));
    // THE AUDIT ROW SAYS WHERE IT CAME FROM, and it is a `session.start` like
    // every other because that is what happened. What tells it apart from the
    // sign-in that produced the ID Token is the summary and the detail: an
    // operator reading two rows a second apart has to be able to see that one
    // is the provider's and one is the application's, or they will read them as
    // the duplicate this deliberately is not.
    audit.audit({
      action: 'session.start',
      actor: username,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: sessionId,
      summary: username + ' signed in to the ' + (spec.label || spec.surface) +
               ' with an ID Token from this service; session ' + sessionId +
               ' was created',
      detail: {
        sessionId: sessionId,
        sub: session.user.sub,
        client_id: session.rpClientId,
        derivedFrom: session.derivedFrom,
        surface: session.rpSurface,
        amr: (session.amr || []).join(', '),
        acr: session.acr || '',
        authTime: session.authTime,
        expiresAt: new Date(session.expires).toISOString(),
        // Whether it renews its own tokens, and until when. Never the tokens.
        renewable: renewable,
        renewableUntil: renewable ?
                        new Date(session.rpRenewableUntil).toISOString() : '',
        note: 'A RELYING PARTY session, established from a verified ID Token ' +
              'rather than from a credential. Nobody authenticated here: the ' +
              'authentication is the session.start row for ' +
              (session.derivedFrom || 'the sign-on session') + '.'
      }
    });
    session.firstPresentationIsTheSignIn = true;
    this.notifySession('established', session,
                       { via: 'OAuth 2.0 / OIDC',
                         req: (spec.res && spec.res.req) || null });
    log.info('authn: ' + username + ' holds a ' + (spec.label || spec.surface) +
             ' session (' + sessionId + ') in realm ' + realms.currentId() +
             ', derived from sign-on session ' + (spec.parent || '(none)') +
             (spec.parent ? ' in realm ' + parentRealm : '') +
             '. No authentication was recorded here — the authorization ' +
             'endpoint already counted it.');
    log.debug("Leaving Authn.startRelyingPartySession(). " + sessionId);
    return session;
  }

  // The kind of authority that vouched for a sign-on session's most recent
  // authentication (see authenticationEvent()), or '' for no session or a row
  // older than events, which nothing may read as this service's own check.
  latestAuthorityOf(session) {
    const { log } = this.deps;
    log.debug("Entering Authn.latestAuthorityOf().");
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const last = events.length ? events[events.length - 1] : null;
    const kind = last && last.authority && last.authority.kind
      ? String(last.authority.kind) : '';
    log.debug("Leaving Authn.latestAuthorityOf(). " + (kind || '(none)'));
    return kind;
  }

  // When a relying party's tokens stop saying anything: the EARLIER of the
  // access token's expiry and the ID Token's, in milliseconds. 0 for a session
  // holding none, which every reader treats as "nothing to renew".
  tokensExpireAt(tokens) {
    const { log } = this.deps;
    log.debug("Entering Authn.tokensExpireAt().");
    if (!tokens) {
      log.debug("Leaving Authn.tokensExpireAt(). No tokens.");
      return 0;
    }
    const instants = [Number(tokens.accessExpiresAt) || 0,
                      Number(tokens.idTokenExpiresAt) || 0]
      .filter(function (ms) { return ms > 0; });
    log.debug("Leaving Authn.tokensExpireAt().");
    return instants.length ? Math.min.apply(null, instants) : 0;
  }

  // ---------------------------------------------------------------------------
  // A RELYING PARTY SESSION'S TOKENS, RENEWED IN PLACE (2026-09-12).
  //
  // Called only from `common/oidc_rp.ts`, after the refresh token grant has
  // answered and the ID Token in that answer has verified. **THE SESSION IS THE
  // SAME SESSION**: same id, same cookie, same CSRF token on every page a
  // person already has open, same `authTime`, `amr` and `acr` — because nobody
  // authenticated. What moves is what a renewal is: the tokens, the instant
  // they next run out, and a count. Nothing is recorded as an authentication
  // and no CAEP event is sent, for `startRelyingPartySession()`'s reason: the
  // authorization endpoint counted the sign-in once, and a renewal is not one.
  //
  // `expires` moves only as far as the new tokens need: a renewal inside the
  // window leaves it at the window's end, and never extends the window itself —
  // that is what keeps a console session somebody keeps using BOUNDED by the
  // refresh token's lifetime from the sign-in rather than renewed for ever.
  //
  // Answers the session as it now is, or null where it is gone.
  // ---------------------------------------------------------------------------
  renewRelyingPartySession(spec) {
    const { realms, log, audit } = this.deps;
    log.debug("Entering Authn.renewRelyingPartySession(). id=" + spec.id);
    const store = sessions.realmMap(spec.realmId || realms.currentId());
    const session = store.get(spec.id);
    if (!session || !session.rpSurface) {
      log.debug("Leaving Authn.renewRelyingPartySession(). No such relying " +
                "party session.");
      return null;
    }
    const previous = session.rpTokens || {};
    session.rpTokens = Object.assign({}, previous, spec.tokens || {});
    session.rpRenewals = (Number(session.rpRenewals) || 0) + 1;
    session.rpRenewedAt = Date.now();
    session.expires = Math.max(Number(session.rpRenewableUntil) || 0,
                               this.tokensExpireAt(session.rpTokens),
                               Number(session.expires) || 0);
    store.set(spec.id, session);
    audit.audit({
      action: 'session.renew',
      outcome: 'success',
      actor: session.user.username,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: spec.id,
      summary: 'the ' + (session.rpLabel || session.rpSurface) + ' renewed ' +
               'the tokens of ' + session.user.username + '\'s session ' +
               spec.id +
               ' with the refresh token grant; the session is unchanged',
      detail: {
        sessionId: spec.id,
        client_id: session.rpClientId,
        surface: session.rpSurface,
        renewals: session.rpRenewals,
        tokensExpireAt: new Date(this.tokensExpireAt(session.rpTokens))
          .toISOString(),
        renewableUntil: session.rpRenewableUntil
          ? new Date(session.rpRenewableUntil).toISOString() : '',
        refreshTokenRotated: !!(spec.tokens && spec.tokens.refreshToken &&
                                spec.tokens.refreshToken !==
                                previous.refreshToken),
        note: 'Not a sign-in and not a new session: the same session id, the ' +
              'same authentication time, new tokens.'
      }
    });
    log.info('authn: the ' + (session.rpLabel || session.rpSurface) +
             ' session ' +
             spec.id + ' for ' + session.user.username +
             ' renewed its tokens (' +
             session.rpRenewals + ' renewal(s)); they now run out at ' +
             new Date(this.tokensExpireAt(session.rpTokens)).toISOString() +
             '.');
    log.debug("Leaving Authn.renewRelyingPartySession().");
    return session;
  }

  // ---------------------------------------------------------------------------
  // THE CONSOLE'S SESSION, AND IT IS ALWAYS THE DEFAULT REALM'S. FOR THE ADMIN
  // CONSOLE, AND FOR NOTHING ELSE IN THIS SERVICE.
  //
  // `sessions` is per realm and `sessionOf()` reads the ambient realm's
  // partition, which is right for every protocol here: signing in to `acme`
  // must not satisfy the default realm's `/oauth2/authorize`, and
  // realmSupport() says so out loud. The console is the one caller that needs a
  // different answer, and what it needs is not "any realm" — it is "the default
  // realm, whichever realm is being read".
  //
  // **THIS FUNCTION USED TO ANSWER "ANY REALM" AND THAT BECAME WRONG ON
  // 2026-08-25**, when the embedded directory became per realm. The old
  // argument was explicit about its own premise: *who may use the console is
  // already shared, because the two roles are groups in the ONE directory this
  // process has, so a session refused for being minted next door would have
  // been refused on a boundary the authorization decision behind it does not
  // have.* That premise is now false. Each realm has its own `ou=groups`, and
  // if a session minted in `acme` still opened the console then anybody who
  // could create a realm could grant themselves both roles inside it and walk
  // back out into the default realm — the realm feature would have become a
  // privilege escalation. `ldap_server.js` pins `admin_rbac.js`'s whole
  // directory to the default realm for that reason, and this is the other half
  // of the same decision. The two have to agree: a gate that accepted an `acme`
  // session while the roster could only name default-realm people would let
  // somebody in and then insist they were nobody. (SINCE 2026-09-14 (#32) a
  // realm has a roster of its own, confined to it by `admin-ui/admin_scope.ts`,
  // and the gate asks the roster of the realm the person signed in through; the
  // default realm's is only what `admin_rbac.js` reads when no realm is named —
  // authn/CLAUDE.md and admin-ui/CLAUDE.md 8d. This function still reads the
  // default realm's partition.)
  //
  // **THERE IS STILL ONE COOKIE, AND THAT IS WHY THIS IS NOT `sessionOf()`.**
  // `startSession()` writes `sts_session` at `Path=/`, deliberately and for
  // a reason that has nothing to do with realms — every protocol here shares
  // one session, so the name, path and SameSite have to agree exactly. A
  // browser therefore holds exactly ONE session id for this whole origin.
  // Reading the AMBIENT realm's partition would make the console's realm
  // switcher a loop: the gate finds nothing in `acme`, sends the reader to
  // `/realm/acme/authn/login`, and that sign-in OVERWRITES the one cookie there
  // is — so switching back finds nothing either, forever, one sign-in per
  // click. Nothing expires and nothing is misconfigured; the two realms take
  // turns holding the only cookie slot the browser has. Pinning to the default
  // realm ends that in the same stroke: there is one realm the console ever
  // signs anybody in to, so there is nothing to take turns over.
  //
  // Two properties this keeps from the version it replaced:
  //
  //   * IT GRANTS NOTHING. Its one caller is `consoleSignOn()` in
  //     `admin-ui/admin.ts`, which REPORTS the sign-on session behind the
  //     console's own relying-party session; since 2026-09-06 the gate
  //     (`gateStateFor()`, now in `admin-core/admin_views.ts`) reads the
  //     relying-party session and not this. No token is issued on the session
  //     it finds, no assertion names it, and `/oauth2/authorize` still calls
  //     `sessionOf()` and still sees only its own realm's.
  //   * ENDING IT STILL ENDS IT. The session is the one object in the default
  //     realm's map — so /logout, /admin/logout and an expiry sweep all shut
  //     the console too, because there is nothing here to end separately.
  //
  // It sweeps an expired session out of the default realm's map exactly as
  // `sessionOf()` does, rather than leaving one for a later reader to clear.
  //
  // The realm is returned alongside the session so that `gateStateFor()` can
  // keep reporting one, and `foreign` says whether the realm being READ is a
  // different one — which is now the ordinary case for every page under a realm
  // prefix, and is what the console's banner says out loud.
  // ---------------------------------------------------------------------------
  consoleSession(req) {
    const { realms, log } = this.deps;
    const self = this;
    log.debug("Entering Authn.consoleSession().");
    // In the default realm this is the ordinary reader, sweep and all, so the
    // common case — a service with no realms defined — is byte-for-byte what it
    // always was.
    if (!realms.active() || realms.currentId() === realms.DEFAULT_ID) {
      const here = this.sessionOf(req);
      log.debug("Leaving Authn.consoleSession(). The default realm is the " +
                "one being read.");
      return here
        ? { session: here, realm: realms.DEFAULT_REALM, foreign: false }
        : null;
    }
    // The default realm's own Map. `realmMap(id)` is the facade's door for
    // exactly this — a caller that wants a NAMED partition rather than the
    // ambient one.
    const store = sessions.realmMap(realms.DEFAULT_ID);
    const found = this.cookieSession(req, SESSION_COOKIE, store);
    if (!found) {
      log.debug("Leaving Authn.consoleSession(). The default realm holds no " +
                "session this cookie names with its current handle.");
      return null;
    }
    const id = found.id;
    const session = found.session;
    const ended = this.sessionEnded(session);
    if (ended) {
      // The DEFAULT realm's store, whichever realm the console is being read in
      // — which is what this whole function is about — so the expiry is run in
      // that realm too, or the event would name the issuer of the realm
      // somebody happened to be looking at.
      realms.run(realms.DEFAULT_REALM, function () {
        self.expireSession(store, id, session, 'the admin console', ended);
      });
      log.debug("Leaving Authn.consoleSession(). The session had expired and " +
                "was discarded.");
      return null;
    }
    log.debug("Leaving Authn.consoleSession(). Signed in as " +
              session.user.username +
              " on the default realm's session.");
    return { session: session, realm: realms.DEFAULT_REALM, foreign: true };
  }

  // --- starting and ending a session -----------------------------------------
  // Both are functions rather than four lines repeated at each call site, and
  // the reason is WS-Federation. `wsfed.ts` signs a user in at its own login
  // screen and must land them in THE SAME session this service owns, because
  // the two protocols share the browser and single sign-on between them is the
  // interesting behaviour: sign in at this screen with a security key, arrive
  // at `wsignin1.0`, and the assertion says a hardware key was used because the
  // session recorded it.
  //
  // The cookie's attributes are the part that must not be written twice.
  // Sharing a session across protocols means the cookie NAME, PATH and SameSite
  // have to agree exactly; a second copy that set Path=/oauth2 or omitted
  // SameSite would produce two sessions that each looked fine on its own and
  // never saw each other, which is a debugging session with no error message
  // anywhere in it.
  //
  // **SameSite=Lax is deliberate and it has one consequence worth knowing.** It
  // is sent on a top-level GET navigation, which is how a relying party sends a
  // browser here in both protocols — but NOT on a cross-site POST, and
  // WS-Federation section 13.2.1 permits the sign-in request to arrive as a
  // form POST. Such a request therefore sees no session and is shown the login
  // screen even though one exists. The alternative is SameSite=None, which
  // requires Secure, which this service cannot be over http://localhost — so
  // the quirk stays, and wsfed.ts says so on the screen rather than leaving it
  // to look like a broken session.
  //
  // `via` names the screen the person actually used, and it is a parameter
  // rather than something derived here because this function cannot tell:
  // WS-Federation's sign-in screen calls it too, and a session started there is
  // indistinguishable afterwards from one started here — which is the point of
  // sharing the store, and is exactly why the admin console would otherwise
  // report every WS-Federation sign-in as an OIDC one. beginAuthentication()
  // carries it from the caller as `protocol`; it still defaults to OIDC, so a
  // call site that omits it says what it always meant. What the console and the
  // audit log call this sign-in. A function because there are THREE of them now
  // and the two-way conditional this replaced could not say the third: it asked
  // whether `hwk` was present, so a passwordless ceremony — amr ["hwk"] and no
  // password anywhere — was reported as a password sign-in with a security key
  // beside it, which is the one thing the two roles must not be confused about.
  //
  // **THERE ARE FOUR NOW (2026-09-10)**, because the authenticator app is a
  // second second factor. `otp` is RFC 8176's value and its registry entry
  // names RFC 4226 and RFC 6238 by number, so there was nothing to invent. The
  // reason this function exists at all is the reason it had to grow a branch
  // rather than letting `otp` fall through: the fall-through answers "sign-in
  // screen (password)", which for somebody who typed a password AND a code is a
  // report that quietly loses the second factor — the same defect the
  // passwordless ceremony had before this function replaced the conditional.
  //
  // **AND FIVE (2026-09-17, #38)**: `pop`, a wallet's presentation. Callers
  // that know better pass their own `method` (`vc_signin.ts` does), and this
  // branch is what a session row reads when nothing did.
  private methodPhraseFor(amr) {
    const { log } = this.deps;
    log.debug("Entering Authn.methodPhraseFor().");
    const factors = amr || [];
    const key = factors.indexOf('hwk') >= 0;
    const password = factors.indexOf('pwd') >= 0;
    const code = factors.indexOf('otp') >= 0;
    // A WALLET (2026-09-17, #38): RFC 8176's `pop`, proof of possession of a
    // key whose storage nobody here knows. Asked first because it is never
    // combined with the others — the sign-in that produces it asks for
    // nothing else.
    if (factors.indexOf('pop') >= 0) {
      log.debug("Leaving Authn.methodPhraseFor().");
      return 'a wallet (a verifiable presentation, proof of possession of ' +
             'the holder key)';
    }
    if (key && password) {
      log.debug("Leaving Authn.methodPhraseFor().");
      return 'sign-in screen (password and a security key)';
    }
    if (key) {
      log.debug("Leaving Authn.methodPhraseFor().");
      return 'sign-in screen (a security key alone, passwordless)';
    }
    if (code && password) {
      log.debug("Leaving Authn.methodPhraseFor().");
      return 'sign-in screen (password and a one-time code)';
    }
    if (code) {
      log.debug("Leaving Authn.methodPhraseFor().");
      // Unreachable today and deliberately written anyway: a one-time code can
      // never be a first factor here (see common/totp.ts), so this branch says
      // what would be true if that ever changed rather than reporting it as a
      // password sign-in.
      return 'sign-in screen (a one-time code alone)';
    }
    log.debug("Leaving Authn.methodPhraseFor().");
    return 'sign-in screen (password)';
  }

  setSessionObserver(fn) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.setSessionObserver().");
    if (typeof fn !== 'function') {
      log.error(errorCodes.tag('STS-AUTHN-0013') +
                'authn: setSessionObserver() was given something that is not ' +
                'a function, and was ignored. Nothing will be told when a ' +
                'session starts or ends.');
      log.debug("Leaving Authn.setSessionObserver(). Refused.");
      return;
    }
    sessionObserver = fn;
    log.info('authn: a session observer was installed; the Shared Signals ' +
             'transmitter will be told when a session is created, presented ' +
             'or ended.');
    log.debug("Leaving Authn.setSessionObserver(). Installed.");
  }

  private notifySession(kind, session, extra) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.notifySession(). " + kind);
    if (!sessionObserver || !session) {
      log.debug("Leaving Authn.notifySession(). Nobody is listening.");
      return;
    }
    try {
      sessionObserver(Object.assign({ kind: kind, session: session },
                                    extra || {}));
    } catch (e) {
      // Swallowed, and the reason is in the header: a transmitter that cannot
      // build an event must not turn a sign-in into a 500.
      log.error(errorCodes.tag('STS-AUTHN-0014') +
                'authn: the session observer threw on a "' + kind + '" and ' +
                'was ignored: ' + e.message);
    }
    log.debug("Leaving Authn.notifySession(). " + kind);
  }

  private sessionEndOnce(id, emit, onLost?) {
    const { log, clusterClaims, errorCodes } = this.deps;
    log.debug("Entering Authn.sessionEndOnce(). id=" + id);
    let shared = null;
    try {
      shared = require('../persistence/persistence').clusterStore();
    } catch (e) {
      log.debug("Caught in Authn.sessionEndOnce(): " + ((e && e.message) || e));
      shared = null;
    }
    if (!shared || !id) {
      emit();
      log.debug("Leaving Authn.sessionEndOnce(). One process; reported " +
                "inline.");
      return;
    }
    clusterClaims.claim({ scope: 'authn.session-end', value: String(id),
                          ttlMs: SESSION_END_CLAIM_TTL_MS })
      .then(function (answer) {
        if (answer.ok) {
          emit();
          return;
        }
        if (answer.reason === 'store') {
          log.warn(errorCodes.tag('STS-AUTHN-0192') + 'authn: whether ' +
                   'another process already reported the end of session ' + id +
                   ' could not be asked (' + (answer.why || '') + '); it is ' +
                   'reported here, and a receiver may be told twice.');
          emit();
          return;
        }
        log.debug('sessionEndOnce(): the end of session ' + id + ' was ' +
                  'already reported by another process.');
        if (typeof onLost === 'function') {
          onLost();
        }
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-AUTHN-0192') + 'authn: reporting the ' +
                  'end of session ' + id + ' failed: ' +
                  ((e && e.message) || e));
      });
    log.debug("Leaving Authn.sessionEndOnce(). Claiming.");
  }

  // ONE PLACE A SESSION ENDS BY RUNNING OUT, called by the two lazy lookups and
  // by the sweep. `via` says which, because "it expired and somebody came back
  // to find out" and "it expired and the sweep noticed" are the same act at
  // different moments and the audit log should not have to guess.
  private expireSession(store, id, session, via, why) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.expireSession(). id=" + id);
    // WHICH LIMIT RAN OUT (2026-09-12). An absolute expiry and an idle timeout
    // are both a policy ending a session nobody signed out of, so they are one
    // act here — but the audit row and the event say which, because "you were
    // away too long" and "your session is an hour old" are different things to
    // tell somebody, and a receiver may treat them differently.
    const idle = why === 'idle';
    store.delete(id);
    // THE BACK-CHANNEL LOGOUT TOKENS, ON AN EXPIRY TOO (2026-09-17, #36
    // follow-up) — while `oauth2.backchannelLogoutOnExpiry` is on, which it is
    // by default: Back-Channel Logout lets the provider notify whenever its
    // session ends, and a relying party never told of an expiry keeps a
    // session this service no longer vouches for. Planned and sent exactly as
    // a sign-out's are, through the same claim. FRONT-CHANNEL LOGOUT CANNOT
    // FOLLOW: it is an iframe in the person's browser, and an expiry — the
    // sweep, an idle timeout noticed on a later request — has no page to
    // draw one on.
    const planned = this.backchannelOnExpiry()
      ? this.planBackchannel(session, idle
          ? 'the session went idle (authn.sessionIdleTimeoutS)'
          : 'the session expired (authn.sessionLifetimeS)', 'expiry')
      : [];
    // THE REPORT ONCE FOR THE CLUSTER; the delete above is this process's own.
    // See sessionEndOnce().
    this.sessionEndOnce(id, function () {
      self.reportExpiry(id, session, via, idle);
      self.dispatchBackchannel(planned);
    });
    log.debug("Leaving Authn.expireSession().");
  }

  // OpenID Connect Session Management's library (#121), LAZILY for the
  // back-channel library's reason below, or null.
  private sessionManagementLibrary() {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionManagementLibrary().");
    let library = null;
    try {
      library = require('../oauth-oidc/session_management');
    } catch (e) {
      log.debug("Caught in Authn.sessionManagementLibrary(): " +
                ((e && e.message) || e));
      library = null;
    }
    log.debug("Leaving Authn.sessionManagementLibrary().");
    return library;
  }

  // The back-channel library, LAZILY (see dropSession()), or null in a
  // process that cannot load it.
  private backchannelLibrary() {
    const { log } = this.deps;
    log.debug("Entering Authn.backchannelLibrary().");
    let library = null;
    try {
      library = require('../oauth-oidc/backchannel_logout');
    } catch (e) {
      log.debug("Caught in Authn.backchannelLibrary(): " +
                ((e && e.message) || e));
      library = null;
    }
    log.debug("Leaving Authn.backchannelLibrary().");
    return library;
  }

  private backchannelOnExpiry() {
    const { log } = this.deps;
    log.debug("Entering Authn.backchannelOnExpiry().");
    const library = this.backchannelLibrary();
    log.debug("Leaving Authn.backchannelOnExpiry().");
    return !!(library && library.onExpiry());
  }

  // Plan a session's Logout Tokens; never throws (the library's plan() does
  // not, and a library that cannot be loaded plans nothing).
  private planBackchannel(session, via, trigger) {
    const { log } = this.deps;
    log.debug("Entering Authn.planBackchannel(). " + trigger);
    const library = this.backchannelLibrary();
    const planned = library && session
      ? library.plan(session, { via: via, trigger: trigger }) : [];
    log.debug("Leaving Authn.planBackchannel(). " + planned.length);
    return planned;
  }

  private dispatchBackchannel(planned) {
    const { log } = this.deps;
    log.debug("Entering Authn.dispatchBackchannel().");
    const library = this.backchannelLibrary();
    if (library && planned && planned.length) {
      library.dispatch(planned);
    }
    log.debug("Leaving Authn.dispatchBackchannel().");
  }

  // The audit row and the event for an expiry — what sessionEndOnce() lets out
  // once for the cluster. Split from expireSession() for that reason only.
  private reportExpiry(id, session, via, idle) {
    const { log, audit } = this.deps;
    log.debug("Entering Authn.reportExpiry(). id=" + id);
    audit.audit({
      action: 'session.end',
      outcome: 'success',
      actor: (session && session.user && session.user.username) || '',
      protocol: (session && session.via) || 'Authentication service',
      channel: 'none',
      target: id,
      summary: ((session && session.user &&
                 session.user.username) || 'somebody') +
               '\'s session ' + id + ' expired and was discarded',
      detail: {
        sessionId: id,
        // Not "signed out": nobody asked for this and no browser was involved.
        // A receiver told the session was established has to be able to tell
        // the two apart, which is what `initiating_entity` carries in the
        // event.
        reason: idle
          ? 'the session went unused for longer than authn.sessionIdleTimeoutS'
          : 'the session lifetime ran out',
        noticedBy: via,
        expiresAt: session && session.expires
          ? new Date(session.expires).toISOString() : ''
      }
    });
    // THE EVENT. `revoked` is CAEP's word for a session that is no longer good,
    // and an expiry is exactly that — the observer decides what to send and
    // this says what happened.
    //
    // `policy` and not `admin`, `user` or `system`, and the choice is the one
    // useful thing this notice carries. Nobody initiated it: a LIFETIME this
    // service configured ran out, which is what CAEP section 2 means by a
    // policy evaluation — `system` is a maintenance activity and the other two
    // name a person who did something. Without it the observer's rule would
    // have made this `user`, and a receiver would have been told the person
    // signed themselves out, which is not vague but false.
    this.notifySession('revoked', session, {
      via: via, byAdmin: false, expired: true,
      initiatingEntity: 'policy',
      reason: idle
        ? 'The session went unused for longer than this service\'s idle ' +
          'timeout. Nobody signed out — this service stopped honouring a ' +
          'session nobody was using.'
        : 'The session lifetime ran out. Nobody signed out — this service ' +
          'stopped honouring the session because its absolute expiry ' +
          'passed, and it is not extended by use.',
      req: null });
    log.debug("Leaving Authn.reportExpiry().");
  }

  sweepExpiredSessions() {
    const { realms, log } = this.deps;
    const self = this;
    log.debug("Entering Authn.sweepExpiredSessions().");
    const nowMs = Date.now();
    let gone = 0;
    realms.list().forEach(function (realm) {
      const store = sessions.realmMap(realm.id);
      if (!store || !store.size) {
        return;
      }
      // Collected first and deleted afterwards: expireSession() deletes from
      // the map being walked, and the observer it then calls is somebody else's
      // code that may reach back into this store.
      const expired = [];
      store.forEach(function (session, id) {
        if (!session) {
          return;
        }
        // The sweep's `<=` against a lookup's `<` is kept: at the exact
        // millisecond both are right, and this is not the place to move it.
        if (session.expires && session.expires <= nowMs) {
          expired.push([id, session, 'expired']);
          return;
        }
        const ended = self.sessionEnded(session, nowMs);
        if (ended) {
          expired.push([id, session, ended]);
        }
      });
      if (!expired.length) {
        return;
      }
      realms.run(realm, function () {
        expired.forEach(function (pair) {
          self.expireSession(store, pair[0], pair[1], 'the session sweep',
                             pair[2]);
          gone++;
        });
      });
    });
    if (gone) {
      log.info('authn: the session sweep ended ' + gone + ' expired ' +
               'session(s). Each one is an audit row and a CAEP ' +
               'session-revoked, which is the whole reason the sweep exists: ' +
               'an expiry noticed only when somebody comes back is an expiry ' +
               'nobody is ever told about.');
    }
    log.debug("Leaving Authn.sweepExpiredSessions(). " + gone + " ended.");
    return gone;
  }

  // ---------------------------------------------------------------------------
  // A SESSION THAT ALREADY EXISTED WAS PRESENTED AND HONOURED — which is single
  // sign-on, and is CAEP's `session-presented`.
  //
  // `oauth-oidc/oauth2.ts` calls this from the one branch that answers an
  // authorization request out of a session rather than by asking anybody who
  // they are. It is not called from `sessionOf()`, which looks like the obvious
  // place and is not: that function is called several times per request, so an
  // event there would be several events for one act.
  //
  // **THE FIRST PRESENTATION OF A BRAND-NEW SESSION IS THE SIGN-IN ITSELF AND
  // IS NOT REPORTED.** Every sign-in here ends with the browser coming back to
  // the authorization endpoint, which is a presentation — so without this the
  // simplest possible flow would emit `session-established` and
  // `session-presented` a few milliseconds apart, every time, and the event
  // that is supposed to mean "single sign-on happened" would mean nothing. The
  // flag is set by startSession() and spent here, so it is exact rather than a
  // time window: a session created by this service is presented once for free.
  // ---------------------------------------------------------------------------
  notePresented(session, via, req) {
    const { log } = this.deps;
    log.debug("Entering Authn.notePresented().");
    if (!session) {
      log.debug("Leaving Authn.notePresented(). No session.");
      return false;
    }
    if (session.firstPresentationIsTheSignIn) {
      session.firstPresentationIsTheSignIn = false;
      // SPENT IN THE STORE TOO (2026-09-14, #46), or a node whose copy still
      // says true swallows the next real presentation's event as well.
      this.noteSessionChanged(session);
      log.debug("Leaving Authn.notePresented(). The sign-in's own return " +
                "trip.");
      return false;
    }
    this.notifySession('presented', session, { via: via || 'OAuth 2.0 / OIDC',
      req: req || null });
    log.debug("Leaving Authn.notePresented(). Reported.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // WRITING THE COOKIE ON A RESPONSE THAT MAY NOT BE EXPRESS'S (2026-09-05).
  //
  // Every caller of `startSession()` handed it an express response until the
  // TLS listeners started signing people in on a verified client certificate.
  // Those two sockets (8443 and 9443) were `https.createServer()` with a
  // handler of their own, not this express app, so their `res` was a bare node
  // `ServerResponse`, which has `setHeader` and no `set`. They were DELETED on
  // 2026-09-16 and the certificate sign-in is now `GET /tls/sign-in`, an
  // express route on the main port — so no caller passes a bare response today.
  // The fallback stays because the failure it prevents is the one below.
  //
  // **THE SYMPTOM WITHOUT THIS WAS THE WORST HALF-STATE AVAILABLE**: the
  // session was created, entered the map, and appeared on `/admin/sessions` —
  // and then `res.set is not a function` threw on the next line, so the cookie
  // never went out and the person who had just signed in had no way to prove
  // it. A session nobody holds is worse than no session, because a global
  // sign-out then reports ending something that was never usable.
  //
  // One function rather than a branch at each of the two call sites, so that
  // the SET and the CLEAR cannot come to disagree about which mechanism they
  // use — clearing a cookie that was set by a different path is the bug
  // `clearSessionCookie()`'s own comment already warns about from the other
  // direction.
  private setCookieHeader(res, value) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.setCookieHeader().");
    if (typeof res.set === 'function') {
      res.set('Set-Cookie', value);
      log.debug("Leaving Authn.setCookieHeader().");
      return;
    }
    if (typeof res.setHeader === 'function') {
      res.setHeader('Set-Cookie', value);
      log.debug("Leaving Authn.setCookieHeader().");
      return;
    }
    // Neither: not a response at all. Logged rather than thrown, because every
    // caller of this is finishing a sign-in that has already succeeded and a
    // throw here would turn "the cookie could not be written" into "the request
    // failed".
    log.error(errorCodes.tag('STS-AUTHN-0015') +
              'authn: a session cookie could not be written — the response ' +
              'object has neither set() nor setHeader(). The session exists ' +
              'and the caller has not been told about it.');
    log.debug("Leaving Authn.setCookieHeader().");
  }

  // ---------------------------------------------------------------------------
  // ONE AUTHENTICATION EVENT: ONE ACT OF PROVING WHO SOMEBODY IS (2026-09-14).
  //
  // A session holds a LIST of these, and the reason is the whole of
  // `authn/CLAUDE.md`'s *What an authenticated identity is here*: a session is
  // the container, and a person may prove themselves to it more than once. The
  // fields are the names specifications already gave them — `at` is
  // `auth_time`, `amr` is RFC 8176's — so a projection into any protocol is a
  // mapping.
  //
  // `authority` is WHO VOUCHED: this service, a federation partner, or a
  // Kerberos principal's realm. It is EVIDENCE about the act and never the
  // identity, which is the rule that keeps a foreign artifact from becoming
  // this service's canonical form. `evidence` is the credential fingerprint a
  // keyed caller passes — a hash, never the value — and empty otherwise.
  //
  // `context` IS WHERE AND WITH WHAT (2026-09-22, #62 P0): the address the
  // act came from, a fingerprint of the browser's `User-Agent` (CAEP's
  // `fp_ua`, never the header), the connection's JA4 TLS fingerprint, and
  // which credential answered — the facts risk scoring compares one sign-in
  // against the last. Until then an event said HOW somebody proved who they
  // were and not one thing about from where, and `admin_stats.js` kept the
  // address on a separate list capped at fifty. Every field is '' when a door
  // has nothing to say — a Kerberos ticket arrives with no `User-Agent`, a
  // plain-HTTP port has no ClientHello — and an empty field is the truth
  // rather than a gap. See `eventContext()`.
  // ---------------------------------------------------------------------------
  private authenticationEvent(amr, acr, via, extra) {
    const { log, nowSec } = this.deps;
    log.debug("Entering Authn.authenticationEvent().");
    const detail = extra || {};
    let authority: Record<string, string> = { kind: 'local' };
    if (detail.federation && detail.federation.id) {
      authority = { kind: 'federation', id: String(detail.federation.id),
                    peer: String(detail.federation.peer || ''),
                    subject: String(detail.federation.subject || '') };
    } else if (detail.protocol === 'Kerberos v5' && detail.presented) {
      authority = { kind: 'kerberos', principal: String(detail.presented) };
    }
    log.debug("Leaving Authn.authenticationEvent(). authority=" +
              authority.kind);
    return {
      at: nowSec(),
      amr: (amr || []).slice(),
      acr: acr || '',
      via: via || 'OAuth 2.0 / OIDC',
      authenticated: detail.authenticated !== false,
      authority: authority,
      evidence: detail.key ? String(detail.key) : '',
      context: this.eventContext(detail)
    };
  }

  // ---------------------------------------------------------------------------
  // WHERE AN AUTHENTICATION CAME FROM, AND WITH WHAT (#62 P0, 2026-09-22).
  //
  // The request is the caller's `detail.request` where it passed one, and
  // otherwise the one the audit log's ambient source holds — which is every
  // HTTP door, including the ones (federation, SPNEGO, the wallet) that hand
  // `startSession()` a detail without it. The address comes from the audit
  // source for the reason `audit.currentAddress()` gives: `/admin/users` and
  // the audit log already answer from it, and a third answer to "where did
  // this sign-in come from" would be one that could disagree.
  //
  // `detail.credential` is what a screen knows about the credential that
  // answered: `{ kind, id, aaguid, backupEligible, backupState }`. The id is
  // kept as a fingerprint only (`stsCrypto.credentialFingerprint()`); the
  // AAGUID is a model number, not an identifier, and is kept as it is.
  // ---------------------------------------------------------------------------
  private eventContext(detail) {
    const { log, audit, stsCrypto, clientHello } = this.deps;
    log.debug("Entering Authn.eventContext().");
    const req = detail.request || audit.currentRequest();
    const headers = (req && req.headers) || {};
    const hello = req ? clientHello.of(req) : null;
    const given = detail.credential || {};
    const credential: Record<string, any> = {};
    if (given.kind) {
      credential.kind = String(given.kind);
    }
    if (given.id) {
      credential.fingerprint = stsCrypto.credentialFingerprint(given.id);
    }
    if (given.aaguid) {
      credential.aaguid = String(given.aaguid);
    }
    if (typeof given.backupEligible === 'boolean') {
      credential.backupEligible = given.backupEligible;
    }
    if (typeof given.backupState === 'boolean') {
      credential.backupState = given.backupState;
    }
    // THE BROWSER FINGERPRINT (#62 P6), where the realm asked for one and
    // the sign-in form carried it — as a digest, like the User-Agent: the
    // value itself is personal data and is never kept.
    let fp = '';
    if (this.fingerprinting() && req && req.body) {
      // The raw body, parsed here only when a fingerprint could be in it.
      const posted: any = typeof req.body === 'string'
        ? this.deps.parseBody(req) : req.body;
      fp = /^[A-Za-z0-9]{8,64}$/.test(String((posted || {}).device_fp || ''))
        ? String(posted.device_fp) : '';
    }
    log.debug("Leaving Authn.eventContext().");
    return {
      address: String(detail.address || audit.currentAddress() || ''),
      uaFingerprint: stsCrypto.userAgentFingerprint(
        headers['user-agent'] || ''),
      ja4: hello ? hello.ja4 : '',
      // What risk compares: the JA4 with the resumption extensions left out
      // (`tls/client_hello.ts`'s `stack()`), or a resumed connection reads
      // as a new TLS client.
      tlsStack: hello ? (hello.stack || hello.ja4) : '',
      device: fp ? stsCrypto.credentialFingerprint('device:' + fp) : '',
      credential: credential
    };
  }

  // When a session BEGAN, in milliseconds: its first authentication event.
  // `authTime` stopped meaning that on 2026-09-14 — it is the MOST RECENT
  // authentication now, and moves on every re-authentication — so a list that
  // drew it as "signed in" would show a session an hour old as a minute old.
  // A row with no events (older than them, or not a sign-on at all) falls back
  // to `authTime`, which for such a row still is the only authentication.
  sessionStartedAt(session) {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionStartedAt().");
    const first = session && Array.isArray(session.events) &&
                  session.events.length ? session.events[0] : null;
    log.debug("Leaving Authn.sessionStartedAt().");
    return ((first && first.at) || (session && session.authTime) || 0) * 1000;
  }

  // HOW A PERSON IS SIGNED IN, READ THROUGH A RELYING-PARTY SESSION
  // (2026-09-14).
  //
  // A console or portal session copies `authTime`, `amr` and `acr` out of the
  // ID Token it was made from, and those stay what the relying party was TOLD —
  // `common/oidc_rp.ts`'s renewal compares against that `authTime`, so it is
  // never rewritten. But a re-authentication on the sign-on session behind it
  // adds an event there and nothing here, so a page that describes the PERSON'S
  // sign-in from the relying-party copy shows a step-up only after the next
  // code flow. This answers from the sign-on session while it is live, and from
  // the session itself otherwise (a sign-on session, a parent that ran out, a
  // process where the parent is in no store this one can read).
  signOnFactsFor(session) {
    const { realms, log } = this.deps;
    log.debug("Entering Authn.signOnFactsFor().");
    let source = session || {};
    let fromParent = false;
    if (session && session.derivedFrom) {
      const parentRealm = String(session.derivedFromRealm ||
                                 realms.currentId());
      const parent = sessions.realmMap(parentRealm).get(session.derivedFrom);
      if (parent && !this.sessionEnded(parent)) {
        source = parent;
        fromParent = true;
      }
    }
    const events = Array.isArray(source.events) ? source.events.length : 1;
    log.debug("Leaving Authn.signOnFactsFor(). fromParent=" + fromParent);
    return {
      startedAt: this.sessionStartedAt(source),
      authTime: (source.authTime || 0) * 1000,
      amr: (source.amr || []).slice(),
      acr: source.acr || '',
      authentications: events + (source.eventsDropped || 0),
      fromParent: fromParent
    };
  }

  // Whether a session's person and the one signing in are the same. The SUBJECT
  // where both have one — `urn:uuid:<entryUUID>`, which a rename does not
  // change and a re-created person does not inherit — and the username
  // otherwise, which is every process with no directory, where nobody has a
  // subject and two empty strings must not make two people one.
  private sameIdentity(user, username) {
    const { log, helpers } = this.deps;
    log.debug("Entering Authn.sameIdentity().");
    const theirs = String((user && user.sub) || '');
    const asked = helpers.subjectForName(username);
    if (theirs && asked) {
      // An ALIAS of that entry's subject is that entry too: a session made on
      // a worker that lost a create race carries the value the directory now
      // keeps as an alias (`ldap_server.js`'s `mergeCreateRace()`).
      const aliased = theirs !== asked &&
        helpers.subjectForName(helpers.nameForSubject(theirs)) === asked;
      log.debug("Leaving Authn.sameIdentity(). By subject.");
      return theirs === asked || aliased;
    }
    log.debug("Leaving Authn.sameIdentity(). By name.");
    return !theirs && !asked &&
           String((user && user.username) || '') === String(username || '');
  }

  // ---------------------------------------------------------------------------
  // THE SAME PERSON, AGAIN, ON THE SESSION THEY ALREADY HOLD (2026-09-14).
  //
  // What a re-authentication DOES, in the order it does it, and the list of
  // what it deliberately does NOT do is the longer and more important half:
  //
  //   * it APPENDS an event, and reassigns `amr`, `acr`, `authTime` and `via`
  //     to the new event's — never editing them in place;
  //   * it ROTATES the cookie handle, since a re-authentication is a change of
  //     privilege, and the `sid` does not move;
  //   * it records the authentication (`recordAuthentication()`), because it is
  //     one — the directory's second-factor flags and `/admin/users` count it;
  //   * it writes `session.reauthenticate`, not `session.start`;
  //   * it tells the observer `reauthenticated` with what the session said
  //     BEFORE, and `ssf/caep.ts` decides whether that is an
  //     `assurance-level-change` (only when `acr` moved);
  //   * it sets `firstPresentationIsTheSignIn`, because the browser is about to
  //     come back to the protocol that asked, and that trip is this act and not
  //     single sign-on.
  //
  // It does NOT end the session, end the sessions derived from it, forget the
  // relying parties it answered, revoke a refresh token, emit
  // `session-revoked` or `session-established`, or move `expires` — a sign-on
  // session's lifetime is absolute (`logout.ts`'s SESSION_EXPIRY_RULES) and
  // proving yourself again is not a reason to extend it.
  //
  // The issuance gate has already been asked by the caller, `startSession()`,
  // because the re-authentication may be for a different application than the
  // one the session began with.
  // ---------------------------------------------------------------------------
  private reauthenticateSession(res, session, username, amr, acr, via, extra) {
    const { log, stats, audit } = this.deps;
    log.debug("Entering Authn.reauthenticateSession(). sid=" + session.id);
    const previous = {
      amr: (session.amr || []).slice(),
      acr: session.acr || '',
      authTime: session.authTime || 0,
      via: session.via || ''
    };
    const event = this.authenticationEvent(amr, acr, via, extra);
    // A row persisted before events existed has none. It is given one standing
    // for the authentication it recorded, so the list is never missing its
    // beginning.
    let events = Array.isArray(session.events) && session.events.length
      ? session.events.slice()
      : [{ at: previous.authTime, amr: previous.amr, acr: previous.acr,
           via: previous.via, authenticated: true,
           authority: { kind: 'unrecorded' }, evidence: '',
           context: { address: '', uaFingerprint: '', ja4: '',
                      credential: {} } }];
    events.push(event);
    if (events.length > MAX_SESSION_EVENTS) {
      const dropped = events.length - MAX_SESSION_EVENTS;
      events = [events[0]].concat(events.slice(dropped + 1));
      session.eventsDropped = (session.eventsDropped || 0) + dropped;
    }
    session.events = events;
    session.amr = event.amr.slice();
    session.acr = event.acr;
    session.authTime = event.at;
    session.via = event.via;
    session.lastSeenAt = Date.now();
    session.firstPresentationIsTheSignIn = true;
    this.bindPartnerSession(session, extra);
    const cookieValue = this.mintSessionHandle(session);
    sessions.set(session.id, session);
    if (extra.cookie !== false) {
      this.setCookieHeader(res, this.sessionCookieLine(SESSION_COOKIE,
                                                       cookieValue));
    }
    const statsExtra = Object.assign({}, extra);
    delete statsExtra.authenticated;
    // The risk assessment and what was decided on it (#62 P3) are recorded
    // on the assessment, not on the authentication's row.
    delete statsExtra.risk;
    delete statsExtra.riskDecision;
    delete statsExtra.riskStepUp;
    // A federation partner's session and its bound (#167) are facts about
    // the SESSION, recorded on it; the authentication's row names the
    // relationship through `federation` already.
    delete statsExtra.fedPartnerSession;
    delete statsExtra.sessionNotOnOrAfter;
    stats.recordAuthentication(Object.assign({
      presented: username, protocol: event.via,
      method: this.methodPhraseFor(event.amr),
      sub: session.user.sub, amr: event.amr, acr: event.acr,
      note: 'A re-authentication on a session this person already held.'
    }, statsExtra, { sessionId: session.id }));
    audit.audit({
      action: 'session.reauthenticate',
      actor: username,
      protocol: event.via,
      channel: 'http',
      target: session.id,
      summary: username + ' re-authenticated through ' + event.via +
               ' on session ' + session.id + ' (acr ' +
               (previous.acr || 'none') + ' to ' + (event.acr || 'none') + ')',
      detail: {
        sessionId: session.id,
        sub: session.user.sub,
        amr: event.amr.join(', '),
        acr: event.acr,
        previousAmr: previous.amr.join(', '),
        previousAcr: previous.acr,
        authTime: event.at,
        events: session.events.length + (session.eventsDropped || 0),
        authority: event.authority.kind,
        // Unchanged, and said so: a re-authentication is not an extension.
        expiresAt: new Date(session.expires).toISOString()
      }
    });
    this.notifySession('reauthenticated', session, { via: event.via,
      previous: previous, req: (res && res.req) || null });
    this.assessRisk(session, event, event.via, extra);
    log.debug("Leaving Authn.reauthenticateSession(). " +
              session.events.length +
              " event(s).");
    return session;
  }

  // ---------------------------------------------------------------------------
  // A FEDERATION PARTNER'S SESSION, AND THE BOUND IT PUTS ON THIS ONE (#167).
  //
  // `detail.fedPartnerSession` is what `federation/federation_sp.ts` knows
  // about the PARTNER's session this sign-in came out of — the relationship,
  // the SAML NameID and SessionIndex, the OpenID Connect `iss`, `sub` and
  // `sid` — and it is kept ON THE SESSION so that a partner's sign-out can
  // find the one session it names (`federation/federation_slo.ts`), on any
  // node: this store is persisted and replicated, so a second index beside it
  // would be a second answer to which session a partner meant. A later
  // federated sign-in on the same session replaces it; a local
  // re-authentication leaves it, because the partner's session did not end.
  //
  // `detail.sessionNotOnOrAfter` is the partner's SAML 2.0
  // `AuthnStatement/@SessionNotOnOrAfter`, as epoch ms: the instant at which
  // "the session between the principal ... and the SAML authority issuing
  // this statement MUST be considered ended" (saml-core-2.0-os section
  // 2.7.2). It can only SHORTEN this session — `expires` becomes the earlier
  // of the two — and it is the absolute expiry `sessionEnded()` already
  // reads, so every reader, the sweep and the lazy lookups honour it with no
  // path of their own. An ID Token's `exp` is NOT such a bound (OpenID
  // Connect Core section 2 makes it the token's lifetime, not the session's)
  // and nothing passes one.
  // ---------------------------------------------------------------------------
  private bindPartnerSession(session, extra) {
    const { log } = this.deps;
    log.debug("Entering Authn.bindPartnerSession().");
    const detail = extra || {};
    if (detail.fedPartnerSession && typeof detail.fedPartnerSession ===
        'object') {
      session.fedPartnerSession = Object.assign({}, detail.fedPartnerSession);
    }
    const bound = Number(detail.sessionNotOnOrAfter) || 0;
    if (bound > 0 && (!session.expires || bound < session.expires)) {
      session.expires = bound;
      session.expiresBoundBy = 'SessionNotOnOrAfter';
      log.info('authn: session ' + session.id + ' ends at ' +
               new Date(bound).toISOString() + ', the partner\'s ' +
               'SessionNotOnOrAfter, which is earlier than its own lifetime.');
    }
    log.debug("Leaving Authn.bindPartnerSession().");
  }

  // ---------------------------------------------------------------------------
  // EVERY SIGN-IN IS ASSESSED FOR RISK, AND NOTHING WAITS FOR IT (#62 P2,
  // 2026-09-23). OBSERVE ONLY.
  //
  // A session just established or re-authenticated is handed to
  // `risk/risk_engine.ts` with its event's context and the request's
  // User-Agent (which the engine reads and drops). Not awaited, and never a
  // reason a sign-in fails: the engine records what it found and decides
  // nothing until P3. Two kinds of session are not assessed: a keyed API
  // caller (SCIM, SPIRE — a credential per request, not a person signing
  // in) and an unauthenticated one (nobody to assess). Required LAZILY: the
  // risk modules are built by the composition root long after this file.
  // ---------------------------------------------------------------------------
  private assessRisk(session, event, via, extra) {
    const { log, audit, realms } = this.deps;
    log.debug("Entering Authn.assessRisk().");
    const detail = extra || {};
    if (!session || !session.user || !session.user.sub || detail.key ||
        detail.authenticated === false) {
      log.debug("Leaving Authn.assessRisk(). Not a person signing in.");
      return;
    }
    // ASSESSED ALREADY, BEFORE THE SESSION (#62 P3): the door handed the
    // assessment in and the policy decided on it. Only a door that assessed
    // nothing has its sign-in assessed here, after the fact, as in P2.
    if (detail.risk !== undefined) {
      log.debug("Leaving Authn.assessRisk(). Assessed before the session.");
      return;
    }
    const req = detail.request || audit.currentRequest();
    const headers = (req && req.headers) || {};
    try {
      require('../risk/risk_engine').assess({
        realm: realms.currentId(), subject: session.user.sub,
        username: String(session.user.username || ''),
        sessionId: session.id, door: String(via || event.via || ''),
        clientId: String(detail.application || ''),
        context: event.context || {},
        userAgent: String(headers['user-agent'] || '') });
    } catch (e) {
      log.debug("Caught in Authn.assessRisk(): " + ((e && e.message) || e));
      // The risk modules are not loaded in this process (a test that loads
      // this file alone): there is nothing to assess with, and the sign-in
      // stands.
    }
    log.debug("Leaving Authn.assessRisk().");
  }

  // ---------------------------------------------------------------------------
  // THE RISK ENGINE, or null (#62 P3). Required LAZILY, as `assessRisk()`
  // does and for its reason: the risk modules are built by the composition
  // root (18j) long after this file, and nothing may require one of them
  // before the root has deferred it. A process without them — a test that
  // loads this file alone — has no risk to decide on.
  // ---------------------------------------------------------------------------
  private riskEngine(): any {
    const { log } = this.deps;
    log.debug("Entering Authn.riskEngine().");
    try {
      log.debug("Leaving Authn.riskEngine().");
      return require('../risk/risk_engine');
    } catch (e) {
      log.debug("Caught in Authn.riskEngine(): " + ((e && e.message) || e));
      // Not in this process: no risk, and the roles decide.
      log.debug("Leaving Authn.riskEngine(). None.");
      return null;
    }
  }

  // What was decided, written onto the assessment — see the engine's
  // `settle()`. Nothing to write for a door that assessed nothing.
  private settleRisk(risk: any, outcome: any): void {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.settleRisk().");
    const engine = risk && risk.assessmentId ? this.riskEngine() : null;
    if (engine) {
      engine.settle(realms.currentId(), risk.assessmentId, outcome);
    }
    log.debug("Leaving Authn.settleRisk().");
  }

  // ---------------------------------------------------------------------------
  // A LIVE SESSION WHOSE CONTEXT MOVED IS ASSESSED AGAIN (#62 P4) —
  // continuous evaluation. Every request that presents a session is compared
  // with the authentication it rests on: the User-Agent's fingerprint, the
  // TLS client (JA4) and the network (/24 or /48). A cookie replayed from
  // another machine changes at least one. When one moved, the session is
  // assessed in the background (`phase: 'session'` — scored against the
  // person's history and not added to it), and the answer becomes the
  // session's risk, so the NEXT issuance on it is decided on where it is
  // now; a change of the person's level is answered by the risk-response
  // policy. Nothing here waits: the request that noticed is answered on the
  // risk the session already had.
  //
  // A HOT PATH — every request that carries a session — so it compares three
  // strings and stops, and assesses a given context once
  // (`riskDriftKey`), not on every request made from it.
  // ---------------------------------------------------------------------------
  private noticeRiskDrift(session, req) {
    const { realms, log } = this.deps;
    const events = session && Array.isArray(session.events) ? session.events
                                                            : [];
    const last = events.length ? events[events.length - 1] : null;
    if (!req || !session.risk || session.credentialKey ||
        session.authenticated === false || !last || !last.context ||
        !session.user || !session.user.sub) {
      return;
    }
    const engine = this.riskEngine();
    if (!engine) {
      return;
    }
    // Both helpers below are on this hot path, and no Entering/Leaving pair
    // on either would say anything a reader of the log could use.
    let prefixOf = function (address: string): string {
      return address;
    };
    try {
      prefixOf = require('../risk/risk_store').prefixOf;
    } catch (e) {
      log.debug("Caught in Authn.noticeRiskDrift(): " +
                ((e && e.message) || e));
      // No risk store in this process: the whole address stands in for
      // its network, which only makes the comparison stricter.
    }
    const now = this.eventContext({ request: req });
    const keyOf = function (c: any): string {
      return [String(c.uaFingerprint || ''),
              String(c.tlsStack || c.ja4 || ''),
              c.address ? prefixOf(String(c.address)) : ''].join('|');
    };
    const is = keyOf(now);
    if (is === keyOf(last.context) || is === session.riskDriftKey) {
      return;
    }
    log.debug("Entering Authn.noticeRiskDrift(). " + session.id);
    const moved = [];
    // A DIFFERENT DEVICE IS A DIFFERENT BROWSER OR OPERATING SYSTEM, not a
    // different User-Agent string: a browser that updated itself mid-session
    // sends a new one. Where the session knows its sign-in's device family,
    // that is compared; a session from before P4 has only the fingerprint.
    if (String(now.uaFingerprint || '') !==
        String(last.context.uaFingerprint || '')) {
      const known = session.risk.device;
      const nowFamily = known ? engine.familyOf(engine.deviceOf(
        String((req.headers || {})['user-agent'] || ''))) : null;
      if (!known || nowFamily.browser !== known.browser ||
          nowFamily.os !== known.os) {
        moved.push('device');
      }
    }
    if (String(now.tlsStack || now.ja4 || '') !==
        String(last.context.tlsStack || last.context.ja4 || '')) {
      moved.push('TLS client');
    }
    if (is.split('|')[2] !== keyOf(last.context).split('|')[2]) {
      moved.push('network');
    }
    session.riskDriftKey = is;
    sessions.set(session.id, session);
    if (!moved.length) {
      // Only the device's version moved: remembered, so it is not
      // compared again, and not assessed.
      log.debug("Leaving Authn.noticeRiskDrift(). A new version of the " +
                "same device.");
      return;
    }
    const self = this;
    const headers = req.headers || {};
    engine.assess({
      realm: realms.currentId(), subject: String(session.user.sub),
      username: String(session.user.username || ''), sessionId: session.id,
      door: 'a live session whose ' + moved.join(' and ') + ' changed',
      clientId: '', context: now, phase: 'session',
      userAgent: String(headers['user-agent'] || '') })
      .then(function (assessment: any): void {
        if (assessment) {
          self.adoptSessionRisk(session.id, engine.riskOf(assessment));
        }
      }, function (e: any): void {
        log.debug("Caught in Authn.noticeRiskDrift(): " +
                  ((e && e.message) || e));
        // assess() never rejects; the session keeps the risk it had.
      });
    log.info('authn: session ' + session.id + ' of "' +
             session.user.username + '" was presented with its ' +
             moved.join(' and ') + ' changed; assessing it again.');
    log.debug("Leaving Authn.noticeRiskDrift().");
  }

  // -------------------------------------------------------------------------
  // A SESSION'S RISK, REPLACED (#62 P4) — by a re-assessment of its moved
  // context, or by the `risk.rescore` job. In the ambient realm; written
  // through the store so every process sees it. A session that has ended
  // since is left ended.
  // -------------------------------------------------------------------------
  adoptSessionRisk(id: string, risk: any): boolean {
    const { log } = this.deps;
    log.debug("Entering Authn.adoptSessionRisk(). " + id);
    const session = sessions.get(String(id || ''));
    if (!session || !risk || this.sessionEnded(session)) {
      log.debug("Leaving Authn.adoptSessionRisk(). No live session.");
      return false;
    }
    session.risk = risk;
    sessions.set(session.id, session);
    log.debug("Leaving Authn.adoptSessionRisk(). " + risk.level + ".");
    return true;
  }

  // Every live, person-held session that carries a risk, in every realm —
  // what the `risk.rescore` job re-checks (#62 P4). `realm` is the realm
  // object `realms.run()` takes.
  sessionsForRisk(): any[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Authn.sessionsForRisk().");
    const out = [];
    realms.list().forEach(function (realm) {
      const store = sessions.realmMap(realm.id);
      if (!store || !store.size) {
        return;
      }
      store.forEach(function (session, id) {
        if (session && session.risk && !session.credentialKey &&
            session.authenticated !== false && !self.sessionEnded(session)) {
          out.push({ realm: realm, id: id, session: session });
        }
      });
    });
    log.debug("Leaving Authn.sessionsForRisk(). " + out.length + ".");
    return out;
  }

  // ---------------------------------------------------------------------------
  // A SURFACE'S OWN SESSIONS FOR ONE PERSON, ENDED (#62, 2026-09-22) — what
  // the console or the portal does with a received signal the
  // `signal-response` policy permits (`ssf/ssf_receivers.ts`). Only the
  // relying-party sessions `surfaceId` holds (`admin` or `portal`,
  // `common/oidc_rp.ts`'s ids), only those that came from `fromRealm` — the
  // realm the event arrived in; the console keeps every realm's sessions in
  // the default realm's partition, and `alice` in one realm is not `alice`
  // in another — and only those whose person `about(user)` says the event
  // names. Each ends through dropSession(), so it is audited and announced as
  // any sign-out is. Answers how many ended.
  // ---------------------------------------------------------------------------
  endRelyingPartySessions(surfaceId: string, fromRealm: string,
                          about: (user: any, session?: any) => boolean,
                          via: string): number {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Authn.endRelyingPartySessions(). " + surfaceId);
    const partition = surfaceId === 'admin' ? realms.DEFAULT_ID : fromRealm;
    const store = sessions.realmMap(partition);
    const doomed: string[] = [];
    if (store) {
      store.forEach(function (session, id) {
        if (session && session.rpSurface === surfaceId &&
            String(session.derivedFromRealm || partition) === fromRealm &&
            session.user && about(session.user, session)) {
          doomed.push(id);
        }
      });
    }
    doomed.forEach(function (id: string): void {
      realms.run(realms.get(partition), function () {
        self.dropSession(id, via, false);
      });
    });
    log.debug("Leaving Authn.endRelyingPartySessions(). " + doomed.length +
              " ended.");
    return doomed.length;
  }

  // Whether this realm fingerprints the browser at the sign-in screen (#62
  // P6, `risk.fingerprinting`, off by default). Asked for every drawing of
  // the screen, which is a hot path, so no Entering/Leaving pair.
  private fingerprinting(): boolean {
    return this.deps.config.value('risk.fingerprinting') === true;
  }

  // ---------------------------------------------------------------------------
  // A SIGN-IN ASSESSED BEFORE ITS SESSION EXISTS (#62 P3). Every door that
  // authenticates a PERSON calls this once the credential has verified and
  // before `startSession()`, and hands the answer in as `detail.risk`: the
  // issuance policy then decides the session on it, and the session carries
  // it for every token issued on it. `detail` is what the door would hand
  // `startSession()` — `request`, `application`, `credential` — and the
  // event's context is built from it exactly as the session's will be.
  //
  // Answers the assessment, or null: a keyed API caller or an
  // unauthenticated session is not a person signing in, a name with no
  // entry has no subject to assess, and a failure in the engine is never a
  // failed sign-in (STS-RISK-0013). Null means "no facts", and the policy
  // decides on roles.
  // ---------------------------------------------------------------------------
  async assessSignIn(req: any, username: string, via: string,
                     detail?: any): Promise<any> {
    const { log, userFor, realms } = this.deps;
    log.debug("Entering Authn.assessSignIn(). username=" + username);
    const d = Object.assign({}, detail || {}, { request: req });
    if (d.key || d.authenticated === false) {
      log.debug("Leaving Authn.assessSignIn(). Not a person signing in.");
      return null;
    }
    const user: any = userFor(username) || {};
    const engine = this.riskEngine();
    if (!user.sub || !engine) {
      log.debug("Leaving Authn.assessSignIn(). Nobody to assess.");
      return null;
    }
    const headers = (req && req.headers) || {};
    const assessment = await engine.assess({
      realm: realms.currentId(), subject: String(user.sub),
      username: String(username), sessionId: '',
      door: String(via || ''), clientId: String(d.application || ''),
      context: this.eventContext(d),
      userAgent: String(headers['user-agent'] || '') });
    log.debug("Leaving Authn.assessSignIn(). " +
              (assessment ? assessment.level : 'Not assessed.'));
    return assessment;
  }

  // ---------------------------------------------------------------------------
  // A REFUSAL SAYS WHY ON THE CALLER'S OWN `detail` (2026-09-22, #62 P0).
  //
  // A refusal is `null`, and the reason it was refused used to stay in here:
  // on the audit row and in the log, and nowhere a caller could read it. So
  // the one screen that looked at a null — `refusedAsDisabled()` — had to ask
  // the directory again whether the account was disabled, and treated every
  // other refusal as not one, returning the browser to a caller whose request
  // sent it straight back to the sign-in screen. Three callers did not look
  // at the null at all.
  //
  // Each refusal below now writes `refusedWith` (its error code) and, for
  // the issuance policy, `refusedWhy` (the sentence the password screen
  // already shows) onto the `detail` the caller passed, which is an object
  // the caller built and still holds. A return value that carried the reason
  // would have changed the type every caller tests, and a null is what the
  // callers that wrap this in a `try` must go on seeing — the reason the
  // policy branch below gives for never throwing. A caller that passed no
  // `detail` has nothing to read and loses nothing.
  //
  // `refusedSession()` is the screen's reader. The risk decision (#62) will
  // refuse here too and say why the same way.
  // ---------------------------------------------------------------------------
  startSession(res, username, amr, acr, via, detail) {
    const { log, randomId, userFor, helpers, stats, gate, audit,
      errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Authn.startSession(). username=" + username + ", acr=" +
              acr);
    const extra = detail || {};
    // -------------------------------------------------------------------------
    // A DISABLED ACCOUNT GETS NO SESSION (2026-09-17, #36 follow-up), from any
    // door, in any mode — FIRST, before the browser's previous session is
    // touched, before the issuance gate (which the password screen skips with
    // `gated: true`) and before the keyed "credential presented again" branch
    // (which would otherwise touch a SCIM or SPIFFE caller's row rather than
    // refuse it). Every door that creates a session reaches this line: the
    // sign-in screen and its three second-factor steps, the enrolment step,
    // federation, SPNEGO, `GET /tls/sign-in`, the wallet door, WS-Trust and
    // the keyed API callers. A refusal is `null`, as the issuance gate's is.
    // An unauthenticated session names nobody's account and is not asked.
    // -------------------------------------------------------------------------
    if (extra.authenticated !== false &&
        this.deps.accountState.isDisabled(username)) {
      log.info('authn: a session for "' + username + '" was REFUSED at the ' +
               (via || 'sign-in') + ' door: the account is disabled.');
      audit.audit({
        action: 'session.refuse', actor: String(username || ''),
        errorCode: 'STS-AUTHN-0201',
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused at the ' +
                 (via || 'sign-in') + ' door: the account is disabled',
        detail: { why: 'pwdAccountLockedTime is set on the entry',
                  application: String(extra.application || '') }
      });
      extra.refusedWith = 'STS-AUTHN-0201';
      log.debug("Leaving Authn.startSession(). The account is disabled.");
      return null;
    }
    // -------------------------------------------------------------------------
    // END WHATEVER SESSION THE BROWSER WAS ALREADY ON (2026-09-06). OWASP A07.
    //
    // **SESSION FIXATION WAS ALREADY PREVENTED AND THIS IS THE OTHER HALF.**
    // The id below is freshly random on every call, so an attacker who plants a
    // cookie value does not end up holding the session that authentication
    // creates — that has been true since this function was written and is worth
    // saying, because it is the half people check for.
    //
    // What was NOT true is that the OLD session ended. A browser that signed in
    // as one person and then as another left the first session alive in the
    // map: unreachable by that browser, still valid to anything holding its id,
    // and still listed as live on /admin/sessions. Every sign-in is a privilege
    // change, and a privilege change that leaves the previous session usable is
    // the vulnerability whether or not the new id is random.
    //
    // `detail.request` is how a caller says which browser this is. A caller
    // that omits it — a Kerberos ticket, a federated assertion arriving without
    // the cookie — ends nothing, which is correct: there is no previous session
    // of THIS browser to end, and guessing one from the username would sign
    // people out of other devices.
    // ---------------------------------------------------------------------
    // THE ARRIVAL SESSION IS READ BEFORE THE PREVIOUS ONE IS ENDED, and the
    // order is the whole of it.
    //
    // The block below ends whatever session the browser was on, because a
    // sign-in is a privilege change and leaving the old one usable would be a
    // second live session for the same browser. An ARRIVAL session is on that
    // cookie too — so with the lookup after this block it found nothing, every
    // sign-in minted a fresh id, and the arrival row was left behind as a
    // stray anonymous session that nobody would ever present again. It looked
    // like the upgrade simply did not work, which is what it was.
    // ---------------------------------------------------------------------
    const arrived = extra.request ? this.arrivalSessionOf(extra.request) : null;
    // -------------------------------------------------------------------------
    // THE SAME PERSON AGAIN IS A RE-AUTHENTICATION, NOT A REPLACEMENT
    // (2026-09-14).
    //
    // Everything below this block used to treat a sign-in on a browser that
    // already held a session as a change of person, whoever it was. For a
    // DIFFERENT person that is right and it is kept. For the SAME person — RFC
    // 9470 step-up, an elapsed `max_age`, `prompt=login`, SAML `ForceAuthn` —
    // it ended a session nobody had signed out of: the portal and console
    // sessions derived from it died with it, the relying parties a sign-out has
    // to reach were forgotten, CAEP was told `session-revoked`, and in RFC 9700
    // mode every refresh token issued on it was revoked, so one client asking
    // for `mfa` took another client's refresh token away. `authn/CLAUDE.md`,
    // *What an authenticated identity is here*, carries the probe that measured
    // it.
    //
    // **"THE SAME PERSON" IS THE SAME `sub`**, which today is the same username
    // exactly. `identityKeyOf()` is deliberately not used: it folds `alice` and
    // `alice@SOME.REALM` together for the console's lists, and a federated or
    // foreign-realm `alice` being treated as a re-authentication of the local
    // one would hand one person's session to another.
    //
    // It needs a SIGNED-IN session on both sides. An arrival session is
    // upgraded below rather than appended to; the anonymous principal has no
    // authentication to add to; a keyed API caller has no browser and no
    // cookie. A relying-party row cannot arrive here at all, because its cookie
    // is not `sts_session`.
    const current = extra.request ? this.cookieSession(extra.request,
                                                       SESSION_COOKIE) : null;
    const reauthenticating = !!(current && !extra.key &&
      extra.authenticated !== false &&
      current.session.chosen !== false &&
      current.session.authenticated !== false &&
      !current.session.rpSurface && !current.session.credentialKey &&
      !this.sessionEnded(current.session) &&
      current.session.user && this.sameIdentity(current.session.user,
                                                username));
    if (extra.request) {
      const previous = current ? current.id : '';
      // AN ARRIVAL SESSION IS NOT ENDED, it is upgraded — ending it would write
      // a sign-out audit row and a CAEP `session-revoked` for a session nobody
      // was ever in, every time anybody signed in. Nor is a session the same
      // person is re-authenticating on.
      if (previous && !reauthenticating &&
          !(arrived && arrived.id === previous)) {
        log.info('authn: ending the session this browser was already on (' +
                 previous + ') because a new sign-in is replacing it. Every ' +
                 'sign-in is a privilege change and the old session must not ' +
                 'outlive it.');
        this.dropSession(previous, 'replaced by a new sign-in', true,
                         extra.request);
      }
    }
    // -------------------------------------------------------------------------
    // THE ISSUANCE GATE, AT THE FUNNEL RATHER THAN AT THE DOORS (2026-09-06).
    //
    // A session IS an issuance — `ISSUANCE.SESSION` has been in the gate's list
    // since it was written — and it was asked at exactly ONE door: this
    // module's own sign-in screen. **Five other paths mint a session and never
    // asked**: a federated assertion, a SPNEGO ticket, a client certificate, a
    // WS-Trust UsernameToken, and this file's own WebAuthn funnel. An
    // application narrowed to a role refused a password sign-in and admitted
    // the same person through any of the five.
    //
    // So it moves to the one place every session is created. That is the same
    // argument `signJwt()` makes about being the single counter and
    // `tokenSet()` makes about the RFC 9700 binding note: five call sites is
    // four that remember and a sixth added later that does not.
    //
    // **IT REFUSES BY RETURNING NULL AND NEVER BY THROWING.** Two of the
    // callers wrap this in a `try` and treat a failure as bookkeeping that must
    // not break an exchange already completed — correct for a bug in this
    // function, and exactly wrong for a refusal, which would be swallowed and
    // the credential issued anyway. A null is a value they have to look at.
    //
    // **`gated: true` IS HOW A CALLER SAYS IT ALREADY ASKED**, and only this
    // module's sign-in screen passes it. That door asks BEFORE drawing anything
    // so that a refusal is a screen with a reason on it rather than a failure
    // half-way through a sign-in, and asking twice there would be one refusal
    // reported in two shapes. The default is therefore SAFE: a sign-in path
    // added tomorrow is gated without its author knowing this exists.
    // -------------------------------------------------------------------------
    // THE RISK OF THIS AUTHENTICATION (#62 P3). A door that assessed the
    // sign-in hands the assessment in as `detail.risk`, made BEFORE any
    // session exists; its facts, with the factors THIS authentication
    // presented, go to the issuance policy in the same question as the roles.
    // A door that assessed nothing names no facts, and the gate finds the
    // person's standing or none. See `risk/risk_engine.ts`.
    // -------------------------------------------------------------------------
    const riskEngine = this.riskEngine();
    const risk = extra.risk && riskEngine ? riskEngine.riskOf(extra.risk)
                                          : null;
    let riskDecision = String(extra.riskDecision || 'permit');
    if (extra.gated !== true) {
      const sessionAnswer = gate.check(Object.assign({
        application: String(extra.application || ''),
        kind: gate.ISSUANCE.SESSION,
        subject: { kind: 'user', name: username,
                   authenticated: extra.authenticated !== false },
        claims: null
      }, extra.risk !== undefined && riskEngine
        ? { risk: riskEngine.factsOf(risk, amr, acr) } : {}));
      if (sessionAnswer.risk) {
        riskDecision = (sessionAnswer.risk.observed ? 'observe:' : '') +
                       sessionAnswer.risk.action;
      }
      if (!sessionAnswer.allowed && sessionAnswer.risk &&
          !sessionAnswer.risk.observed) {
        // REFUSED ON RISK — HIGH, or a step-up this door did not ask for. The
        // caller reads `refusedWith`; one that can ask for the factor reads
        // `riskStepUp` as well. The screen says "Authentication failed".
        const code = sessionAnswer.risk.action === 'step-up'
          ? 'STS-RISK-0017' : 'STS-RISK-0016';
        log.info('authn: a session for "' + username + '" was REFUSED on ' +
                 'risk at the ' + (via || 'sign-in') + ' door (' +
                 sessionAnswer.risk.action + (sessionAnswer.risk.factor
                   ? ': ' + sessionAnswer.risk.factor : '') + ').');
        audit.audit({
          action: 'session.refuse', actor: username, errorCode: code,
          protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
          summary: 'a session for ' + username + ' was refused on risk at ' +
                   'the ' + (via || 'sign-in') + ' door',
          detail: { application: String(extra.application || ''),
                    action: sessionAnswer.risk.action,
                    factor: sessionAnswer.risk.factor,
                    level: risk ? risk.level : '',
                    assessment: risk ? risk.assessmentId : '',
                    policy: sessionAnswer.policy || '' }
        });
        this.settleRisk(risk, { decision: riskDecision, errorCode: code,
                                policy: sessionAnswer.policy });
        extra.refusedWith = code;
        extra.riskStepUp = sessionAnswer.risk.factor || '';
        log.debug("Leaving Authn.startSession(). Refused on risk.");
        return null;
      }
      if (!sessionAnswer.allowed) {
        log.info('authn: a session for "' + username + '" was REFUSED by the ' +
                 'issuance policy at the ' + (via || 'sign-in') + ' door. ' +
                 sessionAnswer.why);
        audit.audit({
          action: 'session.refuse', actor: username,
          errorCode: 'STS-AUTHN-0010',
          protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
          summary: 'a session for ' + username + ' was refused by the ' +
                   'issuance policy at the ' + (via || 'sign-in') + ' door',
          detail: { why: sessionAnswer.why,
                    application: String(extra.application || ''),
                    policy: sessionAnswer.policy || '' }
        });
        extra.refusedWith = 'STS-AUTHN-0010';
        extra.refusedWhy = sessionAnswer.why;
        log.debug("Leaving Authn.startSession(). The issuance policy refused " +
                  "it.");
        return null;
      }
    }

    // -------------------------------------------------------------------------
    // A CREDENTIAL PRESENTED AGAIN IS THE SAME SESSION (2026-09-06).
    //
    // The management API, SCIM and the SPIRE Server API authenticate PER
    // REQUEST — a bearer token, a Basic header, an X509-SVID over mutual TLS —
    // and they sign in through this function like everything else. Without this
    // branch each of their calls would mint a session: a provisioning client
    // doing a thousand PATCHes would leave a thousand rows nothing will ever
    // present again, and `/admin/sessions` would be useless exactly when
    // somebody needed it.
    //
    // **A SECOND SESSION REGISTER WAS THE OBVIOUS ANSWER AND IS THE WRONG
    // ONE.** This map is where a session lives; `logout/logout.ts` reads it,
    // the console draws it, CAEP observes it, and a second store beside it
    // would be a second answer to "is somebody signed in" — the thing rule 3m
    // exists to prevent, with the wrong half being whichever surface a reader
    // happened to look at. So the fix is one field on the record and this
    // branch, not a new file.
    //
    // `detail.key` is a FINGERPRINT OF WHAT WAS PRESENTED and never the value —
    // its caller hashes it, for the reason `logout.ts` gives about not putting
    // an authorization code in a row id. Sessions are already bounded by the
    // sweep, so this scans rather than keeping an index: an index would be a
    // second map to hold in step with this one, which is the same mistake one
    // size down.
    //
    // Touching EXTENDS the session, which is deliberate and is the one place a
    // session here is extended by use — a browser session is absolute and
    // `logout.ts`'s SESSION_EXPIRY_RULES says so. The difference is real: a
    // browser holds a cookie that outlives its own use, and these rows exist
    // only while a client is actually calling.
    if (extra.key) {
      const wanted = String(extra.key);
      let found = null;
      sessions.forEach(function (held) {
        if (!found && held.credentialKey === wanted &&
            !self.sessionEnded(held)) {
          found = held;
        }
      });
      if (found) {
        found.expires = Date.now() + this.sessionLifetimeMs();
        found.lastSeenAt = Date.now();
        found.calls = (found.calls || 1) + 1;
        // AND WRITTEN BACK THROUGH THE STORE (2026-09-14). `sessions` is
        // `realms.map({persist})`, whose journal sees `set()` and not three
        // fields stamped on the object it handed out — so the extension reached
        // this process's memory and nothing else, and in dispatch mode every
        // other process went on holding the OLD expiry and ended a session a
        // SCIM client or SPIRE agent was actively using.
        // `touchArrivalSession()` records the same lesson one function up.
        sessions.set(found.id, found);
        // The name may sharpen between calls — a scheme that authenticated
        // anonymously first and by name later — and the creation instant
        // deliberately does not move.
        this.notifySession('presented', found, { via: via || found.via,
                                                 req: null });
        log.debug("Leaving Authn.startSession(). The credential was " +
                  "presented " +
                  "again; session " + found.id +
                  " was touched rather than replaced.");
        return found;
      }
    }
    if (reauthenticating) {
      // The session's risk becomes this authentication's, where it was
      // assessed; the re-authentication below writes the row.
      if (risk) {
        current.session.risk = risk;
      }
      const again = this.reauthenticateSession(res, current.session, username,
                                               amr,
                                               acr, via, extra);
      this.settleRisk(risk, { decision: riskDecision, sessionId: again.id,
                              context: extra.risk &&
                                       extra.risk.sessionContext });
      log.debug("Leaving Authn.startSession(). " + username +
                " re-authenticated on " +
                "session " + again.id + ".");
      return again;
    }
    // ---------------------------------------------------------------------
    // A TRACKING ROW IS UPGRADED IN PLACE RATHER THAN REPLACED (2026-09-07).
    //
    // The browser was given a cookie when it arrived at the protocol's front
    // door — see startTrackingSession(). Minting a NEW id here would mean the
    // cookie it is already holding names a row that is about to be abandoned,
    // and the sign-in would have to re-issue one. Keeping the id means the
    // identity a flow was correlated by from its first request is the identity
    // it ends up signed in as, which is the whole point of setting it early.
    //
    // Everything else about the row is overwritten below, so an upgraded
    // session differs from a freshly minted one in its ID and its `startedAt`
    // alone — and `startedAt` deliberately does not move, for the reason the
    // credential-fingerprint branch above gives about the creation instant.
    // ---------------------------------------------------------------------
    const sessionId = arrived ? arrived.id : randomId(24);
    const firstEvent = this.authenticationEvent(amr, acr, via, extra);
    const authenticatedNow = extra.authenticated !== false;
    // ---------------------------------------------------------------------
    // THE AUTHENTICATION IS RECORDED BEFORE THE SESSION IS BUILT (2026-09-14),
    // where it used to be recorded after. Recording it is what makes the
    // directory create this person's entry, and a person's `sub` is that
    // entry's `entryUUID` now — so the session cannot be given a subject until
    // the entry exists.
    // ---------------------------------------------------------------------
    // One of the two places a person is authenticated by typing a name at a
    // screen — this one covers both, since WS-Federation signs in through here.
    //
    // AN UNAUTHENTICATED SESSION IS RECORDED HERE TOO, and that needed deciding
    // rather than falling out. What this funnel counts is "an identity was
    // established at a door", which is what happened — the anonymous principal
    // gets its directory entry from this call like anybody else, which is what
    // makes it visible on /admin/users and able to hold a configured role. What
    // it must not do is CLAIM a credential was checked, so `method` says
    // `declined` and the note says so outright; the count on that entry is a
    // count of anonymous sessions, and the method column is what tells a reader
    // which kind of row they are looking at. `authenticated` is stripped from
    // `extra` because it is a fact about the SESSION and this payload is about
    // the act — leaving it in would put a field on the audit detail that
    // nothing reads and that a reader would take for a claim about the
    // credential.
    const statsExtra = Object.assign({}, extra);
    delete statsExtra.authenticated;
    // The risk assessment and what was decided on it (#62 P3) are recorded
    // on the assessment, not on the authentication's row.
    delete statsExtra.risk;
    delete statsExtra.riskDecision;
    delete statsExtra.riskStepUp;
    // A federation partner's session and its bound (#167) are facts about
    // the SESSION, recorded on it; the authentication's row names the
    // relationship through `federation` already.
    delete statsExtra.fedPartnerSession;
    delete statsExtra.sessionNotOnOrAfter;
    stats.recordAuthentication(Object.assign({
      presented: username, protocol: via || 'OAuth 2.0 / OIDC',
      method: authenticatedNow ? this.methodPhraseFor(amr) : 'declined',
      amr: amr, acr: acr, sessionId: sessionId,
      note: authenticatedNow
        ? 'No password was checked; the name typed is the identity.'
        : 'Nobody authenticated: this is the anonymous principal, from ' +
          '"Continue without signing in" at the sign-in screen.'
    }, statsExtra, { sessionId: sessionId }));
    // ---------------------------------------------------------------------
    // NO SIGNED-IN SESSION WITHOUT A DIRECTORY ENTRY (2026-09-14).
    //
    // A stable subject has to be the subject OF something, and what it is the
    // subject of is the person's entry. So where the directory holds no entry
    // after the authentication was recorded — `ldap.autocreateUsers` is off, or
    // a federation relationship has dynamic provisioning off and nobody was
    // provisioned ahead of time (by SCIM, say) — the session is REFUSED rather
    // than started with no subject. That is rcbj's pre-provisioned federation
    // shape, and it is the same rule for every door.
    //
    // Three things are exempt, and each for a reason: a keyed API caller (a
    // SCIM client, a SPIRE agent) is not a person and has no entry to have; an
    // UNAUTHENTICATED session is not an authenticated identity; and a process
    // with no directory at all has no subjects for anybody, so refusing there
    // would refuse every module test that signs somebody in.
    // ---------------------------------------------------------------------
    const user = userFor(username);
    if (!user.sub && authenticatedNow && !extra.key &&
        helpers.hasSubjectResolver()) {
      log.info(errorCodes.tag('STS-AUTHN-0180') +
               'authn: a session for "' + username + '" was REFUSED at the ' +
               (via || 'sign-in') + ' door: the directory holds no entry for ' +
               'them, so there is no subject to give the session. ' +
               (extra.federation && extra.federation.id
                 ? 'Dynamic provisioning is off on the federation ' +
                   'relationship "' + extra.federation.id + '", so the ' +
                   'person has to be provisioned before they sign in.'
                 : 'ldap.autocreateUsers is off, so the person has to be ' +
                   'created before they sign in.'));
      audit.audit({
        action: 'session.refuse', actor: username,
        errorCode: 'STS-AUTHN-0180',
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused: the directory ' +
                 'holds no entry for them',
        detail: { why: 'no directory entry, so no subject',
                  federation: (extra.federation && extra.federation.id) || '',
                  autocreate: extra.federation
                    ? String(extra.federation.autocreate !== false) : '' }
      });
      extra.refusedWith = 'STS-AUTHN-0180';
      log.debug("Leaving Authn.startSession(). There is no entry to be the " +
                "subject of.");
      return null;
    }
    const session: SessionRow = {
      // The id is on the session as well as being the map key, because
      // everything that is handed a session gets the object and not the key —
      // the authorization endpoint, WS-Federation, the console — and without it
      // the tokens issued on a session could not name the session they were
      // issued on.
      id: sessionId,
      user: user, authTime: firstEvent.at,
      // `authn.sessionLifetimeS`, read now, so a change reaches the next
      // session.
      expires: Date.now() + this.sessionLifetimeMs(),
      // WHETHER ANYBODY ACTUALLY AUTHENTICATED (2026-09-05).
      //
      // `true` for every caller that does not say otherwise, which is every
      // caller that existed before this field did — a password screen, a
      // WebAuthn ceremony, a Kerberos ticket, a federated assertion. The one
      // that passes `false` is the sign-in screen's "Continue without signing
      // in" button, and it is what makes ALL_UNAUTHENTICATED_USERS a role
      // something can actually hold at an issuance site.
      //
      // **IT IS ON THE SESSION AND NOT WORKED OUT AGAIN DOWNSTREAM**, which is
      // the whole point: six issuance sites used to hard-code `authenticated:
      // true` into the subject they handed the role gate, so the flag was a
      // constant dressed as a fact. They read this instead. A session object
      // from an older process that lacks the field reads as `undefined`, and
      // every reader treats that as `true` for the same reason the default here
      // is `true` — the absence of this field means the service that made the
      // session had no way to be anything but authenticated.
      authenticated: extra.authenticated !== false,
      // NOT A TRACKING ROW ANY MORE, said explicitly rather than by omission:
      // this object REPLACES the one in the map, and a `chosen` left false here
      // would make sessionOf() go on refusing to hand out a session somebody
      // has just signed in to — which is a sign-in that silently does not take.
      // CHOSEN NOW, whether by signing in or by pressing the button — both come
      // through here. An upgraded row that left this false would be a sign-in
      // that sessionOf() went on hiding, which is a sign-in that does not take.
      chosen: true,
      // Preserved across an upgrade so that "when did this browser arrive" and
      // "when did they authenticate" stay two different facts.
      startedAt: arrived ? arrived.startedAt : Date.now(),
      // Stated rather than omitted: a relying party that asked for a second
      // factor needs to be able to see that it did not get one.
      //
      // **THESE FOUR — `amr`, `acr`, `authTime`, `via` — ARE THE MOST RECENT
      // EVENT'S** (2026-09-14), kept as plain fields because some sixty readers
      // and several test fixtures read them off plain objects. `events` below
      // is the record; these are what it currently says. A re-authentication
      // REASSIGNS them and never edits them in place: an authorization code and
      // a GNAP grant hold the very array a session handed them.
      amr: amr, acr: acr,
      events: [firstEvent],
      // WHICH PROTOCOL THIS SESSION WAS STARTED THROUGH, on the session itself
      // (2026-09-04). It was already handed to `recordAuthentication()` and to
      // the CAEP observer below and kept in neither place the session lives, so
      // "what is this session" could only be answered fully by a register that
      // may not be loaded — `ssf/ssf.ts` is what fills the CAEP one, and a
      // process without it lost the answer entirely. /admin/sessions reads it
      // here, which is the store that owns the session.
      //
      // It is the protocol the sign-in came THROUGH and not the only one the
      // session serves: every browser family here reads this same session, so a
      // row saying `SAML 2.0` may well be carrying OIDC relying parties too,
      // and the page says so rather than letting the column be read as
      // exclusive.
      via: via || 'OAuth 2.0 / OIDC',
      // THE CREDENTIAL FINGERPRINT, where the caller gave one — a hash, never
      // the value. It is what makes a second call with the same token the same
      // session rather than a new one, and it is the only field on this record
      // that is about HOW the session is presented rather than about who is in
      // it. A browser session has none: the cookie is the key and the map
      // already keys on it.
      credentialKey: extra.key ? String(extra.key) : null,
      // Only a keyed session is extended by use, so only a keyed session needs
      // these. They are set unconditionally so that every row has the same
      // shape — `/admin/sessions` reads them and an absent field would draw as
      // "unknown" on the rows where the answer is "once, at sign-in".
      lastSeenAt: Date.now(),
      calls: 1,
      // THE RISK ITS AUTHENTICATION WAS ASSESSED AT (#62 P3), reduced to what
      // the issuance policy reads — level, score, signals, the assessment's
      // id — so every token issued on this session is decided on it. Null
      // where the door assessed nothing. P4's re-scoring replaces it.
      risk: risk
    };
    this.bindPartnerSession(session, extra);
    // A FRESH HANDLE, EVEN FOR AN UPGRADED ARRIVAL ROW. The arrival session's
    // id survives the upgrade on purpose — it is the `sid` a flow was
    // correlated by from its first request — and until 2026-09-14 so did its
    // COOKIE, which made the cookie a browser was handed before anybody
    // authenticated the one that was authenticated afterwards. That is session
    // fixation, whatever the randomness of the id. Rotating the handle keeps
    // the correlation and ends the fixation.
    const cookieValue = this.mintSessionHandle(session);
    sessions.set(sessionId, session);
    // The sweep that ends it if nobody signs it out is the scheduler job
    // `authn.session-expiry` (see the header); nothing is armed here.
    // `Secure` when — and only when — this port is TLS (global.https, which RFC
    // 9700 mode brings with it). It has to be conditional rather than always
    // on: a browser silently DROPS a Secure cookie that arrives over plain
    // http, so setting it unconditionally would leave the default deployment
    // with a sign-in that appears to succeed and a session that is never there
    // again — which is the same symptom as a session that expired and points
    // nowhere near the cookie. `SameSite=Lax` stays as it is: WS-Federation
    // section 13.2.1 sends its sign-in request as a cross-site form POST, and
    // None would be the change that needs its own argument.
    //
    // **AND NO COOKIE AT ALL FOR A CALLER THAT IS NOT A BROWSER (2026-09-06).**
    // The management API, SCIM and the SPIRE Server API sign in through this
    // function and present a credential on every request; handing one of them a
    // session cookie would invite a client to start using it as a credential —
    // a second way to reach those surfaces that none of their own
    // authentication rules would ever see. `detail.cookie === false` is how a
    // caller says so, and it is deliberately opt-OUT: every caller that existed
    // before this field is a browser and must keep getting the cookie.
    if (extra.cookie !== false) {
      this.setCookieHeader(res, this.sessionCookieLine(SESSION_COOKIE,
                                                       cookieValue));
    }
    // The session itself, as its own audit event. It is deliberately separate
    // from the authentication recorded on the line above: the two are one act
    // at this screen and are NOT one act everywhere — a Kerberos AS-REQ and a
    // WS-Trust UsernameToken authenticate somebody and start no session at all,
    // and a session that outlives the sign-in is the thing single sign-on then
    // runs on. An audit log that could not tell those apart could not answer
    // "when did this browser get its session", which is the question a sign-out
    // row is only interesting beside.
    //
    // The session id is recorded WHOLE. It is a credential-shaped thing and
    // this is the one exception to "no credential is ever recorded" — it is not
    // one: the cookie is HttpOnly and the console already prints session ids on
    // /admin/users and /admin/metrics, where the whole point is to line a token
    // up with the session it was issued on. Truncating it here would break that
    // and protect nothing.
    audit.audit({
      action: 'session.start',
      actor: username,
      protocol: via || 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: sessionId,
      // "at the … screen" is wrong for a caller that had no screen, so the
      // phrasing follows the caller where it says so. Federation is the one
      // such caller today: the person signed in somewhere else entirely.
      summary: extra.summary ||
               (username + ' was signed in at the ' +
                (via || 'OAuth 2.0 / OIDC') +
                ' screen; session ' + sessionId + ' was created'),
      detail: {
        sessionId: sessionId,
        sub: session.user.sub,
        amr: (amr || []).join(', '),
        acr: acr || '',
        authTime: session.authTime,
        expiresAt: new Date(session.expires).toISOString(),
        // The caller's own sentence where it has one. A federated sign-in's
        // "No password was checked" is true and useless — nothing was typed
        // here at all — and the row is the only place that distinction will
        // ever be recorded.
        note: extra.note || 'No password was checked; the name typed is the ' +
                            'identity.'
      }
    });
    // THE ONE ACT IN THIS SERVICE THAT MAKES SOMETHING GO OUT WITHOUT ANYBODY
    // ASKING. See setSessionObserver() above, and `ssf/caep.ts` for what is
    // built. It is last in this function on purpose: the audit row and the
    // cookie are this service's own record of the sign-in and must not depend
    // on a transmitter, and the observer is handed a session that is already
    // complete.
    session.firstPresentationIsTheSignIn = true;
    this.notifySession('established', session, { via: via || 'OAuth 2.0 / OIDC',
      // `res.req` is express's own back-reference and is the only request this
      // function is given. See the note in dropSession() for why the observer
      // needs one at all.
      req: (res && res.req) || null });
    this.settleRisk(risk, { decision: riskDecision, sessionId: sessionId,
                            context: extra.risk &&
                                     extra.risk.sessionContext });
    this.assessRisk(session, firstEvent, via, extra);
    log.debug("Leaving Authn.startSession(). " + username +
              " is signed in (amr " +
              (amr || []).join(',') + ").");
    return session;
  }

  // ---------------------------------------------------------------------------
  // ENDING A SESSION, IN THE TWO SHAPES CALLERS NEED, AND ONE BODY UNDER BOTH.
  //
  // `endSession(req, res)` is the browser's: it reads the cookie, drops what it
  // names, and clears the cookie. `endSessionById(id, via)` is the one the
  // PROTOCOL-INDEPENDENT logout needs — /logout ends sessions that are not the
  // caller's own, and /admin/logout ends somebody else's entirely, neither of
  // which has a cookie to read.
  //
  // They share `dropSession()` and MUST keep sharing it. What that function
  // does besides the delete is the whole reason: the RFC 9700 section 2.2.2
  // refresh revocation and the `session.end` audit row. A second copy of either
  // would be a sign-out that revoked nothing on one path, or two audit rows
  // that came to disagree about what a sign-out is — which is exactly the
  // argument that put this code here rather than in /oauth2/logout and
  // wsignout1.0 separately.
  // ---------------------------------------------------------------------------

  // The one place a session actually stops existing. `via` names the door, and
  // it goes on the audit row: "the sign-out endpoint", "a global logout", "the
  // admin console". Returns the session as it was — the caller needs what it
  // WAS, not merely that it is gone, because the lists of relying parties and
  // service providers a federated sign-out has to fan out to live on the object
  // being discarded.
  private dropSession(id, via, cookiePresented, req?) {
    const { realms, log, stats, bcp } = this.deps;
    const self = this;
    log.debug("Entering Authn.dropSession(). id=" + (id || '(none)'));
    const session = id ? sessions.get(id) : null;
    if (id) sessions.delete(id);
    // -------------------------------------------------------------------------
    // AND EVERY SESSION DERIVED FROM IT (2026-09-06).
    //
    // `/admin` and `/portal` hold RELYING PARTY sessions of their own, issued
    // against this one — see startRelyingPartySession() above. A sign-out that
    // ended the provider session and left them alive would be a sign-out that
    // visibly did nothing on the two surfaces an operator or a person is
    // actually looking at, which is the shape of defect `/admin/users`'s
    // "Revoke everything" button already cost this repository once.
    //
    // **HERE RATHER THAN AT THE FOUR SIGN-OUT DOORS**, for the reason the whole
    // of this function is here: `/oauth2/logout`, `wsignout1.0`, SAML Single
    // Logout, `/logout` and the console's own Revoke are five words for one
    // act, and a cascade at each is four that remember and a fifth added later
    // that does not.
    //
    // The recursion is one level deep in practice — a derived session is never
    // itself a parent — and is written as a loop over one generation rather
    // than a recursive walk for exactly that reason: a second level would mean
    // a relying party of a relying party, which this service has no way to
    // create, and code for it would be code nothing exercises.
    //
    // `false` for `cookiePresented`: the browser presented the PROVIDER's
    // cookie, not this one, so nothing here should try to clear a cookie it was
    // not shown. The reader refuses the orphan anyway, and clears it then.
    //
    // **AND A CHILD IS ENDED IN ITS OWN REALM (2026-09-11).** `derivedFrom()`
    // above now reports which partition each child is in, because the admin
    // console deliberately holds its session in the default realm's while
    // authorizing in the ambient one. This function works on the AMBIENT
    // partition, so recursing without re-entering the child's realm would
    // delete nothing at all and the console session would survive the sign-out
    // — the exact defect the cascade exists to prevent, moved one layer along.
    if (id && session) {
      this.derivedFrom(id).forEach(function (child) {
        log.info('authn: ending the ' + (child.session.rpSurface || 'relying ' +
            'party') +
                 ' session ' + child.id + ' (realm ' + child.realm + ') with ' +
                 'the sign-on session it was derived from (' + id + ').');
        const endChild = function () {
          log.debug("Entering endChild().");
          self.dropSession(child.id,
                           'the sign-on session it was derived from ended (' +
                           (via || 'unknown door') + ')', false, req);
          log.debug("Leaving endChild().");
        };
        if (child.realm && child.realm !== realms.currentId()) {
          realms.run(realms.get(child.realm), endChild);
        } else {
          endChild();
        }
      });
    }
    // RFC 9700 section 2.2.2: an authorization server MAY revoke refresh tokens
    // after a security event, and the section names LOGOUT as one; OpenID
    // Connect Back-Channel Logout 1.0 section 2.7 makes it a SHOULD for a
    // token without `offline_access`. IN EVERY MODE since #123 (it was RFC
    // 9700 mode only): every refresh token issued ON this session, through the
    // same revocation set /oauth2/revoke and the console write to, so
    // introspection reports them inactive immediately.
    //
    // HERE and not at any sign-out endpoint, because this function is the
    // single place all of them end a session: /oauth2/logout, WS-Federation's
    // wsignout1.0, SAML 2.0 Single Logout and /logout are four words for one
    // act, and a revocation at each would be four that could come to disagree.
    //
    // Only the REFRESH tokens. An access token issued on this session expires
    // in an hour and revoking it would take away the evidence of what the
    // session did; the refresh token is the thirty-day credential a sign-out is
    // supposed to be about, and leaving it live is what made signing out mean
    // nothing to the back channel. A GLOBAL logout revokes the access tokens
    // too — but it does that itself, as a separate stated act, rather than by
    // widening this one: the two are different promises and only one of them is
    // the BCP's. ASKED PER TOKEN, not once for the sign-out:
    // `oauth2.revokeRefreshOnLogout` is per client since 2026-08-27, and this
    // session may hold refresh tokens for several clients that answer
    // differently. `oauthRevokeRefreshOnLogout: FALSE` on one entry is how a
    // client that refreshes its way back after a sign-out is reproduced.
    //
    // EXCEPT A REFRESH TOKEN GRANTED `offline_access` (#118). OIDC Core
    // section 11 defines that scope as access "even when the End-User is not
    // present (not logged in)" — outliving the session is the whole of what
    // it was granted for, and the person agreed to exactly that. The online
    // ones this revokes are the ones the refresh grant would refuse after the
    // sign-out anyway; a global sign-out (`/logout`) still disowns everything.
    // This service's OWN surfaces are not excepted: the relying-party session
    // that holds each of their tokens ends in this same sign-out's cascade,
    // so an offline token of theirs would be a live credential nobody holds
    // (`applications.HOSTED_SURFACE_CLIENT_IDS`).
    if (id) {
      const revoked = stats.revokeWhere(function (record) {
        const clientId = String(record.client_id || '');
        return record.sessionId === id &&
               String(record.typ || '') === 'Refresh' &&
               (String(record.scope || '').split(/\s+/)
                 .indexOf('offline_access') < 0 ||
                applications.HOSTED_SURFACE_CLIENT_IDS
                  .indexOf(clientId) >= 0) &&
               bcp.revokeRefreshOnLogout(clientId);
      }, 'Back-Channel Logout section 2.7: the sign-on session it was ' +
         'issued on ended');
      if (revoked) {
        log.info('Back-Channel Logout section 2.7: signing out of session ' +
                 id + ' ' +
            'revoked ' + revoked +
                 ' refresh token(s) issued on it. Without that, a sign-out ' +
                 'drops a cookie and leaves a thirty-day credential in the ' +
                 'client\'s hands.');
      }
    }
    // The sign-out, recorded here because this is the one place every door
    // reaches: they are four protocols' words for ending the one session this
    // service holds, and a row per caller would be four rows that could come to
    // disagree about what a sign-out is.
    //
    // A logout with NOTHING TO END is recorded too, as `refused`. That is not
    // pedantry: a relying party looping on wsignout1.0 against a session that
    // expired an hour ago looks identical, from every other page in this
    // console, to one that is working — and the row that says "there was no
    // session to drop" is the only place that shows up.
    // BEFORE the audit row and after the delete, which is the only order that
    // works: the observer is handed the session as it WAS — it needs the user
    // and the id to name the subject — and a sign-out that emitted while the
    // session was still in the store would be a transmitter telling a receiver
    // to stop trusting something this service still honoured.
    // ONCE FOR THE CLUSTER (2026-09-14, #46 section 6): the delete above is
    // this process's, and the event and the audit row go out only if no other
    // process has already reported this session's end — the sweep on another
    // node, or a sign-out racing this one. See sessionEndOnce(). A sign-out
    // that found nothing to end has nothing to claim and is recorded as it was.
    //
    // AND THE BACK-CHANNEL LOGOUT TOKENS GO OUT WITH THE REPORT (2026-09-17,
    // #36). OpenID Connect Back-Channel Logout 1.0 is this function's kind of
    // consequence — every door ends a session here, so here is the one place
    // every relying party on it is told — and it rides the same claim, so a
    // session's end is SENT by the process that reports it. The rows are
    // PLANNED before the claim, synchronously, so the door's answer can list
    // them as pending; they are rows of a persisted, replicated store with an
    // id derived from the session and the client, so a process that loses the
    // claim planned the SAME rows and has nothing to hand off — the winner
    // sends them, and a row only the loser's copy of the session named is
    // sent by the next sweep anywhere (`backchannel_logout.ts`, header points
    // 3 and 4). Each attempt is claimed on its own, which is what makes "once"
    // hold even where this claim cannot be asked. Required LAZILY, as
    // `frontchannel_logout.ts` requires this module: a library loaded long
    // before any session ends. An EXPIRY sends too, from expireSession().
    if (session) {
      const planned = this.planBackchannel(session, via || 'a sign-out',
                                           'sign-out');
      this.sessionEndOnce(session.id, function () {
        self.reportSignOut(session, id, via, cookiePresented, req);
        self.dispatchBackchannel(planned);
      }, function () {
        self.reportSignOutAlreadyEnded(session, via, cookiePresented);
      });
    } else {
      this.reportSignOut(null, id, via, cookiePresented, req);
    }
    log.debug("Leaving Authn.dropSession(). " +
              (session ? 'Dropped the session for ' + session.user.username +
               '.'
                                                   : 'There was no session ' +
                                                     'to drop.'));
    return session || null;
  }

  // The event and the audit row for a sign-out — what sessionEndOnce() lets out
  // once for the cluster. Split from dropSession() for that reason only; the
  // order inside is dropSession()'s own, argued there.
  private reportSignOut(session, id, via, cookiePresented, req) {
    const { log, audit } = this.deps;
    log.debug("Entering Authn.reportSignOut().");
    this.notifySession('revoked', session, { via: via || 'a sign-out endpoint',
      byAdmin: /admin|console/i.test(String(via || '')),
      // THE REQUEST, WHERE THERE IS ONE, AND IT IS NOT A CONVENIENCE. The
      // observer builds a subject naming the person by ISSUER and subject, and
      // this service's issuer is derived from the request — a sign-out reached
      // through a proxy under a different name would otherwise emit an event
      // whose `iss` no receiver recognises, which is refused at the far end
      // and reads as a bad signature. `endSessionById()` genuinely has none:
      // /logout ends sessions that are not the caller's, and the fallback is
      // the configured `ssf.issuer`.
      req: req || null });
    audit.audit({
      action: 'session.end',
      outcome: session ? 'success' : 'refused',
      errorCode: session ? '' : 'STS-AUTHN-0011',
      actor: session ? session.user.username : '',
      channel: 'http',
      target: session ? session.id : (id || ''),
      summary: session
        ? 'the sign-on session for ' + session.user.username + ' was ended'
        : 'a sign-out was asked for and there was no session to end',
      detail: {
        sessionId: session ? session.id : '',
        // How the session was named. A cookie is the browser's own sign-out; an
        // id is /logout or the console ending a session that is not the
        // caller's, and telling the two apart is the difference between "they
        // signed out" and "somebody signed them out".
        cookiePresented: cookiePresented ? 'yes' : 'no',
        namedBy: cookiePresented ? 'the session cookie' : 'its identifier',
        via: via || 'a sign-out endpoint',
        // Whether the name reached a session this service still had. A `yes` on
        // cookiePresented with no session means it had already expired or
        // already been signed out, which are the two ordinary ways this row is
        // a refusal.
        sessionFound: session ? 'yes' : 'no',
        amr: session ? (session.amr || []).join(', ') : '',
        acr: session ? (session.acr || '') : ''
      }
    });
    log.debug("Leaving Authn.reportSignOut().");
  }

  // A sign-out that lost the claim: another process had already reported this
  // session's end. Recorded — somebody did ask — with no event, because a
  // receiver has already been told.
  private reportSignOutAlreadyEnded(session, via, cookiePresented) {
    const { log, audit } = this.deps;
    log.debug("Entering Authn.reportSignOutAlreadyEnded().");
    audit.audit({
      action: 'session.end',
      outcome: 'refused',
      errorCode: 'STS-AUTHN-0191',
      actor: session.user ? session.user.username : '',
      channel: 'http',
      target: session.id,
      summary: 'a sign-out of ' + (session.user ? session.user.username : '') +
               '\'s session ' + session.id + ' found its end already ' +
               'reported by another process',
      detail: {
        sessionId: session.id,
        cookiePresented: cookiePresented ? 'yes' : 'no',
        via: via || 'a sign-out endpoint',
        sessionFound: 'yes, and already ended elsewhere'
      }
    });
    log.debug("Leaving Authn.reportSignOutAlreadyEnded().");
  }

  // Every session this service holds for one person, newest first. The
  // comparison is on the USERNAME as typed, because that is what the session
  // records and what /logout was asked about; admin_stats.js's identityKeyOf()
  // normalisation is applied by the CALLER where it wants `alice` and
  // `alice@REALM` to be one person, so that this function cannot quietly fold
  // two names together for a caller that meant one.
  sessionsOf(username) {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionsOf(). username=" + username);
    const wanted = String(username || '');
    const out = [];
    sessions.forEach(function (session) {
      if (((session.user && session.user.username) || '') === wanted) out.push(
          session);
    });
    out.sort(function (a, b) { return (b.authTime || 0) - (a.authTime || 0); });
    log.debug("Leaving Authn.sessionsOf(). " + out.length + " session(s).");
    return out;
  }

  // One session by its id, without the cookie and without expiring it. Used by
  // /logout to draw a row for a session that is not the caller's; `sessionOf()`
  // stays the function that reads the cookie and sweeps what it finds expired.
  sessionById(id) {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionById().");
    log.debug("Leaving Authn.sessionById().");
    return sessions.get(String(id || '')) || null;
  }

  // End one session named by its id. The protocol-independent logout's door,
  // and the console's. It does NOT touch the caller's cookie: the session being
  // ended is usually not the one the caller is holding, and clearing the cookie
  // of a browser that is signed in as somebody else would sign the operator out
  // instead of the person they asked about.
  endSessionById(id, via) {
    const { log } = this.deps;
    log.debug("Entering Authn.endSessionById(). id=" + id);
    const session = this.dropSession(String(id || ''), via, false);
    log.debug("Leaving Authn.endSessionById(). " + (session ? 'Ended.' :
                                                    'There was ' +
        'no such session.'));
    return session;
  }

  // END EVERY SESSION OF ONE REALM (#48, an emergency key rotation). Each
  // through the same door as one (`dropSession()`), so each is an audit row, a
  // CAEP session-revoked and the back-channel Logout Tokens of its relying
  // parties. Collected first and ended afterwards, for the sweep's reason.
  // Answers who was signed out, so the caller can tell RISC about accounts.
  endEverySessionIn(realmId, via) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Authn.endEverySessionIn(). realm=" + realmId);
    const realm = realms.get(String(realmId || '')) ||
                  realms.get(realms.DEFAULT_ID);
    const store = sessions.realmMap(realm.id);
    const ids = [];
    if (store) {
      store.forEach(function (session, id) {
        if (session) {
          ids.push({ id: id,
                     username: String((session.user &&
                                       session.user.username) || '') });
        }
      });
    }
    const ended = realms.run(realm, function () {
      return ids.filter(function (one) {
        return !!self.dropSession(one.id, via, false);
      });
    });
    log.debug("Leaving Authn.endEverySessionIn(). " + ended.length +
              " ended.");
    return ended;
  }

  // Clear the session cookie on this response, whatever the session it named.
  // It is the second half of a browser sign-out and it is EXPORTED because
  // /logout can end the caller's own session by id — through the list, like any
  // other row — and would otherwise leave the browser holding a cookie naming a
  // session this service no longer has. Same attributes it was SET with, Secure
  // included: a browser matches an expiry against the cookie it holds, and one
  // that disagrees about Secure can leave the original in place — a sign-out
  // that reports success and ends nothing.
  //
  // **IT TAKES A COOKIE NAME SINCE 2026-09-06, AND IT WAS ALREADY BEING CALLED
  // WITH ONE.** `oidc_rp.js`'s `endSessionFor()` has passed `surface.cookie`
  // from the day it was written and this function ignored it — so a hosted
  // surface signing somebody out cleared the SIGN-ON cookie and left its own in
  // place. The symptom was mild and misleading, which is why it lasted: the
  // reader refuses a cookie naming a session that no longer exists, so the
  // surface looked signed out while the browser went on presenting a dead id
  // and the provider's cookie went away instead of the application's.
  //
  // **AND IT APPENDS RATHER THAN SETS.** A sign-out on a hosted surface clears
  // TWO cookies on one response — the surface's own and the sign-on session's —
  // and `res.set('Set-Cookie', …)` REPLACES the header, so the second clear
  // silently threw the first away. `setCookieHeader()` above is left alone
  // deliberately: a SET is one cookie per response and making it append would
  // mean a rotated session id going out beside the one it replaced, with the
  // browser free to keep either.
  clearSessionCookie(res, cookieName?) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.clearSessionCookie().");
    const value = String(cookieName || SESSION_COOKIE) +
                  '=; Path=/; Max-Age=0' +
                  (config.value('global.https') ? '; Secure' : '');
    // THE SIGN-ON SESSION's OP BROWSER STATE GOES WITH IT (#121), so a
    // relying party's OP iframe answers `changed` after any sign-out door.
    // Only for the sign-on cookie: a hosted surface's own cookie is not it.
    const signOn = String(cookieName || SESSION_COOKIE) === SESSION_COOKIE;
    const sessionManagement = signOn ? this.sessionManagementLibrary() : null;
    if (typeof res.append === 'function') {
      res.append('Set-Cookie', value);
      if (sessionManagement && sessionManagement.enabled()) {
        sessionManagement.writeCookie(res, '');
      }
      log.debug("Leaving Authn.clearSessionCookie().");
      return;
    }
    // Not an express response — the same case `setCookieHeader()` guards, and
    // handled the same way rather than thrown, because a sign-out that failed
    // to clear a cookie has still ended the session.
    this.setCookieHeader(res, value);
    log.debug("Leaving Authn.clearSessionCookie().");
  }

  // Ends the session the request carries, and returns it — the caller needs
  // what it was, not merely that it is gone: WS-Federation's sign-out has to
  // send a cleanup request to each relying party the session signed into, and
  // that list lives on the session object it is about to discard.
  endSession(req, res) {
    const { log } = this.deps;
    log.debug("Entering Authn.endSession().");
    // ONLY A COOKIE CARRYING THE CURRENT HANDLE ENDS ANYTHING. The sid is not a
    // secret — every relying party that received an ID Token holds it — so a
    // sign-out endpoint that honoured `sts_session=<sid>` would let any of them
    // sign a person out from a forged cookie. A cookie that names nothing is
    // still recorded as a refused sign-out, by dropSession() below.
    const found = this.cookieSession(req, SESSION_COOKIE);
    const id = found ? found.id : '';
    const presented = !!this.cookiesOf(req)[SESSION_COOKIE];
    const session = this.dropSession(id,
                                     'the sign-out endpoint for this browser',
                                     presented, req);
    this.clearSessionCookie(res);
    log.debug("Leaving Authn.endSession(). " +
              (session ? 'Dropped the session for ' + session.user.username +
               '.'
                                                  : 'There was no session to ' +
                                                    'drop.'));
    return session || null;
  }

  // ---------------------------------------------------------------------------
  // WHERE THIS APPLICATION'S PEOPLE SIGN IN, if its entry says.
  //
  // An application entry may name federation relationships
  // (`appFederationRelationship`), which is the registry answering a question
  // it could not answer before: a relationship under `ou=federations` says how
  // to talk to a foreign identity provider and nothing about WHO should be sent
  // there, and until this attribute existed the only answer was a person
  // choosing a button at the foot of the screen below — home realm discovery
  // performed by the user, against every relationship this service has, once
  // per sign-in.
  //
  // IT HOLDS A LIST SINCE 2026-08-26, AND THAT IS THE ONE THING TO UNDERSTAND
  // ABOUT THIS FUNCTION. An application with two identity providers is the
  // ordinary case in a real deployment — a workforce partner and a customer
  // one, or the same partner reached over two protocols during a migration —
  // and the attribute was single-valued, so the only way to say it was to
  // configure nothing and let the person choose from the whole register. Naming
  // several here is the middle answer: the choice is still made by the person,
  // and the list they choose from is this application's own.
  //
  // WHAT COMES BACK IS THEREFORE A LIST, and the two shapes callers actually
  // want are precomputed rather than left to be derived twice:
  //
  //   ids        every value on the entry, in the order the entry holds them
  //   options    one row per value: { id, relationship, problem, option }, with
  //              `relationship` null and `problem` set for a value that names
  //              something this service cannot use
  //   usable     the subset with a relationship — what a page may offer
  //   id/relationship  the single usable one, when there is EXACTLY one. This
  //              pair is what every caller written before the list existed
  //              reads, and it is null the moment there is a choice to make, so
  //              a caller that has not been taught about the chooser cannot
  //              silently pick the first partner for somebody.
  //   auto       appFederationAutoRedirect, which means "without the sign-in
  //              screen" and never "without a page" — see below.
  //   problem    the FIRST unusable value's sentence, for the caller that shows
  //              one line; `problems` has them all.
  //
  // FOUR CHECKS PER VALUE, AND EACH OF THEM IS MADE HERE RATHER THAN AT THE
  // WRITE. The attribute is a string on a directory entry: `ldapmodify` reaches
  // it, so does the management API, and a relationship it names can be disabled
  // or deleted afterwards by somebody who never looked at this application. A
  // check made when it was written would therefore be a check about the past.
  // The relationship must exist IN THIS REALM (the register is per realm, so an
  // id from another realm names nothing here), must be service-provider-side
  // (the other direction is this service asserting TO that partner — there is
  // nothing to sign in to), must be enabled, and must be fully configured.
  //
  // A failure of any of them is REPORTED rather than swallowed, and the caller
  // shows it. The alternative — falling silently back to the password box — is
  // a federated application quietly authenticating people locally, which looks
  // exactly like it working. WITH A LIST THAT MATTERS MORE rather than less: a
  // list of three whose middle value is disabled draws two buttons, and two
  // buttons is exactly what a correctly configured list of two draws.
  //
  // Returns null when there is nothing to say: no application named, no entry,
  // or no relationship on the entry. That is the ordinary case and it is the
  // first thing checked, because every sign-in in this service passes through
  // here.
  // ---------------------------------------------------------------------------
  private federationFor(applicationId) {
    const { log, federation, applications, errorCodes } = this.deps;
    log.debug("Entering Authn.federationFor(). application=" +
              (applicationId || '(none)'));
    const wanted = String(applicationId || '').trim();
    if (!wanted) {
      log.debug("Leaving Authn.federationFor(). The caller named no " +
                "application.");
      return null;
    }
    let entry = null;
    try {
      entry = applications.get(wanted);
    } catch (e) {
      // Swallowed with a reason, and it is the same reason
      // federatedOptionsHtml() below swallows the register's: this runs on the
      // way to the sign-in screen, so a registry that throws must cost the
      // shortcut and never the screen.
      log.error(errorCodes.tag('STS-AUTHN-0016') +
                'authn: the application registry threw while looking "' +
                wanted +
                '" up on the way to the sign-in screen and was ignored; the ' +
                'screen itself is unaffected: ' + e.message);
      log.debug("Leaving Authn.federationFor(). The registry threw.");
      return null;
    }
    // A LIST OR A STRING, AND BOTH ARE READ. The schema says `multi` and
    // `applications.js` hands back an array for a multi row — but an entry
    // written by an older build of this service, or by an `ldapmodify` against
    // a directory that enforces no schema, can hold a bare string. Normalising
    // here rather than trusting the row is one line, and the alternative fails
    // as `named.filter is not a function` on a sign-in screen.
    const raw = ((entry || {}).fields || {}).appFederationRelationship;
    const ids = (Array.isArray(raw) ? raw : [raw])
      .map(function (one) { return String(one == null ? '' : one).trim(); })
      .filter(Boolean);
    if (!ids.length) {
      log.debug("Leaving Authn.federationFor(). That application names no " +
                "partner.");
      return null;
    }
    const auto = federation.boolOf(((entry || {}).fields ||
                                    {}).appFederationAutoRedirect, true);
    // THE FOUR CHECKS ARE federation.js's, not this function's, since
    // fedAuthnRelationship gave them a second caller — see
    // usableServiceProvider() there. They were written out here first and
    // copying them was never going to hold: a relationship id on an application
    // entry and one on another relationship are the same string, checkable the
    // same four ways, and two implementations of "would this actually work"
    // would answer differently the first time one of them learned a fifth.
    const resolved = federation.usableServiceProviders(ids, 'This application');
    // EXACTLY ONE, or neither. `relationship` is what beginAuthentication()
    // redirects to without asking anybody, so it must be empty whenever there
    // is a question to put to the person — two usable partners and no chooser
    // is this service deciding which identity provider somebody's employer is.
    const only = resolved.usable.length === 1 ? resolved.usable[0] : null;
    log.debug("Leaving Authn.federationFor(). " + ids.length + " named, " +
              resolved.usable.length + " usable, auto=" + auto + ".");
    return { ids: ids,
             options: resolved.all,
             usable: resolved.usable,
             id: only ? only.id : (ids.length === 1 ? ids[0] : ''),
             relationship: only ? only.relationship : null,
             auto: auto,
             problem: resolved.problems[0] || '',
             problems: resolved.problems };
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS SIGN-IN IS ACTUALLY GOING TO DO, from the two places that can
  // say.
  //
  // This is the ONE order in which the two sources are read, and writing it in
  // one function is the price of having two. They answer different questions
  // and that is why both exist:
  //
  //   * an IDENTITY-PROVIDER-SIDE RELATIONSHIP answers "when this partner asks
  //     me to authenticate somebody, what do I do?" — a fact about the
  //     relationship, and the one that makes this service an identity BRIDGE:
  //     `fedAuthnMechanism: federation` sends the person to a relationship in
  //     the other direction, so a SAML 2.0 partner is satisfied by a
  //     WS-Federation identity provider that this service consumes from. That
  //     partner never learns it happened, which is the same property the
  //     application at the top of the chain has, one layer down.
  //
  //   * an APPLICATION ENTRY answers "where do this application's people sign
  //     in?" — `appFederationRelationship`, home realm discovery by
  //     configuration, and what this service has done since 2026-08-26.
  //
  // THE RELATIONSHIP WINS, when one has anything to say. It is the more
  // specific statement: an application entry may be a federation partner AND an
  // ordinary OAuth client, registered by two different people, and only one of
  // those two facts is about the exchange actually in progress.
  //
  // AN EMPTY MECHANISM IS NOT AN ANSWER. A relationship that declares none —
  // which is every relationship created before the attribute existed — falls
  // through to the application entry and then to the screen, so this function
  // returns exactly what federationFor() alone used to return for every
  // configuration that predates it. That is the whole compatibility argument
  // and it is why authenticationFor() returns null rather than 'password'.
  //
  // A PROBLEM IS CARRIED RATHER THAN THROWN. Both sources report a relationship
  // that is missing, disabled, half-configured or pointing the wrong way as a
  // `problem` string, and the screen prints it. Falling silently back to the
  // password box is the failure worth being loud about: a federated application
  // authenticating people locally looks exactly like a federated application
  // working, and a BROKER that has quietly stopped brokering looks exactly like
  // one that is.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // WHAT AN APPLICATION ENTRY DECLARES ABOUT HOW ITS PEOPLE AUTHENTICATE.
  //
  // `appAuthnMechanism`, a single value from the SAME closed table
  // `fedAuthnMechanism` uses — `federation.MECHANISM_IDS`. One table for both
  // because they answer the same question from two sides, and two tables would
  // have drifted the first time either grew a value: this one says "where do
  // THIS APPLICATION's people sign in", and the relationship's says "what do I
  // do when THAT PARTNER asks me to authenticate somebody".
  //
  // IT IS THE GENERALISATION OF `appFederationRelationship`, and it was added
  // on 2026-08-26 with the SPNEGO sign-in — the first mechanism this service
  // has that is neither the screen nor a partner, and therefore the first one
  // an application had no way to ask for. The pair that existed could say "send
  // my people to a federated identity provider" and could not say "my people
  // are on domain-joined machines and hold Kerberos tickets", which is the
  // commonest integrated-authentication deployment there is.
  //
  // AN EMPTY VALUE IS NOT `password` — it is "this entry says nothing" — and
  // that is the whole compatibility argument. Every application entry in the
  // field holds an empty one, so this function must return exactly what
  // `federationFor()` alone used to decide for all of them: the relationships
  // if any are named, and the screen otherwise. Reading an absent value as an
  // explicit "use the password screen" would have switched off every
  // `appFederationRelationship` in existence in one commit.
  //
  // `federation` HERE MEANS "the relationships on this entry" and is therefore
  // the one value that changes nothing: it is what naming a relationship
  // already implied, said out loud. It is accepted because a closed table that
  // silently refused one of its own values would be a worse surprise than a
  // redundant one, and because declaring it and naming NO usable relationship
  // is a state worth REPORTING rather than falling quietly back to a password
  // box — the same argument federationFor() makes about a disabled
  // relationship.
  //
  // THE CHECKS ARE MADE HERE RATHER THAN AT THE WRITE, for federationFor()'s
  // reason exactly: the attribute is a string on a directory entry that
  // `ldapmodify`, the console and the management API can all reach, and the
  // SETTING that decides whether `spnego` will work is settable at runtime. A
  // check made when it was written would be a check about the past.
  // ---------------------------------------------------------------------------
  private declaredMechanismFor(applicationId) {
    const { log, federation, applications, config, errorCodes } = this.deps;
    log.debug("Entering Authn.declaredMechanismFor(). application=" +
              (applicationId || '(none)'));
    let entry = null;
    try {
      entry = applications.get(String(applicationId || ''));
    } catch (e) {
      // Swallowed for federationFor()'s reason and no other: this runs on the
      // way to the sign-in screen, so a registry that throws must cost the
      // shortcut and never the screen.
      log.error(errorCodes.tag('STS-AUTHN-0016') +
                'authn: the application registry threw while reading ' +
                'appAuthnMechanism for "' + applicationId + '" and was ' +
                'ignored; the sign-in screen itself is unaffected: ' +
                e.message);
      log.debug("Leaving Authn.declaredMechanismFor(). The registry threw.");
      return { mechanism: '', problem: '' };
    }
    const declared = String((((entry ||
                               {}).fields || {}).appAuthnMechanism) || '')
      .trim();
    if (!declared) {
      log.debug("Leaving Authn.declaredMechanismFor(). That entry declares " +
                "nothing.");
      return { mechanism: '', problem: '' };
    }
    if (federation.MECHANISM_IDS.indexOf(declared) === -1) {
      log.debug("Leaving Authn.declaredMechanismFor(). Not one of ours.");
      return { mechanism: '', problem: 'The application "' + applicationId +
               '" declares the authentication mechanism "' + declared +
               '", which is not one this service has: they are ' +
               federation.MECHANISM_IDS.join(', ') + '.' };
    }
    // THE ONE MECHANISM THAT CAN BE TURNED OFF SERVICE-WIDE. A relationship or
    // an application entry naming `spnego` while `krb5.spnegoAuthentication` is
    // false is configuration pointing at a door that is shut, and the person
    // meets it as a 403 halfway through a sign-in unless it is said here. The
    // other four cannot be switched off: the screen is always there, and a
    // federation relationship's own `fedEnabled` is checked by
    // usableServiceProviders().
    if (declared === 'spnego' && !config.value('krb5.spnegoAuthentication')) {
      log.debug("Leaving Authn.declaredMechanismFor(). SPNEGO is configured " +
                "and off.");
      return { mechanism: '', problem: 'The application "' + applicationId +
               '" authenticates its users with a Kerberos ticket over ' +
               'SPNEGO, ' +
               'and krb5.spnegoAuthentication is off on this service, so ' +
               'that door will not sign anybody in. The sign-in screen is ' +
               'being shown instead.' };
    }
    // THE SECOND ONE (#38's follow-ups): `wallet` while `oid4vp.signIn` is
    // off is a door that is shut, reported for SPNEGO's reason.
    if (declared === 'wallet' && !config.value('oid4vp.signIn')) {
      log.debug("Leaving Authn.declaredMechanismFor(). The wallet is " +
                "configured and off.");
      return { mechanism: '', problem: 'The application "' + applicationId +
               '" authenticates its users with a wallet, and oid4vp.signIn ' +
               'is off on this service, so that door will not sign anybody ' +
               'in. The sign-in screen is being shown instead.' };
    }
    log.debug("Leaving Authn.declaredMechanismFor(). " + declared + ".");
    return { mechanism: declared, problem: '' };
  }

  private mechanismFor(applicationId) {
    const { log, federation, errorCodes } = this.deps;
    log.debug("Entering Authn.mechanismFor(). application=" +
              (applicationId || '(none)'));
    const wanted = String(applicationId || '').trim();
    if (!wanted) {
      log.debug("Leaving Authn.mechanismFor(). The caller named no " +
                "application.");
      return { mechanism: 'password', source: 'default', federation: null,
               via: '', problem: '' };
    }
    let broker = null;
    try {
      broker = federation.authenticationFor(
        federation.identityProviderFor(wanted));
    } catch (e) {
      // Swallowed for federationFor()'s reason and no other: this runs on the
      // way to the sign-in screen, so a register that throws must cost the
      // shortcut and never the screen. It is logged at error because a throw
      // here is a bug in this service rather than a configuration.
      log.error(errorCodes.tag('STS-AUTHN-0017') +
                'authn: the federation register threw while looking for an ' +
                'identity-provider-side relationship naming "' + wanted +
                '" and was ignored; the sign-in screen itself is unaffected: ' +
                e.message);
      broker = null;
    }
    if (broker) {
      // ONE PARTNER, IN THE SHAPE federationFor() RETURNS.
      // `fedAuthnRelationship` names exactly one onward relationship and is
      // deliberately not a list — the broker case is a relationship SAYING
      // WHERE IT SENDS PEOPLE, which is a statement with one answer, where an
      // application naming several is a person's choice narrowed. But
      // everything downstream of here reads `options` and `usable`, so a broker
      // that filled in only the two legacy fields would draw an empty chooser
      // the first time somebody rearranged this branch. It fills in all of
      // them.
      const home = broker.relationship
        ? { ids: [broker.onward],
            options: [{ id: broker.onward, relationship: broker.relationship,
                        problem: '',
                        option: federation.optionOf(broker.relationship) }],
            usable: [{ id: broker.onward, relationship: broker.relationship,
                       problem: '',
                       option: federation.optionOf(broker.relationship) }],
            id: broker.onward, relationship: broker.relationship, auto: true,
            problem: '', problems: [] }
        : null;
      log.info('authn: the federation relationship "' + broker.via + '" says ' +
               'this sign-in is "' + (broker.mechanism || 'unrecognised') +
               '"' + (broker.onward ? ', through "' + broker.onward + '"' :
                      '') +
               (broker.problem ? ' — and it cannot be done: ' + broker.problem
                               : '') + '.');
      log.debug("Leaving Authn.mechanismFor(). The relationship decided it.");
      return { mechanism: broker.mechanism || 'password',
               source: 'relationship', federation: home, via: broker.via,
               problem: broker.problem };
    }
    // ---------------------------------------------------------------------
    // THE APPLICATION'S OWN DECLARATION, WHICH IS READ BEFORE ITS RELATIONSHIPS
    // AND FALLS THROUGH TO THEM.
    //
    // `appAuthnMechanism` is the explicit statement and
    // `appFederationRelationship` is an implicit one — naming a partner has
    // always MEANT "authenticate my people there" — so the explicit one is read
    // first. It falls through in exactly two cases and both are deliberate:
    //
    //   * it says `federation`, which IS the implicit statement said out loud,
    //     so the list below decides as it always did; and
    //   * it says nothing, which every entry in the field says.
    //
    // A DECLARATION THIS SERVICE CANNOT HONOUR does not fall through silently.
    // It carries its sentence onto the record as `mechanismProblem`, the screen
    // prints it, and the password box underneath is then a fallback somebody
    // was TOLD about rather than a federated application quietly authenticating
    // people locally — which looks exactly like it working.
    // ---------------------------------------------------------------------
    const declared = this.declaredMechanismFor(wanted);
    if (declared.mechanism && declared.mechanism !== 'federation') {
      log.info('authn: "' + wanted +
               '" declares the authentication mechanism "' +
               declared.mechanism + '" on its entry under ou=applications, ' +
               'so that is what this sign-in does.');
      log.debug("Leaving Authn.mechanismFor(). The application entry " +
                "declared it.");
      return { mechanism: declared.mechanism, source: 'application',
               federation: null, via: '', problem: '' };
    }
    const home = this.federationFor(wanted);
    if (home) {
      log.debug("Leaving Authn.mechanismFor(). The application entry decided " +
                "it.");
      return { mechanism: 'federation', source: 'application', federation: home,
               via: '', problem: home.problem || declared.problem };
    }
    // DECLARED `federation` AND NAMING NOTHING USABLE. federationFor() returned
    // null, which means the entry names no relationship at all or the registry
    // could not be read — and an entry that says its people are federated while
    // naming nobody is exactly the half-configured state this whole function is
    // careful to report rather than swallow.
    if (declared.mechanism === 'federation') {
      log.debug("Leaving Authn.mechanismFor(). Declared federation and named " +
                "nobody.");
      return { mechanism: 'password', source: 'application', federation: null,
               via: '',
               problem: 'The application "' + wanted + '" authenticates its ' +
                        'users through a federation relationship and its ' +
                        'entry names none that this service can use. Set ' +
                        'appFederationRelationship on it.' };
    }
    if (declared.problem) {
      log.debug("Leaving Authn.mechanismFor(). A declaration this service " +
                "cannot honour.");
      return { mechanism: 'password', source: 'application', federation: null,
               via: '', problem: declared.problem };
    }
    log.debug("Leaving Authn.mechanismFor(). Nothing configured; the screen " +
              "it is.");
    return { mechanism: 'password', source: 'default', federation: null,
             via: '', problem: '' };
  }

  // ---------------------------------------------------------------------------
  // THE ENTRY POINT A PROTOCOL MODULE CALLS.
  //
  //   returnTo   where to send the browser once they are signed in — a path on
  //              this service, carrying the caller's original request whole, so
  //              that running it again is the same request over again.
  //   details    rows for the screen's footer: [{ label, value, note }]. The
  //              caller writes them because only the caller knows what its own
  //              parameters mean.
  //   hint       what to pre-fill the username with (OIDC's login_hint, and
  //              whatever the next protocol calls its equivalent).
  //   forceMfa   the caller has been told a second factor is required, so the
  //              opt-out is taken away rather than offered.
  //   forceKey   the caller has been told a SECURITY KEY is required
  //              (2026-09-17): the screen offers the key alone
  //              (passwordless) or after a password, and no other second
  //              factor, Kerberos ticket or wallet. With `forceMfa` too it is
  //              the key AFTER a password only. `step_up.screenDemand()`
  //              names the combinations.
  //   protocol   what to record the sign-in AS, for the admin console — this
  //              service cannot tell, and "every sign-in is an OIDC one" is
  //              exactly the wrong answer once more than one protocol uses it.
  //   application the identifier the caller's own protocol presented — a
  //              client_id, an entityID, a relying party id. OPTIONAL, and
  //              every caller that has one passes it, because it is what
  //              decides whether this sign-in is federated: see federationFor()
  //              above. Nothing else is done with it, and an identifier this
  //              registry has never heard of is not an error.
  //
  // Returns the path to redirect to. A path rather than a full URL: the browser
  // is already on this origin, and building an absolute URL here would mean
  // guessing the base the caller was reached on. IT IS NOT ALWAYS THIS MODULE'S
  // SCREEN, and there are now FOUR things it can be:
  //
  //   * the federated flow's own entry point, when the application names
  //     exactly ONE usable relationship and the auto-redirect is left on;
  //   * the CHOOSER at /authn/select-idp, when it names more than one — a page
  //     with one button per partner and no password field;
  //   * the KERBEROS DOOR at /authn/spnego, when the mechanism resolved to
  //     `spnego` — integrated authentication, where the person types nothing
  //     and the credential is a service ticket;
  //   * the sign-in screen, for everything else.
  //
  // The caller cannot tell the four apart and must not: what it asked for is
  // "get this person authenticated and bring them back to returnTo", and which
  // identity provider does the authenticating — or whether the person was asked
  // — is not its business. That is the same property the buttons at the foot of
  // the screen have had all along; what changed is first that nobody has to
  // press one, and then that where there IS a choice it is this application's
  // partners being chosen between rather than every relationship in the
  // register.
  // ---------------------------------------------------------------------------
  beginAuthentication(opts) {
    const { log, randomId, federation } = this.deps;
    log.debug("Entering Authn.beginAuthentication(). protocol=" +
              (opts.protocol || '(unnamed)'));
    const returnTo = String(opts.returnTo || '');
    // Same-origin, and a path: see the header. A caller that gets this wrong is
    // a bug in this service rather than a hostile request, so it throws rather
    // than quietly signing somebody in and sending them somewhere else.
    if (returnTo.charAt(0) !== '/' || returnTo.charAt(1) === '/') {
      throw new Error('beginAuthentication() needs a path on this service to ' +
                      'return to, not "' +
                      returnTo + '".');
    }
    // ---------------------------------------------------------------------
    // HOME REALM DISCOVERY BY CONFIGURATION, and it happens BEFORE a pending
    // record is written because there is nothing pending: the browser is going
    // to a foreign identity provider and comes back to `/federation/acs/{id}`,
    // which finishes the sign-in through startSession() without this screen
    // ever being drawn. A record minted here would be one nothing could ever
    // spend.
    //
    // `returnTo` has already been checked to be a path on this service, and
    // `federation_sp.ts` checks it AGAIN on the way in — see decision 4 there.
    // Two checks on one value is deliberate: this one catches a caller's bug
    // and that one catches somebody handing the federated entry point a
    // returnTo of their own.
    // ---------------------------------------------------------------------
    const chosen = this.mechanismFor(opts.application);
    const home = chosen.federation;
    if (home && home.relationship && home.auto) {
      const target = federation.PATHS.login + '/' +
        encodeURIComponent(home.relationship.fedId) +
        '?returnTo=' + encodeURIComponent(returnTo) +
        // WHICH APPLICATION THIS SIGN-IN IS FOR, carried onward so that the
        // relationship's per-application counts can be moved when it completes.
        // This service knows the pair HERE and only here — the assertion comes
        // back to /federation/acs/{id}, which is handed a signed document about
        // a person and nothing at all about what they were signing in to.
        //
        // IT IS A HINT AND NOT AN AUTHORITY, which federation.js says at length
        // where it is spent: the parameter rides on an endpoint anybody can
        // reach, so what makes it safe to write down is that recordUse() checks
        // the pair against the live register rather than believing this.
        '&application=' + encodeURIComponent(String(opts.application || ''));
      log.info('authn: "' + String(opts.application) + '" authenticates ' +
               'through the federation relationship "' +
               home.relationship.fedId +
               '"' + (chosen.source === 'relationship'
                        ?
                        ', because the identity-provider-side relationship "' +
                          chosen.via + '" brokers it there'
                        : '') +
               ', so this sign-in goes straight there rather than to the ' +
               'sign-in screen.' +
               // SAID HERE OR NOWHERE. This is the one branch that draws no
               // page, so a value on the entry that names something unusable
               // has no banner to appear on — and the flow works, which is
               // exactly why nobody would go looking. An operator who meant to
               // offer two partners and is offering one needs to be told by the
               // log.
               (home.problems && home.problems.length
                  ? ' ' + home.problems.length + ' other value(s) on that ' +
                    'entry name a relationship this service cannot use, and ' +
                    'no page is drawn to say so: ' + home.problems.join(' ')
                  : ''));
      log.debug("Leaving Authn.beginAuthentication(). Federated to " +
                home.relationship.fedId + ".");
      return target;
    }
    // ---------------------------------------------------------------------
    // MORE THAN ONE USABLE PARTNER: THE CHOOSER, AND WHY IT IS A PAGE OF ITS
    // OWN RATHER THAN THE SCREEN BELOW WITH THE PASSWORD BOX HIDDEN.
    //
    // `home.relationship` is deliberately null the moment there is a choice
    // (see federationFor()), so the branch above cannot fire and pick the first
    // partner for somebody. What is left is a question, and a question needs a
    // page.
    //
    // The alternative was the sign-in screen drawn with only its buttons. It
    // was refused because that page is the AUTHENTICATION SERVICE'S own screen:
    // it carries `username`, `password`, `kc-login` and `kc-cancel`, it POSTs
    // to a handler that signs somebody in on a typed name, and every one of
    // those element ids is what four tests and a person's muscle memory look
    // for. Hiding the form would leave a page that is a sign-in screen in
    // everything but what it shows, and the first time somebody re-added a
    // field to it the chooser would grow a password box nobody asked for.
    //
    // `auto` STILL DECIDES WHETHER A SCREEN IS DRAWN, AND IT MEANS WHAT IT
    // ALWAYS MEANT: "without the sign-in screen". With one partner that is a
    // redirect; with several it is THIS PAGE, which is the sign-in screen's job
    // done without the sign-in screen. What it never means is "pick one for
    // them" — there is no value of a boolean that can say which identity
    // provider somebody's employer is.
    //
    // SO auto=FALSE WITH SEVERAL PARTNERS IS THE SCREEN, with one button per
    // partner under the password box, which is exactly what auto=FALSE has done
    // since it existed — "keep the screen, where the partner is then the only
    // button offered", now with the partners plural. That is why this branch
    // tests it: a chooser drawn for an application that asked to keep its
    // sign-in screen would be this attribute quietly meaning the opposite of
    // what it says, on the one page where the password box is the point.
    //
    // The record is minted through the same store the screen uses, which is
    // what keeps `returnTo` server-side and out of the URL — federation_sp.ts's
    // decision 3, one layer up. Without it the chooser would be a page carrying
    // a return address anybody could rewrite, and the buttons on it would be an
    // open redirect with a heading.
    // ---------------------------------------------------------------------
    const choosing = !!home && home.auto && !home.relationship &&
                     home.usable.length > 1;
    // ---------------------------------------------------------------------
    // THE THREE MECHANISMS THAT STILL DRAW THIS SCREEN, folded into the record
    // the screen is drawn from rather than handled beside it — so that a
    // relationship configuring `password-mfa` and a RequestedAuthnContext
    // demanding two factors produce ONE screen and not two code paths that
    // could come to differ.
    //
    // `spnego` IS THE FOURTH AND IT DRAWS NO SCREEN, which is why it is
    // resolved here beside them and spent below the record rather than folded
    // into what the screen offers: it is a redirect, like the federated branch
    // above, and the only thing it has in common with these three is that it
    // loses to forceMfa. That collision is argued where it is made.
    //
    // forceMfa WINS OVER forcePasswordless and says so in the log. They are
    // mutually exclusive by construction — one enum value, one mechanism — but
    // `opts.forceMfa` does not come from the register at all: it comes from the
    // request a protocol module is answering, and a caller that has been told
    // two factors are required does not get a one-factor answer because a
    // relationship preferred one. `webauthn` here is PASSWORDLESS, which is amr
    // ["hwk"] and a single factor, however phishing-resistant it is.
    // ---------------------------------------------------------------------
    const forceMfa = !!opts.forceMfa || chosen.mechanism === 'password-mfa';
    let forcePasswordless = chosen.mechanism === 'webauthn';
    // ---------------------------------------------------------------------
    // AND THE SAME COLLISION A THIRD TIME, for the mechanism added on
    // 2026-08-26. A Kerberos ticket claims whatever its own flags claim — one
    // factor for `pre-authent`, two only where `hw-authent` is there beside it
    // (see `factorsFor()` in kerberos/spnego_authn.ts) — so it cannot be
    // PROMISED to answer a caller that demanded two. The demand wins, exactly
    // as it wins over passwordless WebAuthn and for the identical reason: a
    // request for two factors answered with one is the fake `acr_values` and
    // `wauth` exist to prevent.
    //
    // What that costs is worth stating, because it is not nothing: somebody at
    // a domain-joined machine holding a perfectly good hardware-backed ticket
    // is sent to a password box. The alternative is to send them to the SPNEGO
    // door and find out — and the door cannot refuse them at that point,
    // because by the time the flags are readable the ticket has been accepted
    // and the only options left are to mint a session claiming one factor or to
    // throw away a successful authentication. Refusing to promise is the honest
    // half of that.
    // ---------------------------------------------------------------------
    let integrated = chosen.mechanism === 'spnego';
    const forceKey = !!opts.forceKey;
    if (integrated && forceKey && !forceMfa) {
      log.info('authn: the configured mechanism for "' +
               String(opts.application || '(none)') + '" is a Kerberos ' +
               'ticket over SPNEGO, and this request demands a security key, ' +
               'so the demand wins: the screen asks for the key.');
      integrated = false;
    }
    if (integrated && forceMfa) {
      log.info('authn: the configured mechanism for "' +
               String(opts.application || '(none)') + '" is a Kerberos ' +
               'ticket over SPNEGO, and this request demands two factors, so ' +
               'the demand wins: the screen asks for a password and a key. A ' +
               'ticket claims what its own flags claim and this service ' +
               'cannot promise in advance that they will claim two.');
      integrated = false;
    }
    if (forcePasswordless && forceMfa) {
      log.info('authn: the configured mechanism for "' +
               String(opts.application || '(none)') + '" is a passwordless ' +
               'security key, and this request demands two factors, so the ' +
               'demand wins: the screen asks for a password and a key. One ' +
               'factor does not answer a request for two, however ' +
               'phishing-resistant that factor is.');
      forcePasswordless = false;
    }
    // A SIGN-IN AS ONE NAMED PERSON (#109, 2026-09-22): federation's
    // link-at-first-sign-in, where a partner named an existing person and
    // they must prove they ARE that person before their account is linked.
    // The screen draws the name fixed, and the POST reads it off the RECORD —
    // a typed name is not read at all — so this sign-in can only ever be a
    // sign-in as them. No passwordless key and no anonymous session: the
    // password is what the linking rests on.
    const lockedUsername = String(opts.lockedUsername || '').trim();
    const record = {
      id: randomId(18),
      returnTo: returnTo,
      details: Array.isArray(opts.details) ? opts.details : [],
      hint: lockedUsername || String(opts.hint || ''),
      lockedUsername: lockedUsername,
      forceMfa: forceMfa,
      // A SECURITY KEY DEMANDED (2026-09-17) — alone or after a password; see
      // the entry point's header. On the record for `forcePasswordless`'s
      // reason: the POST at the other end is an answer, not the question.
      forceKey: forceKey,
      // Set only by a relationship configuring `webauthn`. Nothing a protocol
      // module passes can turn it on: a caller asking for a passwordless
      // sign-in is a caller choosing somebody else's authenticator for them,
      // which is a deployment decision and not a request parameter.
      forcePasswordless: forcePasswordless,
      // Set only by a mechanism of `spnego` that survived the collision above.
      // It is on the RECORD rather than re-derived at the screen for the reason
      // `forcePasswordless` is: what the screen offers has to be what
      // beginAuthentication() decided, and re-deriving it from a config read at
      // render time would quietly drop a demand a protocol module made minutes
      // ago.
      integrated: integrated,
      // Set by a mechanism of `wallet` (#38's follow-ups). It does NOT lose to
      // forceMfa: the wallet door asks for a second factor after the
      // presentation when two were demanded.
      walletDoor: chosen.mechanism === 'wallet',
      mechanism: chosen.mechanism,
      mechanismSource: chosen.source,
      mechanismVia: chosen.via,
      // The problem is on the RECORD and not only inside `federation`, because
      // the two sources fail differently: an application entry naming an
      // unusable relationship still produces a `federation` object to hang it
      // on, and a BROKERING relationship whose onward partner is disabled
      // produces no such object at all — there is nothing usable to describe.
      // Reading it from one place is what stops the second case being the
      // silent fallback the first case was made loud to prevent.
      mechanismProblem: chosen.problem || '',
      protocol: opts.protocol || 'OAuth 2.0 / OIDC',
      // Carried so the screen can offer the RIGHT partners rather than every
      // usable one, and so that a relationship this application names and
      // cannot use is reported instead of being replaced by a password box.
      application: String(opts.application || ''),
      federation: home,
      expires: Date.now() + this.pendingTtlMs()
    };
    pending.set(record.id, record);
    pending.forEach(function (v, k) {
      if (v.expires < Date.now()) pending.delete(k);
    });
    // ONE RECORD, TWO PAGES, AND THE PAGE IS THE ONLY DIFFERENCE. The chooser
    // reads the same record the screen does — same store, same ten-minute
    // expiry, same returnTo — so a person who chooses a partner and a person
    // who types a name are spending the same pending authentication. That is
    // why the record is built above this branch rather than inside each of
    // them: two constructions would be two places for `returnTo` to be
    // forgotten, and a federated sign-in that succeeds and lands somebody on a
    // page nobody asked for is the failure federatedButtons() already carries a
    // comment about.
    if (choosing) {
      log.info('authn: "' + String(opts.application || '(none)') + '" names ' +
               home.usable.length + ' usable federation relationships (' +
               home.usable.map(function (one) { return one.id; }).join(', ') +
               '), so this sign-in asks which one rather than choosing.' +
               (home.problems.length
                  ? ' ' + home.problems.length + ' more value(s) on that ' +
                    'entry name something this service cannot use and are ' +
                    'shown on the page as such.'
                  : ''));
      log.debug("Leaving Authn.beginAuthentication(). " + record.id +
                " goes to the chooser and will return to " + returnTo + ".");
      return SELECT_IDP_PATH + '?authn=' + encodeURIComponent(record.id);
    }
    // ---------------------------------------------------------------------
    // INTEGRATED AUTHENTICATION: STRAIGHT TO THE KERBEROS DOOR.
    //
    // A FOURTH thing this function can answer with, and it is the federation
    // auto-redirect's sibling — home realm discovery by configuration, for a
    // home realm that is a Kerberos realm rather than a foreign identity
    // provider. The caller still cannot tell: what it asked for is "get this
    // person authenticated and bring them back to returnTo".
    //
    // IT SPENDS A PENDING RECORD, WHERE THE FEDERATION BRANCH DOES NOT, and the
    // difference is worth knowing rather than looking like an inconsistency.
    // A federated sign-in LEAVES this origin and comes back to
    // `/federation/acs/{id}`, an endpoint that finishes the whole thing through
    // startSession() and never draws this module's screen — so a record minted
    // for it would be one nothing could spend. `/authn/spnego` never leaves:
    // the 401 and the token are the same URL fetched twice, the record is what
    // carries `returnTo` across those two fetches, and it is ALSO what the
    // fallback link on every page of that door points back into. That is the
    // whole reason the door takes an `?authn=` and no `returnTo` of its own —
    // there is no open-redirect surface on it at all.
    // ---------------------------------------------------------------------
    if (record.integrated) {
      log.info('authn: "' + String(opts.application || '(none)') + '" ' +
               'authenticates with a Kerberos ticket over SPNEGO' +
               (chosen.source === 'relationship'
                  ? ', because the identity-provider-side relationship "' +
                    chosen.via + '" says so'
                  : ', because its entry under ou=applications declares it') +
               ', so this sign-in goes straight to ' + SPNEGO_PATH +
               ' rather than to the sign-in screen. A client with no ticket ' +
               'meets a 401 there and a link back to this screen; nothing is ' +
               'lost, because the request is on the pending record either ' +
               'way.');
      log.debug("Leaving Authn.beginAuthentication(). " + record.id +
                " goes to the Kerberos door and will return to " + returnTo +
                ".");
      return SPNEGO_PATH + '?authn=' + encodeURIComponent(record.id);
    }
    // ---------------------------------------------------------------------
    // A WALLET: STRAIGHT TO THE WALLET DOOR (#38's follow-ups), the Kerberos
    // branch's sibling and for its reasons — the record carries `returnTo`,
    // and every page of that door links back to the screen.
    // ---------------------------------------------------------------------
    if (record.walletDoor) {
      log.info('authn: "' + String(opts.application || '(none)') + '" ' +
               'authenticates with a wallet' +
               (chosen.source === 'relationship'
                  ? ', because the identity-provider-side relationship "' +
                    chosen.via + '" says so'
                  : ', because its entry under ou=applications declares it') +
               ', so this sign-in goes straight to ' + WALLET_PATH + '.');
      log.debug("Leaving Authn.beginAuthentication(). " + record.id +
                " goes to the wallet door.");
      return WALLET_PATH + '?authn=' + encodeURIComponent(record.id);
    }
    log.debug("Leaving Authn.beginAuthentication(). " + record.id +
              " will return to " +
              returnTo + ".");
    return LOGIN_PATH + '?authn=' + encodeURIComponent(record.id);
  }

  // Back where they came from, with the outcome on the query string. An error
  // is named in `authn_error` and the CALLER decides what its protocol does
  // about it; a success carries nothing at all, because the session cookie is
  // the answer and a parameter saying so would be a second, weaker way to ask.
  // A STEP WHOSE SIGN-IN DEMANDS A SECURITY KEY (2026-09-17) is answered by
  // the key and by nothing else. The links to these two screens are not drawn
  // under the demand; this is the check, because a link that is not drawn is
  // still a URL. Refused BEFORE the code is checked, so a code is not spent
  // on a step it could not finish. True when it answered.
  private keyDemandRefuses(res, step, what) {
    const { log, errorCodes, oauthError } = this.deps;
    log.debug("Entering Authn.keyDemandRefuses().");
    if (!step || !step.authn || !step.authn.forceKey) {
      log.debug("Leaving Authn.keyDemandRefuses(). No key was demanded.");
      return false;
    }
    log.info('authn: ' + what + ' was offered for "' + step.username + '" ' +
             'where the sign-in demands a security key; refused.');
    errorCodes.mark(res, 'STS-AUTHN-0204');
    oauthError(res, 400, 'invalid_request',
      'This sign-in demands a security key, and ' + what + ' does not ' +
      'answer that. Use the security key on the previous screen.');
    log.debug("Leaving Authn.keyDemandRefuses(). Refused.");
    return true;
  }

  // A SESSION REFUSED AT THE END OF A SCREEN'S CEREMONY (2026-09-17; every
  // refusal since 2026-09-22, #62 P0). The account was disabled between the
  // password and the second factor, the passwordless key was presented for a
  // disabled account, the issuance policy refused a door the screen had not
  // asked it at, or the directory holds no entry to be the subject of. The
  // sign-in screen again rather than a return to the caller, whose request
  // would send the browser straight back here with nothing said.
  //
  // What the screen says follows the password door's own two answers: the
  // issuance policy's sentence, which that door already shows before a
  // password is typed, and otherwise only that authentication failed — the
  // enumeration argument `verify()`'s callers make, which a disabled account
  // and a missing entry both fall under. Why is read off the `detail` the
  // caller handed `startSession()` (see the block above that function); a
  // caller that passed none gets the disabled check it always had.
  // True when it answered.
  private refusedSession(res, base, record, username, started, detail) {
    const { log, accountState, errorCodes } = this.deps;
    log.debug("Entering Authn.refusedSession().");
    if (started) {
      log.debug("Leaving Authn.refusedSession(). Not refused.");
      return false;
    }
    const said = detail || {};
    const code = said.refusedWith ||
      (accountState.isDisabled(username) ? 'STS-AUTHN-0201'
                                         : 'STS-AUTHN-0010');
    const message = code === 'STS-AUTHN-0010' && said.refusedWhy
      ? String(said.refusedWhy)
      : 'Authentication failed for ' + username + '.';
    log.info('authn: the session for "' + username + '" was refused at the ' +
             'end of the sign-in screen (' + code + '); drawing the screen ' +
             'again.');
    // THE SCREEN IS DRAWN FOR A RECORD THAT STILL EXISTS. Every door deletes
    // the pending sign-in before it asks for the session, so the form redrawn
    // here would name a record the next POST cannot find — a second failure
    // saying nothing about the first. Put back while it has time left, so
    // the person can sign in as somebody else, or again once an administrator
    // has acted.
    if (record && record.id && !pending.has(record.id) &&
        !(record.expires < Date.now())) {
      pending.set(record.id, record);
    }
    errorCodes.mark(res, code);
    this.sendLoginPage(res, this.loginPage(base, record, message));
    log.debug("Leaving Authn.refusedSession(). Answered.");
    return true;
  }

  private returnToCaller(res, record, error, description) {
    const { log } = this.deps;
    log.debug("Entering Authn.returnToCaller(). error=" + (error || '(none)'));
    let target = record.returnTo;
    if (error) {
      target += (target.indexOf('?') === -1 ? '?' : '&') +
        'authn_error=' + encodeURIComponent(error) +
        '&authn_error_description=' + encodeURIComponent(description || '');
    }
    // ---------------------------------------------------------------------
    // 303, NOT 302, AND NEVER 307 — RFC 9700 section 4.12.
    //
    // This is the redirect that follows the POST carrying somebody's username
    // and password, and it is the one place in this service where the choice of
    // status code is a security question rather than a formality. A 307
    // PRESERVES the method and the body, so the browser would repeat the POST —
    // credentials and all — to wherever this points, which is a URL the CALLING
    // PROTOCOL composed. That is the section's whole point: the authorization
    // server hands the user's password to the client without either of them
    // doing anything wrong.
    //
    // This service has never used 307. What it used was 302, whose behaviour
    // after a POST is historically ambiguous — every browser turns it into a
    // GET, and the specification does not say they must. 303 says it: change
    // the method to GET. The section asks for 303 by name and there is no
    // reason not to give it.
    //
    // It is NOT gated on RFC 9700 mode, unlike the refusals that mode adds. No
    // client can tell the difference — a browser does the same thing with both
    // — so gating it would leave the default deployment with the ambiguous one
    // and buy nobody an exercise.
    //
    // `returnToCaller()` is the single funnel: the password step and the
    // WebAuthn step both leave through here, so there is one place where this
    // is decided rather than two that could come to differ.
    // ---------------------------------------------------------------------
    res.redirect(303, target);
    log.debug("Leaving Authn.returnToCaller(). Sent the browser to " + target +
              " " +
        "with a 303.");
  }

  // ---------------------------------------------------------------------------
  // SPEND THE RECORD AND GO BACK. The two lines every successful sign-in in
  // this module already runs, as one function, so that a sign-in performed
  // SOMEWHERE ELSE runs the same two.
  //
  // The password path, the WebAuthn path and the SPNEGO door all end with a
  // pending record that has been used and a browser that has to be sent back to
  // what it interrupted. Doing that in three places would be three chances to
  // leave the record behind — which is a sign-in form that still works after
  // somebody has signed in with it — and three places for the 303 to become a
  // 302 or, worse, a 307.
  //
  // It takes no error parameter, and that is deliberate rather than an
  // omission: `returnToCaller()` is still the function for a refusal, and the
  // one caller outside this module has nothing to refuse WITH. A Kerberos
  // sign-in that fails draws a page with the password screen on it, because the
  // person can still sign in — telling the calling protocol `access_denied`
  // would end a flow that has not failed.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE FIRST FACTOR A SECOND-FACTOR STEP FOLLOWS (#38's follow-ups). A step
  // minted by the password screen carries none and means `pwd`, which is what
  // every such step meant before a wallet could be a first factor; one minted
  // after a wallet sign-in carries `['pop']` (or what that presentation
  // claimed). Every second-factor door builds its `amr` from this, so a
  // session never claims a password nobody typed.
  // ---------------------------------------------------------------------------
  private firstAmrOf(step: any): string[] {
    const { log } = this.deps;
    log.debug("Entering Authn.firstAmrOf().");
    const first = step && Array.isArray(step.firstAmr) && step.firstAmr.length ?
      step.firstAmr.map(String) : ['pwd'];
    log.debug("Leaving Authn.firstAmrOf(). " + first.join(','));
    return first;
  }

  // A pending second-factor step, read-only, for the wallet door: a wallet
  // may BE the second factor after a password (`vc_signin.ts`). An expired
  // step is dropped on the way past, as pendingFor() drops a record.
  mfaStepFor(id: unknown): any {
    const { log } = this.deps;
    log.debug("Entering Authn.mfaStepFor().");
    const step = pendingMfa.get(String(id || ''));
    if (!step) {
      log.debug("Leaving Authn.mfaStepFor(). None.");
      return null;
    }
    if (step.expires < Date.now()) {
      pendingMfa.delete(String(id));
      log.debug("Leaving Authn.mfaStepFor(). Expired.");
      return null;
    }
    log.debug("Leaving Authn.mfaStepFor(). Found.");
    return step;
  }

  // ---------------------------------------------------------------------------
  // A WALLET AS THE SECOND FACTOR (#38's follow-ups): the step a password
  // sign-in minted, finished by a verified presentation of a credential this
  // realm issued to THE SAME PERSON. `outcome` is `vc_verifier.ts`'s
  // `signInOutcome()`. Answers the session, or `{ refused, why }`.
  //
  // **THE SAME PERSON, BY SUBJECT.** A step names the person the password was
  // typed for; a wallet presenting somebody else's credential is refused
  // rather than signing either of them in — two factors from two people are
  // not two factors.
  // **NOT A WALLET TWICE.** A step whose first factor was a wallet is not
  // finished by another presentation: one key proved twice is one factor.
  // ---------------------------------------------------------------------------
  finishWithWallet(req: any, res: any, mfaId: string, outcome: any): any {
    const { log, userFor } = this.deps;
    log.debug("Entering Authn.finishWithWallet().");
    const step = this.mfaStepFor(mfaId);
    if (!step) {
      log.debug("Leaving Authn.finishWithWallet(). No step.");
      return { refused: 'expired', why: 'This second-factor step has ' +
               'expired. Start the request again from the application.' };
    }
    const first = this.firstAmrOf(step);
    if (first.indexOf('pop') >= 0) {
      log.debug("Leaving Authn.finishWithWallet(). A wallet twice.");
      return { refused: 'same-factor', why: 'The first factor of this ' +
               'sign-in was already a wallet, and one key proved twice is ' +
               'one factor. Use your authenticator app, your security key or ' +
               'your password.' };
    }
    const stepSub = String((userFor(step.username) || {}).sub || '');
    if (outcome.username !== step.username ||
        (stepSub && outcome.subject && stepSub !== outcome.subject)) {
      log.debug("Leaving Authn.finishWithWallet(). A different person.");
      return { refused: 'other-person', why: 'The credential your wallet ' +
               'presented was issued to somebody other than the person whose ' +
               'password was entered, so neither is signed in.' };
    }
    pendingMfa.delete(String(mfaId));
    const amr = first.concat((outcome.amr || ['pop']).filter(function (one) {
      return first.indexOf(one) < 0;
    }));
    const session = this.startSession(res, step.username, amr, 'mfa',
      step.authn.protocol, {
        request: req,
        // The sign-in's assessment (#62 P3), made when the step was minted.
        risk: step.risk,
        // Which credential answered last (#62 P0): the wallet presentation.
        credential: { kind: 'wallet' },
        application: step.authn.application || '',
        method: 'a password and a wallet (a verifiable presentation, ' +
                'proof of possession of the key its credential is bound to)',
        note: 'Two factors: the password typed at the sign-in screen, then a ' +
              'verified presentation of a credential this realm issued to ' +
              'the same person.',
        summary: step.username + ' completed the second factor with a wallet'
      });
    if (!session) {
      log.debug("Leaving Authn.finishWithWallet(). The policy refused.");
      return { refused: 'policy', why: 'The issuance policy refused this ' +
               'session.' };
    }
    this.returnToCaller(res, step.authn, null, null);
    log.debug("Leaving Authn.finishWithWallet(). Signed in.");
    return session;
  }

  // ---------------------------------------------------------------------------
  // A SECOND FACTOR AFTER A WALLET (#38's follow-ups). Called by the wallet
  // door once a presentation has verified and named a person, instead of
  // starting a session, and it answers whether it took over the response:
  //
  //   * NO SECOND FACTOR IS NEEDED — the request did not demand two
  //     (`record.forceMfa`), no requirement applies (`authn.mfaRequired`,
  //     the account's own), the person holds no second factor they are
  //     configured to be asked for (`mfaRequired`), or the presentation
  //     already claimed two (`acr` `mfa`, from a key attestation) — and it
  //     answers `{ handled: false }`: the door starts the session itself.
  //   * ONE IS NEEDED, and the issuance policy is asked FIRST, as the
  //     password screen asks it before its own second factor. The step is
  //     minted with `firstAmr` — the wallet's `amr` — and the person's
  //     configured factor is drawn: their security key, their authenticator
  //     app, or, where they hold neither, their PASSWORD
  //     (`PASSWORD_FACTOR_PATH`), which every person here can be asked for.
  //     A requirement with nothing enrolled draws the enrolment step exactly
  //     as the password screen does.
  // ---------------------------------------------------------------------------
  beginSecondFactorAfterWallet(req: any, res: any, record: any,
                               username: string, outcome: any,
                               assessment?: any): any {
    const { log, randomId, gate, credentials, crypto, config } = this.deps;
    log.debug("Entering Authn.beginSecondFactorAfterWallet(). username=" +
              username);
    const enrolled = credentials.mechanismsFor(username);
    const requirement = credentials.mfaRequirementFor(username);
    const already = String(outcome.acr || '') === 'mfa';
    // -----------------------------------------------------------------------
    // THE RISK OF THE SIGN-IN, ASKED FIRST (#62 P3) — with the factors the
    // presentation claimed. HIGH refuses; a step-up the policy names is a
    // second factor NEEDED, whatever else says so, and a security key is
    // then the only one offered. A person holding no factor that answers it
    // is refused rather than offered enrolment, as at the password screen.
    // -----------------------------------------------------------------------
    const engine = assessment ? this.riskEngine() : null;
    const risk = engine ? engine.riskOf(assessment) : null;
    let riskFactor = '';
    if (engine) {
      const riskAnswer = gate.check({
        application: String(record.application || ''),
        kind: gate.ISSUANCE.SESSION,
        subject: { kind: 'user', name: username, authenticated: true },
        claims: null,
        risk: engine.factsOf(risk, outcome.amr || ['pop'], outcome.acr || '1')
      });
      if (!riskAnswer.allowed && riskAnswer.risk &&
          !riskAnswer.risk.observed) {
        const holdsKey = enrolled.mfaKeys + enrolled.primaryKeys > 0;
        if (riskAnswer.risk.action === 'refuse' ||
            (riskAnswer.risk.factor === 'security-key' && !holdsKey)) {
          const code = riskAnswer.risk.action === 'refuse' ? 'STS-RISK-0016'
                                                           : 'STS-RISK-0018';
          this.settleRisk(risk, { decision: riskAnswer.risk.action,
                                  errorCode: code,
                                  policy: riskAnswer.policy });
          log.debug("Leaving Authn.beginSecondFactorAfterWallet(). Refused " +
                    "on risk.");
          return { handled: false, refused: 'Authentication failed.',
                   onRisk: true, errorCode: code };
        }
        riskFactor = riskAnswer.risk.factor;
      }
    }
    const needed = !!riskFactor ||
      (!already && (!!record.forceMfa || requirement.required ||
                    !!enrolled.mfaRequired));
    if (!needed) {
      log.debug("Leaving Authn.beginSecondFactorAfterWallet(). Not needed.");
      return { handled: false };
    }
    const roleAnswer = gate.check({
      application: String(record.application || ''),
      kind: gate.ISSUANCE.SESSION,
      subject: { kind: 'user', name: username, authenticated: true },
      claims: null,
      // The roles alone: the risk was asked above.
      risk: null
    });
    if (!roleAnswer.allowed) {
      log.debug("Leaving Authn.beginSecondFactorAfterWallet(). Refused.");
      return { handled: false, refused: roleAnswer.why };
    }
    const base = this.deps.baseUrlOf(req);
    const firstAmr = [].concat(outcome.amr || ['pop']).map(String);
    pending.delete(record.id);
    const configured = riskFactor === 'security-key' ? 'webauthn'
      : (enrolled.secondFactor || '');
    if (requirement.required && !configured && !riskFactor) {
      const offered = this.enrolmentOffered();
      if (offered.totp || offered.webauthn) {
        const setupId = randomId(24);
        pendingMfa.set(setupId, {
          authn: record, username: username,
          challenge: crypto.randomBytes(32).toString('base64url'),
          factor: 'enrol', alternate: '', backup: false, passwordless: false,
          requiredBy: requirement.byUser ? 'account' : 'realm',
          firstAmr: firstAmr,
          expires: Date.now() + this.mfaStepTtlMs()
        });
        this.sendMfaSetupPage(res, this.mfaSetupPage(setupId, username,
                                                     offered, ''));
        log.debug("Leaving Authn.beginSecondFactorAfterWallet(). Enrolment.");
        return { handled: true };
      }
    }
    const factor = configured || 'password';
    const mfaId = randomId(24);
    pendingMfa.set(mfaId, {
      authn: record, username: username,
      challenge: crypto.randomBytes(32).toString('base64url'),
      factor: factor,
      alternate: riskFactor === 'security-key' ? ''
        : ((factor === 'webauthn' && enrolled.totp) ? 'totp'
          : ((factor === 'totp' && enrolled.mfaKeys > 0) ? 'webauthn' : '')),
      backup: riskFactor !== 'security-key' && enrolled.backupCodes
        ? enrolled.backupCodes.remaining > 0 : false,
      passwordless: false,
      firstAmr: firstAmr,
      // A password is always offered after a wallet, beside whatever else the
      // person holds: it is the factor everybody here has — except under a
      // security key demanded on risk (#62 P3).
      passwordAlternate: factor !== 'password' &&
                         riskFactor !== 'security-key',
      // The sign-in's assessment (#62 P3), for the finisher's session.
      risk: assessment || undefined,
      expires: Date.now() + this.mfaStepTtlMs()
    });
    void config;
    log.info('authn: "' + username + '" signed in with a wallet and a second ' +
             'factor is needed (' + (record.forceMfa ? 'the request demands ' +
             'two' : requirement.required ? 'required of them' :
             'they hold one') + '); asking for ' + factor + '.');
    if (factor === 'totp') {
      this.sendTotpPage(res, this.totpPage(base, mfaId, username, '', ''));
    } else if (factor === 'webauthn') {
      this.sendWebauthnPage(res, this.webauthnPage(base, mfaId, username, ''));
    } else {
      this.sendPasswordFactorPage(res, this.passwordFactorPage(mfaId, username,
                                                               ''));
    }
    log.debug("Leaving Authn.beginSecondFactorAfterWallet(). " + factor + ".");
    return { handled: true };
  }

  // The password-as-second-factor page. No script.
  private passwordFactorPage(mfaId: string, username: string,
                             error: string): string {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering Authn.passwordFactorPage().");
    const step = pendingMfa.get(mfaId);
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><title>Your password — mock authentication ' +
      'service</title><style>' + CARD_CSS + '</style></head><body><div ' +
      'class="card"><h1>Your password</h1><p class="sub">Second factor for ' +
      '<code>' + xmlEscape(username) + '</code>, after your wallet.</p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      '<form method="post" action="' + PASSWORD_FACTOR_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<label for="password">Password</label><input type="password" ' +
      'id="password" name="password" autocomplete="current-password" ' +
      'autofocus>' +
      '<button type="submit" id="password-factor-submit">Sign in</button>' +
      '</form><div class="meta"><div>Your wallet has already presented a ' +
      'credential this service issued to you. On success the session ' +
      'records amr ' + xmlEscape(JSON.stringify(
        this.firstAmrOf(step).concat(['pwd']))) + ' and acr "mfa".</div>' +
      (step && step.alternate === 'totp'
        ? '<div><a href="' + TOTP_PATH + '?mfa=' + encodeURIComponent(mfaId) +
          '">Use a code from your authenticator app instead</a></div>'
        : '') +
      '</div></div></body></html>\n';
    log.debug("Leaving Authn.passwordFactorPage().");
    return html;
  }

  // No policy of its own: no script, so the service-wide `script-src 'none'`.
  private sendPasswordFactorPage(res: any, html: string): void {
    const { log } = this.deps;
    log.debug("Entering Authn.sendPasswordFactorPage().");
    res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug("Leaving Authn.sendPasswordFactorPage().");
  }

  // The links a second-factor page draws for the factors a wallet adds: the
  // wallet itself after a password, and the password after a wallet.
  private walletFactorLinksHtml(mfaId: string, step: any): string {
    const { log, config } = this.deps;
    log.debug("Entering Authn.walletFactorLinksHtml().");
    if (!step) {
      log.debug("Leaving Authn.walletFactorLinksHtml(). No step.");
      return '';
    }
    const first = this.firstAmrOf(step);
    let out = '';
    if (first.indexOf('pop') < 0 && !step.passwordless &&
        config.value('oid4vp.signIn')) {
      out += '<div><a id="wallet-second-factor" href="' + WALLET_PATH +
        '?mfa=' + encodeURIComponent(mfaId) + '">Use your wallet ' +
        'instead</a></div>';
    }
    if (step.passwordAlternate) {
      out += '<div><a id="password-second-factor" href="' +
        PASSWORD_FACTOR_PATH + '?mfa=' + encodeURIComponent(mfaId) +
        '">Use your password instead</a></div>';
    }
    log.debug("Leaving Authn.walletFactorLinksHtml().");
    return out;
  }

  completeAuthentication(res, record) {
    const { log } = this.deps;
    log.debug("Entering Authn.completeAuthentication(). id=" + record.id);
    pending.delete(record.id);
    this.returnToCaller(res, record, null, null);
    log.debug("Leaving Authn.completeAuthentication(). Sent them back to " +
              record.returnTo + ".");
  }

  // The record a request names, or null — expired ones are dropped on the way
  // past, which is the only cleanup this store needs beyond the sweep above.
  pendingFor(id) {
    const { log } = this.deps;
    log.debug("Entering Authn.pendingFor(). id=" + (id || '(none)'));
    const record = pending.get(String(id || ''));
    if (!record) {
      log.debug("Leaving Authn.pendingFor(). No such authentication is " +
                "pending.");
      return null;
    }
    if (record.expires < Date.now()) {
      pending.delete(record.id);
      log.debug("Leaving Authn.pendingFor(). It had expired.");
      return null;
    }
    log.debug("Leaving Authn.pendingFor(). Found it.");
    return record;
  }

  // The partner buttons, or nothing at all. Nothing at all is the ordinary
  // state — a service with no federation configured must have a sign-in screen
  // byte for byte the one it always had, which is why this returns an empty
  // string rather than an empty section with a heading.
  private federatedOptionsHtml(record) {
    const { log, federation, config, errorCodes } = this.deps;
    log.debug("Entering Authn.federatedOptionsHtml().");
    // ---------------------------------------------------------------------
    // THE APPLICATION'S OWN PARTNER FIRST, AND ON ITS OWN.
    //
    // An entry naming a relationship has answered the question this list is
    // asking, so offering the other partners beside it would be putting the
    // discovery step back one line below the configuration that removed it.
    //
    // IT IGNORES `federation.loginButtons`, which the generic list below
    // respects, and the asymmetry is the point rather than an oversight: that
    // setting exists so that a service with no federation configured has a
    // sign-in screen byte for byte the one it always had, and an application
    // whose entry names a partner IS federation configured. The auto-redirect
    // above cannot consult a screen setting either — it never draws a screen —
    // so honouring it here would make the same configuration behave two ways
    // depending on one unrelated boolean.
    // ---------------------------------------------------------------------
    //
    // ALL OF THEM, NOT THE FIRST. `appFederationRelationship` holds a list, and
    // this screen is what a person meets when the auto-redirect is OFF — which
    // is precisely the configuration that says "let them choose". Drawing one
    // button for a list of two would make that setting mean the opposite of
    // what it says.
    const home = record.federation;
    if (home && home.usable && home.usable.length) {
      const many = home.usable.length > 1;
      // THE APPLICATION'S OWN PARTNERS, so the pair is named on every href —
      // see federatedButtons(). This is the branch where naming it is correct:
      // every option here came off this application's entry or off the
      // relationship brokering for it, which is exactly the pair federation.js
      // will agree to record.
      const html = this.federatedButtons(record,
        home.usable.map(function (one) { return one.option; }),
        'This application signs its users in at ' +
        (many ? 'one of these federated identity providers. Pick the one you ' +
                'have an account at'
              : 'a federated identity provider') +
        '. No password is typed here and none is checked there ' +
        'either as far as this service can tell — what it checks is the ' +
        'partner\'s signature.');
      log.debug("Leaving Authn.federatedOptionsHtml(). " + home.usable.length +
                " partner(s) this application names.");
      return html;
    }
    if (!config.value('federation.loginButtons')) {
      log.debug("Leaving Authn.federatedOptionsHtml(). " +
                "federation.loginButtons is off.");
      return '';
    }
    let options = [];
    try {
      options = federation.signInOptions();
    } catch (e) {
      // Swallowed with a reason: the sign-in screen is the last thing in this
      // service that may fail to draw. A federation register that throws costs
      // the buttons, never the password field underneath them.
      log.error(errorCodes.tag('STS-AUTHN-0017') +
                'authn: the federation register threw while building the ' +
                'sign-in screen and was ignored; the screen itself is ' +
                'unaffected: ' + e.message);
      log.debug("Leaving Authn.federatedOptionsHtml(). It threw.");
      return '';
    }
    if (!options.length) {
      log.debug("Leaving Authn.federatedOptionsHtml(). No usable partner is " +
                "configured.");
      return '';
    }
    // EVERY USABLE RELATIONSHIP IN THE REGISTER, WHICH IS NOT THIS
    // APPLICATION'S LIST — so no application is named on these hrefs,
    // deliberately. Somebody who picks one off here has signed in through a
    // partner nothing configured for this application, and counting that as a
    // use of the pair would put a number on /admin/federation/map that means
    // something other than what the page says it means.
    const html = this.federatedButtons(record, options,
      'Or sign in with a federated identity provider. No password is typed ' +
      'here and none is checked there either as far as this service can tell ' +
      '— what it checks is the partner\'s signature.');
    log.debug("Leaving Authn.federatedOptionsHtml(). " + options.length + " " +
        "partner(s) offered.");
    return html;
  }

  // The markup, once, for both of the lists above. One function because the two
  // differ only in WHICH partners and what the sentence over them says, and two
  // copies of an anchor carrying a returnTo is two chances to drop the returnTo
  // from one of them — which produces a federated sign-in that succeeds and
  // lands the person on a page nobody asked for.
  //
  // `application` IS PASSED RATHER THAN READ OFF THE RECORD, and that is the
  // one thing about this function worth a second look. `record.application` is
  // set on every pending sign-in — it is what the calling protocol was for —
  // but only SOME of these buttons are that application's OWN partners. The
  // generic list at the foot of the screen (`federation.loginButtons`) offers
  // every usable relationship in the register, and a person who picks one off
  // it has not used a partner the application is configured for; naming the
  // application on those hrefs would ask federation.js to record a pair it is
  // right to refuse, once per click, and fill the log with a warning about a
  // state nothing is wrong with.
  //
  // So the caller says which kind of list it is drawing, because the caller is
  // the only thing that knows.
  private federatedButtons(record, options, blurb, application?) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering Authn.federatedButtons(). " + options.length +
              " option(s).");
    // The whole original request rides along, so that whatever brought the
    // person here resumes once the partner has answered. It is
    // `record.returnTo`, which beginAuthentication() has already checked is a
    // path on this service.
    const back = encodeURIComponent(record.returnTo);
    const forApplication = String(application || '')
      ? '&application=' + encodeURIComponent(String(application))
      : '';
    const html = '<div class="fed"><p>' + blurb + '</p>' +
      options.map(function (one) {
        return '<a class="fedbtn" href="/federation/login/' +
          encodeURIComponent(one.id) +
          '?returnTo=' + back + forApplication + '">' + xmlEscape(one.label) +
          '<span>' + xmlEscape(one.protocolLabel) +
          (one.peer ? ' · ' + xmlEscape(one.peer) : '') + '</span></a>';
      }).join('') + '</div>';
    log.debug("Leaving Authn.federatedButtons().");
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE KERBEROS BUTTON, AND WHY IT IS OFFERED TO EVERY APPLICATION WITHOUT
  // ANYTHING BEING CONFIGURED.
  //
  // This is the same argument `federation.loginButtons` makes and it lands
  // harder here. A person standing at this screen is in the middle of SOMETHING
  // — an authorization request, a `wsignin1.0`, an `AuthnRequest`, the console
  // — and `record.returnTo` is that something, whole. A button that hands the
  // record to `/authn/spnego` therefore makes integrated Kerberos able to
  // satisfy every protocol this service speaks, for every application, with no
  // registration anywhere: the mechanism is a property of the PERSON's machine
  // rather than of the relying party, which is exactly what "integrated
  // authentication" has always meant in a Windows deployment.
  //
  // It is a LINK and not a form control, for `federatedButtons()`' reason: a
  // control in this form would post to the handler that signs somebody in on a
  // typed name, and this has to leave for an endpoint that will not.
  //
  // **IT IS WITHHELD UNDER `forceMfa`.** A ticket claims what its own flags
  // claim, which is usually one factor, and a caller that demanded two must not
  // be handed a session claiming one — the same refusal `beginAuthentication()`
  // makes to a CONFIGURED `spnego` mechanism, made again here because a button
  // is an offer and this offer could not be honoured. It says so rather than
  // vanishing, because a button that is there for everybody else and missing
  // here reads as a broken page.
  //
  // TWO SETTINGS, and they are not one. `krb5.spnegoAuthentication` is whether
  // the DOOR will sign anybody in; `krb5.spnegoLoginButton` is whether this
  // screen advertises it. A deployment that wants the door for a scripted
  // client and not for people at a browser sets the second false, and a screen
  // offering a button to a closed door is what the first check prevents.
  // ---------------------------------------------------------------------------
  private integratedOptionHtml(record) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.integratedOptionHtml().");
    if (!config.value('krb5.spnegoAuthentication') ||
        !config.value('krb5.spnegoLoginButton')) {
      log.debug("Leaving Authn.integratedOptionHtml(). Not offered.");
      return '';
    }
    if (record.forceKey && !record.forceMfa) {
      log.debug("Leaving Authn.integratedOptionHtml(). Withheld: a security " +
                "key was demanded.");
      return '<div class="fed"><p>Integrated Kerberos sign-in is not offered ' +
        'for this request: it demands a security key.</p></div>';
    }
    if (record.forceMfa) {
      log.debug("Leaving Authn.integratedOptionHtml(). Withheld: two factors " +
                "were demanded.");
      return '<div class="fed"><p>Integrated Kerberos sign-in is not offered ' +
        'for this request: it demands two factors, and a ticket claims ' +
        'whatever its own flags claim &mdash; usually one.</p></div>';
    }
    const html = '<div class="fed"><p>Or sign in with a Kerberos ticket, if ' +
      'this machine holds one. Nothing is typed and this service checks the ' +
      'ticket rather than a name &mdash; the only sign-in here that rests on ' +
      'a credential it genuinely verified.</p><a class="fedbtn" ' +
      'href="' + SPNEGO_PATH + '?authn=' +
      encodeURIComponent(record.id) + '">Sign in with Kerberos' +
      '<span>SPNEGO &middot; RFC 4559</span></a></div>';
    log.debug("Leaving Authn.integratedOptionHtml(). Offered.");
    return html;
  }

  // ---------------------------------------------------------------------------
  // THE WALLET BUTTON (2026-09-17, #38) — `integratedOptionHtml()`'s argument
  // made again, and it holds for the same reasons: a person at this screen is
  // in the middle of something, the record carries it, and whether somebody
  // holds a credential this realm issued is a fact about their wallet and not
  // about the relying party. So it is offered to every application with
  // nothing registered, whenever `oid4vp.signIn` is on.
  //
  // **OFFERED UNDER `forceMfa` TOO, SINCE #38's FOLLOW-UPS.** It was withheld
  // there, because a presentation proves one key. A wallet is now a first
  // factor that a second can follow (`beginSecondFactorAfterWallet()`), and
  // a presentation whose key attestation says the key is guarded by user
  // authentication claims two on its own — so the button says what will
  // happen instead of disappearing.
  //
  // ONE SETTING, where Kerberos has two: Kerberos keeps a door for scripted
  // clients that holds no screen, and a wallet sign-in has no use outside a
  // browser that is waiting to be signed in, so a switch that closed the
  // button and left the door open would describe a state nobody can use.
  // ---------------------------------------------------------------------------
  private walletOptionHtml(record) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.walletOptionHtml().");
    if (!config.value('oid4vp.signIn')) {
      log.debug("Leaving Authn.walletOptionHtml(). Not offered.");
      return '';
    }
    if (record.forceKey) {
      log.debug("Leaving Authn.walletOptionHtml(). Withheld: a security key " +
                "was demanded.");
      return '<div class="fed"><p id="wallet-withheld">Signing in with a ' +
        'wallet is not offered for this request: it demands a security ' +
        'key.</p></div>';
    }
    const html = '<div class="fed"><p>Or sign in with a wallet that holds ' +
      'a credential this service issued to you. Nothing is typed: your ' +
      'wallet proves it holds the key the credential is bound to.' +
      (record.forceMfa
        ? ' <span id="wallet-mfa-note">This request needs two factors, so ' +
          'you will be asked for a second one afterwards unless your ' +
          'wallet\'s key is attested to need your PIN or biometric.</span>'
        : '') + '</p>' +
      '<a class="fedbtn" id="wallet-signin" href="' + WALLET_PATH +
      '?authn=' + encodeURIComponent(record.id) + '">Sign in with a wallet' +
      '<span>OpenID4VP &middot; Digital Credentials API</span></a></div>';
    log.debug("Leaving Authn.walletOptionHtml(). Offered.");
    return html;
  }

  // Is a self-service password reset offered in this realm (#63)? Asked of
  // `common/mail_uses.ts` LAZILY — it reaches the credential store, which
  // this module must not load early — and "no" if it cannot be asked.
  private offersPasswordReset(): boolean {
    const { log } = this.deps;
    log.debug("Entering Authn.offersPasswordReset().");
    let offered = false;
    try {
      offered = !!require('../common/mail_uses').resetOffered();
    } catch (e) {
      log.debug("Caught in Authn.offersPasswordReset(): " +
                ((e && e.message) || e));
      offered = false;
    }
    log.debug("Leaving Authn.offersPasswordReset(). " + offered);
    return offered;
  }

  private loginPage(base, record, error) {
    const { log, xmlEscape, config, webauthnPolicy } = this.deps;
    log.debug("Entering Authn.loginPage(). protocol=" + record.protocol +
              (error ? ", showing an error" : ""));
    // What this realm will let a security key BE, read once for the two boxes
    // below. `/admin/webauthn` is where it is set; handleLogin() checks the
    // same three answers, because markup is what a person sees and the handler
    // is what decides.
    const keyPolicy = webauthnPolicy.settings();
    // A sign-in as one named person (#109): the name drawn fixed, and nothing
    // offered that is not a password — see beginAuthentication().
    const locked = String(record.lockedUsername || '');
    const page = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><title>Sign in — mock authentication ' +
      'service</title><style>' + CARD_CSS +
      '</style></head><body><div class="card">' +
      '<h1>Sign in</h1>' +
      '<p class="sub">Mock authentication service at <code>' + xmlEscape(base) +
      '</code></p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      (locked
        ? '<p class="sub"><strong>Link your account.</strong> A federation ' +
          'partner signed you in as <code>' + xmlEscape(locked) + '</code>, ' +
          'and that account is not linked to it yet. Sign in here as ' +
          xmlEscape(locked) + ' to link them; Cancel links nothing.</p>'
        : '') +
      '<form method="post" action="' + LOGIN_PATH + '">' +
      '<input type="hidden" name="authn_id" value="' + xmlEscape(record.id) +
      '">' + (this.fingerprinting()
        ? '<input type="hidden" name="device_fp" id="device-fp" value="">'
        : '') + '<label ' +
      'for="username">Username</label><input type="text" id="username" ' +
      'name="username" autocomplete="username" ' +
      (locked ? 'readonly ' : 'autofocus ') +
      'value="' + xmlEscape(record.hint) + '"><label ' +
      'for="password">Password</label><input type="password" id="password" ' +
      'name="password" autocomplete="current-password">' +
      // Two checkboxes rather than one, because a security key is two different
      // things here and the difference is what the tokens end up claiming:
      // ticked with a password it is a SECOND factor (amr ["pwd","hwk"], acr
      // "mfa"), and on its own it is the PRIMARY one (amr ["hwk"], acr "1").
      // They cannot be made exclusive in the browser — this screen runs no
      // script, by design, and an inline one would not run under script-src
      // 'none' — so the POST handler decides between them and `webauthn_only`
      // wins. Under forceMfa the passwordless box is disabled: one factor does
      // not answer a request for two, however phishing-resistant that factor
      // is. forcePasswordless is the mirror image and arrives from the OTHER
      // direction: forceMfa is a demand the CALLING PROTOCOL made, and this is
      // a mechanism an operator CONFIGURED on the federation relationship the
      // partner is registered under (fedAuthnMechanism: webauthn). Both end
      // here because both decide what this one screen offers, and they cannot
      // both be on — beginAuthentication() resolves that, loudly, before the
      // record is written.
      //
      // THE HIDDEN INPUT IS NOT THE ENFORCEMENT. A disabled checkbox posts
      // nothing and a hidden one can be deleted by anybody with the developer
      // tools open, so handleLogin() reads the RECORD as well: see the note
      // there. The markup is what a person sees; the record is what decides.
      // WHAT THE `webauthn.*` POLICY LEAVES ON THIS SCREEN (2026-09-10). Three
      // settings can take a box away: `webauthn.enabled` takes both,
      // `webauthn.mfaAllowed` the first and `webauthn.primaryAllowed` the
      // second. The box is DISABLED AND LABELLED rather than removed, for the
      // reason every refusal on this console is said out loud: a control that
      // vanishes is read as a bug in the page, and a person who was told to use
      // their key needs to know which setting took it away. THE MARKUP IS NOT
      // THE ENFORCEMENT — handleLogin() checks the same policy, because a
      // disabled checkbox is a property of a browser and not of an HTTP
      // request.
      (keyPolicy.enabled
        ? ''
        : '<label class="chk"><input type="checkbox" disabled> ' +
          'Security keys are switched off in this realm ' +
          '(<code>webauthn.enabled</code>), so neither WebAuthn option is ' +
          'offered. An already-enrolled key still works.</label>') +
      (keyPolicy.enabled && keyPolicy.mfaAllowed
        ? '<label class="chk"><input type="checkbox" id="use_webauthn" ' +
          'name="use_webauthn" value="1"' +
          (record.forceMfa || record.forceKey ? ' checked disabled' : '') +
          (record.forcePasswordless ? ' disabled' : '') +
          '> Use a security key (WebAuthn) as a second factor' +
          (record.forcePasswordless
             ? ' — not available: this partner is configured for a ' +
               'passwordless key'
             : '') +
          (record.forceKey
             ? ' — required after a password: this request demands a ' +
               'security key' + (record.forceMfa ? ' as the second factor'
                                                 : ', alone or as the ' +
                                                   'second factor')
             : '') + '</label>' +
          (record.forceMfa || record.forceKey ?
           '<input type="hidden" name="use_webauthn" value="1">' : '')
        : (keyPolicy.enabled
            ? '<label class="chk"><input type="checkbox" disabled> ' +
              'A security key as a second factor is switched off here ' +
              '(<code>webauthn.mfaAllowed</code>).</label>'
            : '')) +
      (keyPolicy.enabled && keyPolicy.primaryAllowed && !locked
        ? '<label class="chk"><input type="checkbox" id="webauthn_only" ' +
          'name="webauthn_only" value="1"' +
          (record.forceMfa ? ' disabled' : '') +
          (record.forcePasswordless ? ' checked disabled' : '') +
          '> Sign in with the security key alone (passwordless — ' +
          'no password step, and the tokens will say one factor)' +
          (record.forceKey && !record.forceMfa
             ? ' — accepted: this request demands a security key' : '') +
          (record.forceMfa ?
           ' — not available: this request demands two factors' : '') +
          (record.forcePasswordless
             ? ' — required: the federation relationship "' +
               xmlEscape(record.mechanismVia || '') + '" configures this'
             : '') + '</label>' +
          (record.forcePasswordless
             ? '<input type="hidden" name="webauthn_only" value="1">' : '')
        : (keyPolicy.enabled
            ? '<label class="chk"><input type="checkbox" disabled> ' +
              'A passwordless security key is switched off here ' +
              '(<code>webauthn.primaryAllowed</code>).' +
              (record.forcePasswordless
                ? ' <strong>This sign-in cannot complete</strong>: the ' +
                  'federation relationship "' +
                  xmlEscape(record.mechanismVia || '') +
                  '" configures a mechanism this realm has turned off.'
                : '') + '</label>'
            : '')) +
      '<div class="row"><button type="submit" id="kc-login" name="action" ' +
      'value="login">Sign In</button>' +
      // THE THIRD BUTTON, AND IT IS NOT CANCEL (2026-09-05).
      //
      // Cancel is beside it and answers `access_denied` to the calling
      // protocol, creating nothing — that is what a person who wants OUT
      // presses, and it is the OAuth contract. This one is for a person who
      // wants IN WITHOUT SAYING WHO THEY ARE, which is a different act with a
      // different answer: the flow continues, tokens may well be issued, and
      // what the session carries is the fact that nobody authenticated.
      //
      // It is drawn only when `authn.unauthenticatedSessions` is on, so an
      // unedited service's sign-in screen is byte-for-byte what it was. There
      // is no username field to fill in for it and it deliberately does not
      // read one: whatever is typed above is ignored, because a session that
      // took a name from the form and called itself unauthenticated would be
      // claiming both things at once.
      (config.value('authn.unauthenticatedSessions') && !locked
         ? '<button type="submit" id="kc-anonymous" name="action" ' +
           'value="anonymous" class="secondary" title="' +
           xmlEscape('Continue as the anonymous principal. The flow goes on ' +
                     'and tokens may be issued, but the session records that ' +
                     'nobody authenticated — so an application requiring ' +
                     'ALL_AUTHENTICATED_USERS will refuse it. Anything typed ' +
                     'above is ignored.') +
           '">Continue without signing in</button>'
         : '') +
      '<button type="submit" id="kc-cancel" name="action" value="cancel" ' +
      'class="secondary">Cancel</button></div></form>' +
      // FORGOT YOUR PASSWORD? (#63, 2026-09-22): the portal's self-service
      // reset, offered only where `common/mail_uses.ts` says it is — the
      // setting on, a mail transport, and a mode that checks passwords — and
      // never on a screen whose name is locked. A root-relative link on the
      // realm's prefix: it is answered to the browser that is here.
      (!locked && this.offersPasswordReset()
        ? '<p class="meta"><a href="' +
          xmlEscape(realms.currentPrefix() + '/portal/forgot-password') +
          '">Forgot your password?</a></p>' : '') +
      // ---------------------------------------------------------------------
      // AND THE FEDERATION PARTNERS, if any are configured and usable.
      //
      // THIS IS WHY THE BUTTONS ARE HERE RATHER THAN ONLY ON /federation: a
      // person arriving at this screen is in the middle of SOMETHING — an OAuth
      // 2.0 authorization request, a WS-Federation sign-in, a SAML
      // AuthnRequest, the admin console — and `record.returnTo` is that
      // something, whole. Handing it to the federated flow is what lets a
      // foreign identity provider satisfy any protocol this service speaks,
      // without a single one of them being told that federation exists.
      //
      // ONLY USABLE ONES ARE OFFERED. `signInOptions()` filters to
      // relationships that are enabled AND fully configured, because a button
      // leading to a refusal is worse than no button — the person has already
      // left this screen by the time they find out.
      //
      // They are LINKS rather than buttons in the form, and that is not
      // cosmetic: a form control would post to this screen's own handler, which
      // signs somebody in on a typed name. These have to leave for somewhere
      // else entirely, and a GET is what leaving looks like.
      // ---------------------------------------------------------------------
      // None of the three on a linking sign-in (#109): it is a sign-in as
      // one person, with a password, and each of these is another door.
      (locked ? '' : this.federatedOptionsHtml(record)) +
      // AND THE KERBEROS DOOR, under the partners. Under rather than over,
      // because the partners are what an application was CONFIGURED with and
      // this is offered to everybody — a configured route belongs above an
      // ambient one.
      (locked ? '' : this.integratedOptionHtml(record)) +
      // AND THE WALLET (#38), last: offered to everybody, like Kerberos.
      (locked ? '' : this.walletOptionHtml(record)) +
      // WHAT THIS SCREEN CHECKS, BY MODE (2026-09-21). It said "no password
      // is checked" and "a key is enrolled on first use" in product too, where
      // both have been false — the first since 2026-09-06, the second since
      // `mode.enrolsKeysOnFirstUse()`.
      (mode.verifiesCredentials()
        ? '<div class="meta"><div>Your password is checked against your ' +
          'account.</div><div>Passwordless: the password field is not read, ' +
          'and a security key you registered for signing in is the only ' +
          'factor. A key is added at /portal/keys after signing in, never ' +
          'here.</div><div>Signing in for: '
        : '<div class="meta"><div>No password is checked. The username you ' +
          'enter is the identity the issued tokens describe.</div>' +
          '<div>Passwordless: the password field is not read at all, and the ' +
          'security key becomes the only factor — a key is enrolled for this ' +
          'username on first use, so the first person to claim a name here ' +
          'gets it. This service authenticates nobody; that is the same ' +
          'statement as the line above and not a weaker one.</div>' +
          '<div>Signing in for: ') +
      '<code>' + xmlEscape(record.protocol) + '</code></div>' +
      record.details.map(function (d) {
        return '<div>' + xmlEscape(d.label) + ': <code>' +
               xmlEscape(d.value == null ? '' : d.value) +
               '</code>' + (d.note ? ' (' + xmlEscape(d.note) + ')' :
                            '') + '</div>';
      }).join('') +
      '</div></div>' + (this.fingerprinting()
        ? '<script src="' + FINGERPRINT_SCRIPT_PATH + '"></script>' : '') +
      '</body></html>\n';
    log.debug("Leaving Authn.loginPage().");
    return page;
  }

  private sendLoginPage(res, html) {
    const { log, app } = this.deps;
    log.debug("Entering Authn.sendLoginPage().");
    // THE NINTH SCRIPTED PAGE, and only while `risk.fingerprinting` is on in
    // this realm (#62 P6): `script-src 'self'` for `/authn/fingerprint.js`
    // and nothing else, through the builder so the framing clauses stay.
    // The form still works with the script blocked — the fingerprint is an
    // extra field, and an empty one decides nothing.
    if (this.fingerprinting()) {
      res.set('Content-Security-Policy',
              app.contentSecurityPolicy({ 'script-src': "'self'" }));
    }
    res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug("Leaving Authn.sendLoginPage().");
  }

  // ---------------------------------------------------------------------------
  // THE CHOOSER: WHICH OF THIS APPLICATION'S FEDERATION PARTNERS.
  //
  // Drawn when the application entry names MORE THAN ONE usable
  // service-provider-side relationship. It is home realm discovery, narrowed:
  // the buttons at the foot of the sign-in screen offer every relationship this
  // service has, and these offer the ones this application was configured with.
  //
  // THERE IS NO PASSWORD FIELD AND NO FORM. The buttons are links, for
  // federatedButtons()' reason made a second time and with more force here: a
  // form control would post to the sign-in handler, which signs somebody in on
  // a typed name — which is the one thing an application that federates its
  // authentication has said it does not want. Leaving is a GET.
  //
  // THE UNUSABLE VALUES ARE PRINTED, not dropped. A list of three whose middle
  // value names a disabled relationship draws two buttons, and two buttons is
  // exactly what a correct list of two draws — so the difference has to be said
  // in words. Each line is the sentence usableServiceProvider() wrote, which
  // names the id and what is wrong with it.
  //
  // THERE IS NO "NONE OF THESE" ESCAPE, and that is deliberate rather than
  // missing. This page is reached because an application was configured to
  // authenticate its people elsewhere; an escape hatch back to the password box
  // would be that configuration meaning nothing, which is the failure this
  // whole feature is careful about. Somebody who needs the password box clears
  // the attribute — and every relationship being unusable is the one case where
  // this page is not drawn at all, because federationFor() reports no usable
  // partner and beginAuthentication() falls through to the screen with the
  // problems on it.
  // ---------------------------------------------------------------------------
  private selectIdpPage(base, record) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering Authn.selectIdpPage(). " +
              ((record.federation || {}).usable || []).length + " partner(s).");
    const home = record.federation || {};
    const usable = home.usable || [];
    const problems = home.problems || [];
    const page = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
                 'charset="utf-8">' +
      '<title>Choose how to sign in — mock authentication ' +
      'service</title><style>' +
      CARD_CSS + '</style></head><body><div class="card">' +
      '<h1>Choose how to sign in</h1>' +
      '<p class="sub">Mock authentication service at <code>' +
      xmlEscape(base) + '</code></p>' +
      // Every unusable value gets its own banner rather than one banner listing
      // them, because each is a different entry to go and fix and an operator
      // reading this is about to fix one of them.
      problems.map(function (one) {
        return '<div class="err">' + xmlEscape(one) + '</div>';
      }).join('') +
      this.federatedButtons(record,
                            usable.map(function (one) { return one.option; }),
        (record.application
           ? '<code>' + xmlEscape(record.application) + '</code> signs its ' +
                                                             'users in at '
           : 'This application signs its users in at ') +
        'one of these federated identity providers. Pick the one you have an ' +
        'account at. No password is typed here and none is checked there ' +
        'either as far as this service can tell — what it checks is the ' +
        'partner\'s signature.',
        // THIS APPLICATION'S OWN PARTNERS BY CONSTRUCTION — the page is not
        // drawn at all for any other list — so the pair is named on every href.
        // It is the same argument the sign-in screen's first branch makes, and
        // it holds here with less to check: `usable` came from federationFor()
        // against this record's application and from nowhere else.
        record.application) +
      '<div class="meta"><div>These are the relationships named on this ' +
      'application\'s entry under <code>ou=applications</code>, in ' +
      '<code>appFederationRelationship</code> — not every federation ' +
      'relationship this service has.</div><div>Signing in for: ' +
      '<code>' + xmlEscape(record.protocol) + '</code></div>' +
      record.details.map(function (d) {
        return '<div>' + xmlEscape(d.label) + ': <code>' +
               xmlEscape(d.value == null ? '' : d.value) + '</code>' +
               (d.note ? ' (' + xmlEscape(d.note) + ')' : '') + '</div>';
      }).join('') +
      '</div></div></body></html>\n';
    log.debug("Leaving Authn.selectIdpPage().");
    return page;
  }

  // A GET, and it needs the `?authn=` id for the same reason the screen does:
  // what it draws comes off the pending record, and the return address is on
  // that record rather than in this URL. A person who arrives here bare is
  // answered 400 and told to start again at the application, exactly as at the
  // screen — there is no partner list to compose without knowing what was
  // interrupted.
  // ---------------------------------------------------------------------------
  // WHAT THE THREE SIGN-IN DOORS TAKE.
  //
  // **`authn` AND `authn_id` ARE THE SAME PENDING RECORD'S ID UNDER TWO NAMES**
  // — the screen carries it in the query string and the form posts it in a
  // hidden field — and both are minted by `beginAuthentication()` as
  // `randomId()`, which is base64url. Typing them is what makes a lookup key
  // that arrived as an ARRAY impossible: `pendingFor(['a','b'])` would
  // previously have been a Map miss answering "this sign-in has expired", which
  // is a confusing sentence about a request that was malformed rather than
  // stale.
  //
  // **THE USERNAME IS `vt.name` AND DELIBERATELY NOT `vt.identifier`.** This
  // service has always accepted any name at all — that is most of what makes it
  // a mock — so the rule here is a BOUND and the absence of control characters,
  // which `scalar()` has already applied. Narrowing it to printable ASCII would
  // refuse people whose names are none of this service's business.
  //
  // **THE PASSWORD IS BOUNDED AND NOTHING ELSE**, and the bound is generous.
  // Its content is `credentials.js`'s business in product mode and nobody's in
  // development; what a schema can say about it is that a megabyte of it is not
  // a password, and that a scrypt at N=2^15 should not be asked to hash one.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // A REFUSAL FROM `common/validation.js`, IN THIS MODULE'S OWN WORDS.
  //
  // That module deliberately renders nothing — it returns a code, a field and a
  // sentence, and each protocol says what a bad request looks like for itself.
  // Here that is `oauthError()`, the same shape every other refusal on these
  // three doors already uses, so a client that can read one can read this.
  //
  // `invalid_request` rather than a bare 400: the caller of these endpoints is
  // a browser that arrived from an OAuth or SAML flow, and RFC 6749 section
  // 4.1.2.1 is the vocabulary it was already going to be answered in.
  // ---------------------------------------------------------------------------
  // error-code: none — the definition of this helper, not a call to it
  private refuseInvalid(res, why) {
    const { log, oauthError } = this.deps;
    log.debug("Entering Authn.refuseInvalid(). code=" + why.code + " field=" +
              why.field);
    log.debug("Leaving Authn.refuseInvalid().");
    // error-code: none — the helper's own internals; every call site marks its own code first
    return oauthError(res, 400, 'invalid_request', why.detail);
  }

  // The form target. Everything that can go wrong here re-renders the screen
  // with a message rather than redirecting: the person is mid-authentication
  // and the request they interrupted is still waiting.
  // ---------------------------------------------------------------------------
  // EVERYTHING A SIGN-IN DOES AFTER ITS FIRST FACTOR IS ACCEPTED — the role
  // gate, the second factor, the session — as one function (2026-09-13),
  // because it has two callers: the password screen, and the forced password
  // change, which resumes exactly here once the new password is stored. Two
  // copies would be two answers to what a sign-in requires, and the second
  // factor is the half a copy would forget.
  // ---------------------------------------------------------------------------
  private async finishPasswordSignIn(req, res, base, record, username,
                                     passwordless, secondFactor) {
    const { crypto, log, randomId, gate, credentials, audit,
      errorCodes } = this.deps;
    log.debug("Entering Authn.finishPasswordSignIn(). username=" + username);

    // A DISABLED ACCOUNT, BEFORE ANY CEREMONY (2026-09-17). The password path
    // has already been refused by `credentials.verify()`; this is the
    // passwordless one, which presents no password, and it is asked here so
    // that a disabled person is not walked through a security-key ceremony
    // whose result would be refused. The same sentence as a wrong password.
    if (this.deps.accountState.isDisabled(username)) {
      log.info('authn: a sign-in for "' + username + '" was refused: the ' +
               'account is disabled.');
      errorCodes.mark(res, 'STS-AUTHN-0201');
      log.debug("Leaving Authn.finishPasswordSignIn(). Disabled.");
      return this.sendLoginPage(res, this.loginPage(base, record,
        'Authentication failed for ' + username + '.'));
    }

    // THE ROLE GATE, AND IT IS ASKED BEFORE THE SECOND FACTOR RATHER THAN AFTER
    // IT. A person who holds none of the roles this application requires is not
    // going to be signed in whatever their security key says, and asking them
    // to perform a ceremony first would be a screen that takes a credential it
    // has already decided to ignore.
    //
    // THE SUBJECT **IS** AUTHENTICATED HERE, AND THIS SAID THE OPPOSITE UNTIL
    // 2026-09-05. The old comment read "the subject is not authenticated yet,
    // and `authenticated: false` says so rather than flattering the request",
    // which sounds careful and was wrong — not about the wording, about the
    // fact.
    //
    // **LOOK AT WHERE THIS RUNS.** The reserved password has already been
    // refused twelve lines up. Everything this mock does by way of checking a
    // credential has therefore already happened, and this request is the act of
    // authenticating somebody. What has not happened yet is the SESSION, and
    // "the session does not exist yet" is a different sentence from "nobody has
    // authenticated" — the old code collapsed them.
    //
    // **WHAT IT COST WAS THE ROLE ITSELF.** An application whose
    // `appRequiredRole` is `ALL_AUTHENTICATED_USERS` refused EVERY sign-in at
    // this screen, because at this screen nobody had authenticated by that
    // reading — so the one role most likely to be configured could never be
    // satisfied by anybody, and the refusal named the person and the role and
    // looked entirely deliberate. It survived because the test that narrows an
    // application narrows it to a CONFIGURED role, which the register answers
    // the same either way; only a built-in role can see the difference.
    //
    // **AND THE DISTINCTION THE OLD COMMENT WANTED IS REAL NOW, ELSEWHERE.**
    // ALL_UNAUTHENTICATED_USERS is held by the anonymous session minted a few
    // hundred lines up, where nobody authenticated and the flag says so. That
    // is the honest version of what this line was reaching for: a party that
    // did not authenticate, rather than a party in the middle of doing so.
    //
    // A REFUSAL IS THIS PAGE AGAIN WITH THE REASON ON IT, because there is
    // nowhere else to send them: `record.returnTo` is a path on THIS service
    // belonging to the protocol module that started the sign-in, and bouncing
    // somebody back into an authorization endpoint that would refuse them a
    // second time is a loop. The protocol's own refusal happens at its own door
    // — `access_denied` at /oauth2/authorize — for a session that already
    // exists.
    // -----------------------------------------------------------------------
    // THE RISK OF THIS SIGN-IN, ASSESSED NOW (#62 P3) — after the credential
    // verified and before anything is drawn — and asked of the issuance
    // policy in the same question as the roles, with the factor this path
    // has so far: a password (`pwd`), or on the passwordless path the key
    // about to be presented (`hwk`). Three answers come back:
    //
    //   * PERMIT (or development observing a Deny): on as before.
    //   * A STEP-UP: the policy names a factor, and this screen asks for it
    //     below, as it asks for a second factor anybody is configured for.
    //     The assessment rides on the step, and the finisher's session is
    //     decided on it again with both factors, which the policy permits.
    //   * REFUSE: "Authentication failed", and nothing else — the level and
    //     the signals are for the audit row, never for the screen.
    // -----------------------------------------------------------------------
    const assessment = await this.assessSignIn(req, username,
      record.protocol, { application: String(record.application || ''),
                         credential: { kind: passwordless ? 'webauthn'
                                                          : 'password' } });
    const riskEngine = assessment ? this.riskEngine() : null;
    const risk = riskEngine ? riskEngine.riskOf(assessment) : null;
    const roleAnswer = gate.check(Object.assign({
      application: String(record.application || ''),
      kind: gate.ISSUANCE.SESSION,
      subject: { kind: 'user', name: username, authenticated: true },
      claims: null
    }, riskEngine ? { risk: riskEngine.factsOf(risk,
      passwordless ? ['hwk'] : ['pwd'], '1') } : {}));
    let riskDecision = 'permit';
    let riskFactor = '';
    if (roleAnswer.risk) {
      riskDecision = (roleAnswer.risk.observed ? 'observe:' : '') +
                     roleAnswer.risk.action;
    }
    if (!roleAnswer.allowed && roleAnswer.risk && !roleAnswer.risk.observed &&
        roleAnswer.risk.action === 'refuse') {
      log.info('authn: the sign-in for "' + username + '" was refused on ' +
               'risk.');
      this.settleRisk(risk, { decision: riskDecision,
                              errorCode: 'STS-RISK-0016',
                              policy: roleAnswer.policy });
      errorCodes.mark(res, 'STS-RISK-0016');
      log.debug("Leaving Authn.finishPasswordSignIn(). Refused on risk.");
      return this.sendLoginPage(res, this.loginPage(base, record,
        'Authentication failed for ' + username + '.'));
    }
    if (!roleAnswer.allowed && roleAnswer.risk && !roleAnswer.risk.observed) {
      riskFactor = roleAnswer.risk.factor;
    } else if (!roleAnswer.allowed) {
      log.info('authn: the issuance policy refused a session for "' + username +
               '" at "' + String(record.application) + '". ' + roleAnswer.why);
      log.debug("Leaving the authentication endpoint. The issuance policy " +
                "refused the session.");
      errorCodes.mark(res, 'STS-AUTHN-0009');
      log.debug("Leaving Authn.finishPasswordSignIn().");
      return this.sendLoginPage(res, this.loginPage(base, record,
                                                    roleAnswer.why));
    }

    // The security key, in whichever role. On the second-factor path the
    // password step has succeeded and the session is NOT created yet, because a
    // session created here and upgraded later would be a valid single-factor
    // session in the window between — and a request arriving in that window
    // would be answered with tokens that claim one factor's worth of assurance
    // and carry none of the second's. On the passwordless path there is nothing
    // to upgrade FROM, and the rule holds for the same reason: nothing has been
    // authenticated until the ceremony verifies.
    // ---------------------------------------------------------------------
    // WHICH SECOND FACTOR, AND THE ANSWER IS THE PERSON'S RATHER THAN THE
    // FORM'S (2026-09-10).
    //
    // **THIS IS THE CHANGE THAT MAKES `mfaRequired` MEAN ANYTHING.** That flag
    // has been on `credentials.mechanismsFor()` since the portal was written,
    // it is drawn on `/portal/keys` as *a password alone will not sign you in*,
    // and **nothing read it at this door** — so it was a sentence on a page
    // rather than a rule. A person who had enrolled a second factor signed in
    // with a password and an unticked checkbox, exactly as somebody who had
    // enrolled nothing.
    //
    // So the order below is: the passwordless path first (it is a PRIMARY
    // credential and not a second factor at all), then WHAT THIS PERSON IS
    // CONFIGURED FOR, and only then the checkbox.
    //
    // **THE CHECKBOX CANNOT OVERRIDE AN ENROLMENT**, which is
    // `record.forcePasswordless`'s argument read a second time: a configured
    // mechanism a client can opt out of is not a mechanism. It matters more
    // here than there, because opting out would be a real bypass — the
    // security-key page ENROLS on first use, so a person who knows a TOTP
    // user's password could otherwise tick the box, register a brand new
    // authenticator, and be signed in having never met the second factor the
    // account is configured for.
    //
    // What that costs is worth stating rather than discovering: **somebody who
    // already holds a second factor cannot enrol a SECURITY KEY at this
    // screen.** The box is what enrolment goes through, and it is now reserved
    // for people who hold no second factor yet. The other two doors are
    // unaffected — an activation link enrols one, and `/portal/mfa` enrols an
    // authenticator app — and that person's row under `/admin/users` is where
    // an operator clears a factor
    // so that somebody can enrol a different one.
    //
    // **A PERSON WHO HOLDS BOTH IS ASKED FOR THE SECURITY KEY**, with a link to
    // use a code instead. `mechanismsFor().secondFactor` decides, and it
    // prefers the key because the ceremony is bound to this origin and the code
    // is not; the link exists because the commonest reason to hold both is
    // standing at a machine the key is not plugged into.
    const enrolled = credentials.mechanismsFor(username);
    const configuredFactor = enrolled.mfaRequired ? enrolled.secondFactor : '';
    // -----------------------------------------------------------------------
    // A STEP-UP ON RISK ASKS FOR A FACTOR THE PERSON ALREADY HOLDS, AND NEVER
    // ENROLS ONE (#62 P3). The paragraph above closes the same door for a
    // configured factor: somebody who knows the password — which is what an
    // elevated risk suspects — must not be handed a ceremony that registers
    // their own authenticator. So a person holding nothing that answers the
    // demand is refused, and told nothing more than any refusal says.
    // -----------------------------------------------------------------------
    const holdsKey = enrolled.mfaKeys + enrolled.primaryKeys > 0;
    if (riskFactor && ((riskFactor === 'security-key' && !holdsKey) ||
                       (riskFactor !== 'security-key' && !holdsKey &&
                        !enrolled.totp))) {
      log.info('authn: the issuance policy asks "' + username + '" for a ' +
               riskFactor + ' on risk, and they hold none; refused.');
      this.settleRisk(risk, { decision: riskDecision,
                              errorCode: 'STS-RISK-0018',
                              policy: roleAnswer.policy });
      errorCodes.mark(res, 'STS-RISK-0018');
      log.debug("Leaving Authn.finishPasswordSignIn(). No factor to step " +
                "up with.");
      return this.sendLoginPage(res, this.loginPage(base, record,
        'Authentication failed for ' + username + '.'));
    }
    const riskChoice = riskFactor === 'security-key' ? 'webauthn'
      : (riskFactor ? (enrolled.secondFactor ||
                       (holdsKey ? 'webauthn' : 'totp')) : '');
    // A SECURITY KEY DEMANDED (2026-09-17): the second factor is the KEY
    // whatever this person is configured for — a one-time code or a recovery
    // code does not answer the demand, and the step that would ask for one is
    // never drawn. What that must not become is the bypass the paragraph above
    // closes: somebody who holds a second factor and NO key would be handed
    // the enrolling ceremony, and a person who knows their password could
    // register a key of their own. So that person is refused, and told where
    // a key is added; somebody who holds no second factor at all enrols one
    // here as always.
    if (record.forceKey && !passwordless && enrolled.mfaKeys === 0 &&
        enrolled.primaryKeys === 0 && enrolled.mfaRequired) {
      log.info('authn: a security key was demanded of "' + username + '", ' +
               'who holds a second factor and no key; refused.');
      errorCodes.mark(res, 'STS-AUTHN-0204');
      log.debug("Leaving Authn.finishPasswordSignIn(). No key to present.");
      return this.sendLoginPage(res, this.loginPage(base, record,
        'This request needs a security key, and this account holds none. ' +
        'Add one at /portal/keys and sign in again.'));
    }
    const factor = passwordless || record.forceKey ||
                   riskFactor === 'security-key'
      ? 'webauthn'
      : (configuredFactor || riskChoice || (secondFactor ? 'webauthn' : ''));

    // ---------------------------------------------------------------------
    // A SECOND FACTOR REQUIRED OF THIS PERSON (2026-09-13) — by their own entry
    // (`stsMfaRequired`, set from /admin/users) or by the realm
    // (`authn.mfaRequired`).
    //
    // **A PASSWORDLESS SIGN-IN IS REFUSED UNDER IT**, before any ceremony: a
    // security key on its own is ONE factor — `amr ["hwk"]` — and a requirement
    // for two that a passkey answered would be the requirement not asked.
    //
    // **SOMEBODY WHO HOLDS NO SECOND FACTOR IS ASKED TO ENROL ONE** before any
    // session exists, on `MFA_SETUP_PATH`. Somebody who already holds one is
    // asked for it by `factor` above as always, and somebody who ticked the
    // security-key box enrols a key through the ordinary ceremony — both
    // satisfy it, so neither meets the set-up step.
    const requirement = credentials.mfaRequirementFor(username);
    if (requirement.required && passwordless) {
      log.info('authn: a passwordless sign-in for "' + username + '" was ' +
               'refused — a second factor is required of them (' +
               (requirement.byUser ? 'account' : 'realm') + ').');
      errorCodes.mark(res, 'STS-AUTHN-0171');
      log.debug("Leaving Authn.finishPasswordSignIn(). Passwordless under a " +
                "requirement.");
      return this.sendLoginPage(res, this.loginPage(base, record,
        'A second factor is required ' + (requirement.byUser
          ? 'for this account' : 'in this realm') + ', and a security key on ' +
        'its own is one factor. Sign in with your password; you will be ' +
        'asked for your second factor, or to set one up.'));
    }
    if (requirement.required && !factor) {
      const offered = this.enrolmentOffered();
      if (!offered.totp && !offered.webauthn) {
        log.warn(errorCodes.tag('STS-AUTHN-0172') +
                 'authn: a second factor is ' +
                 'required of "' + username + '", who holds none, and ' +
                 'neither mechanism can be enrolled in this realm ' +
                 '(totp.enabled, webauthn.enabled, webauthn.mfaAllowed). The ' +
                 'sign-in is REFUSED rather than let through on one factor.');
        errorCodes.mark(res, 'STS-AUTHN-0172');
        log.debug("Leaving Authn.finishPasswordSignIn(). Nothing can be " +
                  "enrolled.");
        return this.sendLoginPage(res, this.loginPage(base, record,
          'A second factor is required for this account and none can be set ' +
          'up here: authenticator apps and security keys are both switched ' +
          'off in this realm. Ask an administrator.'));
      }
      pending.delete(record.id);
      const setupId = randomId(24);
      pendingMfa.set(setupId, {
        authn: record, username: username,
        challenge: crypto.randomBytes(32).toString('base64url'),
        // `enrol` until a mechanism is chosen; `enrol-totp` once an
        // authenticator app's secret has been shown; `webauthn` once a security
        // key is chosen, which is then the ordinary ceremony — it registers a
        // key in the `mfa` role for somebody who holds none.
        factor: 'enrol', alternate: '', backup: false, passwordless: false,
        requiredBy: requirement.byUser ? 'account' : 'realm',
        expires: Date.now() + this.mfaStepTtlMs()
      });
      audit.audit({
        action: 'authn.mfa.enrolment.required', outcome: 'success',
        actor: username, target: username, channel: 'http',
        protocol: record.protocol,
        summary: username + ' holds no second factor and one is required; ' +
                 'asked to set one up before signing in',
        detail: { requiredBy: requirement.byUser ? 'account' : 'realm' }
      });
      log.info('authn: "' + username + '" holds no second factor and one is ' +
               'required; asking them to set one up.');
      log.debug("Leaving Authn.finishPasswordSignIn(). Enrolment step.");
      return this.sendMfaSetupPage(res, this.mfaSetupPage(setupId, username,
                                                          offered, ''));
    }

    if (factor) {
      pending.delete(record.id);
      const mfaId = randomId(24);
      pendingMfa.set(mfaId, {
        authn: record, username: username,
        challenge: crypto.randomBytes(32).toString('base64url'),
        // WHICH MECHANISM IS BEING ASKED FOR. On the record for the reason
        // `passwordless` is on it: the POST at the other end is an answer and
        // says nothing about what was asked. It is ONE register for both
        // mechanisms rather than a second map beside it — rule 3m, read as it
        // is everywhere else here: a second store would be a second answer to
        // "is there a sign-in waiting for a second factor".
        factor: factor,
        // The OTHER mechanism this person holds, if they hold one. It is what
        // the *use a code instead* link is drawn from, and it is resolved HERE
        // rather than at the page so that the link cannot offer a factor the
        // person does not have.
        // Under a demand for a key there is no other mechanism to offer.
        alternate: record.forceKey || riskFactor === 'security-key' ? ''
          : (factor === 'webauthn' && enrolled.totp) ? 'totp'
          : ((factor === 'totp' && enrolled.mfaKeys > 0) ? 'webauthn' : ''),
        // THE WAY OUT WHEN NEITHER MECHANISM IS TO HAND (2026-09-10). Resolved
        // HERE, when the step is minted, for `alternate`'s reason and with a
        // sharper edge: this link must not be drawn for somebody who holds no
        // unspent recovery code, because a screen that asks for a credential
        // that cannot exist looks exactly like a service that has lost it.
        //
        // **IT IS NOT ON `alternate`** even though it is drawn beside it. That
        // field names the OTHER MECHANISM THIS PERSON IS CONFIGURED FOR and the
        // two screens swap between them; a recovery code is configured for
        // nobody and stands in for whichever of the two they cannot produce.
        // One field carrying both would make *what is this person's second
        // factor* a question with a wrong answer.
        // And no recovery code, which is not a key either.
        backup: !record.forceKey && riskFactor !== 'security-key' &&
                enrolled.backupCodes
          ? enrolled.backupCodes.remaining > 0 : false,
        // Which role, carried on the pending record rather than re-read from
        // the POST at the other end: that POST is the browser's ceremony result
        // and nothing in it says what the person chose a screen ago. Everything
        // the session then claims — amr, acr, and whether the directory entry
        // is flagged as multi-factor — is decided from this one boolean.
        passwordless: passwordless,
        // The sign-in's assessment (#62 P3), which the finisher hands to
        // `startSession()` so the session is decided on it — with both
        // factors this time — and carries it.
        risk: assessment || undefined,
        // A security key demanded ON RISK, for `keyDemandRefuses()`'s
        // reason: the POST at the other end is an answer, not the question.
        riskKey: riskFactor === 'security-key',
        expires: Date.now() + this.mfaStepTtlMs()
      });
      pendingMfa.forEach(function (v, k) {
        if (v.expires < Date.now()) pendingMfa.delete(k);
      });
      if (factor === 'totp') {
        log.debug("Leaving the authentication endpoint. " + username +
                  " passed the password step; asking for the one-time code.");
        log.debug("Leaving Authn.finishPasswordSignIn().");
        return this.sendTotpPage(res, this.totpPage(base, mfaId, username, '',
                                                    ''));
      }
      log.debug("Leaving the authentication endpoint. " + username +
                (passwordless ? " asked for a passwordless sign-in; asking " +
                                "for the security key."
                              : " passed the password step; asking for the " +
                                "security key."));
      log.debug("Leaving Authn.finishPasswordSignIn().");
      return this.sendWebauthnPage(res, this.webauthnPage(base, mfaId, username,
                                                          ''));
    }

    pending.delete(record.id);
    // One factor, and the tokens will say so.
    // `gated: true` — the role gate ran above, before this screen was redrawn,
    // so that a refusal is a screen with a reason on it. Asking again inside
    // startSession() would be one refusal reported in two shapes.
    //
    // A REFUSAL IS ANSWERED HERE (2026-09-22, #62 P0). The role gate ran
    // above, but a session can still be refused — the account disabled a
    // moment ago, no directory entry to be the subject of — and the return
    // value was ignored, so the browser went back to a caller that sent it
    // straight here again.
    const said = { request: req, gated: true,
                   credential: { kind: 'password' },
                   risk: assessment || undefined,
                   riskDecision: riskDecision };
    const started = this.startSession(res, username, ['pwd'], '1',
                                      record.protocol, said);
    if (this.refusedSession(res, base, record, username, started, said)) {
      log.debug("Leaving Authn.finishPasswordSignIn(). Refused.");
      return undefined;
    }

    // Back to whatever sent them here, with its own original request — which
    // now runs a second time, sees the session cookie, and completes.
    this.returnToCaller(res, record, null, null);
    log.debug("Leaving the authentication endpoint. " + username + " is " +
        "signed in; back to " +
              record.returnTo + ".");
    log.debug("Leaving Authn.finishPasswordSignIn().");
    return undefined;
  }

  // ---------------------------------------------------------------------------
  // THE FORCED PASSWORD CHANGE (2026-09-13).
  //
  // Drawn by the password screen for an entry with `pwdReset: TRUE`, and the
  // only way past it is a new password this service stores. Three things about
  // it are deliberate:
  //
  //   * **NO SESSION EXISTS UNTIL IT IS DONE.** The step carries the pending
  //     sign-in record; finishPasswordSignIn() resumes that sign-in afterwards
  //     — role gate, second factor, session — exactly as if the new password
  //     had been typed on the first screen.
  //   * **THE NEW PASSWORD GOES THROUGH `credentials.setPassword()`**, so
  //     product mode holds it to the realm's password policy and history —
  //     which refuses the generated password being set again — and development
  //     mode, as at every other door, does not. The reserved refusal password
  //     is refused here in both modes, because it could never sign anybody in
  //     afterwards.
  //   * **IT HAS NO SCRIPT.** Two password fields and a button; the root
  //     CLAUDE.md's rule is that a scripted page argues its case, and this one
  //     has none to argue.
  // ---------------------------------------------------------------------------
  private passwordChangePage(changeId, username, error) {
    const { log, xmlEscape } = this.deps;
    log.debug('Entering Authn.passwordChangePage(). username=' + username);
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><title>Choose a new password — mock authentication ' +
      'service</title><style>body{font-family:system-ui,-apple-system,"Segoe ' +
      'UI",Arial,sans-serif;background:#f4f4f7;margin:0;display:flex;' +
      'align-items:center;justify-content:center;min-height:100vh;color:#222}' +
      '.card{background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:10px;padding:28px 32px;width:420px;box-shadow:0 ' +
      '6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 ' +
      '4px}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
      '18px}label{display:block;font-size:.8em;color:#444;margin:0 0 4px}' +
      'input{width:100%;box-sizing:border-box;padding:9px 11px;border:1px ' +
      'solid #c8c8d0;border-radius:5px;font-size:.95em;margin-bottom:14px}' +
      'button{padding:9px 12px;border-radius:5px;border:1px solid #12107c;' +
      'background:#12107c;color:#fff;font-size:.95em;cursor:pointer;' +
      'width:100%}.err{background:#fdecea;border:1px solid ' +
      '#f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
      'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;' +
      'padding-top:14px;border-top:1px solid ' +
      '#eee;font-size:.75em;color:#777}code{font-family:ui-monospace,' +
      'SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
      '<h1>Choose a new password</h1><p class="sub">The password for <code>' +
      xmlEscape(username) + '</code> was set for you and must be changed ' +
      'before you continue.</p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      '<form method="post" action="' + PASSWORD_CHANGE_PATH + '">' +
      '<input type="hidden" name="change_id" value="' + xmlEscape(changeId) +
      '">' +
      '<label for="new_password">New password</label><input type="password" ' +
      'id="new_password" name="new_password" autocomplete="new-password" ' +
      'autofocus>' +
      '<label for="confirm_password">Type it again</label><input ' +
      'type="password" id="confirm_password" name="confirm_password" ' +
      'autocomplete="new-password">' +
      '<button type="submit" id="password-change-submit">Change password and ' +
      'continue</button></form>' +
      '<div class="meta">Nothing has been signed in yet. The sign-in you ' +
      'started continues as soon as the new password is stored.</div>' +
      '</div></body></html>\n';
    log.debug('Leaving Authn.passwordChangePage().');
    return html;
  }

  private sendPasswordChangePage(res, html) {
    const { log } = this.deps;
    log.debug('Entering Authn.sendPasswordChangePage().');
    res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug('Leaving Authn.sendPasswordChangePage().');
  }

  // The step, or null with the refusal already sent.
  private passwordChangeStep(res, changeId) {
    const { log, oauthError, errorCodes } = this.deps;
    log.debug('Entering Authn.passwordChangeStep().');
    const step = pendingPasswordChange.get(changeId);
    if (!step || step.expires < Date.now()) {
      pendingPasswordChange.delete(changeId);
      errorCodes.mark(res, 'STS-AUTHN-0144');
      oauthError(res, 400, 'invalid_request',
        'This password change has expired. Start the request again from the ' +
        'application that sent you here.');
      log.debug('Leaving Authn.passwordChangeStep(). Expired.');
      return null;
    }
    log.debug('Leaving Authn.passwordChangeStep().');
    return step;
  }

  // ---------------------------------------------------------------------------
  // /authn/mfa-setup — ENROLLING A SECOND FACTOR AT SIGN-IN, BECAUSE ONE IS
  // REQUIRED (2026-09-13).
  //
  // Reached only from `finishPasswordSignIn()`, for somebody whose password
  // step succeeded, who holds no second factor, and of whom one is required —
  // by their entry or by the realm. No session exists until they finish.
  //
  // **THIS SCREEN ENROLS AN AUTHENTICATOR APP, AND `authn/CLAUDE.md` SAYS A
  // SIGN-IN SCREEN MUST NOT**, so the argument is made again rather than waved
  // through. That rule stops a sign-in handing a shared secret to whoever typed
  // a password, because for a person who ALREADY holds a second factor that
  // would be a bypass: register your own app, never meet the one the account is
  // configured for. It is the same rule that reserves the security-key box for
  // people holding nothing. Here the person holds nothing — the step is refused
  // to anybody else — so there is no factor to bypass, and what the requirement
  // asks is exactly that they come to hold one. It is the security-key box's
  // enrol-on-first-use, extended to the other mechanism, and only while a
  // second factor is required.
  //
  // **WHAT IT DOES NOT CHANGE**: a password alone still reaches this step, as
  // it reaches the security-key box, so whoever knows the password of somebody
  // who holds no second factor can enrol the first. That was true before of the
  // key, and it is what "the first second factor" means anywhere; an activation
  // link, or an administrator watching, is the stronger door.
  //
  // No script: a choice of two buttons, a QR code this server draws, and six
  // digits. A security key is the ordinary `/authn/webauthn` ceremony, which
  // carries its own script.
  // ---------------------------------------------------------------------------
  private enrolmentOffered() {
    const { log, webauthnPolicy, totp } = this.deps;
    log.debug('Entering Authn.enrolmentOffered().');
    const out = {
      totp: totp.offered(),
      webauthn: webauthnPolicy.offered() && webauthnPolicy.roleAllowed('mfa').ok
    };
    log.debug('Leaving Authn.enrolmentOffered(). totp=' + out.totp +
              ', webauthn=' +
              out.webauthn);
    return out;
  }

  private mfaSetupShell(title, body) {
    const { log, xmlEscape } = this.deps;
    log.debug('Entering Authn.mfaSetupShell().');
    log.debug('Leaving Authn.mfaSetupShell().');
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      '<title>' + xmlEscape(title) + ' — mock authentication service</title>' +
      MFA_SETUP_STYLE + '</head><body><div class="card">' + body +
      '</div></body></html>\n';
  }

  // The choice: an authenticator app or a security key, whichever this realm
  // offers.
  private mfaSetupPage(setupId, username, offered, error) {
    const { log, xmlEscape } = this.deps;
    log.debug('Entering Authn.mfaSetupPage(). username=' + username);
    const button = function (action, label) {
      log.debug('Entering button(). ' + action);
      log.debug('Leaving button().');
      return '<form method="post" action="' + MFA_SETUP_PATH + '">' +
        '<input type="hidden" name="mfa_id" value="' + xmlEscape(setupId) +
        '"><input type="hidden" name="action" value="' + action + '">' +
        '<button type="submit" id="mfa-setup-' + action + '">' + label +
        '</button></form>';
    };
    const html = this.mfaSetupShell('Set up a second factor',
      '<h1>Set up a second factor</h1><p class="sub">A second factor is ' +
      'required for <code>' + xmlEscape(username) + '</code>, and you do not ' +
      'have one yet. Nothing is signed in until one is set up.</p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      (offered.totp
        ? '<h2>An authenticator app</h2><p>A six-digit code from an app ' +
          'such as Google Authenticator, Microsoft Authenticator, 1Password ' +
          'or any other RFC 6238 app.</p>' +
          button('totp', 'Set up an authenticator app')
        : '') +
      (offered.webauthn
        ? '<h2>A security key</h2><p>A hardware key or a passkey on this ' +
          'device, used after your password.</p>' +
          button('webauthn', 'Set up a security key')
        : '') +
      '<div class="meta">This step expires in a few minutes; if it does, ' +
      'sign in again from the application that sent you here.</div>');
    log.debug('Leaving Authn.mfaSetupPage().');
    return html;
  }

  // The authenticator app's secret, as a QR code and typed, and the code that
  // confirms it.
  private async mfaSetupTotpPage(base, setupId, username, error) {
    const { log, xmlEscape, credentials, totp } = this.deps;
    log.debug('Entering Authn.mfaSetupTotpPage(). username=' + username);
    const held = credentials.pendingTotpFor(username);
    if (!held) {
      log.debug('Leaving Authn.mfaSetupTotpPage(). Nothing pending.');
      return null;
    }
    const issuer = totp.issuerFor(base);
    const uri = totp.otpauthUri({ issuer: issuer, account: username,
      secret: held.secret, algorithm: held.algorithm, digits: held.digits,
      period: held.period });
    let qr = '';
    try {
      qr = await totp.qrSvgDataUri(uri);
    } catch (e) {
      // Not fatal: the typed secret below is the whole credential.
      log.debug('Caught in Authn.mfaSetupTotpPage(): ' + ((e && e.message) ||
                                                          e));
      qr = '';
    }
    const html = this.mfaSetupShell('Set up your authenticator app',
      '<h1>Scan this with your authenticator app</h1><p class="sub">For ' +
      '<code>' + xmlEscape(username) + '</code>. Nothing is stored until the ' +
      'code below checks out.</p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      (qr ? '<p><img src="' + xmlEscape(qr) + '" width="220" height="220" ' +
            'alt="QR code carrying this account\'s otpauth setup URI"></p>'
          : '') +
      '<p>Or type it in: <code>' + xmlEscape(totp.grouped(held.secret)) +
      '</code> (' + xmlEscape('HMAC-' +
        String(held.algorithm).replace(/^SHA/, 'SHA-') + ', ' + held.digits +
        ' digits, every ' + held.period + ' seconds') + ')</p>' +
      '<form method="post" action="' + MFA_SETUP_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(setupId) + '">' +
      '<input type="hidden" name="action" value="confirm-totp">' +
      '<label for="code">The ' + held.digits + '-digit code your app shows ' +
      'now</label><input type="text" id="code" name="code" ' +
      'autocomplete="one-time-code" inputmode="numeric" maxlength="' +
      held.digits + '" autofocus>' +
      '<button type="submit" id="mfa-setup-confirm">Finish and sign ' +
      'in</button></form>');
    log.debug('Leaving Authn.mfaSetupTotpPage().');
    return html;
  }

  private sendMfaSetupPage(res, html, status?) {
    const { log } = this.deps;
    log.debug('Entering Authn.sendMfaSetupPage().');
    res.status(status || 200).type('text/html').set('Cache-Control', 'no-store')
       .send(html);
    log.debug('Leaving Authn.sendMfaSetupPage().');
  }

  // The step, or null with the refusal already sent. Only a step minted as an
  // enrolment is answered here: an ordinary second-factor step is somebody who
  // HOLDS a factor, and enrolling for them is the bypass the header refuses.
  private mfaSetupStep(res, setupId) {
    const { log, oauthError, errorCodes } = this.deps;
    log.debug('Entering Authn.mfaSetupStep().');
    const step = pendingMfa.get(setupId);
    if (!step || step.expires < Date.now() ||
        ['enrol', 'enrol-totp'].indexOf(step.factor) < 0) {
      if (step && step.expires < Date.now()) {
        pendingMfa.delete(setupId);
      }
      errorCodes.mark(res, 'STS-AUTHN-0173');
      oauthError(res, 400, 'invalid_request',
        'This second-factor set-up has expired or does not exist. Start the ' +
        'request again from the application that sent you here.');
      log.debug('Leaving Authn.mfaSetupStep(). No step.');
      return null;
    }
    log.debug('Leaving Authn.mfaSetupStep().');
    return step;
  }

  // ---------------------------------------------------------------------------
  // WHICH ENROLLED KEY AN ASSERTION IS TO BE CHECKED AGAINST (2026-09-10).
  //
  // A FUNCTION rather than four lines in the handler, because it is a RULE and
  // the handler is where it would quietly stop being one. It is also the only
  // shape in which it can be tested: a person holding TWO keys is the state
  // that tells "check the one the browser named" from "check the first one you
  // find", and no door in this service can currently enrol a second key — see
  // `tests/vendored/sts_webauthn_second_factor.js`'s header.
  //
  // **TWO FILTERS AND BOTH MATTER.**
  //
  //   * **THE ROLE.** A `primary` key signs somebody in ON ITS OWN, so it must
  //     not answer a SECOND-FACTOR step — accepting one there would let a
  //     person satisfy *a password AND a second factor* with a credential this
  //     service already considers sufficient by itself. It is the same filter
  //     `webauthnPage()` builds `allowCredentials` from, and that is a HINT to
  //     the browser where this is the enforcement.
  //   * **THE CREDENTIAL ID.** WebAuthn tolerates several credentials per
  //     person precisely because an assertion NAMES the one that produced it.
  //     Checking the signature against whichever key happens to be first is
  //     correct only while there is one — and then silently refuses every
  //     assertion from the others, which reads as a broken authenticator.
  //
  // The refusal is NAMED because the two reasons are different things to fix:
  // no key of this role at all is an account that should not have reached that
  // screen, and a key that is not one of theirs is an assertion from an
  // authenticator this person never enrolled.
  // ---------------------------------------------------------------------------
  keyForAssertion(username, role, presentedId) {
    const { log, credentials, errorCodes } = this.deps;
    log.debug("Entering Authn.keyForAssertion(). role=" + role);
    const usable = credentials.keysOf(username).filter(function (one) {
      return one.role === role;
    });
    const key = usable.filter(function (one) {
      return one.credentialId === String(presentedId || '');
    })[0];
    if (key) {
      log.debug("Leaving Authn.keyForAssertion(). Matched 1 of " +
                usable.length + ".");
      return { key: key, usable: usable.length };
    }
    log.debug("Leaving Authn.keyForAssertion(). No match among " +
              usable.length + ".");
    return errorCodes.mark({
      key: null, usable: usable.length,
      why: usable.length
        ? 'the assertion names a credential that is not one of the ' +
          usable.length + ' security key(s) enrolled for ' + username +
          ' as a ' + role + ' credential'
        : 'no security key is enrolled for ' + username + ' as a ' + role +
          ' credential'
    }, usable.length ? 'STS-AUTHN-0026' : 'STS-AUTHN-0025');
  }

  // ---------------------------------------------------------------------------
  // TWO SMALL READERS OF WHAT THE BROWSER SAID (2026-09-10).
  //
  // Both are about `clientExtensionResults` and `authenticatorAttachment`,
  // which are REPORTS: nothing signed carries either, so this service records
  // them and refuses nothing on them. They are functions rather than
  // expressions inline because the enrolment branch is already long and because
  // a person's key list is drawn from what they store — a label computed two
  // ways would be two labels for one key.
  // ---------------------------------------------------------------------------

  // Did the ceremony actually produce a DISCOVERABLE credential? `credProps.rk`
  // is the only way to find out — `residentKey: "preferred"` may or may not
  // have done, and nothing in the attestation says which. `null` means the
  // browser did not answer, which older ones and a ceremony run with
  // `webauthn.credProps` off both do; that is a third state and not a `false`.
  private discoverableFrom(credential) {
    const { log } = this.deps;
    log.debug("Entering Authn.discoverableFrom().");
    const results = credential && credential.clientExtensionResults;
    const props = results && results.credProps;
    log.debug("Leaving Authn.discoverableFrom().");
    return (props && typeof props.rk === 'boolean') ? props.rk : null;
  }

  // What a person will see this key called on `/portal/keys` and on their row
  // under `/admin/users`. Theirs to change; this is only the default, and it
  // says the one thing that tells two keys apart at the moment they are
  // enrolled — whether it is built into the machine or something they plugged
  // in.
  //
  // It deliberately does NOT use the AAGUID, which names the MODEL and would be
  // the better label: resolving one to "YubiKey 5 NFC" needs the FIDO metadata
  // service, and this service consults none — see `webauthn.attestation`. A
  // hex string is worse than no label at all.
  private labelForKey(credential, verdict) {
    const { log } = this.deps;
    log.debug("Entering Authn.labelForKey().");
    const attachment = String((credential &&
                               credential.authenticatorAttachment) || '');
    if (attachment === 'platform') {
      log.debug("Leaving Authn.labelForKey().");
      return 'this device';
    }
    if (attachment === 'cross-platform') {
      log.debug("Leaving Authn.labelForKey().");
      return 'security key';
    }
    log.debug("Leaving Authn.labelForKey().");
    return (verdict && verdict.algorithm)
      ? 'security key (' + verdict.algorithm + ')' : 'security key';
  }

  private webauthnPage(base, mfaId, username, error) {
    const { log, xmlEscape, credentials, webauthnPolicy } = this.deps;
    log.debug("Entering Authn.webauthnPage(). username=" + username);
    // ---------------------------------------------------------------------
    // WHICH KEYS THIS PERSON HOLDS, FROM THE ONE STORE (2026-09-10).
    //
    // It was a single credential out of this module's own map. It is now every
    // key on their directory entry, which is what makes `allowCredentials` a
    // LIST — the specification has expected several since Level 1 (a key at the
    // desk and one on the keyring), an assertion NAMES the credential that
    // produced it, and `webauthn.maxKeysPerPerson` is the setting that bounds
    // it.
    //
    // **ONLY THE KEYS THAT ANSWER THIS ROLE.** A `primary` key signs somebody
    // in on its own and an `mfa` key is a second factor beside a password;
    // offering both in one ceremony would let a person satisfy a second-factor
    // step with a credential this service considers a way IN, which is the
    // whole distinction `credentials.js`'s ROLES table exists to keep.
    // ---------------------------------------------------------------------
    const step = pendingMfa.get(mfaId);
    // Absent where the step has already gone — an expired id reaches this
    // function through one of the error paths — and false is the safe reading:
    // the page then describes the more cautious of the two roles.
    const passwordless = !!(step && step.passwordless);
    const wantedRole = passwordless ? 'primary' : 'mfa';
    const known = credentials.keysOf(username).filter(function (one) {
      return one.role === wantedRole;
    });
    const mode = known.length ? 'get' : 'create';
    // Read ONCE and used by the data attribute, the RP ID line and the line
    // that says what is being asked for. rpIdOf() logs when it refuses a
    // configured value, and calling it three times would print that warning
    // three times for one page.
    const rpId = this.rpIdOf(base);
    const options = webauthnPolicy.settings();
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><title>Security key — mock authentication ' +
      'service</title><style>body{font-family:system-ui,-apple-system,"Segoe ' +
      'UI",Arial,sans-serif;background:#f4f4f7;margin:0;display:flex;' +
      'align-items:center;justify-content:center;min-height:100vh;color:#222}' +
      '.card{background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:10px;padding:28px 32px;width:420px;box-shadow:0 ' +
      '6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 ' +
      '4px}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
      '18px}button{padding:9px 12px;border-radius:5px;border:1px solid ' +
      '#12107c;background:#12107c;color:#fff;font-size:.95em;cursor:pointer;' +
      'width:100%}.err{background:#fdecea;border:1px solid ' +
      '#f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
      'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;' +
      'padding-top:14px;border-top:1px solid ' +
      '#eee;font-size:.75em;color:#777;word-break:break-all}.meta ' +
      'div{margin:2px 0}code{font-family:ui-monospace,SFMono-Regular,Menlo,' +
      'monospace}</style></head><body><div ' +
      'class="card"><h1>' + (mode === 'create' ? 'Enrol a security key' :
                             'Use ' +
          'your security key') + '</h1><p ' +
      'class="sub">' + (passwordless
        ? 'Passwordless sign-in as <code>' + xmlEscape(username) + '</code> ' +
            '— the key is the only factor'
        : 'Second factor for <code>' + xmlEscape(username) + '</code>') +
        '</p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      '<button id="wa-go" type="button">' +
      (mode === 'create' ? 'Enrol security key' :
       'Authenticate with security key') + '</button><form ' +
      'method="post" action="' + WEBAUTHN_PATH + '" id="wa-form">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<input type="hidden" name="mode" value="' + mode + '">' +
      '<input type="hidden" name="credential" id="wa-credential">' +
      '</form>' +
      // The ceremony's parameters travel as data attributes and the script is a
      // separate resource, so this page needs no inline script. That is not
      // fastidiousness: this service sets `script-src 'none'` on everything by
      // design (see app.js), and an inline script here would simply not run —
      // silently, with the button doing nothing. One page relaxes it to 'self',
      // which is the smallest exception that works.
      '<div id="wa-data"' +
      ' data-challenge="' + xmlEscape(step ? step.challenge : '') + '"' +
      ' data-rpid="' + xmlEscape(rpId) + '"' +
      ' data-user="' + xmlEscape(username) + '"' +
      // EVERY key of this role, comma-separated, because a person may hold
      // several and the authenticator picks. Empty on the enrolment path, where
      // there is nothing to allow.
      ' data-allow="' + xmlEscape(known.map(function (one) {
        return one.credentialId;
      }).join(',')) + '"' +
      // EVERY key they hold, of EITHER role, so an authenticator already
      // registered here cannot be registered again on the enrolment path. It is
      // a fact about the DEVICE rather than about what the credential is for,
      // which is why it is not the role-filtered list above.
      ' data-exclude="' +
      xmlEscape(credentials.keysOf(username).map(function (one) {
        return one.credentialId;
      }).join(',')) + '"' +
      // THE CEREMONY'S OPTIONS, AS ONE JSON OBJECT (2026-09-10). Every one of
      // these was a literal inside WEBAUTHN_SCRIPT below until this day, which
      // is why /admin/webauthn did not exist: there was nothing to draw. The
      // script is a STATIC resource under `script-src 'self'` and cannot be
      // generated per request, so anything that varies has to travel as data —
      // and one parsed object is one place to get it wrong rather than eleven
      // attributes each coerced by hand. Nothing in it is secret and nothing in
      // it is trusted on the way back: it is a REQUEST to the browser, and
      // every security property is checked against the pending step and the
      // origin when the result arrives.
      ' data-options="' + xmlEscape(JSON.stringify(
          mode === 'create' ? webauthnPolicy.creationOptions(rpId)
                            : webauthnPolicy.requestOptions(rpId))) + '"' +
      ' data-mode="' + mode + '"></div>' +
      '<div class="meta">' +
      '<div>RP ID: <code>' + xmlEscape(rpId) + '</code> — the ceremony is ' +
                                               'bound to this origin' +
      (options.rpId
        ? ', widened to this suffix by <code>webauthn.rpId</code>'
        : '') + '.</div>' +
      '<div>challenge: <code>' + xmlEscape(step ? step.challenge : '') +
      '</code></div>' +
      // WHAT THIS CEREMONY IS ASKING FOR, said on the page rather than only in
      // the options attribute. This is a debugging service and these four are
      // the settings whose effect somebody is most likely to be here to
      // observe; /admin/webauthn is where they are changed.
      '<div>' + xmlEscape(
        (mode === 'create'
          ? 'attestation ' + options.attestation + ', ' +
            'algorithms ' + options.algorithms.join('/') + ', '
          : '') +
        'user verification ' + options.userVerification +
        (options.userVerification === 'required'
          ? ' (CHECKED here — an authenticator that did not verify is refused)'
          : ' (requested, not required)') +
        (mode === 'create' && options.residentKey !== 'discouraged'
          ? ', resident key ' + options.residentKey
          : '') +
        (mode === 'create' && options.authenticatorAttachment !== 'any'
          ? ', ' + options.authenticatorAttachment + ' authenticators only'
          : '')) + '</div>' +
      '<div>' + (mode === 'create'
        ? 'No key is enrolled for this user yet, so this step registers one.'
        : 'A key is already enrolled for this user, so this step is an ' +
          'assertion.') + '</div><div>' + (passwordless
        ? 'No password was presented. On success the session records amr ' +
          '["hwk"] and acr "1" — ONE factor — and this counts as an ' +
          'authentication in its own right, so it appears on /admin/users ' +
          'and the directory grows an entry for ' + xmlEscape(username) + '.'
        : 'A password step has already succeeded. On success the session ' +
          'records amr ["pwd","hwk"] and acr "mfa", and the directory entry ' +
          'for ' + xmlEscape(username) + ' ' +
          'is flagged as having authenticated with more than one ' +
          'factor.') + '</div>' +
      // THE OTHER SECOND FACTOR, WHERE THIS PERSON HOLDS ONE (2026-09-10). The
      // step's `alternate` is resolved when the step is MINTED and not here, so
      // this link cannot offer a mechanism the person has not enrolled — see
      // the branch in the sign-in handler. The commonest reason to hold both is
      // standing at a machine the key is not plugged into, which is exactly the
      // moment a page with no way out is useless.
      (step && step.alternate === 'totp'
        ? '<div><a href="' + TOTP_PATH + '?mfa=' + encodeURIComponent(mfaId) +
          '">Use a code from your authenticator app instead</a></div>'
        : '') +
      this.walletFactorLinksHtml(mfaId, step) +
      // AND THE WAY OUT WHEN THE KEY IS NOT TO HAND AT ALL (2026-09-10), which
      // is the commonest reason somebody is stuck at this screen: the key is in
      // a drawer at home. Drawn only where the step says an unspent recovery
      // code exists, and after the alternative above, because the codes are
      // finite and issued once.
      (step && step.backup
        ? '<div><a href="' + BACKUP_CODE_PATH + '?mfa=' +
          encodeURIComponent(mfaId) + '">I do not have my security key — use ' +
          'a recovery code</a></div>'
        : '') +
      '</div></div>' +
      '<script src="' + WEBAUTHN_SCRIPT_PATH + '"></script></body></html>\n';
    log.debug("Leaving Authn.webauthnPage(). mode=" + mode);
    return html;
  }

  // The one page in this service that runs a script, and the one response that
  // relaxes the policy for it — to 'self', not 'unsafe-inline', so the
  // exception is a named resource rather than a hole. app.js sets script-src
  // 'none' on everything by default and that default is worth keeping.
  private sendWebauthnPage(res, html) {
    const { app, log } = this.deps;
    log.debug("Entering Authn.sendWebauthnPage().");
    // Through the builder, so the framing clauses cannot be lost by editing
    // this line — see the note above contentSecurityPolicy() in app.js. What is
    // being relaxed is script-src and nothing else.
    res.set('Content-Security-Policy',
            app.contentSecurityPolicy({ 'script-src': "'self'" }));
    res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug("Leaving Authn.sendWebauthnPage().");
  }

  // ---------------------------------------------------------------------------
  // THE ORIGIN THE CEREMONY IS BOUND TO, which is NOT this service's base URL —
  // and the difference was a bug for every trust realm from the day realms
  // existed until 2026-08-26.
  //
  // `baseUrlOf(req)` answers what this service calls itself, PREFIX INCLUDED:
  // `https://sts:8081` in the default realm and
  // `https://sts:8081/realm/acme` in `acme`. A browser's
  // `clientDataJSON.origin` is an ORIGIN — scheme, host and port, never a path
  // — so comparing it against the base URL succeeds in the default realm by
  // coincidence and fails in every other one, with `origin matches / got
  // https://sts:8081, expected https://sts:8081/realm/acme`. Every WebAuthn
  // ceremony inside a realm was therefore refused, and nothing noticed because
  // the only test of this step ran in the default realm.
  //
  // It is its own function beside `rpIdOf()` because the two are the same
  // mistake waiting to be made twice: one is the origin, one is its host, and
  // neither is the base URL.
  // ---------------------------------------------------------------------------
  originOf(base) {
    const { log } = this.deps;
    log.debug("Entering Authn.originOf(). base=" + base);
    try {
      const origin = new URL(base).origin;
      log.debug("Leaving Authn.originOf(). " + origin);
      return origin;
    } catch (e) {
      log.debug("Caught in Authn.originOf(): " + ((e && e.message) || e));
      // A base that will not parse is a misconfiguration of this service rather
      // than of the ceremony, and the same fallback rpIdOf() takes: strip
      // whatever path is there and keep the authority, so the comparison below
      // is at least against something of the right shape.
      const stripped = String(base).replace(
        /^(https?:\/\/[^/?#]+).*$/, '$1');
      log.debug("Leaving Authn.originOf(). Unparseable; " + stripped);
      return stripped;
    }
  }

  // ---------------------------------------------------------------------------
  // THE RP ID.
  //
  // **THIS FUNCTION'S COMMENT READ "never anything configurable" UNTIL
  // 2026-09-10, AND THE ARGUMENT IT MADE IS STILL RIGHT ABOUT EVERYTHING EXCEPT
  // ONE CASE.** It said: *a mock that let you set it to something else would be
  // teaching the one lesson WebAuthn exists to prevent* — which is true of an
  // ARBITRARY value, because a credential is bound to its RP ID and letting a
  // relying party claim somebody else's is the whole of the attack the binding
  // exists to stop.
  //
  // What the sentence missed is that WebAuthn itself defines a legal override
  // and browsers enforce it: the RP ID may be a **REGISTRABLE DOMAIN SUFFIX**
  // of the origin's host — `example.com` when reached at `sts.example.com` — so
  // that one credential works across the sibling hosts of a deployment. That is
  // not a weakening of the binding, it is the binding at a coarser grain, and
  // it is a thing a client author testing a real deployment shape needs to be
  // able to arrange.
  //
  // **SO `webauthn.rpId` IS HONOURED AND IS CHECKED HERE AS WELL AS BY THE
  // BROWSER**, which is the part that earns it. A browser refuses an illegal RP
  // ID with a `SecurityError`, and the ceremony reports that as one of its
  // several indistinguishable failures — so an operator who typed the wrong
  // thing sees what looks like a broken authenticator. Refusing it here, by
  // name, in the log, is the difference between a five-minute fix and an
  // afternoon.
  //
  // **WIDENING IT IS NOT FREE AND THE SETTING SAYS SO**: every host under that
  // suffix can then assert these credentials.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // **AND IN PRODUCT MODE A REFUSED VALUE REFUSES THE CEREMONY (2026-09-12).**
  //
  // The fallback below — use the host this was reached on and say why — is a
  // development convenience with a security edge: the HOST is read off the
  // request, so an operator who set `webauthn.rpId` to pin the credential scope
  // got, on any request whose Host did not fit, a ceremony scoped to whatever
  // that Host said. `rpIdProblem()` is the refusal and asks
  // `mode.acceptsUnregisteredAddresses()`, which is the question exactly: may a
  // ceremony run against an address the configuration did not name. It is
  // checked at the doors that DRAW or VERIFY a ceremony, and `rpIdOf()` itself
  // keeps answering, because a page that says what it would have sent is worth
  // more than a page that throws.
  // ---------------------------------------------------------------------------
  rpIdProblem(base) {
    const { log, mode, webauthnPolicy } = this.deps;
    log.debug("Entering Authn.rpIdProblem().");
    const wanted = webauthnPolicy.settings().rpId;
    if (!wanted || mode.acceptsUnregisteredAddresses()) {
      log.debug("Leaving Authn.rpIdProblem().");
      return '';
    }
    let host;
    try {
      host = new URL(base).hostname;
    } catch (e) {
      log.debug("Caught in Authn.rpIdProblem(): " + ((e && e.message) || e));
      // Unparseable base: the same literal fallback `rpIdOf()` takes.
      host = String(base).replace(/^https?:\/\//, '').split(':')[0];
    }
    const lower = String(host).toLowerCase();
    const want = String(wanted).toLowerCase();
    if (lower === want || lower.endsWith('.' + want)) {
      log.debug("Leaving Authn.rpIdProblem().");
      return '';
    }
    log.debug("Leaving Authn.rpIdProblem().");
    return 'webauthn.rpId is "' + wanted + '", which is neither the host ' +
           'this request reached ("' + host + '") nor a registrable domain ' +
           'suffix of it, and in product mode a security-key ceremony is not ' +
           'run against an address the configuration did not name. Reach ' +
           'this service at a host under ' +
           '"' + wanted + '", or set global.publicBaseUrl to one.';
  }

  // ---------------------------------------------------------------------------
  // THE ORIGIN A CEREMONY IS ACCEPTED FROM (2026-09-12).
  //
  // `webauthn.allowedOrigins` EMPTY — the default — is `originOf(base)`, which
  // is what this service always compared against and which
  // `global.publicBaseUrl` already pins when it is set. NON-EMPTY, the list is
  // the whole answer: the clientDataJSON's origin is looked up in it, and one
  // that is not there is answered with the list's first entry so the verifier
  // refuses it in its own words (`origin matches / got …, expected …`) rather
  // than this function inventing a second refusal with a different sentence.
  //
  // The browser's claimed origin is READ here, not trusted: it is only ever
  // returned when it is already on an operator's list, and the verifier still
  // compares the signed bytes against it.
  // ---------------------------------------------------------------------------
  private allowedOrigins() {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering Authn.allowedOrigins().");
    const raw = config.value('webauthn.allowedOrigins');
    log.debug("Leaving Authn.allowedOrigins().");
    return (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .map(function (one) { return String(one || '').trim(); })
      .filter(Boolean)
      .map(function (one) { return self.originOf(one); });
  }

  expectedOriginFor(base, credential) {
    const { log } = this.deps;
    log.debug("Entering Authn.expectedOriginFor().");
    const list = this.allowedOrigins();
    if (!list.length) {
      log.debug("Leaving Authn.expectedOriginFor(). Derived from the base.");
      return this.originOf(base);
    }
    let claimed = '';
    try {
      const clientData = credential && credential.response &&
                         credential.response.clientDataJSON;
      const parsed = JSON.parse(Buffer.from(String(clientData || ''),
                                            'base64url')
                                  .toString('utf8'));
      claimed = String((parsed && parsed.origin) || '');
    } catch (e) {
      log.debug("Caught in Authn.expectedOriginFor(): " + ((e && e.message) ||
                                                           e));
      // Not decodable. The verifier reads the same bytes and refuses them with
      // a sentence about the client data, which is the right place for that.
      claimed = '';
    }
    if (claimed && list.indexOf(claimed) >= 0) {
      log.debug("Leaving Authn.expectedOriginFor(). " + claimed +
                " is on the list.");
      return claimed;
    }
    log.debug("Leaving Authn.expectedOriginFor(). Not on the list; the " +
              "verifier refuses.");
    return list[0];
  }

  rpIdOf(base) {
    const { log, mode, webauthnPolicy } = this.deps;
    log.debug("Entering Authn.rpIdOf(). base=" + base);
    let host;
    try {
      host = new URL(base).hostname;
    } catch (e) {
      log.debug("Caught in Authn.rpIdOf(): " + ((e && e.message) || e));
      // A base that will not parse is a misconfiguration of this service rather
      // than of the ceremony; fall back to the literal so the page still says
      // something true about what it will send.
      host = String(base).replace(/^https?:\/\//, '').split(':')[0];
    }
    const wanted = webauthnPolicy.settings().rpId;
    if (!wanted) {
      log.debug("Leaving Authn.rpIdOf(). " + host +
                " (the host this was reached on).");
      return host;
    }
    // EQUAL, OR A SUFFIX AT A LABEL BOUNDARY. `mple.com` is a suffix of
    // `example.com` as a string and is not a domain suffix of it, and a check
    // written with endsWith() alone accepts it — which is the one mistake this
    // whole function is here to refuse.
    const lower = String(host).toLowerCase();
    const want = String(wanted).toLowerCase();
    if (lower === want || lower.endsWith('.' + want)) {
      log.debug("Leaving Authn.rpIdOf(). " + want +
                " (configured, a domain suffix of " +
                host + ").");
      return want;
    }
    log.warn('authn: webauthn.rpId is "' + wanted + '", which is NOT this ' +
             'origin\'s host ("' + host + '") nor a registrable domain ' +
             'suffix of it. WebAuthn forbids that and the browser would ' +
             'refuse the ceremony with an error indistinguishable from a ' +
             'hardware failure, so this service is using ' +
             '"' + host + '" instead and telling you ' +
             'why. Set webauthn.rpId to "" or to a suffix of the host you ' +
             'reach this service on.' +
             (mode.acceptsUnregisteredAddresses() ? ''
               : ' In product mode the ceremony itself is refused — see ' +
                 'rpIdProblem().'));
    log.debug("Leaving Authn.rpIdOf(). " + host +
              " (the configured value was refused).");
    return host;
  }

  // The rest of the WebAuthn door, split out so the asynchronous spend above
  // reads as one act. Everything below is what the endpoint always did.
  private finishWebauthn(req, res, base, body, step, verdict) {
    const { log, logArtifact, errorCodes, webauthnPolicy,
      credentials } = this.deps;
    log.debug("Entering Authn.finishWebauthn().");
    logArtifact('WebAuthn ' +
                (String(body.mode) === 'create' ? 'registration' : 'assertion'),
                'as verified by this server', { ok: verdict.ok,
                                                checks: verdict.checks });

    if (!verdict.ok) {
      // Name the check that failed. "Authentication failed" would be true and
      // useless, and this is a debugging service.
      errorCodes.mark(res,
                      errorCodes.codeOf(verdict) ||
                      webauthnPolicy.failureCodeFor(verdict));
      // A POLICY refusal made before the verifier's list existed — the two
      // product-mode enrolment refusals (STS-AUTHN-0024, 0206) — carries a
      // `why` and no `failed`. Reading `failed.join()` off one answered 500
      // until 2026-09-21, which hid both refusals behind an error page.
      const failed = Array.isArray(verdict.failed) && verdict.failed.length
        ? verdict.failed : [String(verdict.why || 'refused')];
      log.debug("Leaving Authn.finishWebauthn(). Refused: " +
                failed.join('; '));
      return this.sendWebauthnPage(res,
                                   this.webauthnPage(base, String(body.mfa_id),
                           step.username,
                           'The second factor did not verify — ' +
                           failed.join('; ') + '.'));
    }

    pendingMfa.delete(String(body.mfa_id));
    // What the session claims, which is the whole difference between the two
    // roles and the only place it is decided. `hwk` is the RFC 8176 value for
    // proof of possession of a hardware key, which is what a WebAuthn assertion
    // is; `pwd` is on the list only where a password step actually happened.
    //
    // acr "1" for the passwordless sign-in is deliberate and it is the
    // conservative reading: this ceremony is performed with userVerification
    // "preferred" rather than "required" (see the script above), so the key
    // proves possession and nothing about the person holding it. Calling that
    // "mfa" because it is phishing-resistant would be the fake this profile
    // refuses everywhere else — a relying party that asked for two factors
    // would be told it got them.
    const amr = step.passwordless ? ['hwk'] :
                this.firstAmrOf(step).concat(['hwk']);
    const acr = step.passwordless ? '1' : 'mfa';
    // The single funnel, reached through startSession() as every sign-in at
    // these screens is. It is what puts the person on /admin/users and what
    // seeds their entry in the embedded directory — so a PRIMARY WebAuthn
    // sign-in creates that entry exactly as a password one does, and a SECOND
    // FACTOR adds no second identity, because the person it authenticates is
    // the one the password step already named. What the second factor adds to
    // the entry is a flag; see ldap_server.js's applyAuthenticationFactors(),
    // which reads the amr below.
    // WHICH KEY, AND WHAT IT SAID ABOUT ITSELF (#62 P0): the credential that
    // answered — the one just registered, or the stored one an assertion
    // named — and the authenticator data's backup flags (WebAuthn Level 3,
    // section 6.1: BE, whether the credential can be synced; BS, whether it
    // is). A device-bound key and a synced passkey are different evidence
    // about where a sign-in came from.
    const answered = verdict.answeredBy ||
      { id: verdict.credentialId, aaguid: verdict.aaguid };
    const flags = verdict.flags || {};
    const said = { request: req, risk: step.risk, credential: {
      kind: 'webauthn', id: answered.id || '',
      aaguid: answered.aaguid
        ? credentials.Credentials.aaguidString(answered.aaguid) : '',
      backupEligible: typeof flags.be === 'boolean' ? flags.be : undefined,
      backupState: typeof flags.bs === 'boolean' ? flags.bs : undefined } };
    const started = this.startSession(res, step.username, amr, acr,
                                      step.authn.protocol, said);
    if (this.refusedSession(res, base, step.authn, step.username, started,
                            said)) {
      log.debug("Leaving Authn.finishWebauthn(). Refused.");
      return;
    }
    // Back to the caller, exactly as the password-only path returns: the
    // session now records what happened, and the request that was interrupted
    // runs again and sees it.
    this.returnToCaller(res, step.authn, null, null);
    log.debug("Leaving Authn.finishWebauthn(). " + step.username +
              (step.passwordless ? " signed in with a security key alone."
                                 : " completed the second factor."));
  }

  // ===========================================================================
  // THE ONE-TIME CODE STEP (RFC 6238), 2026-09-10.
  //
  // The other second factor, and the one that needs no browser API, no
  // authenticator attached to this machine and no origin. A form with one
  // field.
  //
  // ---------------------------------------------------------------------------
  // IT IS A PAGE WITH NO SCRIPT, WHICH IS WHY IT IS NOT DRAWN LIKE THE ONE
  // ABOVE.
  //
  // `/authn/webauthn` is one of the six pages in this service that relax
  // `script-src`, because a WebAuthn ceremony IS a browser API call and there
  // is no way to perform one without script. **This page needs none** — a
  // person reads six digits off a phone and types them into an input — so it is
  // served under the service-wide `script-src 'none'` like everything else, and
  // `sendTotpPage()` sets no policy of its own.
  //
  // That is worth saying out loud because the obvious move when adding a second
  // factor beside the first is to copy its `sendWebauthnPage()`. Doing that
  // would have quietly added a seventh scripted page to the inventory in the
  // root `CLAUDE.md` — for a page with no script on it — and the test for a
  // script is that the page CANNOT work without one.
  //
  // ---------------------------------------------------------------------------
  // THERE IS NO ENROLMENT HERE, AND THAT IS THE DIFFERENCE FROM THE
  // SECURITY-KEY PAGE THAT MATTERS MOST.
  //
  // That page enrols on first use: a person who has never registered a key is
  // shown the registration ceremony, and a session comes out of it. **This page
  // only ever VERIFIES.** Enrolling an authenticator means being shown a
  // secret, which means the enrolment must happen somewhere the person is
  // already authenticated — `/portal/mfa` — or somewhere a credential
  // authorises it — `/portal/activate`. A sign-in screen that handed out a
  // shared secret to whoever typed a password would be a second factor anybody
  // could set up for themselves, which is not a second factor.
  //
  // So a person with no enrolment never reaches this page: `mechanismsFor()`
  // reports no second factor and the sign-in completes on one.
  // ===========================================================================
  private totpPage(base, mfaId, username, error, notice) {
    const { log, xmlEscape, credentials } = this.deps;
    log.debug('Entering Authn.totpPage(). username=' + username);
    const step = pendingMfa.get(mfaId);
    // What the AUTHENTICATOR was told, off the person's own enrolment, so the
    // field asks for the right number of digits. A missing enrolment reads as
    // six, which is what the page would have said anyway and is only reachable
    // through an error path where the step has already gone.
    const enrolled = credentials.mechanismsFor(username);
    const digits = (enrolled.totpDetail && enrolled.totpDetail.digits) || 6;
    const alternate = step && step.alternate === 'webauthn';
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><title>One-time code — mock authentication ' +
      'service</title><style>body{font-family:system-ui,-apple-system,"Segoe ' +
      'UI",Arial,sans-serif;background:#f4f4f7;margin:0;display:flex;' +
      'align-items:center;justify-content:center;min-height:100vh;color:#222}' +
      '.card{background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:10px;padding:28px 32px;width:420px;box-shadow:0 ' +
      '6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 ' +
      '4px}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
      '18px}label{display:block;font-size:.8em;color:#444;margin:0 0 4px}' +
      // A WIDE, MONOSPACED, LETTER-SPACED FIELD. `inputmode="numeric"` puts a
      // phone's number pad up, `autocomplete="one-time-code"` is what lets iOS
      // and Android offer the code from the notification, and `autofocus` means
      // somebody arriving here can start typing. None of the three is script.
      'input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px ' +
      'solid #c8c8d0;border-radius:5px;font-size:1.4em;letter-spacing:.35em;' +
      'text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,' +
      'monospace;margin-bottom:14px}button{padding:9px ' +
      '12px;border-radius:5px;border:1px solid #12107c;background:#12107c;' +
      'color:#fff;font-size:.95em;cursor:pointer;width:100%}' +
      '.err{background:#fdecea;border:1px solid ' +
      '#f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
      'font-size:.85em;margin-bottom:12px}.ok{background:#eef7ee;border:1px ' +
      'solid #cfe6cf;color:#1d5c1d;padding:8px 10px;border-radius:5px;' +
      'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;' +
      'padding-top:14px;border-top:1px solid ' +
      '#eee;font-size:.75em;color:#777}.meta div{margin:2px 0}.meta ' +
      'a{color:#12107c}code{font-family:ui-monospace,SFMono-Regular,Menlo,' +
      'monospace}</style></head><body><div class="card"><h1>Your one-time ' +
      'code</h1><p class="sub">Second factor for <code>' + xmlEscape(username) +
      '</code></p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      (notice ? '<div class="ok">' + xmlEscape(notice) + '</div>' : '') +
      '<form method="post" action="' + TOTP_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<label for="code">The ' + digits + '-digit code from your ' +
      'authenticator app</label><input type="text" id="code" name="code" ' +
      'autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]*" ' +
      'maxlength="' + digits + '" ' +
      'autofocus placeholder="' + '0'.repeat(digits) + '">' +
      '<button type="submit" id="totp-submit">Sign in</button>' +
      '</form>' +
      '<div class="meta">' +
      '<div>The code changes every ' +
      xmlEscape(String((enrolled.totpDetail &&
                        enrolled.totpDetail.period) || 30)) +
      ' seconds. A code can only be used once (RFC 6238 section 5.2), so if ' +
      'you have just signed in, wait for the next one.</div>' +
      (alternate
        ? '<div><a href="/authn/webauthn?mfa=' + encodeURIComponent(mfaId) +
          '">Use your security key instead</a></div>'
        : '') +
      this.walletFactorLinksHtml(mfaId, step) +
      // THE WAY OUT (2026-09-10), drawn only where the step says this person
      // holds an unspent recovery code. It is LAST on purpose: the codes are a
      // finite, single-use resource issued once, and a link offered above the
      // ordinary alternative would spend them on a phone that was merely in the
      // next room.
      (step && step.backup
        ? '<div><a href="' + BACKUP_CODE_PATH + '?mfa=' +
          encodeURIComponent(mfaId) + '">I cannot use my authenticator app — ' +
          'use a recovery code</a></div>'
        : '') +
      '</div></div></body></html>\n';
    log.debug('Leaving Authn.totpPage().');
    return html;
  }

  // NO `Content-Security-Policy` OF ITS OWN. See the header — this page has no
  // script, so it inherits the `script-src 'none'` that `app.js` puts on every
  // response, which is the whole of what that setting is for.
  //
  // `no-store` for the reason every page in a sign-in carries it: it names the
  // person being authenticated and is reached from shared browsers.
  private sendTotpPage(res, html) {
    const { log } = this.deps;
    log.debug('Entering Authn.sendTotpPage().');
    res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug('Leaving Authn.sendTotpPage().');
  }

  private finishTotp(req, res, base, mfaId, step, verdict) {
    const { log, logArtifact, websecurity, errorCodes } = this.deps;
    log.debug('Entering Authn.finishTotp().');
    if (!verdict.ok) {
      // THE REASON IS SHOWN HERE, WHERE THE SIGN-IN SCREEN SHOWS NONE. That
      // screen hides which of "wrong password" and "no such person" happened,
      // because either answer is account enumeration. **Nothing is enumerable
      // at this door**: the person has already authenticated with a first
      // factor, so the only new fact on offer is about their own account — and
      // "that code has already been used" against "that code is not right" is
      // the difference between waiting thirty seconds and thinking your
      // authenticator is broken.
      log.info('authn: the one-time code for "' + step.username +
               '" was refused (' + verdict.reason + ').');
      log.debug('Leaving Authn.finishTotp(). Refused: ' + verdict.reason + '.');
      errorCodes.mark(res, errorCodes.codeOf(verdict) || 'STS-AUTHN-0105');
      return this.sendTotpPage(res, this.totpPage(base, mfaId, step.username,
                                                  verdict.detail, ''));
    }
    // Not awaited: this function answers synchronously, and a clear that lands
    // a moment after the page is only a count forgotten slightly late.
    websecurity.succeededShared('mfa-code', req, step.username);
    pendingMfa.delete(mfaId);

    logArtifact('RFC 6238 one-time code', 'as verified by this server',
                { username: step.username, step: verdict.counter,
                  drift: verdict.drift });

    // WHAT THE SESSION CLAIMS. `otp` is RFC 8176's value and its registry entry
    // names RFC 4226 and RFC 6238 explicitly, so there is nothing to invent;
    // the `acr` is `mfa` because two factors really were presented — a password
    // and a code — which is the one case where this service can say that
    // honestly.
    //
    // There is no passwordless branch here and there cannot be: a one-time code
    // is never a first factor (see common/totp.ts), so the first factor's own
    // `amr` is always in the list — `pwd`, or since #38's follow-ups `pop`
    // for a wallet presentation (firstAmrOf()).
    // is never a first factor (see common/totp.ts), so `pwd` is always in the
    // list.
    const amr = this.firstAmrOf(step).concat(['otp']);
    const said = { request: req, risk: step.risk,
                   credential: { kind: 'totp' } };
    const started = this.startSession(res, step.username, amr, 'mfa',
                                      step.authn.protocol, said);
    if (this.refusedSession(res, base, step.authn, step.username, started,
                            said)) {
      log.debug('Leaving Authn.finishTotp(). Refused.');
      return;
    }
    this.returnToCaller(res, step.authn, null, null);
    log.debug('Leaving Authn.finishTotp(). ' + step.username +
              ' completed the second factor with a one-time code.');
  }

  // ===========================================================================
  // /authn/backup-code — THE WAY BACK IN WHEN THE SECOND FACTOR IS NOT TO HAND
  // (2026-09-10).
  //
  // The third second-factor screen, and the only one that is never what a
  // sign-in ASKS for. `credentials.mechanismsFor().secondFactor` answers
  // `webauthn` or `totp` and never this: a person is CONFIGURED for one of
  // those two, and a recovery code stands in for whichever of them they cannot
  // produce right now. So this screen is reachable only from one of the other
  // two, with a step id they already hold.
  //
  // ---------------------------------------------------------------------------
  // IT IS A PAGE WITH NO SCRIPT, LIKE `/authn/totp` AND UNLIKE
  // `/authn/webauthn`.
  //
  // A person reads a string off a piece of paper and types it into an input.
  // There is no browser API in that, so this is served under the service-wide
  // `script-src 'none'` and `sendBackupCodePage()` sets no policy of its own —
  // which is worth stating rather than leaving to be noticed, because the root
  // `CLAUDE.md` keeps an inventory of the seven pages here that relax the
  // policy and the test for being on it is that the page CANNOT work without a
  // script. `/authn/totp` had to make this argument the same day and this one
  // makes it again rather than citing it.
  //
  // ---------------------------------------------------------------------------
  // THERE IS NO ENROLMENT HERE AND THERE IS NO ISSUE HERE.
  //
  // `/authn/webauthn` enrols on first use. This screen does neither: a set of
  // recovery codes is issued by the act of enrolling a second factor, once, and
  // `common/credentials.ts` is where that happens. A sign-in screen that could
  // ISSUE a set would be a door that hands a working second factor to whoever
  // typed a password — which is the same refusal the console is held to for
  // TOTP enrolment.
  //
  // ---------------------------------------------------------------------------
  // **THE CODE IS SPENT AND THE PERSON IS TOLD HOW MANY ARE LEFT**, on the way
  // through rather than afterwards. That is the one thing this screen does that
  // the other two do not, and it is the whole of what makes a finite credential
  // usable: somebody down to their last code needs to know it now, while they
  // are signed in and able to do something about it, rather than the next time
  // they are locked out.
  // ===========================================================================
  private backupCodePage(base, mfaId, username, error, notice) {
    const { log, xmlEscape, credentials } = this.deps;
    log.debug('Entering Authn.backupCodePage(). username=' + username);
    const step = pendingMfa.get(mfaId);
    // WHAT THEY HOLD, off the credential store rather than off the step: the
    // step was minted before this screen was reached and a code may have been
    // spent since. It is the COUNT and never the codes — `backupCodeStatus()`
    // exists so that a page cannot ask for one and receive the other.
    const status = credentials.mechanismsFor(username).backupCodes ||
                   { remaining: 0, total: 0 };
    // WHICH MECHANISM THEY ARE STANDING IN FOR, so the page can say what this
    // is instead of. It is the step's, because that is what was asked for.
    const insteadOf = step && step.factor === 'webauthn'
      ? 'your security key' : 'your authenticator app';
    const low = status.remaining > 0 && status.remaining <= 3;
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><title>Recovery code — mock authentication ' +
      'service</title><style>body{font-family:system-ui,-apple-system,"Segoe ' +
      'UI",Arial,sans-serif;background:#f4f4f7;margin:0;display:flex;' +
      'align-items:center;justify-content:center;min-height:100vh;color:#222}' +
      '.card{background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:10px;padding:28px 32px;width:420px;box-shadow:0 ' +
      '6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 ' +
      '4px}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
      '18px}label{display:block;font-size:.8em;color:#444;margin:0 0 4px}' +
      // WIDER AND LESS LETTER-SPACED THAN THE ONE-TIME CODE FIELD NEXT DOOR. A
      // recovery code is ten characters with a dash in the middle rather than
      // six digits, so the spacing that makes a PIN readable makes this one
      // overflow. `autocomplete="one-time-code"` is still right — a password
      // manager that stored the list offers it — and `inputmode` is
      // deliberately NOT numeric here, because these are letters as well.
      'input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px ' +
      'solid #c8c8d0;border-radius:5px;font-size:1.15em;letter-spacing:.12em;' +
      'text-align:center;text-transform:uppercase;font-family:ui-monospace,' +
      'SFMono-Regular,Menlo,monospace;margin-bottom:14px}button{padding:9px ' +
      '12px;border-radius:5px;border:1px solid #12107c;background:#12107c;' +
      'color:#fff;font-size:.95em;cursor:pointer;width:100%}' +
      '.err{background:#fdecea;border:1px solid ' +
      '#f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
      'font-size:.85em;margin-bottom:12px}.ok{background:#eef7ee;border:1px ' +
      'solid #cfe6cf;color:#1d5c1d;padding:8px 10px;border-radius:5px;' +
      'font-size:.85em;margin-bottom:12px}.warn{background:#fff8e6;' +
      'border:1px solid #f0dca8;color:#7a5a00;padding:8px ' +
      '10px;border-radius:5px;font-size:.85em;margin-bottom:12px}' +
      '.meta{margin-top:20px;padding-top:14px;border-top:1px solid ' +
      '#eee;font-size:.75em;color:#777}.meta div{margin:2px 0}.meta ' +
      'a{color:#12107c}code{font-family:ui-monospace,SFMono-Regular,Menlo,' +
      'monospace}</style></head><body><div class="card"><h1>Use a recovery ' +
      'code</h1><p class="sub">Instead ' +
      'of ' + xmlEscape(insteadOf) + ', for <code>' +
      xmlEscape(username) + '</code></p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      (notice ? '<div class="ok">' + xmlEscape(notice) + '</div>' : '') +
      // HOW MANY ARE LEFT, ON THE WAY IN AND NOT ONLY AFTERWARDS. See the
      // header: somebody down to their last code needs to know while they can
      // still do something about it.
      (low
        ? '<div class="warn">' + xmlEscape('Only ' + status.remaining +
            ' of your ' + status.total + ' recovery codes are unused. A set ' +
            'is issued once and is never topped up — after the last one an ' +
            'administrator has to clear the set before a new one can be ' +
            'issued.') + '</div>'
        : '') +
      '<form method="post" action="' + BACKUP_CODE_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<label for="code">One of the recovery codes you were given</label>' +
      '<input type="text" id="code" name="code" autocomplete="one-time-code" ' +
      'autocapitalize="characters" spellcheck="false" maxlength="64" ' +
      'autofocus placeholder="XXXXX-XXXXX">' +
      '<button type="submit" id="backup-submit">Sign in</button>' +
      '</form>' +
      '<div class="meta">' +
      '<div>Each code works <strong>once</strong>. The dashes and the case ' +
      'do not matter — type it however you can read it.</div>' +
      (status.total
        ? '<div>' + xmlEscape(String(status.remaining) + ' of ' +
            String(status.total) + ' unused.') + '</div>'
        : '') +
      // BACK TO THE MECHANISM THEY ARE ACTUALLY CONFIGURED FOR. A screen with
      // no way back is what made this whole family of links necessary, and
      // arriving here by mistake — the phone was in the next room after all —
      // must not cost a code.
      '<div><a href="' +
      (step && step.factor === 'webauthn' ? WEBAUTHN_PATH : TOTP_PATH) +
      '?mfa=' + encodeURIComponent(mfaId) + '">Go back and use ' +
      xmlEscape(insteadOf) + ' after all</a></div>' +
      '</div></div></body></html>\n';
    log.debug('Leaving Authn.backupCodePage().');
    return html;
  }

  // NO `Content-Security-Policy` OF ITS OWN — see the header. This page has no
  // script, so it inherits the service-wide `script-src 'none'`, which is the
  // whole of what that setting is for. `no-store` because the page names the
  // person being authenticated and is reached from shared browsers.
  private sendBackupCodePage(res, html) {
    const { log } = this.deps;
    log.debug('Entering Authn.sendBackupCodePage().');
    res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug('Leaving Authn.sendBackupCodePage().');
  }

  // The rest of the door, split out so that the asynchronous check above reads
  // as one act. Everything below the comparison is unchanged.
  private finishBackupCode(req, res, base, mfaId, step, verdict) {
    const { log, logArtifact, websecurity, errorCodes } = this.deps;
    log.debug('Entering Authn.finishBackupCode().');
    {
    if (!verdict.ok) {
      // THE REASON IS SHOWN, where the sign-in screen shows none, for `POST
      // /authn/totp`'s reason: nothing is enumerable at this door — the person
      // has already presented a first factor — and "that one has already been
      // used" against "that is not one of your codes" is the difference between
      // reading the next line on a printed list and believing the list is dead.
      log.info('authn: a recovery code for "' + step.username +
               '" was refused (' + verdict.reason + ').');
      log.debug('Leaving the recovery code endpoint. Refused: ' +
                verdict.reason + '.');
      errorCodes.mark(res, errorCodes.codeOf(verdict) || 'STS-AUTHN-0092');
      log.debug("Leaving Authn.finishBackupCode().");
      return this.sendBackupCodePage(res, this.backupCodePage(base, mfaId,
                                                              step.username,
                                                              verdict.detail,
                                                              ''));
    }
    // Not awaited, for finishTotp()'s reason.
    websecurity.succeededShared('mfa-code', req, step.username);
    pendingMfa.delete(mfaId);

    logArtifact('recovery code', 'as verified and spent by this server',
                { username: step.username, remaining: verdict.remaining,
                  total: verdict.total });

    // ---------------------------------------------------------------------
    // WHAT THE SESSION CLAIMS, AND `otp` IS A CHOICE RATHER THAN AN OBVIOUS
    // ANSWER.
    //
    // RFC 8176 registers no value for a recovery code, and inventing one would
    // put a string in `amr` that no relying party can look up — the exact fake
    // this profile refuses everywhere else. `otp` is the registered value and
    // its registry entry describes "one-time password", which a single-use
    // recovery code is by the plainest reading of the words: a password, used
    // once. So it is the honest choice among the registered ones, and it is
    // the same value the authenticator-app door asserts.
    //
    // **`acr` IS `mfa` BECAUSE TWO FACTORS REALLY WERE PRESENTED** — a password
    // and something from a list only this person holds. A recovery code is a
    // WEAKER second factor than the one it stands in for, and there is no
    // vocabulary here in which to say so: this service will not invent an `acr`
    // value, and downgrading to `1` would claim ONE factor when two were
    // checked. The audit row and `/admin/sessions` say which mechanism it was.
    //
    // There is no passwordless branch and there cannot be: a recovery code is
    // never a first factor, so the first factor's `amr` is always in the list.
    // never a first factor, so `pwd` is always in the list.
    const amr = this.firstAmrOf(step).concat(['otp']);
    const said = { request: req, risk: step.risk,
                   credential: { kind: 'backup-code' } };
    const started = this.startSession(res, step.username, amr, 'mfa',
                                      step.authn.protocol, said);
    if (this.refusedSession(res, base, step.authn, step.username, started,
                            said)) {
      log.debug('Leaving Authn.finishBackupCode(). Refused.');
      return;
    }
    this.returnToCaller(res, step.authn, null, null);
    log.debug('Leaving Authn.finishBackupCode(). ' + step.username +
              ' completed the second factor with a recovery code; ' +
              verdict.remaining + ' of ' + verdict.total + ' left.');
    }
    log.debug("Leaving Authn.finishBackupCode().");
  }

  // ---------------------------------------------------------------------------
  // WHO POSTED THAT FORM: the audit log's actor, filled from here.
  //
  // Every row on /admin/audit that came in over HTTP wants a name against it,
  // and this module is the only one that can supply it — it owns the cookie and
  // the session store. It cannot be REQUIRED from audit.js, though: that module
  // is required by app.js, this module requires app.js, and a require the other
  // way would close the loop and hand back a half-initialised module whose
  // exports are undefined. So the direction is inverted the same way
  // helpers.js's setJwtRecorder and admin_stats.js's setUserObserver are —
  // audit.js offers a slot and this file fills it at require time, which is
  // before any route can be called because every protocol module requires
  // app.js.
  //
  // It is deliberately NOT sessionOf(). Three differences, and each of them is
  // the reason:
  //
  //   * It has NO SIDE EFFECTS. sessionOf() deletes an expired session as it
  //     finds it, which is right for a protocol endpoint deciding whether to
  //     show the login screen and wrong for an observer: an audit log that
  //     quietly ended sessions while reporting on them would be changing the
  //     thing it describes.
  //   * It says WHO the cookie names even when the session has expired, marked
  //     as such by the caller's own vocabulary rather than reported as nobody.
  //     "alice, whose session had expired" is the answer to what happened; ""
  //     is not.
  //   * It adds no log lines of its own. sessionOf()'s four say what a protocol
  //     endpoint decided; this runs once per answered request, beside the two
  //     the call log already writes, and repeating them would be most of the
  //     log. (cookiesOf() writes its own pair, which is one parser rather than
  //     two.)
  // ---------------------------------------------------------------------------
  auditActorOf(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.auditActorOf().");
    const found = this.cookieSession(req, SESSION_COOKIE);
    const session = found ? found.session : null;
    if (!session) {
      log.debug("Leaving Authn.auditActorOf().");
      return '';
    }
    log.debug("Leaving Authn.auditActorOf().");
    return session.user.username;
  }

  // The routes, in the order they were always registered (rule 1). Called by
  // `common/protocol_stack.ts` through the module's `registerRoutes(app)`.
  registerRoutes(app: AppModule) {
    const { log, baseUrlOf, randomId, parseBody, oauthError, stats, config,
      gate, credentials, websecurity, mode, validation, audit, errorCodes,
      webauthnVerifier, webauthnPolicy } = this.deps;
    const self = this;
    log.debug("Entering Authn.registerRoutes().");

    app.use((req, res, next) => {
      // ---------------------------------------------------------------------
      // THE SLIDE RUNS ON EVERY REQUEST; THE MINT ONLY ON A FRONT DOOR.
      //
      // They are two different questions and were one for an hour. "Has this
      // browser been quiet for ten minutes" is asked of every request that
      // presents the cookie — the sign-in screen, the form post, the consent
      // screen, none of which is a front door — because inactivity is about the
      // BROWSER and not about which path it happened to ask for. "Should this
      // browser be given an identity" is asked only where a protocol actually
      // begins, or a metadata poll would mint one per poll for ever.
      // ---------------------------------------------------------------------
      this.touchArrivalSession(req);

      // The realm prefix is already stripped by app.js's first middleware, so
      // this sees the path as the routes are registered — which is the whole
      // reason no route in this service carries a realm.
      const pathOnly = String(req.url || '').split('?')[0];
      if (!this.isArrivalPath(pathOnly)) {
        next();
        return;
      }
      try {
        this.startArrivalSession(req, res, 'arrival');
      } catch (e) {
        // A session that could not be started must not fail the request it was
        // started for: the person is trying to sign in, and the flow works
        // without this — a sign-in mints its own session at the end exactly as
        // it always did. Logged because it is a fault rather than an ordinary
        // outcome.
        log.error(errorCodes.tag('STS-AUTHN-0012') +
                  'authn: an arrival session could not be started for ' +
                  pathOnly + ': ' + e.message);
      }
      next();
    });

    app.get(SELECT_IDP_PATH, (req, res) => {
      log.debug("Entering the federation chooser.");
      const asked = validation.check(req, 'query', PENDING_ID_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0001');
        return this.refuseInvalid(res, asked);
      }
      const record = this.pendingFor(asked.value.authn);
      if (!record) {
        log.debug("Leaving the federation chooser. Nothing is pending under " +
                  "that id.");
        errorCodes.mark(res, 'STS-AUTHN-0003');
        return oauthError(res, 400, 'invalid_request',
          'There is no sign-in waiting under that id, or it has expired. ' +
          'Start the request again from the application that sent you here.');
      }
      // ---------------------------------------------------------------------
      // RESOLVED AGAIN HERE, AND THE RECORD IS UPDATED WITH THE ANSWER.
      //
      // beginAuthentication() decided this record goes to the chooser, but the
      // list it decided from is TEN MINUTES OLD by the time this page can be
      // reloaded, and the register is four doors wide — the console, the
      // management API, an `ldapmodify` and this module. A relationship can be
      // disabled between the redirect and the click, and drawing a button for
      // it would send somebody to a refusal at a foreign service.
      //
      // So the entry is read again rather than the snapshot trusted, and the
      // snapshot is REPLACED — because the sign-in screen reads the same field,
      // and a chooser that had refreshed while the screen it falls back to had
      // not would be two pages disagreeing about what is configured.
      //
      // ONLY THE PARTNER LIST IS REFRESHED, not the mechanism. `forceMfa` and
      // `forcePasswordless` were resolved against the request the calling
      // protocol made — a RequestedAuthnContext, a wauth — and that request is
      // not in scope here. Re-deriving them from a config read would quietly
      // drop a demand for two factors that a protocol module made minutes ago.
      // ---------------------------------------------------------------------
      // AND ONLY WHEN THE APPLICATION ENTRY IS WHAT DECIDED THIS. A record
      // whose mechanism came from a BROKERING relationship names one onward
      // partner and can never reach this page — `fedAuthnRelationship` holds a
      // single id, so there is nothing to choose — but re-reading the
      // application entry for such a record would answer a different question
      // and could replace a live federation object with null. The guard costs
      // one line and removes the whole class of that mistake.
      const fresh = record.mechanismSource === 'relationship'
        ? record.federation
        : this.federationFor(record.application);
      record.federation = fresh;
      const usable = (fresh || {}).usable || [];
      if (usable.length < 2) {
        log.info('authn: the chooser was asked for ' + record.id + ' and "' +
                 (record.application || '(none)') + '" now names ' +
                 usable.length +
                 ' usable federation relationship(s), so there is nothing to ' +
                 'choose between — a relationship was disabled, deleted or ' +
                 'unconfigured since this sign-in began. The sign-in screen ' +
                 'is drawn instead, and it offers whatever is left.');
        log.debug("Leaving the federation chooser. Nothing left to choose " +
                  "between.");
        return res.redirect(303,
                            LOGIN_PATH + '?authn=' +
                            encodeURIComponent(record.id));
      }
      res.status(200).type('text/html').set('Cache-Control', 'no-store')
         .send(this.selectIdpPage(baseUrlOf(req), record));
      log.debug("Leaving the federation chooser. Offered " + usable.length +
                " partner(s) for " + record.id + ".");
    });

    // The screen. A GET, because that is what a redirect from a protocol
    // endpoint produces — and it is why this is a service rather than a page:
    // it can be linked, reloaded and bookmarked while the request it
    // interrupted waits.
    app.get(LOGIN_PATH, (req, res) => {
      log.debug("Entering the authentication screen.");
      const asked = validation.check(req, 'query', PENDING_ID_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0001');
        return this.refuseInvalid(res, asked);
      }
      const record = this.pendingFor(asked.value.authn);
      if (!record) {
        log.debug("Leaving the authentication screen. Nothing is pending " +
                  "under that id.");
        errorCodes.mark(res, 'STS-AUTHN-0003');
        return oauthError(res, 400, 'invalid_request',
          'There is no sign-in waiting under that id, or it has expired. ' +
          'Start the request again from the application that sent you here.');
      }
      // A relationship this application NAMES and cannot use is shown here
      // rather than being replaced silently by the password box below it. That
      // fallback is the failure worth being loud about: a federated application
      // authenticating people locally looks exactly like a federated
      // application working.
      //
      // EVERY UNUSABLE VALUE, not the first. `appFederationRelationship` holds
      // a list, and an entry naming three partners of which two are disabled
      // has two things wrong with it — showing one would have somebody fix it,
      // reload, and meet the next one. `mechanismProblem` comes first because a
      // BROKERING relationship that cannot broker is a statement about this
      // exchange rather than about the application's own configuration.
      //
      // DEDUPLICATED, because the two sources overlap by construction: when the
      // application entry is what decided this sign-in, mechanismFor() copies
      // that entry's FIRST problem onto the record as `mechanismProblem`, so a
      // plain concatenation prints it twice and reads as two faults.
      const seenProblem: Record<string, any> = {};
      const problem = [record.mechanismProblem]
        .concat(((record.federation || {}).problems) || [])
        .filter(function (one) {
          if (!one || seenProblem[one]) return false;
          seenProblem[one] = true;
          return true;
        })
        .join(' ');
      this.sendLoginPage(res, this.loginPage(baseUrlOf(req), record, problem));
      log.debug("Leaving the authentication screen. Showed the form for " +
                record.id +
                (problem ? ", with a federation problem." : "."));
    });

    // ASYNCHRONOUS SINCE 2026-09-14 (#46), for one line: the rate limit below
    // counts in the cluster's shared window, which is a round trip.
    app.post(LOGIN_PATH, async (req, res) => {
      log.debug("Entering the authentication endpoint.");
      const base = baseUrlOf(req);
      // `parseBody()` and not `req.body`: this service's body parser is
      // `bodyParser.text({ type: () => true })`, so `req.body` is the raw
      // string and the parsed object is what a handler holds. `checkParsed()`
      // is the entry point for exactly that, and its header argues why.
      const posted = validation.checkParsed(parseBody(req), 'body', LOGIN_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0002');
        return this.refuseInvalid(res, posted);
      }
      const body = posted.value;
      const record = this.pendingFor(body.authn_id);
      if (!record) {
        log.debug("Leaving the authentication endpoint. The form had expired.");
        errorCodes.mark(res, 'STS-AUTHN-0003');
        return oauthError(res, 400, 'invalid_request',
          'This sign-in form has expired. Start the request again from the ' +
          'application that sent you here.');
      }

      if (String(body.action || '') === 'cancel') {
        pending.delete(record.id);
        log.debug("Leaving the authentication endpoint. The user cancelled.");
        errorCodes.mark(res, 'STS-AUTHN-0004');
        return this.returnToCaller(res, record, 'access_denied',
          'The user cancelled at the sign-in screen.');
      }

      // ---------------------------------------------------------------------
      // "CONTINUE WITHOUT SIGNING IN" (2026-09-05).
      //
      // The opposite of the branch above it in the one way that matters: Cancel
      // ENDS the flow with `access_denied` and creates nothing, and this one
      // lets the flow go on with a session that says nobody authenticated. Both
      // are a person declining to type a password; only one of them is
      // declining the application.
      //
      // **THE SETTING IS CHECKED HERE AND NOT ONLY ON THE PAGE**, because the
      // page is markup and this is the door. A form posted by hand with
      // `action=anonymous` while the setting is off must not mint a session
      // that the console then lists and that an application's required role is
      // then decided against — the button being absent is a fact about one
      // rendering, and the refusal has to be a fact about the endpoint. It
      // falls through to the ordinary path rather than erroring, so the form
      // simply asks for a name again.
      //
      // **THE USERNAME IN THE FORM IS IGNORED**, deliberately and not as a
      // shortcut. A session that took the typed name and called itself
      // unauthenticated would claim two things at once — that this is somebody
      // in particular, and that nobody proved it — and every downstream reader
      // would have to decide which half to believe. The anonymous principal is
      // a stable name so that it has one directory entry, one row on
      // /admin/users and one place to be granted a configured role, rather than
      // a fresh identity per session that nothing could ever be said about.
      //
      // **THE ROLE GATE IS ASKED HERE TOO**, with `authenticated: false`,
      // exactly as the password path asks it below with the same flag. An
      // application that requires ALL_AUTHENTICATED_USERS therefore refuses
      // this at the SESSION door, before a session exists — which is a better
      // place to refuse it than the authorization endpoint, because there is
      // still a screen to say so on.
      if (String(body.action || '') === 'anonymous' &&
          !record.lockedUsername &&
          config.value('authn.unauthenticatedSessions')) {
        const anonRoleAnswer = gate.check({
          application: String(record.application || ''),
          kind: gate.ISSUANCE.SESSION,
          subject: { kind: 'user', name: ANONYMOUS_USERNAME,
                     authenticated: false },
          claims: null
        });
        if (!anonRoleAnswer.allowed) {
          log.info('authn: the issuance policy refused an unauthenticated ' +
                   'session at ' +
                   '"' + String(record.application) + '". ' +
                   anonRoleAnswer.why);
          log.debug("Leaving the authentication endpoint. The issuance " +
                    "policy refused the anonymous session.");
          errorCodes.mark(res, 'STS-AUTHN-0005');
          return this.sendLoginPage(res, this.loginPage(base, record,
                                                        anonRoleAnswer.why));
        }
        pending.delete(record.id);
        // `amr` is EMPTY and `acr` is '0', which is RFC 8176 read literally:
        // there are no authentication methods to name because none was used,
        // and an acr of 0 is the conventional "no assurance" value. Stating
        // them is what lets a relying party that asked for a factor see that it
        // got none. `gated: true` for the reason the password door gives: the
        // anonymous branch asked the gate a few lines above, at the door, where
        // there is still a screen to say no on.
        // `request` so this replaces whatever session the browser was on — an
        // anonymous sign-in is still a privilege CHANGE, and leaving the
        // previous one alive would mean somebody who was signed in as a
        // person and then chose to continue anonymously still had the first
        // session.
        //
        // Nothing refuses an unauthenticated session in `startSession()`
        // today, and the null is looked at anyway (2026-09-22, #62 P0): a
        // refusal added there later would otherwise loop the browser.
        const anonymousSaid = { request: req, authenticated: false,
                                gated: true };
        const anonymous = this.startSession(res, ANONYMOUS_USERNAME, [], '0',
                                            record.protocol, anonymousSaid);
        if (this.refusedSession(res, base, record, ANONYMOUS_USERNAME,
                                anonymous, anonymousSaid)) {
          log.debug("Leaving the authentication endpoint. The anonymous " +
                    "session was refused.");
          return undefined;
        }
        this.returnToCaller(res, record, null, null);
        log.debug("Leaving the authentication endpoint. An unauthenticated " +
                  "session was started; back to " +
                  record.returnTo + ".");
        return undefined;
      }

      // A LOCKED RECORD'S NAME IS THE RECORD'S (#109): see
      // beginAuthentication(). Whatever was typed is not read.
      const username = record.lockedUsername ||
                       String(body.username || '').trim();
      // The only two ways to fail: no username to put in the tokens, and the
      // reserved password the rest of this mock also refuses.
      if (!username) {
        log.debug("Leaving the authentication endpoint. No username was " +
                  "entered, so the form is shown again.");
        errorCodes.mark(res, 'STS-AUTHN-0006');
        return this.sendLoginPage(res, this.loginPage(base, record,
          'Enter a username. It does not have to exist — it is the identity ' +
          'the issued tokens will describe.'));
      }
      // Which role the security key is in, if it is in one at all. The two
      // boxes cannot be made exclusive on a screen that runs no script, so a
      // POST can carry both — and `webauthn_only` wins, because the two mean
      // different things and answering "both" with the second-factor path would
      // put somebody through a password step they explicitly asked not to have.
      // READ OFF THE RECORD AND NOT ONLY OFF THE BODY. The screen posts a
      // hidden `webauthn_only` when the mechanism demands one, and a hidden
      // input is a suggestion: it is deleted by anybody with the developer
      // tools open, and the request that arrives then looks exactly like an
      // ordinary password sign-in. A configured mechanism that a client can opt
      // out of is not a mechanism, so the record decides and the markup only
      // shows.
      const passwordless = !!record.forcePasswordless ||
                           String(body.webauthn_only || '') === '1';
      // `record.forceMfa` for `forcePasswordless`'s reason one line up (RFC
      // 9470, 2026-09-13): the hidden `use_webauthn` the screen posts under a
      // demand for two factors is a suggestion too, and a POST without it
      // signed in with one. The authorization endpoint would refuse that
      // session on the way back; this makes the screen ask for the factor
      // instead of letting a sign-in finish that was always going to be
      // refused.
      // And `record.forceKey` (2026-09-17) the same way: a demand for a
      // security key that is not met passwordless is met by the key as the
      // second factor, whatever the POST carried.
      const secondFactor = !passwordless &&
                           (!!record.forceMfa || !!record.forceKey ||
                            String(body.use_webauthn || '') === '1');

      // LINKING RESTS ON THE PASSWORD (#109). A passwordless key would be one
      // factor the person may have enrolled at this very screen in
      // development, which is no proof they are the local person a partner
      // named; the screen does not offer it and this is the check.
      if (passwordless && record.lockedUsername) {
        log.debug("Leaving the authentication endpoint. Passwordless at a " +
                  "linking sign-in.");
        errorCodes.mark(res, 'STS-AUTHN-0212');
        return this.sendLoginPage(res, this.loginPage(base, record,
          'Linking an account signs in with its password — and its second ' +
          'factor, where it has one — so a security key on its own is not ' +
          'offered here.'));
      }

      // ---------------------------------------------------------------------
      // THE POLICY, CHECKED HERE AND NOT ONLY ON THE SCREEN (2026-09-10).
      //
      // `loginPage()` draws the boxes this realm allows; this is what makes
      // that mean anything. A checkbox that is absent from the markup is absent
      // from a browser's POST and from nobody else's — a hand-made form
      // carrying `webauthn_only=1` against a realm with
      // `webauthn.primaryAllowed` off would otherwise take the passwordless
      // path, which is the same "a hidden input is a suggestion" argument the
      // comment above `passwordless` makes about `forcePasswordless`, read the
      // other way round.
      //
      // **THE REFUSAL NAMES THE SETTING.** A person who was told to use their
      // key and is being sent back to a password field needs to know that the
      // answer is a knob rather than their hardware.
      if (passwordless || secondFactor) {
        const allowed = webauthnPolicy.roleAllowed(passwordless ? 'primary' :
                                                   'mfa');
        if (!allowed.ok) {
          log.info('authn: a security-key sign-in was asked for as a ' +
                   (passwordless ? 'primary' : 'second-factor') +
                   ' credential ' +
                   'and this realm does not allow it. ' + allowed.why);
          log.debug("Leaving the authentication endpoint. The security-key " +
                    "path is switched off in this realm.");
          errorCodes.mark(res, errorCodes.codeOf(allowed) || 'STS-AUTHN-0044');
          return this.sendLoginPage(res, this.loginPage(base, record,
                                                        allowed.why));
        }
      }

      // A caller that demanded a second factor does not get the passwordless
      // path. The checkbox is rendered disabled for this reason and THIS is the
      // check that matters: `disabled` is a property of a browser, not of an
      // HTTP request, and the whole value of acr_values and wauth is that the
      // answer cannot be chosen by whoever is answering.
      if (passwordless && record.forceMfa) {
        log.debug("Leaving the authentication endpoint. Passwordless was " +
                  "asked " +
                  "for where the caller demands a second factor, so the form " +
                  "is shown again.");
        errorCodes.mark(res, 'STS-AUTHN-0007');
        return this.sendLoginPage(res, this.loginPage(base, record,
          'This request asked for a second factor, so a security key on its ' +
          'own ' +
          'cannot answer it — one factor is one factor. Sign in with a ' +
          'password and the key together.'));
      }

      // ---------------------------------------------------------------------
      // NO ENROLMENT ON FIRST USE IN PRODUCT (2026-09-21).
      //
      // The passwordless path reads no password, and `webauthnPage()` answers
      // a person who holds no `primary` key with the ENROL ceremony — so in
      // product, where the only other check was that the name exists
      // (`knownUser()` at the registration), anybody who knew a username
      // could register their own authenticator as that person's primary
      // credential and be signed in as them. And stay: the key is on the
      // entry until somebody notices it. Development keeps "the first person
      // to claim a name gets it", which the screen says.
      //
      // Refused HERE, before a step is minted, so the ceremony is never drawn;
      // the registration branch below asks the same question as well, because
      // a step minted on one side of a mode change is still a step. **The
      // sentence is the same whether the name exists or not**, so this is not
      // a way to find out which usernames do.
      if (passwordless && !mode.enrolsKeysOnFirstUse() &&
          credentials.mechanismsFor(username).primaryKeys < 1) {
        log.info('authn: product mode, so a passwordless sign-in for "' +
                 username + '", who holds no primary security key, was ' +
                 'refused rather than enrolling one at the sign-in screen.');
        log.debug("Leaving the authentication endpoint. No primary key to " +
                  "sign in with, and product mode enrols none here.");
        errorCodes.mark(res, 'STS-AUTHN-0206');
        return this.sendLoginPage(res, this.loginPage(base, record,
          'There is no security key registered for signing in to this ' +
          'account. Sign in with your password, then add a key at ' +
          '/portal/keys.'));
      }

      // ---------------------------------------------------------------------
      // THE CREDENTIAL (2026-09-06). One call, both modes.
      //
      // **THIS USED TO BE THE RESERVED-PASSWORD CHECK AND NOTHING ELSE**, and
      // the difference is the architecture of the two modes rather than a new
      // feature at this door: development mode still refuses only `invalid` and
      // accepts everything else, product mode verifies against the hashed
      // `userPassword` on the person's entry — and `common/credentials.ts` is
      // the single place either answer is given, so the sign-in screen, an LDAP
      // bind, a UsernameToken and SCIM Basic cannot come to disagree about what
      // a password is worth.
      //
      // It is NOT read at all on the passwordless path: no password was
      // presented there, so there is nothing to verify, and failing a field the
      // screen says it will ignore would make the screen wrong about what it
      // does. The security key is the credential on that path and `webauthn.js`
      // owns it.
      //
      // **THE MESSAGE SHOWN IS THE SAME WHATEVER FAILED**, deliberately. The
      // reason from `verify()` goes to the LOG, where an operator can see
      // whether a sign-in failed for a wrong password or for a person who holds
      // no credential at all; the SCREEN says only that authentication failed,
      // because telling a browser which of the two happened is the account
      // enumeration answer.
      // Set when the password just verified is known from a breach (#62 P6).
      let breachedAtSignIn = false;
      if (!passwordless) {
        // ---------------------------------------------------------------------
        // RATE LIMITED (2026-09-06). OWASP A04/A07.
        //
        // **THIS IS THE ENDPOINT THAT MATTERS MOST**, because it is the one an
        // attacker reaches first and the one with the smallest search space
        // behind it. Nothing throttled it before: a password was guessable at
        // network speed, and in product mode that is the whole security of the
        // service.
        //
        // Two buckets — by identity and by address — because either alone is
        // the half an attacker does not use. See websecurity.js.
        //
        // **IT COUNTS IN BOTH MODES.** Development checks no password, so a
        // refusal there protects nothing... except that the suite drives this
        // endpoint hundreds of times, which is exactly how a limit that is too
        // tight gets found. The default of 5 per identity per minute is
        // generous enough for a person and stops a script.
        //
        // **ONE BUDGET FOR THE CLUSTER SINCE 2026-09-14 (#46)** —
        // `attemptShared()`, which counts in the store every node shares and is
        // `attempt()` where none is shared.
        const allowed = await websecurity.attemptShared('sign-in', req,
                                                        username);
        if (!allowed.ok) {
          log.warn('authn: too many sign-in attempts for "' + username + '" (' +
                   allowed.kind + ' bucket). Refusing for ' +
                   allowed.retryAfterS +
                   's.');
          log.debug("Leaving the authentication endpoint. Rate limited.");
          errorCodes.mark(res, 'STS-AUTHN-0008');
          return this.sendLoginPage(res, this.loginPage(base, record,
                                                        allowed.detail));
        }
        // `allowPasswordReset`: this is the one door that can ask for a new
        // password, so a password flagged `pwdReset` is accepted HERE and the
        // change step below is drawn instead of a session. See credentials.js.
        // `secondFactor: 'asked-next'` (#101): this screen asks for the second
        // factor right after, so the password-only-door refusal does not
        // apply. It passes no `door`, so an app password is NEVER accepted
        // here.
        const credential = credentials.verify(username, String(body.password ||
                                                               ''),
                                              { via: 'the sign-in screen',
                                                allowPasswordReset: true,
                                                secondFactor: 'asked-next' });
        if (!credential.ok) {
          log.info('authn: the sign-in for "' + username + '" was refused (' +
                   credential.reason + '): ' + credential.detail);
          log.debug("Leaving the authentication endpoint. The credential was " +
                    "refused, so the form is shown again.");
          errorCodes.mark(res, errorCodes.codeOf(credential) ||
                               'STS-AUTHN-0054');
          return this.sendLoginPage(res, this.loginPage(base, record,
            'Authentication failed for ' + username + '.'));
        }
        // A SUCCESSFUL SIGN-IN FORGETS THE COUNTERS, so somebody who mistyped
        // their password four times is not one attempt from a lockout the
        // moment they get it right.
        await websecurity.succeededShared('sign-in', req, username);
        // A PASSWORD KNOWN FROM A DATA BREACH MUST BE CHANGED BEFORE THIS
        // SIGN-IN FINISHES (#62 P6, `risk.breachCheckAtSignIn`). It verified,
        // so it is this person's — and it is on a list people guess from.
        // `pwdReset` is set, and the change step just below asks for a new
        // one, saying why; the new one is screened like any other.
        if (this.deps.config.value('risk.breachCheckAtSignIn') !== false) {
          const breach = await require('../common/breached_passwords')
            .screen(String(body.password || ''));
          if (breach.breached) {
            credentials.setPasswordResetRequired(username, true);
            breachedAtSignIn = true;
            log.info('authn: the password "' + username + '" signed in with ' +
                     'has appeared in a data breach; it must be changed ' +
                     'before the sign-in finishes.');
          }
        }
      }

      // ---------------------------------------------------------------------
      // A PASSWORD THAT MUST BE CHANGED (2026-09-13), in both modes.
      //
      // `pwdReset: TRUE` on the entry — the bootstrap administrator is created
      // with it — means the password just accepted was not chosen by this
      // person. No session, no second factor and no role decision happen until
      // a new one is stored: the change step holds the pending record, and
      // finishPasswordSignIn() resumes the sign-in from there. Only the
      // PASSWORD path is stopped; a passwordless security-key sign-in presented
      // no password to replace.
      if (!passwordless && credentials.passwordResetRequired(username)) {
        pending.delete(record.id);
        const changeId = randomId(24);
        pendingPasswordChange.set(changeId, {
          authn: record, username: username, secondFactor: secondFactor,
          expires: Date.now() + this.mfaStepTtlMs()
        });
        pendingPasswordChange.forEach(function (v, k) {
          if (v.expires < Date.now()) {
            pendingPasswordChange.delete(k);
          }
        });
        log.info('authn: "' + username + '" must change their password ' +
                 'before this sign-in continues (pwdReset).');
        log.debug("Leaving the authentication endpoint. Asking for a new " +
                  "password.");
        return this.sendPasswordChangePage(res,
          this.passwordChangePage(changeId, username, breachedAtSignIn
            ? 'The password you signed in with has appeared in a data ' +
              'breach, so it has to be changed now. Choose one you have ' +
              'not used anywhere else.' : ''));
      }

      await this.finishPasswordSignIn(req, res, base, record, username,
                                      passwordless, secondFactor);
      log.debug("Leaving the authentication endpoint.");
      return undefined;
    });

    // GET — redraws the step (a reload of the page the password screen drew).
    // It changes nothing.
    app.get(PASSWORD_CHANGE_PATH, (req, res) => {
      log.debug('Entering the password change screen.');
      const asked = validation.check(req, 'query', PASSWORD_CHANGE_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0145');
        return this.refuseInvalid(res, asked);
      }
      const changeId = String(asked.value.change || '');
      const step = this.passwordChangeStep(res, changeId);
      if (!step) {
        log.debug('Leaving the password change screen. No step.');
        return undefined;
      }
      log.debug('Leaving the password change screen.');
      return this.sendPasswordChangePage(res,
        this.passwordChangePage(changeId, step.username, ''));
    });

    app.post(PASSWORD_CHANGE_PATH, async (req, res) => {
      log.debug('Entering the password change endpoint.');
      const base = baseUrlOf(req);
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            PASSWORD_CHANGE_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0145');
        return this.refuseInvalid(res, posted);
      }
      const body = posted.value;
      const changeId = String(body.change_id || '');
      const step = this.passwordChangeStep(res, changeId);
      if (!step) {
        log.debug('Leaving the password change endpoint. No step.');
        return undefined;
      }
      const chosen = String(body.new_password || '');
      const again = String(body.confirm_password || '');
      let problem = '';
      if (!chosen) {
        problem = 'Enter a new password.';
      } else if (chosen !== again) {
        problem = 'The two passwords are not the same.';
      } else if (chosen === credentials.RESERVED_REFUSAL) {
        problem = 'That password is reserved and is refused at every ' +
                  'sign-in, so it cannot be yours.';
      }
      if (problem) {
        errorCodes.mark(res, 'STS-AUTHN-0146');
        log.debug('Leaving the password change endpoint. ' + problem);
        return this.sendPasswordChangePage(res,
          this.passwordChangePage(changeId, step.username, problem));
      }
      // Screened against Pwned Passwords first (#62 P6).
      await require('../common/breached_passwords').screen(chosen);
      const written = credentials.setPassword(step.username, chosen,
                                              { via: 'the forced password ' +
                                                  'change' });
      if (!written.ok) {
        errorCodes.mark(res, errorCodes.codeOf(written) || 'STS-AUTHN-0146');
        log.debug('Leaving the password change endpoint. The store refused ' +
                  'it.');
        return this.sendPasswordChangePage(res,
          this.passwordChangePage(changeId, step.username,
                                  (written.errors || []).join(' ') ||
                                  'The new password was not accepted.'));
      }
      if (!credentials.setPasswordResetRequired(step.username, false)) {
        // The password IS changed. Carrying on would leave pwdReset on the
        // entry and ask again at the next sign-in, which is a nuisance and not
        // a hole; refusing here would throw away a password the person has just
        // chosen.
        log.warn(errorCodes.tag('STS-AUTHN-0143') +
                 'authn: the password for "' +
                 step.username + '" was changed and pwdReset could not be ' +
                 'cleared, so it will be asked for again.');
      }
      pendingPasswordChange.delete(changeId);
      audit.audit({
        action: 'authn.password.changed', outcome: 'success',
        actor: step.username, target: step.username, channel: 'http',
        protocol: step.authn && step.authn.protocol,
        summary: step.username + ' changed a password they were required to ' +
                 'change at sign-in',
        detail: { forced: true }
      });
      log.info('authn: "' + step.username + '" chose a new password; the ' +
               'sign-in continues.');
      this.deps.accountSignals.credentialChanged({ username: step.username,
        credentialType: 'password', changeType: 'update',
        initiatingEntity: 'user', via: 'sign-in',
        reasonAdmin: step.username + ' changed a password they were ' +
                     'required to change at sign-in.',
        reasonUser: 'You changed your password.' });
      await this.finishPasswordSignIn(req, res, base, step.authn,
                                      step.username, false,
                                      !!step.secondFactor);
      log.debug('Leaving the password change endpoint.');
      return undefined;
    });

    app.get(MFA_SETUP_PATH, async (req, res) => {
      log.debug('Entering the second-factor set-up screen.');
      const asked = validation.check(req, 'query', MFA_STEP_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0174');
        log.debug('Leaving the second-factor set-up screen. Bad shape.');
        return this.refuseInvalid(res, asked);
      }
      const setupId = String(asked.value.mfa || '');
      const step = this.mfaSetupStep(res, setupId);
      if (!step) {
        log.debug('Leaving the second-factor set-up screen. No step.');
        return undefined;
      }
      if (step.factor === 'enrol-totp') {
        const drawn = await this.mfaSetupTotpPage(baseUrlOf(req), setupId,
                                                  step.username, '');
        if (drawn) {
          log.debug('Leaving the second-factor set-up screen. The secret.');
          return this.sendMfaSetupPage(res, drawn);
        }
      }
      log.debug('Leaving the second-factor set-up screen. The choice.');
      return this.sendMfaSetupPage(res, this.mfaSetupPage(
        setupId, step.username, this.enrolmentOffered(), ''));
    });

    app.post(MFA_SETUP_PATH, async (req, res) => {
      log.debug('Entering the second-factor set-up endpoint.');
      const base = baseUrlOf(req);
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            MFA_SETUP_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0174');
        log.debug('Leaving the second-factor set-up endpoint. Bad shape.');
        return this.refuseInvalid(res, posted);
      }
      const body = posted.value;
      const setupId = String(body.mfa_id || '');
      const step = this.mfaSetupStep(res, setupId);
      if (!step) {
        log.debug('Leaving the second-factor set-up endpoint. No step.');
        return undefined;
      }
      const offered = this.enrolmentOffered();
      const action = String(body.action || '');
      // THE PERSON MUST STILL HOLD NOTHING. A factor enrolled in another tab
      // since the step was minted makes this an ordinary sign-in again, and
      // enrolling a second one here would be the bypass the header refuses.
      if (credentials.mechanismsFor(step.username).mfaRequired) {
        pendingMfa.delete(setupId);
        errorCodes.mark(res, 'STS-AUTHN-0175');
        log.debug('Leaving the second-factor set-up endpoint. They hold one ' +
                  'now.');
        return oauthError(res, 400, 'invalid_request',
          'A second factor is already set up for this account. Start the ' +
          'request again from the application that sent you here and sign in ' +
          'with it.');
      }

      if (action === 'webauthn') {
        if (!offered.webauthn) {
          errorCodes.mark(res, 'STS-AUTHN-0175');
          log.debug('Leaving the second-factor set-up endpoint. Keys are off.');
          return this.sendMfaSetupPage(res, this.mfaSetupPage(setupId,
                                                              step.username,
            offered, 'Security keys cannot be set up in this realm.'), 400);
        }
        // THE ORDINARY CEREMONY FROM HERE: a step asking for `webauthn` for a
        // person who holds no `mfa` key draws the registration, and a verified
        // one enrols the key and starts the session exactly as the security-key
        // box does.
        step.factor = 'webauthn';
        pendingMfa.set(setupId, step);
        log.debug('Leaving the second-factor set-up endpoint. The key ' +
                  'ceremony.');
        return this.sendWebauthnPage(res, this.webauthnPage(base, setupId,
                                                            step.username,
                                                            this.rpIdProblem(
                                                                base)));
      }

      if (action === 'totp') {
        if (!offered.totp) {
          errorCodes.mark(res, 'STS-AUTHN-0175');
          log.debug('Leaving the second-factor set-up endpoint. TOTP is off.');
          return this.sendMfaSetupPage(res, this.mfaSetupPage(setupId,
                                                              step.username,
            offered, 'Authenticator apps cannot be set up in this realm.'),
            400);
        }
        const begun = credentials.beginTotpEnrolment(step.username,
                                                     { base: base });
        const drawn = begun.ok
          ? await this.mfaSetupTotpPage(base, setupId, step.username, '') :
          null;
        if (!drawn) {
          errorCodes.mark(res, errorCodes.codeOf(begun) || 'STS-AUTHN-0176');
          log.debug('Leaving the second-factor set-up endpoint. Not started.');
          return this.sendMfaSetupPage(res, this.mfaSetupPage(setupId,
                                                              step.username,
            offered, ((begun.errors || [])[0]) ||
            'The authenticator app could not be set up.'), 400);
        }
        step.factor = 'enrol-totp';
        pendingMfa.set(setupId, step);
        audit.audit({
          action: 'authn.mfa.enrolment.started', outcome: 'success',
          actor: step.username, target: step.username, channel: 'http',
          protocol: step.authn && step.authn.protocol,
          summary: 'an authenticator app secret was shown to ' + step.username +
                   ' at sign-in, because a second factor is required',
          detail: { requiredBy: step.requiredBy || '' }
        });
        log.debug('Leaving the second-factor set-up endpoint. The secret.');
        return this.sendMfaSetupPage(res, drawn);
      }

      // confirm-totp
      if (step.factor !== 'enrol-totp') {
        errorCodes.mark(res, 'STS-AUTHN-0174');
        log.debug('Leaving the second-factor set-up endpoint. Nothing to ' +
                  'confirm.');
        return this.sendMfaSetupPage(res, this.mfaSetupPage(setupId,
            step.username, offered,
          'Choose a second factor to set up first.'), 400);
      }
      const allowed = await websecurity.attemptShared('mfa-code', req,
                                                      step.username);
      if (!allowed.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0040');
        log.debug('Leaving the second-factor set-up endpoint. Rate limited.');
        const again = await this.mfaSetupTotpPage(base, setupId, step.username,
                                                  allowed.detail);
        return this.sendMfaSetupPage(res, again || this.mfaSetupPage(setupId,
            step.username,
          offered, allowed.detail), 429);
      }
      const confirmed = credentials.confirmTotpEnrolment(step.username,
                                                         String(body.code ||
                                                                ''));
      if (!confirmed.ok) {
        errorCodes.mark(res, errorCodes.codeOf(confirmed) || 'STS-AUTHN-0177');
        const reason = (confirmed.errors || ['That code is not right.'])[0];
        // THE SAME SECRET IS REDRAWN: mistyping six digits must not mean
        // scanning again. An enrolment that expired meanwhile goes back to the
        // choice.
        const again = await this.mfaSetupTotpPage(base, setupId, step.username,
                                                  reason);
        if (!again) {
          step.factor = 'enrol';
          pendingMfa.set(setupId, step);
        }
        log.debug('Leaving the second-factor set-up endpoint. Not confirmed.');
        return this.sendMfaSetupPage(res, again || this.mfaSetupPage(setupId,
            step.username,
          offered,
          'That set-up expired before it was confirmed. Start it again.'),
          400);
      }
      await websecurity.succeededShared('mfa-code', req, step.username);
      pendingMfa.delete(setupId);
      audit.audit({
        action: 'authn.mfa.enrolled', outcome: 'success',
        actor: step.username, target: step.username, channel: 'http',
        protocol: step.authn && step.authn.protocol,
        summary: step.username + ' set up an authenticator app at sign-in, ' +
                 'because a second factor is required',
        detail: { requiredBy: step.requiredBy || '' }
      });
      log.info('authn: "' + step.username + '" enrolled an authenticator app ' +
               'at sign-in; signing them in with two factors.');
      this.deps.accountSignals.credentialChanged({ username: step.username,
        credentialType: this.deps.accountSignals.TOTP_CREDENTIAL_TYPE,
        changeType: 'create', initiatingEntity: 'user', via: 'sign-in',
        reasonAdmin: step.username + ' set up an authenticator app at ' +
                     'sign-in.',
        reasonUser: 'You set up an authenticator app.' });
      // Two factors really were presented: the password, and a code from the
      // app enrolled a moment ago. `otp` and `mfa`, as at `/authn/totp`.
      const said = { request: req, risk: step.risk,
                     credential: { kind: 'totp' } };
      const started = this.startSession(res, step.username,
                                        this.firstAmrOf(step).concat(['otp']),
                                        'mfa', step.authn.protocol, said);
      if (this.refusedSession(res, base, step.authn, step.username, started,
                              said)) {
        log.debug('Leaving the second-factor set-up endpoint. Refused.');
        return undefined;
      }
      this.returnToCaller(res, step.authn, null, null);
      log.debug('Leaving the second-factor set-up endpoint. Signed in.');
      return undefined;
    });

    // The browser fingerprint's script (#62 P6), served only while a realm
    // has `risk.fingerprinting` on — otherwise nothing draws a page that asks
    // for it, and a 404 says so.
    app.get(FINGERPRINT_SCRIPT_PATH, (req, res) => {
      log.debug('Entering the fingerprint script endpoint.');
      if (!this.fingerprinting()) {
        errorCodes.mark(res, 'STS-AUTHN-0225');
        res.status(404).type('text/plain').send('Not found');
        log.debug('Leaving the fingerprint script endpoint. Off.');
        return;
      }
      let library = '';
      try {
        library = require('fs').readFileSync(require.resolve(
          '@fingerprintjs/fingerprintjs/dist/fp.min.js'), 'utf8');
      } catch (e) {
        log.debug('Caught in the fingerprint script endpoint: ' +
                  ((e && e.message) || e));
        // The library is not installed: the glue finds no FingerprintJS and
        // does nothing, so the form is sent without a fingerprint.
        library = '';
      }
      res.status(200).type('application/javascript')
        .set('Cache-Control', 'public, max-age=3600')
        .send(library + '\n' + FINGERPRINT_GLUE + '\n');
      log.debug('Leaving the fingerprint script endpoint.');
    });

    app.get(WEBAUTHN_SCRIPT_PATH, (req, res) => {
      log.debug("Serving the WebAuthn ceremony script.");
      // A script resource cannot be clicked through, so framing it is not the
      // clickjacking vector the page it belongs to is — but it goes through the
      // builder anyway, because "this one does not need it" is the reasoning
      // that ends with a PAGE that does not have it.
      res.set('Content-Security-Policy',
              app.contentSecurityPolicy({ 'style-src': null,
                                                                     'img-src':
                                                                       null }));
      res.type('application/javascript')
         .set('Cache-Control', 'no-store')
         .send(WEBAUTHN_SCRIPT);
    });

    // -------------------------------------------------------------------------
    // GET /authn/webauthn — the *use your security key instead* link
    // (2026-09-10).
    //
    // It draws the ceremony for a step that ALREADY EXISTS and creates nothing,
    // exactly as `GET /authn/totp` does in the other direction. There was no
    // GET on this path before, because until there were two second factors
    // nothing ever needed to arrive at this page other than by completing a
    // password step.
    //
    // **IT CHECKS THAT THE PERSON HOLDS A KEY**, which the POST beside it does
    // not have to: this is a link and a link is markup, so a hand-made GET must
    // not draw the ENROLMENT ceremony for somebody whose account is configured
    // for an authenticator app. That would be the bypass the sign-in handler's
    // own comment argues about — register a fresh key, skip the configured
    // factor — reached through a different door.
    // -------------------------------------------------------------------------
    app.get(WEBAUTHN_PATH, (req, res) => {
      log.debug("Entering the WebAuthn second-factor screen.");
      const asked = validation.check(req, 'query', MFA_STEP_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0018');
        return this.refuseInvalid(res, asked);
      }
      const mfaId = String(asked.value.mfa || '');
      const step = pendingMfa.get(mfaId);
      if (!step || step.expires < Date.now()) {
        pendingMfa.delete(mfaId);
        log.debug("Leaving the WebAuthn second-factor screen. The step had " +
                  "expired.");
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'This second-factor step has expired. Start the request again from ' +
          'the application that sent you here.');
      }
      if (credentials.mechanismsFor(step.username).mfaKeys < 1) {
        log.info('authn: a security-key screen was asked for "' +
                 step.username +
                 '", who holds no key marked as a second factor. Refused.');
        log.debug("Leaving the WebAuthn second-factor screen. No key is " +
                  "enrolled.");
        errorCodes.mark(res, 'STS-AUTHN-0025');
        return oauthError(res, 400, 'invalid_request',
          'No security key is enrolled as a second factor for that account.');
      }
      log.debug("Leaving the WebAuthn second-factor screen. Drawn for " +
                step.username + ".");
      // In product mode an RP ID that does not fit is said HERE, on the page,
      // as well as refused at the POST — a ceremony drawn under a refusal would
      // be a browser prompt whose answer is thrown away.
      const rpProblem = this.rpIdProblem(baseUrlOf(req));
      if (rpProblem) {
        errorCodes.mark(res, 'STS-AUTHN-0023');
      }
      return this.sendWebauthnPage(res, this.webauthnPage(baseUrlOf(req), mfaId,
                                                          step.username,
                                                          rpProblem));
    });

    app.post(WEBAUTHN_PATH, (req, res) => {
      log.debug("Entering the WebAuthn second-factor endpoint.");
      const base = baseUrlOf(req);
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            WEBAUTHN_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0020');
        return this.refuseInvalid(res, posted);
      }
      const body = posted.value;
      const step = pendingMfa.get(String(body.mfa_id || ''));
      if (!step || step.expires < Date.now()) {
        pendingMfa.delete(String(body.mfa_id || ''));
        log.debug("Leaving the WebAuthn endpoint. The step had expired.");
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'This security-key step has expired. Start the request again from ' +
          'the application that sent you here.');
      }

      let credential;
      try {
        credential = JSON.parse(String(body.credential || '{}'));
      } catch (e) {
        log.debug("Caught in a callback in module scope: " +
                  ((e && e.message) || e));
        log.debug("Leaving the WebAuthn endpoint. The posted credential was " +
                  "not JSON.");
        errorCodes.mark(res, 'STS-AUTHN-0021');
        return this.sendWebauthnPage(res,
                                     this.webauthnPage(base,
                             step.authn && String(body.mfa_id), step.username,
                             'The browser returned something this server ' +
                             'could not read.'));
      }
      if (credential.error) {
        // The browser refused the ceremony. Its error is deliberately ambiguous
        // — no credential, declined, and timed out are one error — so report it
        // as given rather than guessing which happened.
        log.debug("Leaving the WebAuthn endpoint. The browser refused: " +
                  credential.error);
        errorCodes.mark(res, 'STS-AUTHN-0022');
        return this.sendWebauthnPage(res,
                                     this.webauthnPage(base,
                                                       String(body.mfa_id),
            step.username,
            credential.error + ': ' + (credential.message || '') +
            '  (WebAuthn reports one error for several situations, so this ' +
            'does not say which.)'));
      }

      // THE RP ID MUST FIT, IN PRODUCT MODE, BEFORE ANYTHING IS VERIFIED. See
      // rpIdProblem(): the fallback to the request's host is a development
      // convenience and not something a deployment's ceremony may rest on.
      const rpRefusal = this.rpIdProblem(base);
      if (rpRefusal) {
        log.warn('authn: a WebAuthn ceremony for "' + step.username + '" was ' +
                 'REFUSED. ' + rpRefusal);
        log.debug("Leaving the WebAuthn endpoint. The RP ID does not fit.");
        errorCodes.mark(res, 'STS-AUTHN-0023');
        return this.sendWebauthnPage(res, this.webauthnPage(base,
                                                            String(body.mfa_id),
                                                            step.username,
                                                            rpRefusal));
      }
      // THE ORIGIN, NOT THE BASE URL. See originOf() — a realm's base URL
      // carries a path and a clientDataJSON origin never does. And
      // `webauthn.allowedOrigins` where it is set — see expectedOriginFor().
      const expectedOrigin = this.expectedOriginFor(base, credential);
      const expectedRpId = this.rpIdOf(base);
      let verdict;
      // An assertion that verified and still has to be SPENT. See below.
      let toSpend = null;
      // A registration that verified and still has to be WRITTEN through its
      // credential-id claim (2026-09-14). See below.
      let toRegister = null;
      try {
        if (String(body.mode || '') === 'create') {
          // ENROLMENT IS WHAT `webauthn.enabled` GATES, AND ONLY ENROLMENT
          // (2026-09-10). The assertion branch below is deliberately NOT gated:
          // turning the mechanism off must not lock out somebody who already
          // holds a key, for the reason the setting itself states — an account
          // configured for two factors is still configured for two, and a
          // switch that silently downgraded it would be a security control
          // whose off position does something other than what it says. What it
          // stops is new ceremonies.
          if (!webauthnPolicy.offered()) {
            log.info('authn: a WebAuthn ENROLMENT was refused for "' +
                     step.username + '" — security keys are switched off in ' +
                     'this realm (webauthn.enabled). An already-enrolled key ' +
                     'is unaffected.');
            log.debug("Leaving the WebAuthn endpoint. Enrolment is switched " +
                      "off.");
            errorCodes.mark(res, 'STS-AUTHN-0044');
            return this.sendWebauthnPage(res, this.webauthnPage(base,
                String(body.mfa_id),
              step.username,
              'Security keys are switched off in this realm ' +
              '(webauthn.enabled), ' +
              'so a new one cannot be enrolled here. A key already enrolled ' +
              'goes on working.'));
          }
          verdict = webauthnVerifier.verifyRegistration({
            attestationObject: credential.response.attestationObject,
            clientDataJSON: credential.response.clientDataJSON,
            expectedChallenge: step.challenge,
            expectedOrigin: expectedOrigin,
            expectedRpId: expectedRpId,
            // FROM THE SETTING, AND IT IS THE ONE CEREMONY OPTION THIS SERVICE
            // CHECKS AS WELL AS ASKS FOR. The UV flag is inside the bytes the
            // authenticator signed, so `webauthn.userVerification: required` is
            // a claim that can be verified rather than a preference that can
            // only be expressed — unlike attestation, the resident key and the
            // attachment, which nothing signed says anything about. It was the
            // literal `false` until 2026-09-10, which made `required` a request
            // a browser could decline with nothing here noticing.
            requireUserVerification: webauthnPolicy.requireUserVerification(),
            // WebAuthn Level 3 section 7.1: the credential's alg must be one
            // of the pubKeyCredParams this realm offered (#105).
            expectedAlgorithms: webauthnPolicy.algorithmIds()
          });
          if (verdict.ok) {
            // ---------------------------------------------------------------
            // THE PERSON EXISTS FROM THE MOMENT THE KEY DOES (2026-09-06).
            //
            // **A REGISTERED KEY IS A CREDENTIAL, AND A CREDENTIAL WITH NOBODY
            // BEHIND IT IS A DANGLING ONE.** Until this, enrolment wrote only
            // the in-memory `webauthnCredentials` map: the directory entry
            // appeared at the first successful SIGN-IN, through the observer
            // `startSession()` reaches. So between enrolling a key and using
            // it, this service held a working credential for a person it could
            // not list, could not show on /admin/users, and could not have
            // shown you the keys of.
            //
            // For a PRIMARY (passwordless) key that gap is the whole account:
            // the key is the only credential there is, so "the key exists and
            // the person does not" is the only state that account is ever in
            // until somebody uses it.
            //
            // **PRODUCT MODE REFUSES TO ENROL FOR SOMEBODY WHO DOES NOT
            // EXIST**, which is requirement two applied where it belongs — a
            // key enrolled for an unknown name would create that name, and
            // creating objects because something referenced them is exactly
            // what product mode removes. Development creates the entry, which
            // is what it does everywhere else.
            // AND A PRIMARY KEY IS NOT ENROLLED HERE AT ALL IN PRODUCT
            // (2026-09-21) — the sign-in handler refuses before the ceremony
            // is drawn, and this is the same refusal for a step that got past
            // it. Nothing on the passwordless path proved who is asking.
            if (step.passwordless && !mode.enrolsKeysOnFirstUse()) {
              log.info('authn: product mode, so a primary security key was ' +
                       'NOT enrolled for "' + step.username + '" at the ' +
                       'sign-in screen.');
              verdict = errorCodes.mark({ ok: false,
                          why: 'This service is in product mode, where a ' +
                               'security key that signs in on its own is ' +
                               'added at /portal/keys after signing in, ' +
                               'never at the sign-in screen.' },
                          'STS-AUTHN-0206');
            } else if (!mode.autoCreates() &&
                       !stats.knownUser(step.username)) {
              log.info('authn: product mode, so a WebAuthn key was NOT ' +
                       'enrolled for "' + step.username + '" — there is no ' +
                       'directory entry for them and enrolling would create ' +
                       'one.');
              verdict = errorCodes.mark({ ok: false,
                          why: 'This service is in product mode, where a ' +
                               'security key can only be enrolled for ' +
                               'somebody who already exists. Create the ' +
                               'person first.' }, 'STS-AUTHN-0024');
            } else {
              // THE ENTRY FIRST, AND THE ORDER IS NOW LOAD-BEARING RATHER THAN
              // TIDY. `credentials.addKey()` writes an ATTRIBUTE ON THE
              // PERSON'S ENTRY and answers "there is nobody called that in this
              // realm's directory" when there is none — so in development the
              // entry has to be seeded before the write, where the old code
              // could set a map key for anybody and seed the entry afterwards.
              //
              // Through the same observer every other identity here reaches —
              // `admin_stats.js`'s `setUserObserver()`, filled by
              // `ldap_server.js` — and with the event named, so the directory
              // can tell an enrolment from an authentication. It is NOT
              // `recordAuthentication()`: nobody authenticated by enrolling a
              // key, and counting it would inflate the one number /admin/users
              // is about.
              stats.noteWebauthnEnrolled(step.username);

              // ---------------------------------------------------------------
              // THE ROLE COMES OFF THE PENDING RECORD AND NOWHERE ELSE.
              //
              // `step.passwordless` is what the person chose a screen ago, and
              // it is on the record for the reason the comment beside it gives:
              // the POST at this end is the browser's ceremony RESULT and
              // nothing in it says what was asked for. A role read from the
              // body would be a caller choosing whether their own credential is
              // a way IN or a second factor — which is the whole of what the
              // two roles mean.
              //
              // **AND THIS IS WHERE THE `webauthn.*` POLICY BITES**, because
              // `addKey()` is where it is enforced: a realm with
              // `primaryAllowed` off refuses the passwordless enrolment here,
              // by name, and one at its `maxKeysPerPerson` refuses the next
              // key. Until 2026-09-10 this branch wrote a map and no policy
              // could reach it.
              // ---------------------------------------------------------------
              const role = step.passwordless ? 'primary' : 'mfa';
              // WRITTEN BELOW, THROUGH `credentials.addKeyClaimed()`, since
              // 2026-09-14: the credential id is claimed across nodes before
              // the row is written, and this block cannot await. Recorded here.
              toRegister = { username: step.username, role: role, record: {
                credentialId: verdict.credentialId,
                publicKeyJwk: verdict.publicKeyJwk,
                signCount: verdict.signCount,
                label: this.labelForKey(credential, verdict),
                // WHAT THE BROWSER SAID ABOUT THE AUTHENTICATOR (2026-09-10).
                // Both are REPORTS and neither is checked:
                // `authenticatorAttachment` is what answered rather than what
                // `webauthn.authenticatorAttachment` asked for, and
                // `credProps.rk` is the only way to find out whether a
                // `residentKey: "preferred"` ceremony actually produced a
                // discoverable credential — nothing in the attestation says.
                // `null` means the browser did not say, which older ones do
                // not.
                attachment: credential.authenticatorAttachment || null,
                discoverable: this.discoverableFrom(credential),
                userVerified: !!(verdict.flags && verdict.flags.uv),
                aaguid: verdict.aaguid || null,
                algorithm: verdict.algorithm || null
              }, registration: verdict };
            }
          }
        } else {
          // ---------------------------------------------------------------
          // THE ASSERTION IS CHECKED AGAINST THE KEY THAT PRODUCED IT, PICKED
          // BY THE CREDENTIAL ID THE BROWSER SENT (2026-09-10).
          //
          // It was a single credential out of this module's own map, so there
          // was nothing to pick: whatever was there was what the signature was
          // checked against. With several keys per person there is a choice,
          // and **the browser's `rawId` is what makes it** — that is what an
          // assertion NAMES itself with, and it is the reason WebAuthn
          // tolerates several credentials where a shared secret cannot.
          //
          // **THE ROLE IS PART OF THE MATCH AND NOT A DETAIL.** A key enrolled
          // as `primary` must not answer a SECOND-FACTOR step: it is a way IN
          // on its own, so accepting one here would let somebody satisfy
          // "password AND a second factor" with a credential this service
          // already considers sufficient by itself. The filter is the same one
          // `webauthnPage()` drew `allowCredentials` from, so the ceremony and
          // the check agree by construction — `allowCredentials` is a HINT to
          // the browser and this is the enforcement.
          // ---------------------------------------------------------------
          const picked = this.keyForAssertion(step.username,
            step.passwordless ? 'primary' : 'mfa',
            String(credential.rawId || credential.id || ''));
          if (!picked.key) {
            throw errorCodes.mark(new Error(picked.why),
                                  errorCodes.codeOf(picked));
          }
          const known = picked.key;
          verdict = webauthnVerifier.verifyAssertion({
            authenticatorData: credential.response.authenticatorData,
            clientDataJSON: credential.response.clientDataJSON,
            signature: credential.response.signature,
            publicKeyJwk: known.publicKeyJwk,
            expectedChallenge: step.challenge,
            expectedOrigin: expectedOrigin,
            expectedRpId: expectedRpId,
            // The same setting as the registration branch above, for the same
            // reason. Both halves of the ceremony or neither: a service that
            // demanded user verification to enrol and not to sign in would be
            // demanding it exactly once, at the moment it matters least.
            requireUserVerification: webauthnPolicy.requireUserVerification(),
            previousSignCount: known.signCount
          });
          if (verdict.ok) {
            // WHICH KEY ANSWERED, for the authentication event (#62 P0): the
            // stored record, since the assertion names itself only by id.
            verdict.answeredBy = { id: known.credentialId,
                                   aaguid: known.aaguid || null };
            // THROUGH `credentials.spendAssertion()` AND NOT A WRITE OF ITS
            // OWN, which is the same argument `removeKey()` carries: that file
            // is the one place the signature counter is recorded, and a second
            // writer here would be a second answer to what the last counter was
            // — with the replay defence quietly stopping at whichever one lost.
            //
            // **SPENT AFTER THIS BLOCK, ASYNCHRONOUSLY, SINCE 2026-09-14
            // (#46).** It used to be `noteKeyUsed()` right here, which on
            // several nodes let the counter go BACKWARDS and one assertion sign
            // in twice. The spend claims the challenge and advances the counter
            // in the store before the sign-in stands; `spendAssertion()` argues
            // both. It is recorded here and run below because this block is
            // synchronous and a refusal must reach the same page every other
            // refusal does.
            toSpend = { username: step.username,
                        credentialId: known.credentialId,
                        signCount: verdict.signCount,
                        challenge: step.challenge,
                        ttlMs: this.mfaStepTtlMs() };
          }
        }
      } catch (e) {
        log.debug("Leaving the WebAuthn endpoint. Verification threw: " +
                  e.message);
        errorCodes.mark(res, errorCodes.codeOf(e) || 'STS-AUTHN-0027');
        return this.sendWebauthnPage(res,
                                     this.webauthnPage(base,
                                                       String(body.mfa_id),
                             step.username,
                             'The second factor could not be checked: ' +
                             e.message));
      }

      if (toRegister) {
        // THE ATTESTATION STATEMENT FIRST (#105): section 7.1 steps 21-25,
        // asynchronous because a certificate path and its revocation are, and
        // BEFORE the credential id is claimed, so a refused statement leaves
        // nothing behind. What it answers is recorded on the key row.
        self.deps.webauthnAttestation.assess(toRegister.registration)
          .then(function (attested) {
            if (!attested.ok) {
              log.info('authn: the security key "' + step.username + '" ' +
                       'presented was NOT registered: ' + attested.why);
              verdict = errorCodes.mark({ ok: false,
                                          checks: verdict.checks,
                                          failed: [attested.why],
                                          why: attested.why },
                                        errorCodes.codeOf(attested) ||
                                        'STS-AUTHN-0241');
              return null;
            }
            toRegister.record.attestation = attested.attestation;
            return credentials.addKeyClaimed(toRegister.username,
                                             toRegister.record,
                                             toRegister.role);
          }).then(function (stored) {
          if (stored === null) {
            // The attestation refused it, above; the verdict says why.
            self.finishWebauthn(req, res, base, body, step, verdict);
            return;
          }
          if (!stored.ok) {
            // **A REFUSED WRITE IS A REFUSED CEREMONY.** The old code could not
            // fail here — a map takes anything — so there was no branch for it,
            // and reporting success on a credential that was not recorded would
            // sign somebody in with a key that will not work the next time. The
            // sentence is `addKey()`'s own, which names the setting or the
            // missing entry — or the claim's, when another request registered
            // that key.
            log.info('authn: the security key "' + step.username + '" just ' +
                     'registered was NOT stored: ' +
                     (stored.errors || []).join(' '));
            verdict = errorCodes.mark({ ok: false,
                                        checks: verdict.checks,
                                        failed: [(stored.errors || [])
                                          .join(' ')],
                                        why: (stored.errors || []).join(' ') },
                                      errorCodes.codeOf(stored) ||
                                      'STS-AUTHN-0068');
          } else {
            // A key registered during a sign-in is a credential created
            // (#145), described by what the registration recorded.
            self.deps.accountSignals.credentialChanged({
              username: toRegister.username,
              credentialType: self.deps.accountSignals.keyCredentialType(
                toRegister.record),
              fido2Aaguid: credentials.Credentials.aaguidString(
                toRegister.record.aaguid),
              friendlyName: String(toRegister.record.label || ''),
              changeType: 'create', initiatingEntity: 'user',
              via: 'sign-in',
              reasonAdmin: toRegister.username + ' registered a security ' +
                           'key while signing in.',
              reasonUser: 'You registered a security key.' });
          }
          self.finishWebauthn(req, res, base, body, step, verdict);
        }).catch(function (e) {
          log.error(errorCodes.tag('STS-AUTHN-0068') + 'authn: recording the ' +
                    'security key "' + step.username + '" registered threw: ' +
                    (e && e.stack ? e.stack : e));
          errorCodes.mark(res, 'STS-AUTHN-0068');
          self.sendWebauthnPage(res, self.webauthnPage(base,
                                                       String(body.mfa_id),
            step.username,
            'The security key could not be recorded. Try again.'));
        });
        log.debug("Leaving the WebAuthn endpoint. Writing the registration.");
        return undefined;
      }
      if (!toSpend) {
        log.debug("Leaving the WebAuthn endpoint. Nothing to spend.");
        return this.finishWebauthn(req, res, base, body, step, verdict);
      }
      credentials.spendAssertion(toSpend).then(function (spent) {
        if (!spent.ok) {
          // A REFUSAL LIKE EVERY OTHER CHECK THE CEREMONY FAILS, so it reaches
          // the same page with the check that failed named — "the signature
          // counter did not increase" is worth a person reading.
          verdict = errorCodes.mark({ ok: false, checks: verdict.checks,
                                      failed: [spent.detail] },
                                    errorCodes.codeOf(spent) ||
                                    'STS-AUTHN-0182');
        } else if (!spent.recorded) {
          // **A failure to record it on the ENTRY is LOGGED and does not undo
          // the sign-in**, as before: the counter is advanced in the store,
          // which is what the next assertion is decided by, so all that is lost
          // is the "last used" a page draws.
          log.warn(errorCodes.tag('STS-AUTHN-0038') +
                   'authn: the signature counter for "' + step.username +
                   '" could not be recorded on the entry. The sign-in ' +
                   'stands; the counter is advanced in the store.');
        }
        self.finishWebauthn(req, res, base, body, step, verdict);
      }).catch(function (e) {
        // Express 4 does not look at what a handler returns; see the recovery
        // code door for the trap this is.
        log.error(errorCodes.tag('STS-AUTHN-0182') + 'authn: spending a ' +
                  'security-key assertion for "' + step.username + '" threw: ' +
                  (e && e.stack ? e.stack : e));
        errorCodes.mark(res, 'STS-AUTHN-0182');
        self.sendWebauthnPage(res, self.webauthnPage(base, String(body.mfa_id),
          step.username, 'The second factor could not be checked. Try again.'));
      });
      log.debug("Leaving the WebAuthn endpoint. Spending the assertion.");
      return undefined;
    });

    // -------------------------------------------------------------------------
    // GET /authn/totp — the *use a code instead* link, and the ONLY thing it
    // does is draw the page for a step that already exists.
    //
    // It creates nothing and decides nothing: the pending record was minted
    // when the password step succeeded, and both mechanisms answer against the
    // same one. A step id naming nothing is refused exactly as the POST refuses
    // it, so this endpoint is not a way to find out whether a sign-in is in
    // progress.
    //
    // **IT CHECKS THAT THE PERSON ACTUALLY HOLDS AN ENROLMENT**, because a link
    // is markup and this is a door: a hand-made GET must not draw a code form
    // for somebody who has no authenticator, which would ask for something that
    // can never be right and would look like a service that has lost their
    // enrolment.
    // -------------------------------------------------------------------------
    app.get(TOTP_PATH, (req, res) => {
      log.debug('Entering the one-time code screen.');
      const asked = validation.check(req, 'query', MFA_STEP_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0018');
        return this.refuseInvalid(res, asked);
      }
      const mfaId = String(asked.value.mfa || '');
      const step = pendingMfa.get(mfaId);
      if (!step || step.expires < Date.now()) {
        pendingMfa.delete(mfaId);
        log.debug('Leaving the one-time code screen. The step had expired.');
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'This second-factor step has expired. Start the request again from ' +
          'the application that sent you here.');
      }
      if (this.keyDemandRefuses(res, step, 'a one-time code')) {
        log.debug('Leaving the one-time code screen. A key was demanded.');
        return undefined;
      }
      if (!credentials.mechanismsFor(step.username).totp) {
        log.info('authn: a one-time code screen was asked for "' +
                 step.username +
                 '", who has no authenticator enrolled. Refused.');
        log.debug('Leaving the one-time code screen. Nothing is enrolled.');
        errorCodes.mark(res, 'STS-AUTHN-0076');
        return oauthError(res, 400, 'invalid_request',
          'No authenticator app is enrolled for that account, so there is no ' +
          'code to ask for.');
      }
      log.debug('Leaving the one-time code screen. Drawn for ' + step.username +
                '.');
      return this.sendTotpPage(res,
                          this.totpPage(baseUrlOf(req), mfaId, step.username,
                                        '', ''));
    });

    // -------------------------------------------------------------------------
    // POST /authn/totp — the code, checked for real.
    //
    // **RATE LIMITED, AND THIS IS THE ENDPOINT IN THIS SERVICE WHERE THAT
    // MATTERS MOST.** A password has an unbounded search space and — in
    // development mode — is not checked at all. A six-digit code has a MILLION
    // values, it is checked properly in both modes, and the window forgives a
    // step either side, so an unthrottled door here is roughly a one-in-333,000
    // chance per attempt at a second factor. Five attempts a minute is what
    // `security.rateLimitPerIdentity` gives it, by identity AND by address,
    // which is the same pair the sign-in screen uses and for the same reason:
    // either bucket alone is the half an attacker does not use.
    //
    // **A REFUSED CODE REDRAWS THIS PAGE AND KEEPS THE STEP**, rather than
    // sending the person back to the password screen. Mistyping six digits is
    // the ordinary case, and throwing away a password step that succeeded would
    // make the commonest mistake the most expensive one. The step still expires
    // (`MFA_TTL_MS`), so this is a window and not an open door — and the rate
    // limiter is what bounds the attempts inside it.
    //
    // **THE STEP IS SPENT ON SUCCESS AND ONLY ON SUCCESS.**
    // -------------------------------------------------------------------------
    // ASYNCHRONOUS SINCE 2026-09-14 (#46) for the rate limit's shared window.
    // -------------------------------------------------------------------------
    // GET|POST /authn/password-factor — a password after a wallet (#38's
    // follow-ups). The GET only draws the page for a step that exists and
    // whose first factor was not a password; the POST checks the password
    // with `credentials.verify()`, rate limited on the sign-in bucket, and
    // finishes the step.
    // -------------------------------------------------------------------------
    app.get(PASSWORD_FACTOR_PATH, (req, res) => {
      log.debug('Entering the password-factor screen.');
      const asked = validation.check(req, 'query', MFA_STEP_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0018');
        return this.refuseInvalid(res, asked);
      }
      const mfaId = String(asked.value.mfa || '');
      const step = this.mfaStepFor(mfaId);
      if (!step || this.firstAmrOf(step).indexOf('pwd') >= 0) {
        log.debug('Leaving the password-factor screen. No such step.');
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'There is no sign-in waiting for a password as its second factor. ' +
          'Start the request again from the application that sent you here.');
      }
      log.debug('Leaving the password-factor screen. Drawn.');
      return this.sendPasswordFactorPage(res,
        this.passwordFactorPage(mfaId, step.username, ''));
    });

    app.post(PASSWORD_FACTOR_PATH, async (req, res) => {
      log.debug('Entering the password-factor endpoint.');
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            PASSWORD_FACTOR_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0020');
        return this.refuseInvalid(res, posted);
      }
      const mfaId = String(posted.value.mfa_id || '');
      const step = this.mfaStepFor(mfaId);
      if (!step || this.firstAmrOf(step).indexOf('pwd') >= 0) {
        log.debug('Leaving the password-factor endpoint. No such step.');
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'This second-factor step has expired. Start the request again from ' +
          'the application that sent you here.');
      }
      const allowed = await websecurity.attemptShared('sign-in', req,
                                                      step.username);
      if (!allowed.ok) {
        log.debug('Leaving the password-factor endpoint. Rate limited.');
        errorCodes.mark(res, 'STS-AUTHN-0008');
        return this.sendPasswordFactorPage(res,
          this.passwordFactorPage(mfaId, step.username, allowed.detail));
      }
      // `asked-next` (#101): here the password IS the second factor, after
      // the wallet's presentation, so the password-only-door refusal is not
      // this door's. No `door`, so no app password.
      const credential = credentials.verify(step.username,
        String(posted.value.password || ''),
        { via: 'the password-factor screen', secondFactor: 'asked-next' });
      if (!credential.ok) {
        log.info('authn: the password second factor for "' + step.username +
                 '" was refused (' + credential.reason + ').');
        errorCodes.mark(res, errorCodes.codeOf(credential) ||
                             'STS-AUTHN-0196');
        return this.sendPasswordFactorPage(res,
          this.passwordFactorPage(mfaId, step.username,
                                  'That password is not right.'));
      }
      await websecurity.succeededShared('sign-in', req, step.username);
      pendingMfa.delete(mfaId);
      const amr = this.firstAmrOf(step).concat(['pwd']);
      // Looked at since 2026-09-22 (#62 P0): the account may have been
      // disabled after the wallet step, and a null here returned the browser
      // to a caller that sent it straight back.
      const said = { request: req, risk: step.risk,
                     credential: { kind: 'password' } };
      const started = this.startSession(res, step.username, amr, 'mfa',
                                        step.authn.protocol, said);
      if (this.refusedSession(res, baseUrlOf(req), step.authn, step.username,
                              started, said)) {
        log.debug('Leaving the password-factor endpoint. Refused.');
        return undefined;
      }
      this.returnToCaller(res, step.authn, null, null);
      log.debug('Leaving the password-factor endpoint. Signed in.');
      return undefined;
    });

    app.post(TOTP_PATH, async (req, res) => {
      log.debug('Entering the one-time code endpoint.');
      const base = baseUrlOf(req);
      const posted = validation.checkParsed(parseBody(req), 'body', TOTP_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0039');
        return this.refuseInvalid(res, posted);
      }
      const body = posted.value;
      const mfaId = String(body.mfa_id || '');
      const step = pendingMfa.get(mfaId);
      if (!step || step.expires < Date.now()) {
        pendingMfa.delete(mfaId);
        log.debug('Leaving the one-time code endpoint. The step had expired.');
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'This second-factor step has expired. Start the request again from ' +
          'the application that sent you here.');
      }

      if (this.keyDemandRefuses(res, step, 'a one-time code')) {
        log.debug('Leaving the one-time code endpoint. A key was demanded.');
        return undefined;
      }
      const allowed = await websecurity.attemptShared('mfa-code', req,
                                                      step.username);
      if (!allowed.ok) {
        log.warn('authn: too many one-time code attempts for "' +
                 step.username +
                 '" (' + allowed.kind + ' bucket). Refusing for ' +
                 allowed.retryAfterS + 's.');
        log.debug('Leaving the one-time code endpoint. Rate limited.');
        errorCodes.mark(res, 'STS-AUTHN-0040');
        return this.sendTotpPage(res, this.totpPage(base, mfaId, step.username,
                                                    allowed.detail, ''));
      }

      // **THE ASYNCHRONOUS DOOR SINCE 2026-09-14 (#46)**, because the step is
      // now spent in the store as well as on the entry: two nodes reading "last
      // step 41" off their own copies both accepted step 42.
      // `common/credentials.ts`'s `verifyTotpAsync()` argues it; everything it
      // refuses before the store is what the synchronous door refused, in the
      // same order.
      credentials.verifyTotpAsync(step.username, String(body.code || ''))
        .then(function (verdict) {
          self.finishTotp(req, res, base, mfaId, step, verdict);
        })
        .catch(function (e) {
          // Caught here for the recovery-code door's reason below: Express 4
          // does not look at what a handler returns.
          log.error(errorCodes.tag('STS-AUTHN-0182') +
                    'authn: checking a one-time code for "' + step.username +
                    '" threw: ' + (e && e.stack ? e.stack : e));
          errorCodes.mark(res, 'STS-AUTHN-0182');
          self.sendTotpPage(res, self.totpPage(base, mfaId, step.username,
            'That code could not be checked. Try the next one.', ''));
        });
      log.debug('Leaving the one-time code endpoint. Checking.');
      return undefined;
    });

    // -------------------------------------------------------------------------
    // GET /authn/backup-code — the *use a recovery code* link, and all it does
    // is draw the page for a step that already exists.
    //
    // It creates nothing and decides nothing, exactly as `GET /authn/totp`
    // does: the pending record was minted when the password step succeeded, and
    // all three screens answer against the same one.
    //
    // **IT CHECKS THAT AN UNSPENT CODE ACTUALLY EXISTS**, because a link is
    // markup and this is a door. A hand-made GET must not draw a recovery form
    // for somebody who holds no codes or has spent them all: that would ask for
    // a credential which cannot exist, which reads as a service that has lost
    // it.
    // -------------------------------------------------------------------------
    app.get(BACKUP_CODE_PATH, (req, res) => {
      log.debug('Entering the recovery code screen.');
      const asked = validation.check(req, 'query', MFA_STEP_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0018');
        return this.refuseInvalid(res, asked);
      }
      const mfaId = String(asked.value.mfa || '');
      const step = pendingMfa.get(mfaId);
      if (!step || step.expires < Date.now()) {
        pendingMfa.delete(mfaId);
        log.debug('Leaving the recovery code screen. The step had expired.');
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'This second-factor step has expired. Start the request again from ' +
          'the application that sent you here.');
      }
      const held = credentials.mechanismsFor(step.username).backupCodes;
      if (!held || !held.remaining) {
        log.info('authn: a recovery code screen was asked for "' +
                 step.username +
                 '", who has ' + ((held && held.total)
                   ? 'spent every code in their set' : 'no recovery codes')
                 + '. Refused.');
        log.debug('Leaving the recovery code screen. Nothing left to present.');
        errorCodes.mark(res,
                        (held && held.total) ? 'STS-AUTHN-0088' :
                        'STS-AUTHN-0087');
        return oauthError(res, 400, 'invalid_request',
          (held && held.total)
            ? 'Every recovery code on that account has been used. A set is ' +
              'issued once and is never topped up, so an administrator has ' +
              'to clear it before a new one can be issued.'
            : 'No recovery codes have been issued for that account, so there ' +
              'is nothing to ask for.');
      }
      log.debug('Leaving the recovery code screen. Drawn for ' + step.username +
                '.');
      return this.sendBackupCodePage(res, this.backupCodePage(baseUrlOf(req),
                                                              mfaId,
                                                              step.username, '',
                                                              ''));
    });

    // -------------------------------------------------------------------------
    // POST /authn/backup-code — the code, checked for real and SPENT.
    //
    // **RATE LIMITED, THROUGH THE SAME BUCKETS AS THE ONE-TIME CODE DOOR.**
    // Fifty bits is not guessable and that is not why the limit is here: this
    // endpoint answers *is this one of your codes* and an unthrottled one would
    // let somebody walk a list at network speed, which is the shape of attack a
    // finite set of static strings actually has.
    // `security.rateLimitPerIdentity` gives it five a minute, by identity AND
    // by address.
    //
    // **A REFUSED CODE REDRAWS THIS PAGE AND KEEPS THE STEP**, for
    // `POST /authn/totp`'s reason: mistyping ten characters off paper is the
    // ordinary case, and throwing away a password step that succeeded would
    // make the commonest mistake the most expensive one.
    //
    // **THE CODE IS SPENT INSIDE `verifyBackupCode()` AND A FAILED SPEND IS A
    // REFUSAL.** That is the one place these three screens differ from each
    // other and it is argued in `common/credentials.ts`: a one-time code whose
    // counter fails to write can be replayed inside ninety seconds, and a
    // recovery code that cannot be marked spent works for ever.
    // -------------------------------------------------------------------------
    // ASYNCHRONOUS SINCE 2026-09-14 (#46) for the rate limit's shared window.
    app.post(BACKUP_CODE_PATH, async (req, res) => {
      log.debug('Entering the recovery code endpoint.');
      const base = baseUrlOf(req);
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            BACKUP_CODE_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0041');
        return this.refuseInvalid(res, posted);
      }
      const body = posted.value;
      const mfaId = String(body.mfa_id || '');
      const step = pendingMfa.get(mfaId);
      if (!step || step.expires < Date.now()) {
        pendingMfa.delete(mfaId);
        log.debug('Leaving the recovery code endpoint. The step had expired.');
        errorCodes.mark(res, 'STS-AUTHN-0019');
        return oauthError(res, 400, 'invalid_request',
          'This second-factor step has expired. Start the request again from ' +
          'the application that sent you here.');
      }

      if (this.keyDemandRefuses(res, step, 'a recovery code')) {
        log.debug('Leaving the recovery code endpoint. A key was demanded.');
        return undefined;
      }
      const allowed = await websecurity.attemptShared('mfa-code', req,
                                                      step.username);
      if (!allowed.ok) {
        log.warn('authn: too many recovery code attempts for "' +
                 step.username +
                 '" (' + allowed.kind + ' bucket). Refusing for ' +
                 allowed.retryAfterS + 's.');
        log.debug('Leaving the recovery code endpoint. Rate limited.');
        errorCodes.mark(res, 'STS-AUTHN-0042');
        return this.sendBackupCodePage(res, this.backupCodePage(base, mfaId,
                                                                step.username,
                                                                allowed.detail,
                                                                ''));
      }

      // **THE ASYNCHRONOUS DOOR, SINCE 2026-09-11, AND IT IS NOT AN
      // OPTIMISATION.** A recovery code is stored as a scrypt hash now, and a
      // WRONG one has to be compared against every code in the set — ten by
      // default. Measured on this machine: 860ms with the event loop ticking
      // **zero** times, against 263ms with it ticking 56. Node runs every
      // listener family this service has on one thread, so the synchronous door
      // here would mean the KDC, the directory and every other endpoint
      // answering nobody for most of a second every time somebody mistypes ten
      // characters off a printed list — which is the ordinary case at this
      // screen.
      //
      // `common/credentials.ts`'s `verifyBackupCodeAsync()` puts the candidates
      // on the worker pool in parallel and refuses in exactly the order the
      // synchronous door does, because both go through one `backupPrepare()`.
      credentials.verifyBackupCodeAsync(step.username, String(body.code || ''))
        .then(function (verdict) {
          self.finishBackupCode(req, res, base, mfaId, step, verdict);
        })
        .catch(function (e) {
          // **CAUGHT HERE BECAUSE EXPRESS 4 DOES NOT LOOK AT WHAT A HANDLER
          // RETURNS.** A rejection would be an unhandled rejection and a
          // request that never gets an answer — the trap the token endpoint's
          // wrapper exists for, met again by the second asynchronous door in
          // this file.
          log.error(errorCodes.tag('STS-AUTHN-0043') +
                    'authn: checking a recovery code for "' + step.username +
                    '" threw: ' + (e && e.stack ? e.stack : e));
          errorCodes.mark(res, 'STS-AUTHN-0043');
          self.sendBackupCodePage(res, self.backupCodePage(base, mfaId,
                                                           step.username,
            'That code could not be checked. Try again.', ''));
        });
      log.debug('Leaving the recovery code endpoint. Checking.');
      return undefined;
    });
    log.debug("Leaving Authn.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Authn>(
  'authn/authn',
  () => new Authn(Authn.defaultDeps()),
  Authn.wire,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

// ---------------------------------------------------------------------------
// THE SESSION-EXPIRY SWEEP, AS A SCHEDULER JOB (#49, 2026-09-22) — see the
// header's *THE SWEEP IS A SCHEDULER JOB*. Registered here, at load, and run
// only by the scheduler's leader; it ends every expired session in every
// realm through `expireSession()`, so the audit row, CAEP session-revoked and
// the back-channel Logout Tokens keep coming from the one path.
// ---------------------------------------------------------------------------
scheduler.register({
  id: SESSION_EXPIRY_JOB,
  title: 'Session expiry',
  describe: 'Ends every sign-on session whose lifetime or idle timeout has ' +
            'passed, in every realm: an audit row, CAEP session-revoked and ' +
            'the back-channel Logout Tokens, once for the whole cluster.',
  owner: 'authn/authn.ts',
  everySetting: SESSION_SWEEP_SETTING,
  everySettingUnit: 's',
  run: function (): any {
    return { ended: slot.get().sweepExpiredSessions() };
  }
});

// ---------------------------------------------------------------------------
// What the rest of this service uses.
//
// `sessions` is handed out rather than copied because the admin console reports
// on the live store; `startSession` / `endSession` are functions rather than
// four lines repeated per call site for the reason written above them.
// ---------------------------------------------------------------------------

export = {
  registerRoutes: slot.forward('registerRoutes'),
  Authn: Authn,
  installInstance: (instance: Authn): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // What two nodes' copies of one session become, for
  // `tests/cluster_lww_stores.js` — the merge is declared on the store and
  // the store is reached through the persistence layer, so the rule itself is
  // asserted here directly.
  mergeSessionRows: slot.forward('mergeSessionRows'),
  noteSessionChanged: slot.forward('noteSessionChanged'),
  LOGIN_PATH: LOGIN_PATH,
  MFA_SETUP_PATH: MFA_SETUP_PATH,
  // WHICH ENROLLED KEY AN ASSERTION IS CHECKED AGAINST, exported for
  // `tests/webauthn_policy.js` and for no caller. The state that makes it
  // worth asserting — one person, two keys — cannot be built through any door
  // this service has, so it cannot be reached over HTTP; see the function's
  // own header and the vendored job's.
  keyForAssertion: slot.forward('keyForAssertion'),
  // THE ORIGIN AND THE RP ID, EXPORTED TOGETHER (2026-09-10). `/portal/keys`
  // runs a registration ceremony of its own and has to tell the verifier what
  // the browser was talking to — and these are, as `originOf()`'s own header
  // says, THE SAME MISTAKE WAITING TO BE MADE TWICE: one is the origin, one is
  // its host, and neither is the base URL, which in a realm carries a path.
  // A caller computing either for itself is a caller that will get the realm
  // case wrong exactly as this module once did.
  originOf: slot.forward('originOf'),
  // THE TWO ADDRESS RULES OF 2026-09-12, beside the helpers they refine:
  // `/portal/keys` verifies a ceremony of its own and must refuse and accept
  // exactly what this module does.
  expectedOriginFor: slot.forward('expectedOriginFor'),
  rpIdProblem: slot.forward('rpIdProblem'),
  // The one script this service serves for a WebAuthn ceremony, for
  // `/portal/keys`, which runs a registration of its own against it rather
  // than carrying a second copy — see that page's own argument.
  WEBAUTHN_SCRIPT_PATH: WEBAUTHN_SCRIPT_PATH,
  // THE RP ID, EXPORTED FOR ONE TEST AND FOR NO CALLER (2026-09-10).
  //
  // `webauthn.rpId` may only widen the RP ID to a REGISTRABLE DOMAIN SUFFIX of
  // the origin's host, and the check that enforces it is four lines that are
  // easy to write wrongly in a way nothing notices: `endsWith()` alone accepts
  // `mple.com` as a suffix of `example.com`, which is precisely the confusion
  // WebAuthn's binding exists to prevent. `tests/webauthn_policy.js` asserts
  // it, and it cannot be asserted over HTTP — the value only ever appears
  // inside a ceremony a browser performs.
  //
  // Nothing in this service calls it from outside this file, and nothing
  // should: the RP ID is decided where the ceremony is drawn.
  rpIdOf: slot.forward('rpIdOf'),
  SESSION_COOKIE: SESSION_COOKIE,
  // THE SESSION CLOCKS (2026-09-12). `sessionEnded()` is exported for
  // `logout/logout.ts`'s list of what is live, which must agree with this file
  // about what has ended; the three readers are for the tests and for the
  // sentences `/admin/sessions` prints about the rule in force.
  sessionEnded: slot.forward('sessionEnded'),
  sessionLifetimeMs: slot.forward('sessionLifetimeMs'),
  sessionIdleTimeoutMs: slot.forward('sessionIdleTimeoutMs'),
  pendingTtlMs: slot.forward('pendingTtlMs'),
  mfaStepTtlMs: slot.forward('mfaStepTtlMs'),
  // WHAT AN AUTHENTICATED IDENTITY IS (2026-09-14). `sessionStartedAt()` is
  // for every list that draws when a session BEGAN, now that `authTime` is
  // the most recent authentication; `cookieSession()` is the one reader of a
  // session cookie's `<sid>.<handle>`, exported for the tests that hold a
  // stale handle and for nothing else — a module reading the cookie for
  // itself would be a second place to get the handle check wrong.
  sessionStartedAt: slot.forward('sessionStartedAt'),
  signOnFactsFor: slot.forward('signOnFactsFor'),
  cookieSession: slot.forward('cookieSession'),
  MAX_SESSION_EVENTS: MAX_SESSION_EVENTS,
  startArrivalSession: slot.forward('startArrivalSession'),
  ANONYMOUS_USERNAME: ANONYMOUS_USERNAME,
  sessions: sessions,
  cookiesOf: slot.forward('cookiesOf'),
  sessionOf: slot.forward('sessionOf'),
  // The console's reader, and the ONE caller it has. It answers the same
  // question across every realm's partition because there is only ever one
  // session cookie in the browser; the header above it argues why that is the
  // boundary already drawn rather than a hole in this one. Every protocol
  // module keeps calling sessionOf() and keeps seeing its own realm only.
  consoleSession: slot.forward('consoleSession'),
  startSession: slot.forward('startSession'),
  // THE RELYING-PARTY HALF (2026-09-06), for `common/oidc_rp.ts` and for the
  // two surfaces that read what it makes. Three functions and no more: a
  // caller that wanted to create one of these without going through the code
  // flow would be a caller inventing a session out of nothing, which is the
  // thing moving these surfaces onto OIDC was for.
  startRelyingPartySession: slot.forward('startRelyingPartySession'),
  renewRelyingPartySession: slot.forward('renewRelyingPartySession'),
  tokensExpireAt: slot.forward('tokensExpireAt'),
  relyingPartySessionOf: slot.forward('relyingPartySessionOf'),
  endRelyingPartySessions: slot.forward('endRelyingPartySessions'),
  // Exported for `logout/logout.ts`, which lists what is live and has to be
  // able to say which rows hang off which. It is a walk rather than an index;
  // see its header.
  derivedFrom: slot.forward('derivedFrom'),
  endSession: slot.forward('endSession'),
  // The inverted hook `ssf/ssf.ts` fills, and the one call site that spends
  // it from outside this module. See setSessionObserver()'s header for why a
  // require the other way would move every /ssf route.
  setSessionObserver: slot.forward('setSessionObserver'),
  notePresented: slot.forward('notePresented'),
  // The three the protocol-independent logout needs, and the reason each is
  // here rather than reimplemented over there: /logout ends sessions it was not
  // handed a cookie for, so it names them by id — and every one of them still
  // has to go through dropSession(), which is where the RFC 9700 refresh
  // revocation and the one `session.end` audit row live. A second delete
  // somewhere else would be a sign-out that revoked nothing and logged nothing,
  // and it would look exactly like this one from the outside.
  sessionsOf: slot.forward('sessionsOf'),
  sessionById: slot.forward('sessionById'),
  endSessionById: slot.forward('endSessionById'),
  endEverySessionIn: slot.forward('endEverySessionIn'),
  clearSessionCookie: slot.forward('clearSessionCookie'),
  beginAuthentication: slot.forward('beginAuthentication'),
  // THE SIGN-IN SCREEN'S STYLESHEET, for oauth-oidc/consent_screen.ts. A
  // person meets that screen and this one seconds apart in one flow, so two
  // hand-maintained copies would drift into looking like two services. It is
  // exported rather than copied for that reason and for no other — nothing here
  // treats CSS as a contract, and a page wanting a different look should say so
  // in rules of its own appended after this, which is what that file does.
  CARD_CSS: CARD_CSS,
  // ---------------------------------------------------------------------
  // THE THREE THE SPNEGO SIGN-IN DOOR NEEDS, and the reason each is here
  // rather than reimplemented in `kerberos/spnego_authn.ts`.
  //
  // That module is a fourth thing beginAuthentication() can send a browser to
  // (see its own header, and the branch above). It is not a protocol module
  // borrowing the screen — it REPLACES the screen for one sign-in — so it
  // needs exactly what the screen's own POST handler needs: the pending
  // record, and the way back out of it.
  //
  //   SPNEGO_PATH            the path, declared here because this module owns
  //                          `/authn/*` and builds two links to it. The
  //                          endpoint is over there because of the require
  //                          order; see the constant.
  //   pendingFor             READ-ONLY. It sweeps an expired record on the way
  //                          past, exactly as it does for the screen, so a
  //                          door reached ten minutes late behaves the same
  //                          way the screen would.
  //   completeAuthentication the way OUT: spend the record and 303 back to
  //                          whatever was interrupted. It is one function
  //                          rather than an exported `pending` and an exported
  //                          `returnToCaller()` because the two acts are one
  //                          act — a record left behind is one somebody can
  //                          spend twice, and a redirect written at a second
  //                          call site is a second place for RFC 9700 section
  //                          4.12's 303-not-307 to be got wrong.
  // ---------------------------------------------------------------------
  SPNEGO_PATH: SPNEGO_PATH,
  // The wallet door's two paths (#38), for `oid4vc/vc_signin.ts`, which uses
  // `pendingFor` and `completeAuthentication` for the Kerberos door's reasons.
  WALLET_PATH: WALLET_PATH,
  WALLET_WAIT_PATH: WALLET_WAIT_PATH,
  WALLET_DCAPI_PATH: WALLET_DCAPI_PATH,
  WALLET_SCRIPT_PATH: WALLET_SCRIPT_PATH,
  PASSWORD_FACTOR_PATH: PASSWORD_FACTOR_PATH,
  // The wallet as a factor (#38's follow-ups): read a second-factor step,
  // finish one with a presentation, and ask for a second factor after one.
  mfaStepFor: slot.forward('mfaStepFor'),
  finishWithWallet: slot.forward('finishWithWallet'),
  beginSecondFactorAfterWallet: slot.forward('beginSecondFactorAfterWallet'),
  assessSignIn: slot.forward('assessSignIn'),
  adoptSessionRisk: slot.forward('adoptSessionRisk'),
  sessionsForRisk: slot.forward('sessionsForRisk'),
  pendingFor: slot.forward('pendingFor'),
  completeAuthentication: slot.forward('completeAuthentication')
};
