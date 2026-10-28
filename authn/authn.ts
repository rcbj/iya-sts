// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// The constant-time comparison a session handle is checked with, its digest,
// and every challenge's random bytes (#453). A LEAF that never requires
// anything here back (rule 3r).
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
// The keyed digest the session index files a subject, a username and a
// parent under (#350). It requires realms, not this module.
import keystore = require('../common/keystore');
import InstanceSlot = require('../common/instance_slot');
// The sign-in mechanisms an application allows and a session satisfies
// (#457): a leaf, so requiring it closes no cycle.
import mechanismLib = require('../common/authn_mechanisms');
// The second factors an application allows and a session gave (#475): a
// leaf, for the same reason.
import mfaLib = require('../common/mfa_mechanisms');
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
// WHICH REGISTERED DEVICE PROVED AN AUTHENTICATION (#164 phase 2): a
// library over the device register that registers nothing and requires
// nothing of this module's (`common/device_recognition.ts`).
import deviceRecognition = require('../common/device_recognition');
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
// A SERVICE DEPLOYED AS CELLS (#98): which cell this is, where a person is
// homed, and the browser's pin — all LIBRARIES with no route, so a require
// here moves nothing. The sign-in screen is where D9's restart happens.
import cells = require('../common/cells');
import cellRouting = require('../common/cell_routing');
import cellPlacement = require('../common/cell_placement');
import sessionWindow = require('./session_window');
// A BROWSER'S ACCOUNT SET (#561): the list of sign-on sessions one browser
// holds while `authn.multipleAccounts` is on, and the selection tickets. A
// LIBRARY that requires only `common/` leaves and nothing of this file, so
// the require closes no cycle and moves no route.
import AccountSets = require('./account_sets');

// The path a caller sends the browser to. Exported, because the two callers
// build a URL out of it and a string spelled twice is a string that drifts.
/**
 * The path of the sign-in screen a caller sends the browser to.
 */
const LOGIN_PATH = '/authn/login';
// WHERE A PERSON PICKS BETWEEN AN APPLICATION'S FEDERATION PARTNERS. A page of
// its own rather than the screen above with its form suppressed — see
// beginAuthentication(), where the choice between the two is argued. It is
// reached only with an `?authn=` id, exactly as the screen is, because what it
// needs is the pending record and not a partner list somebody could compose.
const SELECT_IDP_PATH = '/authn/select-idp';
// THE ACCOUNT PICKER (#561): which of a browser's signed-in accounts a flow
// continues as, or Use another account. A page of the sign-in surface,
// keyed by the pending sign-in's id as the chooser is.
const ACCOUNTS_PATH = '/authn/accounts';
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
/**
 * The path of the recovery-code screen, reached only as a way out of another
 * second-factor screen.
 */
const BACKUP_CODE_PATH = '/authn/backup-code';
// THE FORCED PASSWORD CHANGE (2026-09-13): drawn after a password is accepted
// for an entry carrying `pwdReset: TRUE`, before any session exists.
const PASSWORD_CHANGE_PATH = '/authn/password-change';
// THE LANGUAGE CHOOSER (#539, 2026-10-09): every user-facing page's chooser
// posts here. Here, in the module that owns the SESSION, because a signed-in
// person's choice is written to their own entry as well as to the cookie.
/**
 * The path every page's language chooser posts to.
 */
const LANGUAGE_PATH = '/authn/language';
// A SECOND FACTOR ENROLLED BECAUSE ONE IS REQUIRED (2026-09-13) — see the
// block above `enrolmentOffered()` for why a sign-in may now enrol an
// authenticator app where it never used to.
/**
 * The path where a sign-in enrols a second factor that is required and not yet
 * held.
 */
const MFA_SETUP_PATH = '/authn/mfa-setup';
// A POST-LOGIN ACTIVITY (#1096): the step that asks a person, after they
// signed in and before any session starts, to do what the realm's post-login
// activity policy asks of them — today, to register a post-quantum passkey.
/**
 * The path where a sign-in asks for a post-login activity.
 */
const POST_LOGIN_PATH = '/authn/post-login';
// ---------------------------------------------------------------------------
// THE SIGN-IN SCREEN AS A STATIC SURFACE (#571, 2026-10-12).
//
// `/authn/login`, `/authn/select-idp` and `/authn/password-change` answer
// the SHELL (`signInShell()`), and the browser draws each page from
// `/authn-api` (`authn/authn_api.ts`) with the runtime `build-typescript.sh`
// bundles from `web_authn.ts` — on disk `authn-spa.js`, never `authn.js`,
// which is this module compiled — served at `SIGNIN_SCRIPT_PATH`.
// ---------------------------------------------------------------------------
/**
 * The path of the sign-in surface's script (#571).
 */
const SIGNIN_SCRIPT_PATH = '/authn/signin.js';
// The bundle's file beside this module.
const SIGNIN_BUNDLE_FILE = 'authn-spa.js';
/**
 * The sign-in API's base (#571): `authn/authn_api.ts` registers under it.
 */
const AUTHN_API_PATH = '/authn-api';
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
// requires `kerberos/spnego.js`, which is JavaScript (the parent's tests
// image copies it) and still registers its routes when required.
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
/**
 * The path of the Kerberos (SPNEGO) sign-in door, whose endpoint is registered
 * by `kerberos/spnego_authn.ts`.
 */
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
/**
 * The path of the wallet sign-in, whose endpoint is registered by
 * `oid4vc/vc_signin.ts`.
 */
const WALLET_PATH = '/authn/wallet';
/**
 * The path of the wallet sign-in's waiting page.
 */
const WALLET_WAIT_PATH = '/authn/wallet/wait';
// The Digital Credentials API answer the wait page's script posted to
// (`/authn/wallet/dc-api`) and that script (`/authn/wallet.js`) were declared
// here until #574: both are the sign-in surface's now — the answer an
// `/authn-api/wallet` operation, the call the surface's runtime.

// ---------------------------------------------------------------------------
// A PASSWORD AS THE SECOND FACTOR (#38's follow-ups). A wallet presentation is
// one factor — something the person holds — and a request that demands two
// may be answered by a wallet and then something the person knows. This is
// that screen: one password field, checked by `credentials.verify()` exactly
// as the sign-in screen checks one, rate limited on the same bucket, and
// reached only with a pending second-factor step whose FIRST factor was not a
// password. No script.
// ---------------------------------------------------------------------------
/**
 * The path of the screen that asks for a password as the second factor after a
 * wallet or emailed first factor.
 */
const PASSWORD_FACTOR_PATH = '/authn/password-factor';

// ---------------------------------------------------------------------------
// THE EMAILED CODE AND THE EMAILED LINK (#64), declared here for SPNEGO's and
// the wallet's reason: this module owns `/authn/*` and draws the buttons and
// links that lead to them, and `authn/email_factor.ts` — required just after
// this module, and reading its pending steps through the functions exported
// below — registers the endpoints. No slot: nothing has to point anywhere.
//
//   EMAIL_CODE_PATH       the code screen: GET draws it for a step, POST
//                         sends a code (`action=send`) or checks one.
//   EMAIL_LINK_PATH       the waiting screen of a link: GET draws it, POST
//                         sends a link. It refreshes itself with a <meta>.
//   EMAIL_LINK_OPEN_PATH  where the mailed link lands: GET draws a Continue
//                         button and spends NOTHING (mail scanners fetch
//                         links), POST spends it — in the browser that
//                         started the sign-in only (D3).
// ---------------------------------------------------------------------------
/**
 * The path of the emailed-code screen, registered by `authn/email_factor.ts`.
 */
const EMAIL_CODE_PATH = '/authn/email-code';
/**
 * The path of the emailed sign-in link's waiting screen, registered by
 * `authn/email_factor.ts`.
 */
const EMAIL_LINK_PATH = '/authn/email-link';
/**
 * The path a mailed sign-in link lands on; a GET spends nothing and a POST
 * spends the link.
 */
const EMAIL_LINK_OPEN_PATH = '/authn/email-link/open';

/**
 * The name of the sign-on session cookie, whose value is `<sid>.<handle>`.
 */
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
/**
 * The one username every unauthenticated (anonymous) session carries.
 */
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
// The columns `sts_sessions` holds beside the sealed body (#350). Not an
// `expiresAt` hook: `sts_minted.expires_at` stays NULL so the generic purge
// cannot end a session. Null when no digest key is held, which writes no
// index row.
function sessionIndexOf(value: any) {
  helpers.log.debug("Entering sessionIndexOf().");
  try {
    if (!value || typeof value !== 'object') {
      helpers.log.debug("Leaving sessionIndexOf(). Not a session.");
      return null;
    }
    const subjectId = value.subjectId == null ? ''
      : String(value.subjectId);
    const subjectKey = keystore.keyedDigest('session-subject', subjectId);
    if (!subjectKey) {
      helpers.log.debug("Leaving sessionIndexOf(). No digest.");
      return null;
    }
    let username = '';
    if (value.user && typeof value.user === 'object' &&
        value.user.username != null) {
      username = String(value.user.username);
    }
    const usernameKey = keystore.keyedDigest('session-username', username);
    if (!usernameKey) {
      helpers.log.debug("Leaving sessionIndexOf(). No username digest.");
      return null;
    }
    const parentSid = value.derivedFrom ? String(value.derivedFrom) : '';
    let parentKey = '';
    if (parentSid) {
      parentKey = keystore.keyedDigest('session-parent', parentSid);
      if (!parentKey) {
        helpers.log.debug("Leaving sessionIndexOf(). No parent digest.");
        return null;
      }
    }
    const credentialKey = value.credentialKey
      ? String(value.credentialKey) : '';
    let kind = 'sign-on';
    if (parentSid) {
      kind = 'relying-party';
    } else if (credentialKey) {
      kind = 'keyed';
    } else if (value.chosen === false) {
      kind = 'arrival';
    }
    const partner = value.fedPartnerSession;
    let relationship = '';
    if (partner && typeof partner === 'object' && partner.relationship) {
      relationship = String(partner.relationship);
    }
    const expires = Number(value.expires);
    const lastSeen = Number(value.lastSeenAt);
    const started = Number(value.startedAt);
    helpers.log.debug("Leaving sessionIndexOf().");
    return {
      expiresAt: Number.isFinite(expires) && expires > 0
        ? Math.floor(expires) : null,
      lastSeenAt: Number.isFinite(lastSeen)
        ? Math.max(0, Math.floor(lastSeen)) : 0,
      startedAt: Number.isFinite(started)
        ? Math.max(0, Math.floor(started)) : 0,
      subjectKey: subjectKey,
      usernameKey: usernameKey,
      chosen: value.chosen !== false,
      authenticated: value.authenticated !== false,
      kind: kind,
      rpSurface: value.rpSurface ? String(value.rpSurface) : '',
      parentKey: parentKey,
      backsConsole: value.backsConsole === true,
      credentialKey: credentialKey,
      partnerRelationship: relationship
    };
  } catch (e) {
    helpers.log.debug("Caught in sessionIndexOf(): " +
                      ((e && e.message) || e));
    helpers.log.debug("Leaving sessionIndexOf().");
    return null;
  }
}

/**
 * The sign-on session store, per trust realm: session id to session row.
 *
 * Persisted, tombstoned and merged across nodes with `mergeSessionRows()`.
 * Handed out rather than copied because the console reports on the live store.
 */
const sessions = realms.map({ persist: 'authn.sessions', tombstone: true,
                              // Not expiresAt: that column stays NULL so the
                              // generic purge cannot end a session (#350).
                              indexOf: sessionIndexOf,
                              // A hosted surface's sessions, filed by the
                              // surface (#767): `endRelyingPartySessions()`
                              // visits those rather than every session held.
                              // `rpSurface` is set when a session is made and
                              // never changed on it (`realms.map()`'s rule).
                              indexBy: function (session: any): string[] {
                                return session && session.rpSurface
                                  ? ['rp:' + String(session.rpSurface)] : [];
                              },
                              // Late-bound to the instance in the slot at
                              // the bottom: a merge happens only once the
                              // store is open, after the root installed it.
                              mergeRow: function (mine, theirs) {
                                return slot.get().mergeSessionRows(mine,
                                                                   theirs);
                              } });

// A coalesced touch writes back through the facade, in the realm the
// touch belongs to. Registered once: clearing it would drop later touches.
sessionWindow.setTouchFlusher(function (realmId, sid, session) {
  realms.run(realms.get(realmId) || null, function () {
    sessions.set(sid, session);
  });
});

// The requests waiting at the login screen: what to do with the person once
// they have signed in, and what to tell them they are signing in FOR.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// authn id -> { returnTo, details, ... }
const pending = realms.map({ persist: 'authn.pending', retain: 'age',
                             // #333: the sign-in's `expires`, ms.
                             expiresAt: realms.expiryField('expires', 1) });

// ONE DEVICE RECOGNITION PER REQUEST AND CREDENTIAL (#164 phase 5): see
// `registeredDeviceFor()`. Keyed WEAKLY by the request object, so it lives
// exactly as long as the request and needs no sweep.
const recognitionMemo = new WeakMap<object, Map<string, any>>();

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
// THE AUTHENTICATION POLICY (#64): which mechanisms are first and second
// factors. A LEAF (common/authn_policy.ts), so no cycle and no route.
import authnPolicy = require('../common/authn_policy');
// The passkey policy (#528): whether a synced passkey may sign anybody in.
import passkeyPolicy = require('../common/passkey_policy');
// THE POST-LOGIN ACTIVITIES (#1096): who is due one at a sign-in. A LIBRARY
// over the credential store and three policies, none of which requires this
// module, so no cycle and no route.
import postLogin = require('../common/post_login');
// The language a page is drawn in, and the chooser (#539). Libraries.
import i18n = require('../common/i18n');
import PageLocale = require('../common/page_locale');
// THE SIGN-IN SURFACE'S SHELL AND BUNDLE (#571, 3cl). A LIBRARY (rule 3):
// `helpers` and node's modules; it takes the express app as an argument.
import ShellDocument = require('../common/shell_document');
import WebCardCss = require('../common/web_card_css');
// THE ATTESTATION STATEMENT, VERIFIED (#105). Rule 3 as well: a library that
// requires the policy above, `crypto`, `pki` and `error_codes`, and reaches
// the FIDO metadata and revocation lazily — nothing that reaches back here.
import webauthnAttestation = require('./webauthn_attestation');
// EVERY CEREMONY'S AUDIT ROW, AND THE ALGORITHM MISMATCH (#943). Rule 3: a
// library over the audit log and the passkey policy, requiring nothing here.
import webauthnCeremonies = require('./webauthn_ceremonies');
// THE USERNAMELESS SIGN-IN'S CEREMONY IN HAND (#943), by the response it
// will answer: `passkeySignIn()` learns the credential, the owner and the
// key as it goes, and its one refusal funnel, `passkeyRefused()`, writes
// the ceremony's row from what was learnt. Keyed by the response object so
// it dies with the request, as the passkey policy's selection does.
const passkeyCeremonies = new WeakMap<object, any>();
// DEVICE BOUND SESSION CREDENTIALS (#725): the registration header on the
// answer that sets the session cookie, and the bound cookie a bound session
// needs. A route module of its own that reaches this one LAZILY, so the
// require closes no cycle; being converted, requiring it registers nothing
// and moves no route (rule 1).
import deviceBound = require('./device_bound_sessions');
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
const pendingMfa = realms.map({ persist: 'authn.pendingMfa', retain: 'age',
                                // #333: the step's `expires`, ms.
                                expiresAt: realms.expiryField('expires', 1) });
// change id -> { authn, username, secondFactor, expires }. A password that must
// be changed before the sign-in it opened goes any further (2026-09-13). A
// store of its own rather than a `factor` on the one above: that register is
// "a sign-in waiting for a SECOND FACTOR", and a new password is not one — the
// person has presented one factor and is being asked to replace it.
const pendingPasswordChange = realms.map({
  persist: 'authn.pendingPasswordChange', retain: 'age',
  // #333: the step's `expires`, ms.
  expiresAt: realms.expiryField('expires', 1) });
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
  '/admin',
  // THE SIGN-IN SURFACE'S THREE SHELLS (#571). Every act on `/authn-api` is
  // bound to the cookie a front door minted (the CSRF token is derived from
  // its session id, `authn/authn_api.ts`), so the page a browser is sent to
  // mints one where the browser arrived without — a flow begun by a door
  // that is not on this list, or a cookie that ran out at the screen.
  '/authn/login',
  '/authn/select-idp',
  '/authn/password-change',
  // AND THE ACCOUNT PICKER (#561), whose acts are bound to the same cookie.
  '/authn/accounts',
  // AND THE STEPS AFTER IT (#572, #573), for the same reason: each is a
  // shell whose acts are bound to that cookie. `/authn/email-link` covers
  // `/authn/email-link/open`, where a mailed link lands.
  '/authn/mfa-setup',
  // AND THE POST-LOGIN ACTIVITY'S (#1096), for the same reason.
  '/authn/post-login',
  '/authn/webauthn',
  '/authn/totp',
  '/authn/backup-code',
  '/authn/password-factor',
  '/authn/email-code',
  '/authn/email-link',
  // AND THE WALLET'S TWO (#574): `/authn/wallet` and `/authn/wallet/wait`,
  // matched by prefix. A wallet's same-device redirect brings a browser
  // back to the wait page, and the sign-in a person starts from a second
  // factor's page or from the portal starts here.
  '/authn/wallet',
  // AND GNAP'S TWO PAGES (#578), the user code page and the approval page,
  // whose acts on `/gnap-api` are bound to this cookie as `/authn-api`'s
  // are. A person types a user code on a device that may never have been
  // here; the approval page is where a start link lands.
  '/gnap/code',
  '/gnap/approve',
  // AND THE SIGN-OUT (#577): `/logout` answers a shell whose act is bound
  // to this cookie as the screen's are. A browser holding a session already
  // has one; this mints one only where `?username=` names somebody (a
  // development test control) for a browser that holds none.
  '/logout'
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
  '/portal/signals/receive',
  // THE SIGNED-OUT DOCUMENT (#577) is the end of a sign-out: the browser
  // whose session it ended is not arriving, and a fresh cookie minted on
  // the page that says it is signed out would be a session it never asked
  // for.
  '/logout/signed-out'
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
// The account sets' clean-up job (#561).
const ACCOUNT_SET_EXPIRY_JOB = 'authn.account-set-expiry';

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

// A claim that REJECTS (rather than answering) is asked again this many times
// in all, the pause growing by this much each time (#242). See
// sessionEndOnce().
const SESSION_END_CLAIM_ATTEMPTS = 3;
const SESSION_END_CLAIM_RETRY_MS = 250;

// Session ends waiting on that claim in this process (#232).
let endReportsPending = 0;

// CAEP section 2's four words for who ended a session (#242, initiatorOf()).
const INITIATING_ENTITIES = ['admin', 'user', 'policy', 'system'];

// How many events a session keeps. A `max_age=0` client re-authenticates on
// every request and a list that grew without bound would be a persisted row
// that grew without bound. The FIRST event is always kept — it is how the
// session began — and the most recent ones after it; `eventsDropped` says how
// many went, so a reader never mistakes a trimmed list for a whole one.
/**
 * How many authentication events a session keeps: the first, and the most
 * recent after it.
 */
const MAX_SESSION_EVENTS = 20;

// The screen itself. Unchanged from the one that used to be rendered inside the
// authorization endpoint, in everything a person or a test can see: the same
// element ids (`username`, `password`, `kc-login`, `kc-cancel`), the same
// Keycloak-shaped vocabulary, the same statement that no password is checked
// — drawn in development mode only (`tests/passkey_first_use_product.js`).
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
// THE TWO STYLESHEETS LIVE IN `common/web_card_css.ts` SINCE #570, a `web_`
// module, so the static public surfaces of #569 are drawn with the same card
// a server-drawn page here carries inline — served once, as
// `/web/card.css` (`common/public_assets.ts`), rather than copied.
/**
 * The language chooser's stylesheet (#539): `WebCardCss.CHOOSER_CSS`.
 */
const CHOOSER_CSS = WebCardCss.CHOOSER_CSS;

/**
 * The stylesheet of the sign-in screen and the federation chooser, shared with
 * the consent screen: `WebCardCss.CARD_CSS`.
 */
const CARD_CSS = WebCardCss.CARD_CSS;

const PENDING_ID_QUERY = vz.object({
  authn: vt.opt(vt.base64url)
});

// Is a second factor required of this person BECAUSE they are an
// administrator (#246)? Such a requirement is never answered by a remembered
// browser (#265).
function requirementForAdministrator(credentials: any, username: string) {
  helpers.log.debug("Entering requirementForAdministrator().");
  const requirement = credentials.mfaRequirementFor(username) || {};
  helpers.log.debug("Leaving requirementForAdministrator().");
  return !!(requirement.byAdministrator || requirement.offered);
}

// THE SIGN-IN SCREEN'S FORM IS GONE (#571): its fields are the bodies of
// `/authn-api`'s operations, declared and checked in `authn/authn_api.ts`,
// which hands `screenAct()` the object this module's handler used to read.

const PASSWORD_CHANGE_QUERY = vz.object({
  change: vt.opt(vt.base64url)
});

// The chooser's form (#539): a language tag and the local path to return to.
// `common/page_locale.ts` holds the return to a local path; the tag is
// checked against the catalogs.
const LANGUAGE_FORM = vz.object({
  lang: vz.string().max(64).optional(),
  return: vz.string().max(2048).optional()
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
//
// SINCE #572 THE CEREMONY RUNS IN THE SIGN-IN SURFACE'S BUNDLE
// (`web_authn.ts` over `common/web_webauthn.ts`), armed by `POST
// /authn-api/mfa/{id}/webauthn/options` and answered to `POST
// /authn-api/mfa/{id}/webauthn`; `/authn/webauthn.js`, the script this page
// loaded, is no longer served, since nothing draws a page that loads it.

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
  // Kept on the window as well (#571): the sign-in screen is drawn in the
  // browser, and a field drawn again after this ran would be empty.
  '    .then(function (result) { field.value = result.visitorId;',
  '      window.stsDeviceFingerprint = result.visitorId; })',
  '    .catch(function () { field.value = ""; });',
  '})();'
].join('\n');

// THE SECOND-FACTOR STEPS' PAGES (#572), by the name `/authn-api` gives
// each (`GET /authn-api/mfa/{id}?page=`).
const STEP_PAGES: Record<string, string> = {
  totp: TOTP_PATH,
  webauthn: WEBAUTHN_PATH,
  'backup-code': BACKUP_CODE_PATH,
  password: PASSWORD_FACTOR_PATH,
  setup: MFA_SETUP_PATH,
  'post-login': POST_LOGIN_PATH
};

const MFA_STEP_QUERY = vz.object({
  mfa: vt.opt(vt.base64url),
  // THE ONE PASSKEY A PERSON CHOSE (#534), where the passkey policy offers
  // them one by one: a credential id, base64url.
  key: vt.opt(vt.base64url)
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
  deviceRecognition: typeof deviceRecognition;
  // Remembered browsers (#265), found lazily: that library reaches the
  // keystore and the device register, which a process loading this file for
  // one of its helpers has no need of.
  browserDevices: () => any;
  // The sign-in screen's certificate door (#1051): `tls/tls_server.js`
  // where it is loaded already, or null. See `certificateDoor()`.
  certificateDoor: () => any;
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
  authnPolicy: typeof authnPolicy;
  passkeyPolicy: typeof passkeyPolicy;
  postLogin: typeof postLogin;
  webauthnAttestation: typeof webauthnAttestation;
  webauthnCeremonies: typeof webauthnCeremonies;
  totp: typeof totp;
}

/**
 * The authentication service: the sign-in screen, the second-factor steps, and
 * the sign-on session every protocol reads.
 *
 * It owns the session cookie and is the only place the session store is
 * written. A protocol module calls `beginAuthentication()`, redirects to the
 * path it returns, and finds the session with `sessionOf()` when the browser
 * comes back.
 */
class Authn {
  // The sign-in surface's bundle, once read (`signInBundle()`, #571).
  private bundleFile: any = null;

  /**
   * Builds the service over its dependencies.
   *
   * @param deps - the modules and helpers it uses
   */
  constructor(private readonly deps: AuthnDeps) {
    deps.log.debug("Entering Authn.constructor().");
    deps.log.debug("Leaving Authn.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies built from the real modules, as the composition
   * root passes them.
   *
   * @returns the dependency object
   */
  static defaultDeps(): AuthnDeps {
    helpers.log.debug("Entering Authn.defaultDeps().");
    helpers.log.debug("Leaving Authn.defaultDeps().");
    return {
      accountSignals: accountSignals,
      clientHello: clientHello,
      deviceRecognition: deviceRecognition,
      browserDevices: function browserDevices() {
        helpers.log.debug("Entering browserDevices().");
        helpers.log.debug("Leaving browserDevices().");
        return require('../common/browser_devices');
      },
      // ONLY WHERE IT IS LOADED ALREADY: `tls/tls_server.js` is a JavaScript
      // route module (#20), and requiring it from here would register its
      // `/tls*` views wherever this ran first and close a cycle (it requires
      // this module). In every process that serves the screen the
      // composition root has loaded it long before a request arrives; one
      // that has not offers no certificate.
      certificateDoor: function certificateDoor() {
        helpers.log.debug("Entering certificateDoor().");
        let door: any = null;
        try {
          const file = require.resolve('../tls/tls_server');
          door = require.cache[file] ? require.cache[file].exports : null;
        } catch (e) {
          helpers.log.debug("Caught in certificateDoor(): " +
                            ((e && e.message) || e));
          door = null;
        }
        helpers.log.debug("Leaving certificateDoor(). " +
                          (door ? 'Loaded.' : 'Not loaded.'));
        return door &&
          typeof door.screenCertificateHolder === 'function' ? door : null;
      },
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
      authnPolicy: authnPolicy,
      passkeyPolicy: passkeyPolicy,
      postLogin: postLogin,
      webauthnAttestation: webauthnAttestation,
      webauthnCeremonies: webauthnCeremonies,
      totp: totp
    };
  }

  // What loading this module did with its instance before #50's R2, now
  // done by the slot for whichever instance is installed: the audit log's
  // actor resolver.
  /**
   * Installs an instance's audit-log actor resolver, as loading this module did
   * before the composition root.
   *
   * @param instance - the installed instance
   */
  static wire(instance: Authn): void {
    helpers.log.debug("Entering Authn.wire().");
    audit.setActorResolver(instance.auditActorOf.bind(instance));
    // AND THE SESSION THE ACTOR ACTED AS (#561): with several accounts in
    // one browser the name alone does not say which session a row was.
    audit.setActorSessionResolver(
      instance.auditActorSessionOf.bind(instance));
    helpers.log.debug("Leaving Authn.wire().");
  }

  private secondsSetting(key, fallbackMs) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.secondsSetting().");
    const n = Number(config.value(key));
    log.debug("Leaving Authn.secondsSetting().");
    return (isFinite(n) && n > 0 ? Math.floor(n) * 1000 : fallbackMs);
  }

  /**
   * Returns the absolute session lifetime, `authn.sessionLifetimeS`, in
   * milliseconds.
   *
   * @returns the lifetime in milliseconds, one hour when the setting is unset
   */
  sessionLifetimeMs() {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionLifetimeMs().");
    log.debug("Leaving Authn.sessionLifetimeMs().");
    return this.secondsSetting('authn.sessionLifetimeS', SESSION_TTL_MS);
  }

  // ZERO IS THE DEFAULT AND MEANS NONE, so this is NOT `secondsSetting()`,
  // whose fallback would turn a deliberate zero into an hour.
  /**
   * Returns the session idle timeout, `authn.sessionIdleTimeoutS`, in
   * milliseconds.
   *
   * @returns the idle timeout in milliseconds, or 0 for none (the default)
   */
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
  /**
   * Says whether a session is over: the one answer for every reader, the sweep
   * and `/logout`'s list.
   *
   * An arrival session is exempt from the idle rule.
   *
   * @param session - the session row
   * @param nowMs - the instant to judge at, in milliseconds; now by default
   * @returns '' when live, 'expired' when the absolute expiry passed (or there
   *   is no session), 'idle' when unused past the idle timeout
   */
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
  /**
   * Writes a session changed in place back to the store so every node sees the
   * change.
   *
   * It never brings back a session another request ended; where the store holds
   * a different object for the id, the two are merged with
   * `mergeSessionRows()`.
   *
   * @param session - the changed session row
   * @returns true when the row was re-set, false when there is no session or it
   *   is gone
   */
  noteSessionChanged(session) {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.noteSessionChanged().");
    if (!session || !session.id) {
      log.debug("Leaving Authn.noteSessionChanged(). No session.");
      return false;
    }
    // A read error is not "the session is gone": the change is written so a
    // parent that only the index holds still records backsConsole.
    if (this.windowOn()) {
      const read = sessionWindow.get(realms.currentId(), session.id);
      if (!read.ok && read.error) {
        sessions.set(session.id, session);
        log.debug("Leaving Authn.noteSessionChanged(). Re-set.");
        return true;
      }
      if (!read.ok) {
        log.debug("Leaving Authn.noteSessionChanged(). The session is gone.");
        return false;
      }
      const held = sessions.get(session.id);
      if (!held) {
        sessions.set(session.id, session);
        log.debug("Leaving Authn.noteSessionChanged(). Re-set.");
        return true;
      }
      sessions.set(session.id, held === session
        ? session
        : this.mergeSessionRows(session, held));
      log.debug("Leaving Authn.noteSessionChanged(). Re-set.");
      return true;
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

  /**
   * Returns how long an interrupted request waits at the sign-in screen,
   * `authn.pendingTtlS`, in milliseconds.
   *
   * @returns the lifetime of a pending record in milliseconds
   */
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
  /**
   * Merges two nodes' copies of one session row.
   *
   * The copy further along wins the scalar fields, the clocks take the latest,
   * and the relying-party lists and events are unions.
   *
   * @param mine - this process's copy
   * @param theirs - the stored copy
   * @returns the merged row, or whichever copy exists when one is missing
   */
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
    // THE DEVICE BINDING (#725) is made once and never replaced, so a copy
    // that has one is ahead of a copy that has none whichever is the base,
    // and two copies of one binding keep the larger refresh count.
    if (other.dbsc && other.dbsc.jkt) {
      const mineBinding = base.dbsc && base.dbsc.jkt ? base.dbsc : null;
      out.dbsc = !mineBinding ? other.dbsc
        : mineBinding.id !== other.dbsc.id ? mineBinding
        : Number(other.dbsc.refreshes || 0) >
          Number(mineBinding.refreshes || 0) ? other.dbsc : mineBinding;
    } else if ((base.dbsc || other.dbsc) &&
               !(base.dbsc && base.dbsc.jkt) &&
               !(other.dbsc && other.dbsc.jkt)) {
      // NEITHER COPY IS BOUND (#743). A skip or an offer has no jkt, and
      // the assign above would keep only the further-along copy's dbsc.
      // The earliest offer starts the wait; a copy that recorded reasons
      // keeps them.
      const left = base.dbsc || {};
      const right = other.dbsc || {};
      const offered = [Number(left.offeredAt) || 0,
                       Number(right.offeredAt) || 0].filter(function (n) {
        return n > 0;
      });
      const leftSkipped = Array.isArray(left.skippedReasons) &&
        left.skippedReasons.length;
      const rightSkipped = Array.isArray(right.skippedReasons) &&
        right.skippedReasons.length;
      const skip = leftSkipped ? left : (rightSkipped ? right : null);
      out.dbsc = Object.assign({}, left, right);
      if (offered.length) {
        out.dbsc.offeredAt = Math.min.apply(null, offered);
      }
      if (skip) {
        out.dbsc.skippedReasons = skip.skippedReasons.slice();
        out.dbsc.skippedIds = Array.isArray(skip.skippedIds)
          ? skip.skippedIds.slice() : [];
      }
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
    // A stale copy that is further along must not clear a console child
    // the other copy already recorded, and an empty subjectId must not
    // wipe the one frozen at creation. Two different non-empty ids keep
    // the further-along copy's.
    out.backsConsole = !!(mine.backsConsole || theirs.backsConsole);
    const baseSub = base.subjectId ? String(base.subjectId) : '';
    const otherSub = other.subjectId ? String(other.subjectId) : '';
    if (baseSub && otherSub && baseSub !== otherSub) {
      out.subjectId = baseSub;
    } else {
      out.subjectId = baseSub || otherSub;
    }
    // THE ACCOUNT SET A SESSION JOINED (#561) is stamped once, like the
    // binding above, so a copy that has it is ahead of one that does not:
    // lost in a merge, the session's end could not find its set, and its
    // account would never move to remembered. Absent on both copies — every
    // row while `authn.multipleAccounts` is off — nothing is written.
    if (!out.accountSetId && other.accountSetId) {
      out.accountSetId = other.accountSetId;
    }
    log.debug("Leaving Authn.mergeSessionRows(). " +
              (mineAhead ? "Mine is ahead." : "The stored copy is ahead."));
    return out;
  }

  /**
   * Returns how long a pending second-factor step lives, `authn.mfaStepTtlS`,
   * in milliseconds.
   *
   * @returns the step lifetime in milliseconds
   */
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
  /**
   * Parses a request's Cookie header.
   *
   * @param req - the request
   * @returns a map of cookie name to decoded value
   */
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
    const { stsCrypto, log } = this.deps;
    log.debug("Entering Authn.handleHashOf().");
    log.debug("Leaving Authn.handleHashOf().");
    return stsCrypto.digest('sha256', String(handle), 'base64url');
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
  //
  // THE SIGN-ON COOKIE CARRIES `authn.cookieDomain` WHEN IT IS SET (#472,
  // rcbj's D3), so that the applications reading it may sit on listeners with
  // different host names under one domain; a hosted surface's own cookie
  // (the portal's, the console's until #446) is read by that surface alone
  // and stays host-only. The clear below carries the same Domain, or it
  // would clear nothing.
  private sessionCookieLine(name, value) {
    const { log, config, helpers } = this.deps;
    log.debug("Entering Authn.sessionCookieLine(). name=" + name);
    log.debug("Leaving Authn.sessionCookieLine().");
    return String(name) + '=' + value + '; Path=/; HttpOnly; SameSite=Lax' +
           (String(name) === SESSION_COOKIE
             ? helpers.cookieDomainAttribute() : '') +
           (config.value('global.https') ? '; Secure' : '');
  }

  // Hot path: every session read. No Entering/Leaving pair — one would
  // drown the log. True for explicit on and for auto, and only while
  // minted persistence, one cell, and a digest key all hold.
  private windowOn(): boolean {
    return sessionWindow.active();
  }

  // A session read failed. The code is recorded and is not in the body.
  // The cookie stays; no replacement arrival is minted.
  private refuseUnread(res): boolean {
    const { errorCodes, log } = this.deps;
    log.debug("Entering Authn.refuseUnread().");
    if (res && !res.headersSent && typeof res.status === 'function') {
      errorCodes.mark(res, 'STS-AUTHN-0338');
      res.setHeader('Retry-After', '5');
      res.setHeader('Cache-Control', 'no-store');
      res.status(503).json({
        error: 'unavailable',
        error_description: 'The session store could not be read. Try again.'
      });
    } else {
      errorCodes.mark(res, 'STS-AUTHN-0338');
    }
    log.debug("Leaving Authn.refuseUnread().");
    return true;
  }

  // The session a request's cookie names, IF the cookie also carries that
  // session's current handle. `{ id, session }`, `{ error: true, id }`, or
  // null. A read error is not absence and does not clear the cookie.
  // `store` is a realm's partition where the caller is reading a named one;
  // the ambient partition otherwise. It EXPIRES NOTHING: the callers that
  // sweep what they find
  // (`sessionOf()`, `relyingPartySessionOf()`, `consoleSession()`) still do,
  // and an observer that ended sessions while reporting on them would be
  // changing the thing it describes.
  /**
   * Finds the session a request's cookie names, if the cookie also carries that
   * session's current handle.
   *
   * It expires nothing; the callers that sweep what they find still do.
   *
   * @param req - the request
   * @param cookieName - the cookie to read; the sign-on cookie by default
   * @param store - a realm's partition to look in; the ambient one by default
   * @param realmId - the realm the window reads when it is on
   * @returns `{ id, session }`, `{ error: true, id }`, or null
   */
  cookieSession(req, cookieName, store?, realmId?) {
    const { stsCrypto, log, realms } = this.deps;
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
    let session = null;
    if (this.windowOn()) {
      const read = sessionWindow.get(realmId || realms.currentId(), id);
      if (!read.ok && read.error) {
        log.debug("Leaving Authn.cookieSession(). The session could not " +
                  "be read.");
        return { error: true, id: id };
      }
      session = read.ok ? read.session : null;
    } else {
      session = (store || sessions).get(id);
    }
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

  /**
   * Returns the signed-in session a request's sign-on cookie names, in the
   * ambient realm.
   *
   * An expired or idle session is ended and swept on the way past, as is one
   * whose account is disabled or deleted; an unauthenticated (arrival) session
   * is never returned.
   *
   * @param req - the request
   * @param ignoreBinding - true to hand out a device-bound session without
   *   its bound cookie, which only `device_bound_sessions.ts`'s two endpoints
   *   pass (#725)
   * @returns the session row, or null
   */
  sessionOf(req, ignoreBinding?) {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionOf().");
    // -----------------------------------------------------------------------
    // SEVERAL ACCOUNTS IN ONE BROWSER (#561): WHICH SESSION, ASKED FIRST.
    //
    // Off — `authn.multipleAccounts` is ON by default since 2026-10-20 —
    // nothing below this block changes and the cookie alone decides, as it
    // always did. On, `resolveAccount()` answers from the browser's account
    // set in the order the plan's section 2 gives: a selection ticket spent on this
    // request, then a protocol hint (`hintAccount()`), then the only live
    // session; with several live and nothing to choose by it answers
    // nobody, and `accountChoiceNeeded()` says why — so every protocol that
    // sends a person to `beginAuthentication()` reaches the picker with no
    // change of its own. A browser with no set, or a set with no live
    // session, falls through to the cookie, exactly as before. The session
    // it names is then held to every rule below, as the cookie's is.
    // -----------------------------------------------------------------------
    if (AccountSets.enabled()) {
      const resolved = this.resolveAccount(req, true);
      if (!resolved.fallback) {
        if (!resolved.sid) {
          log.debug("Leaving Authn.sessionOf(). Several accounts and " +
                    "nothing chooses one (" + resolved.reason + ").");
          return null;
        }
        // The account set's choice meets the binding gate (#725) as the
        // cookie's session does: a bound session chosen here is honoured
        // only beside ITS OWN bound cookie, so a set whose handle was
        // copied cannot reach past a key it does not hold.
        const chosen = this.honouredSession(req, resolved.sid,
                                            this.accountSessionRead(
                                              resolved.sid).session,
                                            ignoreBinding);
        log.debug("Leaving Authn.sessionOf(). The account set's choice (" +
                  resolved.how + ").");
        return chosen;
      }
    }
    const found = this.cookieSession(req, SESSION_COOKIE);
    if (!found || found.error) {
      log.debug("Leaving Authn.sessionOf(). No session cookie naming a " +
                "session this server holds, with its current handle.");
      return null;
    }
    const session = this.honouredSession(req, found.id, found.session,
                                         ignoreBinding);
    log.debug("Leaving Authn.sessionOf().");
    return session;
  }

  // What `sessionOf()` holds a session to once it knows which one: ended
  // or idle, an arrival nobody chose, a disabled or deleted account — each
  // swept on the way past — and otherwise the session, its use noted. Split
  // out for #561 so that the cookie's session and the account set's choice
  // meet exactly the same rules; the body is `sessionOf()`'s as it was —
  // `ignoreBinding` included (#725), which the merge with #561 has to carry
  // into here, because the binding gate is one of those rules.
  private honouredSession(req, id, session, ignoreBinding?) {
    const { log } = this.deps;
    log.debug("Entering Authn.honouredSession(). sid=" + id);
    if (!session) {
      log.debug("Leaving Authn.honouredSession(). No such session.");
      return null;
    }
    const ended = this.sessionEnded(session);
    if (ended) {
      // Through expireSession() and not a bare delete: this is a session ENDING
      // and it owes the same audit row and the same CAEP event every other way
      // of ending one writes. See that function's header.
      this.expireSession(sessions.realmMap(), id, session, 'a request that ' +
                                                           'presented it',
                         ended);
      log.debug("Leaving Authn.honouredSession(). The session had " +
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
      log.debug("Leaving Authn.honouredSession(). An anonymous session " +
                "nobody has " +
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
      this.dropSession(id, 'an administrator disabling the account',
                       false, req, 'admin');
      log.debug("Leaving Authn.honouredSession(). The account is " +
                "disabled; the " +
                "session was ended.");
      return null;
    }
    // A SESSION WHOSE PERSON WAS DELETED IS OVER (#241, 2026-09-26). Deleting
    // a person ends every session at once, the way disabling does (the
    // directory hands the delete to `common/account_state.ts`); this is the
    // catch-up half, for a session that act could not reach — above all a
    // delete made on ANOTHER node, which reaches this one as a replicated
    // entry going away and nothing else. Until #241 a missing entry read as
    // "not disabled", so a deleted person's browser went on signing in to
    // every relying party until the session ran out.
    if (this.sessionAccountGone(session)) {
      this.dropSession(id, 'the deletion of the account', false, req,
                       'admin');
      log.debug("Leaving Authn.honouredSession(). The account was " +
                "deleted; the " +
                "session was ended.");
      return null;
    }
    // A SESSION BOUND TO A BROWSER KEY NEEDS ITS BOUND COOKIE (#725). Not
    // honoured without one, and NOT ended: the browser that holds the key
    // renews the cookie before it sends a request, so a request without it
    // is a copied `sts_session` or a skipped refresh, and the person's
    // session stays theirs. An unbound session, and every session while
    // `authn.deviceBoundSessions` is off, passes as it always did.
    // A browser that declines or fails registration says so on
    // Secure-Session-Skipped (#743). Recorded on the session this request
    // presents, including one read with ignoreBinding so a refresh can
    // finish. A well-formed skip is not a failure and does not end the
    // session; a malformed one is recorded and the request goes on.
    deviceBound.noteSkipped(session, req);
    if (ignoreBinding !== true && !deviceBound.honours(session, req)) {
      log.debug("Leaving Authn.honouredSession(). A device-bound session " +
                "without its bound cookie.");
      return null;
    }
    this.noteSessionUsed(sessions.realmMap(), id, session);
    this.noticeRiskDrift(session, req);
    log.debug("Leaving Authn.honouredSession(). Signed in as " +
              session.user.username + ".");
    return session;
  }

  // ===========================================================================
  // SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER (#561).
  //
  // `authn/account_sets.ts` holds the list — which sessions one browser
  // signed in to, which accounts signed out there — and the selection
  // tickets. What follows is what this module does with it: which session a
  // request acts as (`resolveAccount()`, read by `sessionOf()`), the hint a
  // protocol passes (`hintAccount()`), why no session was answered
  // (`accountChoiceNeeded()`), the ticket a flow resumes on, the enrolment
  // of a session that just started, the move to "remembered" of one that
  // ended, and the picker's views and acts. Every one of them is a no-op
  // with `authn.multipleAccounts` off, which is the default, and
  // `authn/CLAUDE.md`, *Several signed-in accounts in one browser*, argues
  // the design.
  // ===========================================================================

  // The browser's account set: the one this request created or rotated, or
  // the one its cookie names. Null when it has none, or when reading it
  // threw — which marks the request (`stsAccountSetUnread`), because a set
  // that could not be read is not a browser with none.
  private accountSetOf(req) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.accountSetOf().");
    if (!req) {
      log.debug("Leaving Authn.accountSetOf(). No request.");
      return null;
    }
    try {
      const row = req.stsAccountSetId
        ? AccountSets.byId(req.stsAccountSetId)
        : AccountSets.setOf(this.cookiesOf(req));
      log.debug("Leaving Authn.accountSetOf(). " + (row ? row.id : 'None.'));
      return row;
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0344') + 'authn: a browser\'s ' +
                'account set could not be read: ' + ((e && e.message) || e));
      // NOT ABSENCE (#350's rule, rcbj's decision 3 on #561): the request
      // remembers that its set could not be read, so `resolveAccount()`
      // answers nobody rather than the cookie's account, no set is made
      // around the cookie in its place, and the picker answers 503.
      req.stsAccountSetUnread = true;
      log.debug("Leaving Authn.accountSetOf(). Threw.");
      return null;
    }
  }

  // Whether a session may be in an account set at all: a browser's own
  // sign-in, not an arrival nobody chose, not the anonymous principal, not a
  // hosted surface's relying-party row and not a keyed API caller.
  private accountEligible(session) {
    const { log } = this.deps;
    log.debug("Entering Authn.accountEligible().");
    const ok = !!(session && session.user && session.chosen !== false &&
                  session.authenticated !== false && !session.rpSurface &&
                  !session.credentialKey);
    log.debug("Leaving Authn.accountEligible(). " + ok);
    return ok;
  }

  // Whether the session a set lists is live, with no side effects: the
  // store holds it, it is eligible, and neither clock has run out. A set
  // lists sids and never decides this itself (the plan's section 1). The
  // session chosen from the list is then held to `honouredSession()`, which
  // also asks about a disabled or deleted account.
  private accountSessionLive(sid) {
    const { log } = this.deps;
    log.debug("Entering Authn.accountSessionLive().");
    const session = this.accountSessionRead(sid).session;
    const live = !!(session && this.accountEligible(session) &&
                    !this.sessionEnded(session));
    log.debug("Leaving Authn.accountSessionLive(). " + live);
    return live;
  }

  // ---------------------------------------------------------------------------
  // THE SESSION A SET LISTS, READ THE WAY #350'S READERS READ ONE. With
  // `authn.sessionWindow` on (and `auto` turns it on whenever minted
  // persistence is) the realm map holds only the window's resident rows, so
  // a set member evicted from it is NOT in `sessions.get()` and is still
  // live: reading the map would have made the expiry job move every
  // non-resident account to remembered, and the picker forget it. So the
  // window when it is on, the map when it is off, as `sessionById()` reads.
  //
  // `{ session }`, null where the store holds none, or `{ session: null,
  // error: true }` where the read FAILED — which is not absence (#350): a
  // caller that would end, forget or substitute on absence keeps the member
  // instead (`accountSessionKept()`), and `resolveAccount()` answers nobody
  // rather than choosing among the members it could read.
  // ---------------------------------------------------------------------------
  private accountSessionRead(sid): { session: any; error?: boolean } {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.accountSessionRead().");
    const key = String(sid || '');
    if (!key) {
      log.debug("Leaving Authn.accountSessionRead(). No sid.");
      return { session: null };
    }
    if (this.windowOn()) {
      const read = sessionWindow.get(realms.currentId(), key);
      if (!read.ok && read.error) {
        log.debug("Leaving Authn.accountSessionRead(). Unread.");
        return { session: null, error: true };
      }
      log.debug("Leaving Authn.accountSessionRead(). Through the window.");
      return { session: read.ok ? read.session : null };
    }
    log.debug("Leaving Authn.accountSessionRead().");
    return { session: sessions.get(key) || null };
  }

  // Whether a set should KEEP listing a session: it is live, or its read
  // failed and nothing can be said about it. What the prune, the expiry job
  // and the full-set count ask, so that a store that could not answer for a
  // moment never signs an account out of its browser's set (#350's rule that
  // a failed read is not absence).
  private accountSessionKept(sid) {
    const { log } = this.deps;
    log.debug("Entering Authn.accountSessionKept().");
    const kept = this.accountSessionLive(sid) ||
                 !!this.accountSessionRead(sid).error;
    log.debug("Leaving Authn.accountSessionKept(). " + kept);
    return kept;
  }

  // What a set remembers of a session's account: its subject, its name and
  // the name to show. Never the sid, which the set keys it by.
  private accountOf(session) {
    const { log } = this.deps;
    log.debug("Entering Authn.accountOf().");
    const user = (session && session.user) || {};
    log.debug("Leaving Authn.accountOf().");
    return { sub: String(user.sub || ''),
             username: String(user.username || ''),
             displayName: String(user.name || user.username || '') };
  }

  // A session's own set, stamped on the row so that its end can find the
  // set by key (`accountSessionEnded()`) without a scan.
  private stampAccountSet(sid, session, setId) {
    const { log } = this.deps;
    log.debug("Entering Authn.stampAccountSet().");
    if (session && session.accountSetId !== setId) {
      session.accountSetId = setId;
      sessions.set(String(sid), session);
    }
    log.debug("Leaving Authn.stampAccountSet().");
  }

  // ---------------------------------------------------------------------------
  // THE BROWSER'S SET, MADE AROUND ITS SESSION WHERE IT HAS NONE (the plan's
  // D12). Turning the setting on ends nothing and asks nobody to sign in
  // again: the first request that needs the set and carries a live
  // `sts_session` and no `sts_accounts` makes the set around that session,
  // which becomes its first account. `create` false (the audit actor, an
  // observer) only reads. The cookie goes on the request's own response
  // (`req.res`), and a response already sent makes nothing — a set the
  // browser was never told about would be a row nothing could reach.
  // ---------------------------------------------------------------------------
  private ensureAccountSet(req, create) {
    const { log, audit, stats } = this.deps;
    log.debug("Entering Authn.ensureAccountSet().");
    const have = this.accountSetOf(req);
    if (have || !create || !req || req.stsAccountSetUnread) {
      log.debug("Leaving Authn.ensureAccountSet(). " +
                (have ? 'It has one.' : 'None, and none made.'));
      return have;
    }
    const found = this.cookieSession(req, SESSION_COOKIE);
    const res = req.res;
    if (!found || !this.accountEligible(found.session) ||
        !this.accountSessionLive(found.id) || !res || res.headersSent ||
        typeof res.append !== 'function') {
      log.debug("Leaving Authn.ensureAccountSet(). Nothing to make it " +
                "around.");
      return null;
    }
    const row = AccountSets.fresh();
    AccountSets.addSession(row, found.id, this.accountOf(found.session));
    const value = AccountSets.rotate(row);
    AccountSets.save(row);
    AccountSets.writeCookie(res, value);
    req.stsAccountSetId = row.id;
    this.stampAccountSet(found.id, found.session, row.id);
    stats.recordAccountChoice('added');
    audit.audit({
      action: 'account.add', actor: String(found.session.user.username || ''),
      protocol: 'Authentication', channel: 'http', target: found.id,
      summary: 'the browser\'s session for ' + found.session.user.username +
               ' became the first account of a new account set ' + row.id,
      detail: { accountSet: row.id, sessionId: found.id,
                sub: String(found.session.user.sub || ''), adopted: true }
    });
    log.debug("Leaving Authn.ensureAccountSet(). Made " + row.id + ".");
    return row;
  }

  // ---------------------------------------------------------------------------
  // WHICH SESSION A REQUEST ACTS AS, WITH SEVERAL IN THE BROWSER (the plan's
  // section 2), in this order:
  //
  //   1. a selection ticket spent on this request (`spendAccountTicket()`
  //      left its sid on `req.stsAccountSelection`);
  //   2. a protocol hint (`hintAccount()`): a sid, a subject, a login name;
  //      a hint that names no live session here answers NOBODY
  //      (`hint-unmatched`) — never another account in its place;
  //   3. the only live session;
  //   4. nobody (`ambiguous`).
  //
  // `{ fallback: true }` where the browser has no set or no live session in
  // it: the caller reads the cookie, as with the setting off. Otherwise
  // `{ sid, how }` or `{ sid: '', reason, live, hint }`. No side effects but
  // the D12 set (`create`).
  // ---------------------------------------------------------------------------
  private resolveAccount(req, create) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.resolveAccount().");
    const row = this.ensureAccountSet(req, create);
    if (!row && req && req.stsAccountSetUnread) {
      // The set could not be read (STS-AUTHN-0344): nobody, as for a member
      // below — the cookie's account could be the one this browser did not
      // choose.
      log.debug("Leaving Authn.resolveAccount(). The set could not be read.");
      return { sid: '', reason: 'unread', row: null, live: 0 };
    }
    if (!row && req && req.stsAccountSelectionEnded) {
      // A ticket that chose a session this browser cannot present (below,
      // and `spendAccountTicket()`): nobody, not the cookie's account.
      log.debug("Leaving Authn.resolveAccount(). No set, and a ticket that " +
                "chose nobody here.");
      return { sid: '', reason: 'hint-unmatched', row: null, live: 0,
               hint: String(req.stsAccountSelectionEnded.username || '') };
    }
    if (!row) {
      log.debug("Leaving Authn.resolveAccount(). No set.");
      return { fallback: true };
    }
    // A MEMBER WHOSE READ FAILED (#350) is not absent, so choosing among
    // the others — "the only live one" — could act as the wrong person.
    // Nobody, then: the request is sent to sign in, never substituted.
    const unread = Object.keys(row.sessions || {}).some(function (sid) {
      return !!self.accountSessionRead(sid).error;
    });
    if (unread) {
      log.debug("Leaving Authn.resolveAccount(). A member could not be " +
                "read.");
      return { sid: '', reason: 'unread', row: row, live: 0 };
    }
    const live = Object.keys(row.sessions || {}).filter(function (sid) {
      return self.accountSessionLive(sid);
    });
    if (!live.length && req && req.stsAccountSelectionEnded) {
      log.debug("Leaving Authn.resolveAccount(). No live session, and a " +
                "ticket that chose nobody here.");
      return { sid: '', reason: 'hint-unmatched', row: row, live: 0,
               hint: String(req.stsAccountSelectionEnded.username || '') };
    }
    if (!live.length) {
      log.debug("Leaving Authn.resolveAccount(). No live session in it.");
      return { fallback: true, row: row };
    }
    const selected = String((req && req.stsAccountSelection) || '');
    if (selected && live.indexOf(selected) >= 0) {
      log.debug("Leaving Authn.resolveAccount(). The ticket's.");
      return { sid: selected, how: 'ticket', row: row, live: live.length };
    }
    // THE TICKET'S SESSION ENDED IN FLIGHT (#731, `spendAccountTicket()`):
    // nobody, never another account in its place — before the hint and the
    // only-live rule, either of which would otherwise answer somebody else.
    // The same account signed in again meanwhile is that account's
    // session, and is what was chosen.
    const ended = req && req.stsAccountSelectionEnded;
    const again = ended && ended.username
      ? this.matchAccountHint(live, { loginHint: ended.username }) : '';
    if (again) {
      log.debug("Leaving Authn.resolveAccount(). The ticket's account, " +
                "signed in again.");
      return { sid: again, how: 'ticket', row: row, live: live.length };
    }
    if (ended) {
      log.debug("Leaving Authn.resolveAccount(). The ticket's session " +
                "ended.");
      return { sid: '', reason: 'hint-unmatched', row: row,
               live: live.length, hint: String(ended.username || '') };
    }
    const hint = req && req.stsAccountHint;
    const match = hint ? this.matchAccountHint(live, hint) : '';
    if (hint && (match || !hint.soft)) {
      log.debug("Leaving Authn.resolveAccount(). " +
                (match ? 'The hint\'s.' : 'The hint names nobody here.'));
      return match
        ? { sid: match, how: 'hint', row: row, live: live.length }
        : { sid: '', reason: 'hint-unmatched', row: row, live: live.length,
            hint: String(hint.loginHint || '') };
    }
    // A SOFT hint naming nobody here is no hint (GNAP's `user`, whose
    // naming somebody other than the person at the browser has a meaning
    // of its own — `hintAccount()`'s header).
    if (live.length === 1) {
      log.debug("Leaving Authn.resolveAccount(). The only one.");
      return { sid: live[0], how: 'only', row: row, live: 1 };
    }
    log.debug("Leaving Authn.resolveAccount(). Ambiguous: " + live.length +
              " live.");
    return { sid: '', reason: 'ambiguous', row: row, live: live.length };
  }

  // The live session a hint names: its sid, then its subject, then its login
  // name or e-mail address (or the subject that name resolves to), or ''.
  private matchAccountHint(live, hint) {
    const { log, helpers } = this.deps;
    const self = this;
    log.debug("Entering Authn.matchAccountHint().");
    if (hint.sid && live.indexOf(String(hint.sid)) >= 0) {
      log.debug("Leaving Authn.matchAccountHint(). By sid.");
      return String(hint.sid);
    }
    const users = live.map(function (sid) {
      return { sid: sid,
               user: (self.accountSessionRead(sid).session || {}).user ||
                     {} };
    });
    const bySub = hint.sub ? users.filter(function (one) {
      return String(one.user.sub || '') === String(hint.sub);
    })[0] : null;
    if (bySub) {
      log.debug("Leaving Authn.matchAccountHint(). By subject.");
      return bySub.sid;
    }
    const name = String(hint.loginHint || '').trim().toLowerCase();
    if (name) {
      let subject = '';
      try {
        subject = String(helpers.subjectForName(hint.loginHint) || '');
      } catch (e) {
        // A directory that cannot answer leaves the name to match by itself.
        log.debug("Caught in Authn.matchAccountHint(): " +
                  ((e && e.message) || e));
        subject = '';
      }
      const byName = users.filter(function (one) {
        return String(one.user.username || '').toLowerCase() === name ||
          String(one.user.email || '').toLowerCase() === name ||
          (!!subject && String(one.user.sub || '') === subject);
      })[0];
      if (byName) {
        log.debug("Leaving Authn.matchAccountHint(). By name.");
        return byName.sid;
      }
    }
    log.debug("Leaving Authn.matchAccountHint(). None.");
    return '';
  }

  /**
   * Says why `sessionOf()` answered nobody for a browser holding several
   * accounts (#561), or null where it did not.
   *
   * `ambiguous`: more than one live account and nothing in this request
   * chose one — the account picker is the answer, or OpenID Connect's
   * `account_selection_required` under `prompt=none`. `hint-unmatched`: a
   * protocol hint named an account with no live session in this browser —
   * the sign-in screen is the answer, with the hint's name filled in. Null
   * with `authn.multipleAccounts` off.
   *
   * @param req - the request
   * @returns `{ reason, accounts, hint }`, or null
   */
  accountChoiceNeeded(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.accountChoiceNeeded().");
    if (!AccountSets.enabled() || !req) {
      log.debug("Leaving Authn.accountChoiceNeeded(). Off.");
      return null;
    }
    const resolved = this.resolveAccount(req, true);
    if (resolved.fallback || resolved.sid) {
      log.debug("Leaving Authn.accountChoiceNeeded(). Resolved.");
      return null;
    }
    log.debug("Leaving Authn.accountChoiceNeeded(). " + resolved.reason);
    return { reason: resolved.reason, accounts: resolved.live,
             hint: resolved.hint || '' };
  }

  /**
   * Passes a protocol's hint about which account a request is for (#561):
   * OpenID Connect's `login_hint` and the `sub` and `sid` of a verified
   * `id_token_hint`, a SAML `<Subject>`'s name, a GNAP subject hint.
   *
   * Call it BEFORE `sessionOf()`. It changes nothing with
   * `authn.multipleAccounts` off; on, a hint naming a live account in the
   * browser's set chooses it silently, and one naming none makes
   * `sessionOf()` answer nobody (never another account) and
   * `accountChoiceNeeded()` answer `hint-unmatched`. Empty members are
   * ignored; a hint with none is no hint.
   *
   * `soft` (#561 step 3, for GNAP) makes a hint that names nobody live
   * here no hint at all rather than a choice of nobody: the request then
   * resolves as if it carried none. GNAP's `user` is that kind — a person
   * at the browser who is not the user the grant request named is a case
   * RFC 9635 and #432's owner approval give a meaning of their own — and so
   * is a session id a page recorded for its own later calls.
   *
   * @param req - the request
   * @param hint - `{ loginHint, sub, sid, soft }`; `username` is read as
   *   `loginHint`
   */
  hintAccount(req, hint) {
    const { log } = this.deps;
    log.debug("Entering Authn.hintAccount().");
    const h = hint || {};
    const loginHint = String(h.loginHint || h.username || '').slice(0, 512);
    const sub = String(h.sub || '').slice(0, 512);
    const sid = String(h.sid || '').slice(0, 128);
    if (req && (loginHint || sub || sid)) {
      req.stsAccountHint = { loginHint: loginHint, sub: sub, sid: sid,
                             soft: !!h.soft };
    }
    log.debug("Leaving Authn.hintAccount().");
  }

  // ---------------------------------------------------------------------------
  // A SELECTION TICKET ON THIS REQUEST (the plan's section 2, step 1),
  // taken off before any route reads the query and spent at once: a later
  // request carrying it finds nothing. It counts only where it was minted
  // for THIS browser's set, for THIS path, and names a session still live in
  // the set; anything else is ignored (STS-AUTHN-0346) and the request
  // resolves its account as if it had carried none. With the setting off
  // the request is not touched at all.
  // ---------------------------------------------------------------------------
  /**
   * Takes an account selection ticket off a request and spends it (#561);
   * the middleware every request passes. Exported for
   * `tests/multi_account_sessions.js`.
   *
   * @param req - the request
   */
  spendAccountTicket(req) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.spendAccountTicket().");
    if (!AccountSets.enabled()) {
      log.debug("Leaving Authn.spendAccountTicket(). Off.");
      return;
    }
    const ticket = AccountSets.stripTicket(req);
    if (!ticket) {
      log.debug("Leaving Authn.spendAccountTicket(). None.");
      return;
    }
    const row = AccountSets.spendTicket(ticket);
    const set = this.accountSetOf(req);
    const path = String(req.url || '').split('?')[0];
    // A BROWSER THAT PRESENTS NO SET AT ALL, BUT THE VERY SESSION THE TICKET
    // NAMES (2026-10-22, the full run). A client that keeps its sign-on
    // cookie and not `sts_accounts` — an API client, a relying party's own
    // HTTP stack, four of this repository's jobs — signed in, was handed a
    // ticket for the set the sign-in made, and returned without it; the
    // rule below for a set the request does not carry then chose nobody,
    // and it was sent to sign in again. That rule exists so a request never
    // acts as ANOTHER account (#561, rcbj's decision 1); a request whose own
    // sign-on cookie is the ticket's session is not another account, so the
    // ticket counts. A request presenting a different set still chooses
    // nobody.
    if (row && !set && !req.stsAccountSetUnread && row.path === path) {
      const presented = this.cookieSession(req, SESSION_COOKIE);
      if (presented && !presented.error &&
          presented.id === String(row.sid) &&
          this.accountSessionLive(row.sid)) {
        req.stsAccountSelection = row.sid;
        log.debug("Leaving Authn.spendAccountTicket(). Spent, on the " +
                  "session the browser presents and no set.");
        return;
      }
    }
    const why = !row ? 'it is unknown, spent or expired'
      : !set || set.id !== row.setId ? 'it was issued to another browser'
      : row.path !== path ? 'it was issued for another address'
      : !set.sessions[row.sid] || !this.accountSessionLive(row.sid)
        ? 'the session it names is no longer live in this browser'
        : '';
    if (why) {
      // A CHOICE WHOSE SESSION ENDED IN FLIGHT CHOOSES NOBODY (#731). The
      // ticket is this browser's, for this address, and names a session
      // that was signed out, expired or revoked between the choice and this
      // request. Ignoring it, as every other ticket here is ignored, let the
      // request resolve as if nothing had been chosen — and with one other
      // account live that is "the only live session", so a flow the person
      // resumed as alice went on as bob without a word
      // (`tests/multi_account_concurrency.js` 4). It is a hint naming
      // nobody here instead (`hint-unmatched`): the flow goes to sign in as
      // that account, its name filled in, as a `login_hint` for a signed-out
      // account does.
      const ended = !!(row && set && set.id === row.setId &&
                       row.path === path);
      if (ended) {
        req.stsAccountSelectionEnded = {
          username: String(row.username || ''), sid: String(row.sid) };
      }
      // A LIVE TICKET FOR THIS PATH FROM A SET THIS REQUEST DOES NOT CARRY
      // chooses nobody too (batch 10, with rcbj's decision 1): a set
      // rotated by one tab's choice while another tab's request was in
      // flight can leave a flow's ticket naming a set the browser no longer
      // presents. Falling through would answer "the only live session" of
      // the set it does present — another account. Nobody, then, with NO
      // name filled in: the ticket may as well be another browser's, and
      // its account's name is not this browser's to be shown.
      if (!ended && row && row.path === path) {
        req.stsAccountSelectionEnded = { username: '', sid: '' };
      }
      log.info(errorCodes.tag('STS-AUTHN-0346') + 'authn: an account ' +
               'selection ticket on ' + path + ' was ignored: ' + why +
               (ended ? '; the request acts as nobody, and the flow signs ' +
                        'in again as that account' : '') + '.');
      log.debug("Leaving Authn.spendAccountTicket(). Ignored.");
      return;
    }
    req.stsAccountSelection = row.sid;
    log.debug("Leaving Authn.spendAccountTicket(). Spent.");
  }

  // The address a finished sign-in returns to, with a ticket for the session
  // it started or re-authenticated where a set holds it (`res.locals`, set
  // by `enrolInAccountSet()`). Unchanged with the setting off, or where the
  // sign-in added nothing to a set.
  private ticketedReturn(res, record, target) {
    const { log } = this.deps;
    log.debug("Entering Authn.ticketedReturn().");
    const locals = (res && res.locals) || {};
    if (!AccountSets.enabled() || !locals.stsAccountSession ||
        !locals.stsAccountSet) {
      log.debug("Leaving Authn.ticketedReturn(). Unchanged.");
      return target;
    }
    const ticket = AccountSets.mintTicket(locals.stsAccountSet,
                                          locals.stsAccountSession,
                                          String(target).split('?')[0],
                                          (record && record.id) || '');
    log.debug("Leaving Authn.ticketedReturn().");
    return AccountSets.withTicket(target, ticket);
  }

  /**
   * Adds a selection ticket to an address a flow resumes on, for the
   * account a hint names in this browser's set (#561). The consent screen
   * calls it, so the authorization request it returns to acts as the
   * account that consented.
   *
   * Unchanged with `authn.multipleAccounts` off, or where the hint names no
   * live account here.
   *
   * @param req - the request
   * @param target - the address, a path on this service
   * @param hint - `{ loginHint, sub, sid }`, as `hintAccount()` takes
   * @returns the address, with `sts_account=` on it where one was minted
   */
  accountTicketFor(req, target, hint) {
    const { log } = this.deps;
    log.debug("Entering Authn.accountTicketFor().");
    if (!AccountSets.enabled() || !req) {
      log.debug("Leaving Authn.accountTicketFor(). Off.");
      return target;
    }
    const prior = req.stsAccountHint;
    this.hintAccount(req, hint);
    const resolved = this.resolveAccount(req, false);
    req.stsAccountHint = prior;
    if (resolved.fallback || !resolved.sid || !resolved.row) {
      log.debug("Leaving Authn.accountTicketFor(). Nobody to name.");
      return target;
    }
    const ticket = AccountSets.mintTicket(resolved.row.id, resolved.sid,
                                          String(target).split('?')[0], '');
    log.debug("Leaving Authn.accountTicketFor().");
    return AccountSets.withTicket(target, ticket);
  }

  // How many live sessions a browser holds for the cap: its set's, and the
  // default cookie's where that is live and not in the set yet (D12).
  private liveAccountCount(row, defaultFound) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.liveAccountCount().");
    let n = row ? Object.keys(row.sessions || {}).filter(function (sid) {
      return self.accountSessionKept(sid);
    }).length : 0;
    if (defaultFound && this.accountEligible(defaultFound.session) &&
        this.accountSessionLive(defaultFound.id) &&
        !(row && row.sessions && row.sessions[defaultFound.id])) {
      n++;
    }
    log.debug("Leaving Authn.liveAccountCount(). " + n);
    return n;
  }

  // A live session of the person signing in, in this browser's set: the
  // session a second sign-in as them re-authenticates (one live session per
  // subject per browser), or null.
  private accountSessionFor(row, username) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.accountSessionFor().");
    const sid = row ? Object.keys(row.sessions || {}).filter(function (one) {
      const session = self.accountSessionRead(one).session;
      return self.accountSessionLive(one) &&
        self.sameIdentity(session.user, username);
    })[0] : '';
    log.debug("Leaving Authn.accountSessionFor(). " + (sid ? 'One.' : 'None.'));
    return sid ? { id: sid, session: this.accountSessionRead(sid).session }
               : null;
  }

  // ---------------------------------------------------------------------------
  // A SESSION THAT STARTED (OR WAS RE-AUTHENTICATED) GOES INTO THE BROWSER'S
  // SET. The browser's previous default session goes in first where it is
  // live and not there yet (D12); sessions that ended meanwhile move to
  // remembered; a remembered entry for this account is replaced; the handle
  // rotates (a sign-in is a change of privilege) and the cookie is appended
  // AFTER the session cookie, which `setCookieHeader()` writes by
  // replacing. `res.locals` then names the session and the set, which is
  // what `returnToCaller()` mints the flow's ticket from.
  // ---------------------------------------------------------------------------
  private enrolInAccountSet(req, res, session, defaultFound) {
    const { log, audit, stats, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Authn.enrolInAccountSet(). sid=" + session.id);
    try {
      const row = this.accountSetOf(req) || AccountSets.fresh();
      if (defaultFound && defaultFound.id !== session.id &&
          this.accountEligible(defaultFound.session) &&
          this.accountSessionLive(defaultFound.id) &&
          !row.sessions[defaultFound.id]) {
        AccountSets.addSession(row, defaultFound.id,
                               this.accountOf(defaultFound.session));
        this.stampAccountSet(defaultFound.id, defaultFound.session, row.id);
      }
      AccountSets.prune(row, function (sid) {
        return sid === session.id || self.accountSessionKept(sid);
      });
      const added = !row.sessions[session.id];
      const done = AccountSets.addSession(row, session.id,
                                          this.accountOf(session));
      if (!done.ok) {
        // `startSessionHere()` refused a full set before the session was
        // made, so this is two sign-ins racing for the last place.
        log.warn(errorCodes.tag('STS-AUTHN-0340') + 'authn: session ' +
                 session.id + ' could not join its browser\'s account set, ' +
                 'which is full; it is the browser\'s session alone.');
        log.debug("Leaving Authn.enrolInAccountSet(). Full.");
        return;
      }
      const value = AccountSets.rotate(row);
      AccountSets.save(row);
      AccountSets.writeCookie(res, value);
      if (req) {
        req.stsAccountSetId = row.id;
      }
      this.stampAccountSet(session.id, session, row.id);
      if (res && res.locals) {
        res.locals.stsAccountSession = session.id;
        res.locals.stsAccountSet = row.id;
      }
      if (added) {
        stats.recordAccountChoice('added');
        audit.audit({
          action: 'account.add', actor: String(session.user.username || ''),
          protocol: session.via || 'Authentication', channel: 'http',
          target: session.id,
          summary: session.user.username + ' was added to account set ' +
                   row.id + ' (' + Object.keys(row.sessions).length +
                   ' signed in)',
          detail: { accountSet: row.id, sessionId: session.id,
                    sub: String(session.user.sub || ''),
                    signedIn: Object.keys(row.sessions).length,
                    droppedRemembered: done.dropped }
        });
      }
      log.debug("Leaving Authn.enrolInAccountSet(). " + row.id);
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0344') + 'authn: session ' +
                session.id + ' could not be put in its browser\'s account ' +
                'set: ' + ((e && e.message) || e));
      log.debug("Leaving Authn.enrolInAccountSet(). Threw.");
    }
  }

  // A session that ended — signed out, expired, evicted, ended by an
  // administrator — moves to its set's remembered accounts, found by the
  // set id stamped on it. Never throws: the session has ended whatever
  // happens to the list.
  private accountSessionEnded(session) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.accountSessionEnded().");
    if (!session || !session.accountSetId) {
      log.debug("Leaving Authn.accountSessionEnded(). In no set.");
      return;
    }
    try {
      const row = AccountSets.byId(session.accountSetId);
      if (row && AccountSets.endSession(row, session.id)) {
        AccountSets.save(row);
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0344') + 'authn: session ' +
                session.id + ' ended and could not be moved to its ' +
                'account set\'s remembered accounts: ' +
                ((e && e.message) || e));
    }
    log.debug("Leaving Authn.accountSessionEnded().");
  }

  // Makes a session the browser's default — the one `sts_session` names —
  // by minting it a fresh handle: the browser lost the old one when another
  // sign-in wrote the cookie, and the set is what proved it may have it.
  // Written by replacing, so before any cookie appended to `res`.
  private makeDefaultSession(res, session) {
    const { log } = this.deps;
    log.debug("Entering Authn.makeDefaultSession(). sid=" + session.id);
    // The OP browser state (#121) is KEPT: becoming the default is not a
    // sign-in, and a fresh state would tell every relying party of this
    // account "changed" (OpenID Connect Session Management, the plan's
    // section 7). Only the handle is new.
    const browserState = session.browserState;
    const value = this.mintSessionHandle(session);
    if (browserState) {
      session.browserState = browserState;
    }
    sessions.set(session.id, session);
    this.setCookieHeader(res, this.sessionCookieLine(SESSION_COOKIE, value));
    log.debug("Leaving Authn.makeDefaultSession().");
  }

  // The accounts a set holds, as the picker and `GET /authn-api/accounts`
  // show them: key, subject, names, state and times — never a sid or a
  // token. Live accounts first, in the order they signed in; then the
  // signed-out ones, the latest first.
  private accountRows(row, req) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.accountRows().");
    if (!row) {
      log.debug("Leaving Authn.accountRows(). No set.");
      return [];
    }
    const own = req ? this.cookieSession(req, SESSION_COOKIE) : null;
    const live = Object.keys(row.sessions || {}).filter(function (sid) {
      return self.accountSessionLive(sid);
    }).sort(function (a, b) {
      return (Number(row.sessions[a].addedAt) || 0) -
             (Number(row.sessions[b].addedAt) || 0);
    }).map(function (sid) {
      const session = self.accountSessionRead(sid).session;
      const entry = row.sessions[sid];
      const account = self.accountOf(session);
      return { key: AccountSets.keyOf(account), sub: account.sub,
               username: account.username,
               displayName: account.displayName || entry.displayName,
               state: 'signed-in',
               signedInAt: self.sessionStartedAt(session) || 0,
               authTime: Number(session.authTime) || 0,
               current: !!(own && own.id === sid) };
    });
    const remembered = Object.keys(row.remembered || {}).map(function (key) {
      const entry = row.remembered[key];
      return { key: key, sub: String(entry.sub || ''),
               username: String(entry.username || ''),
               displayName: String(entry.displayName || entry.username || ''),
               state: 'signed-out',
               signedOutAt: Number(entry.signedOutAt) || 0,
               current: false };
    }).sort(function (a, b) {
      return b.signedOutAt - a.signedOutAt;
    });
    log.debug("Leaving Authn.accountRows(). " + live.length + " live, " +
              remembered.length + " remembered.");
    return (live as any[]).concat(remembered);
  }

  // A browser's set brought up to date for a page: sessions that ended move
  // to remembered and old remembered accounts go, written back only where
  // something changed.
  private freshAccountSet(req) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.freshAccountSet().");
    const row = this.ensureAccountSet(req, true);
    if (row) {
      const done = AccountSets.prune(row, function (sid) {
        return self.accountSessionKept(sid);
      });
      if (done.ended || done.expired) {
        AccountSets.save(row);
      }
    }
    log.debug("Leaving Authn.freshAccountSet().");
    return row;
  }

  /**
   * The accounts this browser holds, for `GET /authn-api/accounts` (#561):
   * each account's key, subject, names, state (`signed-in` or
   * `signed-out`), times and whether it is the browser's default — never a
   * sid or a token.
   *
   * @param req - the request
   * @returns `{ enabled, accounts, max }`; with `authn.multipleAccounts`
   *   off, `{ enabled: false, accounts: [] }`
   */
  browserAccounts(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.browserAccounts().");
    if (!AccountSets.enabled()) {
      log.debug("Leaving Authn.browserAccounts(). Off.");
      return { enabled: false, accounts: [], max: 0 };
    }
    const row = this.freshAccountSet(req);
    log.debug("Leaving Authn.browserAccounts().");
    return { enabled: true, accounts: this.accountRows(row, req),
             max: AccountSets.maxAccounts() };
  }

  /**
   * The live sessions this browser's account set holds (#561), in the order
   * they joined it, with no side effects: for the OP browser state of
   * OpenID Connect Session Management, and for sign-out's account choice.
   *
   * @param req - the request
   * @returns the session rows; [] with `authn.multipleAccounts` off or for a
   *   browser with no set
   */
  accountSessionsOf(req) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.accountSessionsOf().");
    if (!AccountSets.enabled() || !req) {
      log.debug("Leaving Authn.accountSessionsOf(). Off.");
      return [];
    }
    const row = this.accountSetOf(req);
    const out = row ? Object.keys(row.sessions || {}).filter(function (sid) {
      return self.accountSessionLive(sid);
    }).sort(function (a, b) {
      return (Number(row.sessions[a].addedAt) || 0) -
             (Number(row.sessions[b].addedAt) || 0);
    }).map(function (sid) {
      return self.accountSessionRead(sid).session;
    }) : [];
    log.debug("Leaving Authn.accountSessionsOf(). " + out.length);
    return out;
  }

  /**
   * The signed-in session a device-binding request is about (#725 with
   * #561), chosen from every live session this browser's account set holds
   * — and its default cookie's, where that is not in the set yet — by what
   * the browser's own proof names (`pick`). The one picked is then held to
   * `honouredSession()`'s rules but the binding gate, which is what the
   * binding endpoints decide for themselves; the others are not touched, so
   * a refresh of one account is never a use of another. Null with
   * `authn.multipleAccounts` off, or for a browser with no set, where the
   * caller reads `sessionOf(req, true)` exactly as before.
   *
   * WHY NOT `sessionOf()`: a registration or a refresh names no account the
   * way a flow does — no ticket, no hint — so with two accounts signed in
   * `sessionOf()` answers nobody, and every second account's binding would
   * be refused. The challenge minted for one session at registration, and
   * the DBSC session identifier at refresh, name it instead.
   *
   * @param req - the request
   * @param pick - asked of each live session; the first it accepts is it
   * @returns `{ session, others }` — `others` true where the browser holds
   *   signed-in sessions and `pick` took none — or null
   */
  bindingSessionOf(req, pick) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.bindingSessionOf().");
    if (!AccountSets.enabled() || !req || typeof pick !== 'function') {
      log.debug("Leaving Authn.bindingSessionOf(). Off.");
      return null;
    }
    const row = this.accountSetOf(req);
    if (!row) {
      log.debug("Leaving Authn.bindingSessionOf(). No set.");
      return null;
    }
    const sids = Object.keys(row.sessions || {});
    const own = this.cookieSession(req, SESSION_COOKIE);
    if (own && !own.error && sids.indexOf(String(own.id)) < 0) {
      sids.push(String(own.id));
    }
    const live = sids.filter(function (sid) {
      return self.accountSessionLive(sid);
    });
    const sid = live.filter(function (one) {
      return !!pick(self.accountSessionRead(one).session);
    })[0];
    const session = sid
      ? this.honouredSession(req, sid, this.accountSessionRead(sid).session,
                             true)
      : null;
    log.debug("Leaving Authn.bindingSessionOf(). " +
              (session ? session.id : 'None of ' + live.length + '.'));
    return { session: session, others: !session && live.length > 0 };
  }

  /**
   * Says whether a request's `sts_session` cookie names a session (#725
   * with #561): a binding that ended clears the browser's default cookie
   * only where the cookie is that session's, never another account's.
   *
   * @param req - the request
   * @param sid - the session id
   * @returns true when the cookie names it
   */
  sessionCookieNames(req, sid) {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionCookieNames().");
    const own = req ? this.cookieSession(req, SESSION_COOKIE) : null;
    const names = !!(own && !own.error && String(own.id) === String(sid));
    log.debug("Leaving Authn.sessionCookieNames(). " + names);
    return names;
  }

  /**
   * The session id an audit row's actor acted as, resolved the way
   * `sessionOf()` resolves it, with no side effects (#561). '' with
   * `authn.multipleAccounts` off, so a row is then unchanged.
   *
   * @param req - the request
   * @returns the sid, or ''
   */
  auditActorSessionOf(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.auditActorSessionOf().");
    if (!AccountSets.enabled() || !req) {
      log.debug("Leaving Authn.auditActorSessionOf(). Off.");
      return '';
    }
    const resolved = this.resolveAccount(req, false);
    if (!resolved.fallback) {
      log.debug("Leaving Authn.auditActorSessionOf(). The set's.");
      return String(resolved.sid || '');
    }
    const found = this.cookieSession(req, SESSION_COOKIE);
    log.debug("Leaving Authn.auditActorSessionOf(). The cookie's.");
    return found ? String(found.id) : '';
  }

  /**
   * Records that a request could not tell which of several accounts it was
   * for (#561): the `account.ambiguous` audit row and its counter. The
   * picker records its own; `oauth2.ts` calls this where it answers
   * `account_selection_required`.
   *
   * @param req - the request
   * @param via - the protocol, for the row
   * @param answer - what was done about it, for the summary
   */
  noteAccountAmbiguous(req, via, answer) {
    const { log, audit, stats } = this.deps;
    log.debug("Entering Authn.noteAccountAmbiguous().");
    const row = this.accountSetOf(req);
    stats.recordAccountChoice('ambiguous');
    audit.audit({
      action: 'account.ambiguous', actor: '', protocol: via || '',
      channel: 'http', target: row ? row.id : '',
      summary: 'a request from a browser with several signed-in accounts ' +
               'named none of them; ' + String(answer || 'the account ' +
                                               'picker was shown'),
      detail: { accountSet: row ? row.id : '',
                signedIn: row ? Object.keys(row.sessions || {}).length : 0 }
    });
    log.debug("Leaving Authn.noteAccountAmbiguous().");
  }

  /**
   * The body of the scheduler job `authn.account-set-expiry` (#561): every
   * account set in the ambient realm pruned — sessions that ended move to
   * remembered, remembered accounts past `authn.rememberedAccountDays` are
   * dropped — and every set left empty deleted.
   *
   * @returns `{ sets, ended, expired, deleted }`
   */
  sweepAccountSets() {
    const { log, stats } = this.deps;
    const self = this;
    log.debug("Entering Authn.sweepAccountSets().");
    const done = AccountSets.sweep(function (sid) {
      return self.accountSessionKept(sid);
    });
    if (done.expired) {
      stats.recordAccountChoice('expired', done.expired);
    }
    log.debug("Leaving Authn.sweepAccountSets().");
    return done;
  }

  /**
   * One run of the account-set sweep: at most about a second of work, from
   * where the last run stopped (#784). The scheduler job's body.
   *
   * @returns a promise of the run's counts and how far through the pass
   */
  sweepAccountSetsBudgeted(): Promise<any> {
    const { log, stats } = this.deps;
    const self = this;
    log.debug("Entering Authn.sweepAccountSetsBudgeted().");
    log.debug("Leaving Authn.sweepAccountSetsBudgeted().");
    return AccountSets.sweepBudgeted(function (sid) {
      return self.accountSessionKept(sid);
    }).then(function (done) {
      if (done.expired) {
        stats.recordAccountChoice('expired', done.expired);
      }
      return done;
    });
  }

  /**
   * `sweepAccountSets()`, a slice at a time, yielding the event loop between
   * slices (#780).
   *
   * @returns a promise of `{ sets, ended, expired, deleted, slices }`
   */
  sweepAccountSetsInSlices(): Promise<any> {
    const { log, stats } = this.deps;
    const self = this;
    log.debug("Entering Authn.sweepAccountSetsInSlices().");
    log.debug("Leaving Authn.sweepAccountSetsInSlices().");
    return AccountSets.sweepInSlices(function (sid) {
      return self.accountSessionKept(sid);
    }).then(function (done) {
      if (done.expired) {
        stats.recordAccountChoice('expired', done.expired);
      }
      return done;
    });
  }

  // Whether a signed-in session's person is disabled. The anonymous principal
  // and an unauthenticated session are nobody's account.
  /**
   * Says whether a signed-in session's person is disabled.
   *
   * The anonymous principal and an unauthenticated session are nobody's
   * account.
   *
   * @param session - the session row
   * @returns true when the account is disabled
   */
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

  // Whether a signed-in session's person has no directory entry any more
  // (#241). Asked of the SUBJECT, `urn:uuid:<entryUUID>`, and not of the name:
  // a person deleted and made again under the same name is a new entry with a
  // new subject, and the old session is still the deleted one's. A session
  // with no such subject — the anonymous principal before it is chosen, a
  // keyed API caller, a process with no directory to ask — is never "gone".
  /**
   * Says whether a signed-in session's person no longer has a directory entry,
   * asked by subject.
   *
   * A session with no `urn:uuid:` subject, or a process with no directory to
   * ask, is never gone.
   *
   * @param session - the session row
   * @returns true when the entry is gone
   */
  sessionAccountGone(session) {
    const { log, helpers } = this.deps;
    log.debug("Entering Authn.sessionAccountGone().");
    if (!session || !session.user || session.authenticated === false ||
        session.chosen === false || session.credentialKey) {
      log.debug("Leaving Authn.sessionAccountGone(). Not a person's.");
      return false;
    }
    const sub = String(session.user.sub || '');
    if (!/^urn:uuid:/i.test(sub) || !helpers.hasSubjectResolver()) {
      log.debug("Leaving Authn.sessionAccountGone(). No subject to ask " +
                "about.");
      return false;
    }
    const gone = helpers.nameForSubject(sub) === '';
    log.debug("Leaving Authn.sessionAccountGone(). " + gone);
    return gone;
  }

  // ---------------------------------------------------------------------------
  // DOES THIS PERSON EXIST, FOR THE PRODUCT-MODE ENROLMENT DOOR (#613).
  //
  // The door asked `stats.knownUser()`, the identity register, which was
  // filled with every restored person at start-up — and the register keeps
  // `stats.MAX_USERS` identities a realm, so on a directory larger than that
  // most people were not in it and were refused a key as "nobody". #613
  // stopped the pre-fill (it held the event loop for seconds in every
  // process), and the question is the DIRECTORY's anyway: the register first,
  // because it answers from memory for anybody seen, and then the person's
  // entry in the ambient realm (`personDnOf`, one lookup; in a windowed
  // process one read of the store). A directory that cannot answer counts as
  // nobody, which refuses rather than creates — the door's own direction.
  // ---------------------------------------------------------------------------
  /**
   * Says whether a name is a person this realm knows: seen by the identity
   * register, or holding an entry in the directory.
   *
   * @param username - the name as presented
   * @returns true when the person exists
   */
  knownPerson(username) {
    const { log, stats, credentials } = this.deps;
    log.debug("Entering Authn.knownPerson().");
    if (stats.knownUser(username)) {
      log.debug("Leaving Authn.knownPerson(). The register knows them.");
      return true;
    }
    let dn = '';
    try {
      dn = String(credentials.deviceStore('personDnOf', [username]) || '');
    } catch (e) {
      log.debug("Caught in Authn.knownPerson(): " + ((e && e.message) || e));
      // Nobody, for the reason above: refusing is the safe direction.
      dn = '';
    }
    log.debug("Leaving Authn.knownPerson(). " + (dn ? "An entry." : "None."));
    return !!dn;
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
  /**
   * Gives a browser that arrives with no session cookie an arrival session that
   * holds no principal.
   *
   * `startSession()` later upgrades the same row in place, so the cookie goes
   * on naming the person's session.
   *
   * @param req - the request
   * @param res - the response the cookie is set on
   * @param via - the door that started it, for the log and the row
   * @returns the new session, or null when the browser already has one
   */
  startArrivalSession(req, res, via) {
    const { log, nowSec, randomId, userFor } = this.deps;
    log.debug("Entering Authn.startArrivalSession().");
    const existing = this.cookieSession(req, SESSION_COOKIE);
    if (existing && existing.error) {
      log.debug("Leaving Authn.startArrivalSession(). The session could " +
                "not be read.");
      return null;
    }
    if (existing) {
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
      events: [],
      // Not a person. Arrivals share one username, so the per-subject cap
      // must not group them, and they are not countable.
      subjectId: ''
    };
    const room = this.makeRoomForSession(sessions.realmMap(), session);
    if (room === 'error') {
      log.debug("Leaving Authn.startArrivalSession(). The session store " +
                "could not be read.");
      return null;
    }
    if (!room) {
      log.debug("Leaving Authn.startArrivalSession(). The realm is full.");
      return null;
    }
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
    const { log, realms } = this.deps;
    log.debug("Entering Authn.touchArrivalSession().");
    const found = this.cookieSession(req, SESSION_COOKIE);
    if (found && found.error) {
      log.debug("Leaving Authn.touchArrivalSession().");
      return;
    }
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
    // using. While the window is on, touches inside one second stay on the
    // dirty pin and flush once.
    if (this.windowOn() &&
        sessionWindow.holdTouch(realms.currentId(), id, session)) {
      log.debug("Leaving Authn.touchArrivalSession().");
      return;
    }
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
    if (found && found.error) {
      log.debug("Leaving Authn.arrivalSessionOf().");
      return null;
    }
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
  //
  // **AND A THIRD, NAMED BY THE CALLER (2026-09-30).** A portal session ADOPTED
  // from a console session (`adoptRelyingPartySession()`) is a child of that
  // console session, which lives in the default partition, while the portal
  // session lives in the realm its person signed in through — which is the
  // console session's own `derivedFromRealm`. So `dropSession()` names that
  // one realm when the session being ended is a console session, and this
  // walks it as well. It is the "another named partition" the paragraph above
  // asked for, and still not a walk over `realms.list()`.
  /**
   * Lists the relying-party sessions derived from one session.
   *
   * It looks in the given partition, in the default realm's, and in `alsoRealm`
   * when named; a child found outside the ambient partition must name this
   * parent's realm.
   *
   * @param parentId - the parent session id
   * @param store - the partition to look in; the ambient one by default
   * @param alsoRealm - one further realm whose partition is walked
   * @returns the derived sessions found, or null when a children read
   *   failed. Null is not an empty generation.
   */
  derivedFrom(parentId, store?, alsoRealm?) {
    const { realms, log, errorCodes } = this.deps;
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
    const also = String(alsoRealm || '');
    const asked = [here];
    if (here !== realms.DEFAULT_ID) {
      scan(realms.DEFAULT_ID, sessions.realmMap(realms.DEFAULT_ID));
      asked.push(realms.DEFAULT_ID);
    }
    if (also && also !== here && also !== realms.DEFAULT_ID &&
        realms.get(also)) {
      scan(also, sessions.realmMap(also));
      asked.push(also);
    }
    // Unflushed children are already in the map. The index names children
    // this process has not loaded. A failed read is not that shorter list:
    // the caller must not delete the parent while a child could not be read.
    if (this.windowOn()) {
      const parentKey = keystore.keyedDigest('session-parent',
                                              String(parentId));
      if (!parentKey) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: the parent digest ' +
                  'is missing.');
        log.debug("Leaving Authn.derivedFrom(). Unread.");
        return null;
      }
      for (let i = 0; i < asked.length; i++) {
        const realmId = asked[i];
        const keys = sessionWindow.indexKeys('session.children',
                                              [realmId, parentKey]);
        if (keys === null) {
          log.error(errorCodes.tag('STS-AUTHN-0338') +
                    'authn: a session could not be read: the children of ' +
                    parentId + ' in ' + realmId + '.');
          log.debug("Leaving Authn.derivedFrom(). Unread.");
          return null;
        }
        for (let j = 0; j < keys.length; j++) {
          const loaded = sessionWindow.loadByDigest(realmId, keys[j]);
          if (!loaded.ok && loaded.error) {
            log.error(errorCodes.tag('STS-AUTHN-0338') +
                      'authn: a session could not be read: a child of ' +
                      parentId + ' would not open.');
            log.debug("Leaving Authn.derivedFrom(). Unread.");
            return null;
          }
          if (!loaded.ok || !loaded.session) {
            continue;
          }
          const held = loaded.session;
          const id = String(held.id || '');
          if (!id || held.derivedFrom !== parentId || seen[id]) {
            continue;
          }
          if (String(held.derivedFromRealm || realmId) !== here) {
            continue;
          }
          seen[id] = true;
          found.push({ id: id, session: held, realm: realmId });
        }
      }
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
  /**
   * Returns the session one hosted surface (the console or the portal) holds
   * for a request.
   *
   * The parent sign-on session is checked as well as the clock: a derived
   * session whose parent is gone is not honoured.
   *
   * @param req - the request
   * @param cookie - the surface's own cookie name
   * @param realmId - the realm partition to read; the ambient one by default
   * @returns the session row, or null
   */
  relyingPartySessionOf(req, cookie, realmId) {
    const { realms, log } = this.deps;
    const self = this;
    log.debug("Entering Authn.relyingPartySessionOf(). cookie=" + cookie);
    const store = realmId ? sessions.realmMap(realmId) : sessions.realmMap();
    // THE SAME `<id>.<handle>` SHAPE AS THE SIGN-ON COOKIE (2026-09-14), and
    // for a reason that is sharper here: these ids are printed on
    // /admin/sessions to every holder of Admin Read, and a bare id in
    // `sts_admin` was a console session belonging to whoever held Admin Write.
    const found = this.cookieSession(req, String(cookie || ''), store,
                                     realmId);
    if (!found || found.error) {
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
    let parent = null;
    let parentUnread = false;
    if (session.derivedFrom) {
      if (this.windowOn()) {
        const read = sessionWindow.get(parentRealm, session.derivedFrom);
        if (!read.ok && read.error) {
          parentUnread = true;
        } else if (read.ok) {
          parent = read.session;
        }
      } else {
        parent = parentStore.get(session.derivedFrom) || null;
      }
    }
    if (parentUnread) {
      log.debug("Leaving Authn.relyingPartySessionOf(). The parent could " +
                "not be read.");
      return null;
    }
    if (session.derivedFrom && !parent && !parentRanOut) {
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
          self.dropSession(id, 'the end of the sign-on session it came ' +
                           'from', true, req, 'system');
        });
      } else {
        this.dropSession(id, 'the end of the sign-on session it came ' +
                         'from', true, req, 'system');
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
    if (session.derivedFrom && parent) {
      this.noteSessionUsed(parentStore, session.derivedFrom, parent);
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
  /**
   * Creates a hosted surface's relying-party session from a verified ID Token's
   * claims.
   *
   * Called only from `common/oidc_rp.ts`; it records no authentication, since
   * the authorization endpoint already counted it.
   *
   * @param spec - the surface, the claims, the tokens and the parent sign-on
   *   session
   * @returns the new session
   */
  startRelyingPartySession(spec) {
    const { realms, log, nowSec, randomId, userFor, audit,
            errorCodes } = this.deps;
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
    let parent = null;
    if (spec.parent && this.windowOn()) {
      const read = sessionWindow.get(parentRealm, spec.parent);
      if (!read.ok && read.error) {
        this.refuseUnread(spec.res);
        log.debug("Leaving Authn.startRelyingPartySession(). The parent " +
                  "could not be read.");
        return null;
      }
      parent = read.ok ? read.session : null;
    } else if (spec.parent) {
      parent = parentStore.get(spec.parent) || null;
    }
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
      calls: 1,
      // Said explicitly: a missing chosen is treated as a real session by
      // the merge, and the per-subject cap counts only chosen rows.
      chosen: true
    };
    session.subjectId = this.subjectIdOf(session.user);
    const room = this.makeRoomForSession(store, session);
    if (room === 'error') {
      this.refuseUnread(spec.res);
      log.debug("Leaving Authn.startRelyingPartySession(). The session " +
                "store could not be read.");
      return null;
    }
    if (!room) {
      this.auditCapRefusal(username, 'OAuth 2.0 / OIDC',
                           session.rpClientId, 'ID Token');
      if (spec.res) {
        errorCodes.mark(spec.res, 'STS-AUTHN-0337');
      }
      log.debug("Leaving Authn.startRelyingPartySession(). Refused.");
      return null;
    }
    const cookieValue = this.mintSessionHandle(session);
    store.set(sessionId, session);
    this.setCookieHeader(spec.res, this.sessionCookieLine(spec.cookie,
                                                          cookieValue));
    if (session.rpSurface === 'admin') {
      this.noteBacksConsole(session);
    }
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

  // ---------------------------------------------------------------------------
  // ADOPTING ANOTHER SURFACE'S SESSION (2026-09-30). The one other way a
  // relying-party session is made, and ONE DIRECTION ONLY: the user portal
  // establishing its own session from a LIVE console session in the same
  // browser (`portal/portal.ts`'s `adoptConsoleSession()`, which is the one
  // caller and argues why).
  //
  // What it was for, observed on a product deployment: an administrator
  // followed the console's link to their own account and was asked to sign in
  // AGAIN, because the sign-on session behind the console had run out
  // (`authn.sessionLifetimeS`, absolute) while the console session renewed its
  // own tokens past it (`common/oidc_rp.ts` section 4). The portal's code flow
  // then met no sign-on session. The owner's decision was that the portal reads
  // the realm and the authentication from the console session.
  //
  // **IT INVENTS NOTHING.** Everything on the new row comes off the console
  // row, which was itself made from an ID Token this service verified — the
  // person, the authentication time, `amr`, `acr`, whether they authenticated,
  // and the authority that vouched for the sign-in. So the export list's rule
  // ("a caller that wanted to create one of these without going through the
  // code flow would be a caller inventing a session out of nothing") still
  // holds one step removed: the code flow ran, for the console.
  //
  // **ITS PARENT IS THE CONSOLE SESSION, AND IT DIES WITH IT** — `derivedFrom`
  // names it and `derivedFromRealm` says it is in the default partition, so:
  //   * the reader (`relyingPartySessionOf()`) ends it on the first request
  //     after the console session is gone, for whatever reason;
  //   * `dropSession()`'s cascade ends it WITH the console session, in any
  //     realm (see `derivedFrom()`'s `alsoRealm`);
  //   * it holds NO TOKENS, so it never renews and "a parent that ran out" is
  //     never an excuse to outlive it; and its expiry is the console
  //     session's at the moment it was adopted.
  //
  // It records no authentication, for `startRelyingPartySession()`'s reason.
  // It writes a `session.start` row that says it was adopted, and announces an
  // `established` session, because a new session is what it is.
  // ---------------------------------------------------------------------------
  /**
   * Creates a surface's relying-party session from another surface's live
   * relying-party session in the same browser — the user portal adopting the
   * console's. Created in the ambient realm's partition.
   *
   * @param spec - `{ res, source, sourceRealm, surface, label, clientId,
   *   cookie, req }`: the response the cookie is set on, the live session
   *   adopted and the realm whose partition holds it, and the adopting
   *   surface's identity
   * @returns the new session
   */
  adoptRelyingPartySession(spec) {
    const { realms, log, randomId, userFor, audit, errorCodes } = this.deps;
    log.debug("Entering Authn.adoptRelyingPartySession(). surface=" +
              spec.surface);
    const source = spec.source;
    const sourceRealm = String(spec.sourceRealm || realms.currentId());
    const username = String(source.user.username);
    const sessionId = randomId(24);
    const store = sessions.realmMap();
    const session: SessionRow = {
      id: sessionId,
      // Built HERE, in the realm the portal session lives in, which is the
      // realm the person signed in through: the console row's own `user` was
      // built in the default partition and names that realm's view of them.
      user: userFor(username),
      authTime: source.authTime,
      expires: Number(source.expires) || 0,
      authenticated: source.authenticated !== false,
      amr: Array.isArray(source.amr) ? source.amr.slice() : [],
      acr: source.acr || '',
      via: spec.label || spec.surface,
      signInAuthority: source.signInAuthority || '',
      derivedFrom: source.id,
      derivedFromRealm: sourceRealm,
      rpSurface: String(spec.surface || ''),
      rpLabel: String(spec.label || spec.surface || ''),
      rpClientId: String(spec.clientId || ''),
      // The sign-on session's `sid` the console was told, so a front-channel
      // logout naming that sign-on session names this one too.
      rpSid: String(source.rpSid || ''),
      // WHICH SURFACE IT WAS ADOPTED FROM, and the one field no code-flow row
      // carries — what `/admin/sessions` and the portal's sign-out read to
      // tell the two kinds apart.
      rpAdoptedFrom: String(source.rpSurface || ''),
      // No tokens: it never renews, and see relyingPartySessionOf() for why
      // that is what makes a missing parent always end it.
      rpTokens: null,
      rpRenewableUntil: 0,
      rpRenewals: 0,
      rpRenewedAt: 0,
      derivedFromExpires: 0,
      credentialKey: null,
      lastSeenAt: Date.now(),
      calls: 1,
      chosen: true
    };
    session.subjectId = this.subjectIdOf(session.user);
    const room = this.makeRoomForSession(store, session);
    if (room === 'error') {
      this.refuseUnread(spec.res);
      log.debug("Leaving Authn.adoptRelyingPartySession(). The session " +
                "store could not be read.");
      return null;
    }
    if (!room) {
      this.auditCapRefusal(username, 'OAuth 2.0 / OIDC',
                           session.rpClientId, 'ID Token');
      if (spec.res) {
        errorCodes.mark(spec.res, 'STS-AUTHN-0337');
      }
      log.debug("Leaving Authn.adoptRelyingPartySession(). Refused.");
      return null;
    }
    const cookieValue = this.mintSessionHandle(session);
    store.set(sessionId, session);
    this.setCookieHeader(spec.res, this.sessionCookieLine(spec.cookie,
                                                          cookieValue));
    if (session.rpSurface === 'admin') {
      this.noteBacksConsole(session);
    }
    audit.audit({
      action: 'session.start',
      actor: username,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: sessionId,
      summary: username + ' was signed in to the ' +
               (spec.label || spec.surface) + ' from their live ' +
               (source.rpLabel || source.rpSurface) + ' session ' +
               source.id + '; session ' + sessionId + ' was created',
      detail: {
        sessionId: sessionId,
        sub: session.user.sub,
        client_id: session.rpClientId,
        derivedFrom: session.derivedFrom,
        derivedFromRealm: sourceRealm,
        adoptedFrom: session.rpAdoptedFrom,
        surface: session.rpSurface,
        amr: (session.amr || []).join(', '),
        acr: session.acr || '',
        authTime: session.authTime,
        expiresAt: new Date(session.expires).toISOString(),
        note: 'A RELYING PARTY session ADOPTED from another surface\'s live ' +
              'session in the same browser. Nobody authenticated here and no ' +
              'code flow ran: the authentication is the one behind ' +
              source.id + ', and this session ends when that one does.'
      }
    });
    session.firstPresentationIsTheSignIn = true;
    this.notifySession('established', session,
                       { via: spec.label || spec.surface,
                         req: spec.req || null });
    log.info('authn: ' + username + ' holds a ' + (spec.label || spec.surface) +
             ' session (' + sessionId + ') in realm ' + realms.currentId() +
             ', adopted from their ' + (source.rpLabel || source.rpSurface) +
             ' session ' + source.id + ' in realm ' + sourceRealm +
             '. No authentication was recorded and no code flow ran.');
    log.debug("Leaving Authn.adoptRelyingPartySession(). " + sessionId);
    return session;
  }

  // The kind of authority that vouched for a sign-on session's most recent
  // authentication (see authenticationEvent()), or '' for no session or a row
  // older than events, which nothing may read as this service's own check.
  /**
   * Returns the kind of authority that vouched for a session's most recent
   * authentication event.
   *
   * @param session - the sign-on session
   * @returns the authority kind, or '' for no session or a row older than
   *   events
   */
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
  /**
   * Returns when a relying party's tokens stop saying anything: the earlier of
   * the access and ID Token expiries.
   *
   * @param tokens - the relying party's stored tokens
   * @returns the instant in milliseconds, or 0 when it holds none
   */
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
  /**
   * Records a hosted surface's token renewal on its relying-party session.
   *
   * Nothing is recorded as an authentication; `expires` moves only as far as
   * the new tokens need and never past the original window.
   *
   * @param spec - the session id, its realm and the new tokens
   * @returns the session as it now is, or null when it is gone
   */
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
  /**
   * Returns the console's session for a request, read from the default realm's
   * partition whichever realm is being viewed.
   *
   * An expired session is swept as `sessionOf()` does.
   *
   * @param req - the request
   * @returns `{ session, realm, foreign }` where `foreign` says the realm being
   *   read is not the session's, or null
   */
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
    const found = this.cookieSession(req, SESSION_COOKIE, store,
                                     realms.DEFAULT_ID);
    if (!found || found.error) {
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
  //
  // The two facts an application's Authentication attempts tab matches and
  // draws (#954). `application` is the protocol's name for who was being
  // signed in to — a client_id, an entityID, a wtrealm — and `method` is
  // the phrase `methodPhraseFor()` gives the acceptance. Empty strings are
  // dropped by the audit log, and neither is a client_id the funnel would
  // count: copying one into the other would count a sign-in twice.
  /**
   * The application name and authentication method for an audit detail.
   *
   * @param application - the protocol's name for the application
   * @param method - the authentication method
   * @returns those two fields
   */
  private attemptFacts(application, method):
      { application: string, method: string } {
    const { log } = this.deps;
    log.debug("Entering Authn.attemptFacts().");
    const facts = {
      application: String(application || ''),
      method: String(method || '')
    };
    log.debug("Leaving Authn.attemptFacts().");
    return facts;
  }

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
      // REACHABLE SINCE #64: an emailed code or link as the first factor is
      // `amr ["otp"]` alone. An authenticator app still never is (see
      // common/totp.ts). The credential kind on the event says which.
      return 'sign-in screen (a one-time code alone — an emailed code or ' +
             'link)';
    }
    log.debug("Leaving Authn.methodPhraseFor().");
    return 'sign-in screen (password)';
  }

  // THE NOTE A SIGN-IN'S ROWS CARRY WHERE THE CALLER WROTE NONE (#543 round
  // 2). It was the literal "No password was checked; the name typed is the
  // identity." in both modes, so every verified password sign-in in a product
  // realm was recorded, on its stats row and its audit row, as the opposite
  // of what happened. Asked per sign-in, because the mode is per realm.
  private defaultSignInNote(): string {
    const { log } = this.deps;
    log.debug("Entering Authn.defaultSignInNote().");
    log.debug("Leaving Authn.defaultSignInNote().");
    return mode.verifiesCredentials()
      ? 'What was presented was verified before the session started; the ' +
        'method says what it was.'
      : 'No password was checked (development mode); the name typed is ' +
        'the identity.';
  }

  /**
   * Installs the one observer told when a session is established, presented or
   * ended (the inverted hook `ssf/ssf.ts` fills).
   *
   * Something that is not a function is logged and ignored.
   *
   * @param fn - the observer
   */
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
    // AN ARRIVAL SESSION IS NOBODY'S AND IS NEVER ANNOUNCED (#242,
    // 2026-09-26). `startArrivalSession()` mints one for every cookie-less
    // visitor at a front door and tells nobody, so its END was the first thing
    // a receiver ever heard of it: a `session-revoked` about a session that
    // never had a `session-established`, for every visitor who did not sign
    // in, on every stream covering everybody. Filtered HERE, the one place
    // every notice passes, for `sessionOf()`'s reason: the expiry, the sweep,
    // a realm's every-session end and a sign-out are four callers that would
    // otherwise each have to remember. Once somebody signs in the row is
    // replaced with `chosen: true` and is announced from then on.
    if (session.chosen === false) {
      log.debug("Leaving Authn.notifySession(). An arrival session nobody " +
                "signed in to; nothing is said about it.");
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

  // ---------------------------------------------------------------------------
  // WHO ENDED A SESSION, AS THE CALLER SAYS IT (#242, 2026-09-26).
  //
  // CAEP section 2's `initiating_entity` was GUESSED: `reportSignOut()` tested
  // the door's own sentence for `admin` or `console`. So the console's own
  // Sign out button ("the Sign out button on the admin console") said an
  // ADMINISTRATOR had ended the session of a person who signed themselves
  // out, and so did every child it cascaded to; an emergency key rotation and
  // the risk engine ending everything said the PERSON had. Each caller knows
  // which it is, so each says it — `admin`, `user`, `policy` or `system` — and
  // this only checks the word. A caller that says nothing is a defect worth
  // seeing, and is reported as `system` (nobody in particular) with a
  // warning, never guessed from the sentence.
  // ---------------------------------------------------------------------------
  private initiatorOf(asked, via) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.initiatorOf().");
    const word = String(asked || '');
    if (INITIATING_ENTITIES.indexOf(word) >= 0) {
      log.debug("Leaving Authn.initiatorOf(). " + word);
      return word;
    }
    log.warn(errorCodes.tag('STS-AUTHN-0290') + 'authn: a session was ended ' +
             '(' + String(via || 'no door named') + ') without saying who ' +
             'initiated it' + (word ? ' ("' + word + '" is not one of ' +
             INITIATING_ENTITIES.join(', ') + ')' : '') + '; CAEP ' +
             'session-revoked says "system".');
    log.debug("Leaving Authn.initiatorOf(). system");
    return 'system';
  }

  // How many session ends are waiting on the cluster claim that decides who
  // reports them (#232): a realm being removed waits for none to be left
  // before its stores are purged.
  /**
   * Returns how many session ends in this process are waiting on the cluster
   * claim that decides who reports them.
   *
   * @returns the count
   */
  pendingEndReports() {
    const { log } = this.deps;
    log.debug("Entering Authn.pendingEndReports().");
    log.debug("Leaving Authn.pendingEndReports(). " + endReportsPending);
    return endReportsPending;
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
    // A CLAIM THAT CANNOT BE ASKED IS ASKED AGAIN, AND THEN THE END IS
    // REPORTED ANYWAY (#242, 2026-09-26). A rejected claim — the store
    // unreachable for a moment, a driver error — used to be logged and the
    // report dropped: a receiver told the session was established was told
    // nothing when it ended. It is tried SESSION_END_CLAIM_ATTEMPTS times with
    // a growing pause (a retry inside one operation, which the scheduler rule
    // does not cover), and after the last the report is made here, as the
    // `store` answer already does: told twice is the side to err on, never
    // told the one that is not. The report itself runs outside the claim's
    // chain, so a report that throws is never mistaken for a claim to retry.
    const self = this;
    endReportsPending += 1;
    let settled = false;
    const finish = function (answer) {
      if (settled) {
        return;
      }
      settled = true;
      endReportsPending = Math.max(0, endReportsPending - 1);
      if (answer.ok) {
        self.reportEnd(id, emit);
        return;
      }
      if (answer.reason === 'store') {
        log.warn(errorCodes.tag('STS-AUTHN-0192') + 'authn: whether ' +
                 'another process already reported the end of session ' + id +
                 ' could not be asked (' + (answer.why || '') + '); it is ' +
                 'reported here, and a receiver may be told twice.');
        self.reportEnd(id, emit);
        return;
      }
      log.debug('sessionEndOnce(): the end of session ' + id + ' was ' +
                'already reported by another process.');
      if (typeof onLost === 'function') {
        onLost();
      }
    };
    const attempt = function (n) {
      const failed = function (e) {
        log.debug("Caught in Authn.sessionEndOnce(): " +
                  ((e && e.message) || e));
        if (n + 1 < SESSION_END_CLAIM_ATTEMPTS) {
          setTimeout(function () {
            attempt(n + 1);
          }, SESSION_END_CLAIM_RETRY_MS * (n + 1));
          return;
        }
        finish({ ok: false, reason: 'store',
                 why: 'the claim failed ' + SESSION_END_CLAIM_ATTEMPTS +
                      ' times: ' + ((e && e.message) || e) });
      };
      let asked = null;
      try {
        asked = clusterClaims.claim({ scope: 'authn.session-end',
                                      value: String(id),
                                      ttlMs: SESSION_END_CLAIM_TTL_MS });
      } catch (e) {
        // A claim that throws before it has a promise to reject is the same
        // failure, and must not take the sign-out down with it.
        failed(e);
        return;
      }
      Promise.resolve(asked).then(function (answer) {
        finish(answer || { ok: false, reason: 'store',
                           why: 'the claim answered nothing' });
      }, failed);
    };
    attempt(0);
    log.debug("Leaving Authn.sessionEndOnce(). Claiming.");
  }

  // The report of one session's end, which the claim above lets out. A throw
  // is a defect in the report and is logged, never retried: the claim has
  // been spent, and trying again would be telling a receiver twice.
  private reportEnd(id, emit) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.reportEnd(). id=" + id);
    try {
      emit();
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0291') + 'authn: reporting the ' +
                'end of session ' + id + ' failed: ' +
                ((e && e.message) || e));
    }
    log.debug("Leaving Authn.reportEnd().");
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
    // THE THIRD WAY A SESSION RUNS OUT (#345, #350): this subject's own
    // oldest countable row, so one more session of theirs can take its
    // place, or one row the sweep sheds. Never another subject's row.
    const evicted = why === 'capacity';
    store.delete(id);
    // An expiry and an eviction move the account to remembered too (#561).
    this.accountSessionEnded(session);
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
      ? this.planBackchannel(session, evicted
          ? 'this subject was at authn.maxSessionsPerSubject, and this ' +
            'was their own oldest countable session'
          : idle
            ? 'the session went idle (authn.sessionIdleTimeoutS)'
            : 'the session expired (authn.sessionLifetimeS)', 'expiry')
      : [];
    // THE REPORT ONCE FOR THE CLUSTER; the delete above is this process's own.
    // See sessionEndOnce().
    this.sessionEndOnce(id, function () {
      self.reportExpiry(id, session, via, evicted ? 'capacity'
                                                  : (idle ? 'idle' : ''));
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
  // `kind` is 'idle', 'capacity' (#350: this subject's own oldest
  // countable row) or '' for the absolute expiry.
  private reportExpiry(id, session, via, kind) {
    const { log, audit } = this.deps;
    log.debug("Entering Authn.reportExpiry(). id=" + id);
    const idle = kind === 'idle';
    const evicted = kind === 'capacity';
    const row: any = {
      action: 'session.end',
      outcome: 'success',
      actor: (session && session.user && session.user.username) || '',
      protocol: (session && session.via) || 'Authentication service',
      channel: 'none',
      target: id,
      summary: ((session && session.user &&
                 session.user.username) || 'somebody') +
               '\'s session ' + id + (evicted
                 ? ' was ended at the per-subject session cap: it was ' +
                   'that subject\'s own oldest countable session'
                 : ' expired and was discarded'),
      detail: {
        sessionId: id,
        // Not "signed out": nobody asked for this and no browser was involved.
        // A receiver told the session was established has to be able to tell
        // the two apart, which is what `initiating_entity` carries in the
        // event.
        reason: evicted
          ? 'this subject was at authn.maxSessionsPerSubject, and this ' +
            'was their own oldest countable session — never another ' +
            'subject\'s row and never an arrival'
          : idle
            ? 'the session went unused for longer than ' +
              'authn.sessionIdleTimeoutS'
            : 'the session lifetime ran out',
        noticedBy: via,
        expiresAt: session && session.expires
          ? new Date(session.expires).toISOString() : ''
      }
    };
    if (evicted) {
      row.errorCode = 'STS-AUTHN-0292';
    }
    audit.audit(row);
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
      reason: evicted
        ? 'This subject was at the per-subject session cap, and this was ' +
          'their own oldest countable session. Nobody signed out — this ' +
          'service stopped honouring it. It was not another subject\'s ' +
          'session and not an arrival.'
        : idle
        ? 'The session went unused for longer than this service\'s idle ' +
          'timeout. Nobody signed out — this service stopped honouring a ' +
          'session nobody was using.'
        : 'The session lifetime ran out. Nobody signed out — this service ' +
          'stopped honouring the session because its absolute expiry ' +
          'passed, and it is not extended by use.',
      req: null });
    log.debug("Leaving Authn.reportExpiry().");
  }

  /**
   * Ends every expired or idle session in every realm; the body of the
   * session-expiry scheduler job.
   *
   * @returns how many sessions were ended
   */
  sweepExpiredSessions() {
    const { realms, log } = this.deps;
    const self = this;
    log.debug("Entering Authn.sweepExpiredSessions().");
    const nowMs = Date.now();
    let gone = 0;
    realms.list().forEach(function (realm) {
      const store = sessions.realmMap(realm.id);
      // While the window is on the index names expired rows. An empty map
      // is not an empty realm, and a failed index read skips the realm.
      if (self.windowOn()) {
        realms.run(realm, function () {
          const idle = self.sessionIdleTimeoutMs();
          const cutoff = idle > 0 ? nowMs - idle : 0;
          const keys = sessionWindow.indexKeys('session.expired',
                                                [realm.id, nowMs, cutoff]);
          if (keys === null) {
            return;
          }
          keys.forEach(function (digest) {
            const loaded = sessionWindow.loadByDigest(realm.id, digest);
            if (!loaded.ok) {
              return;
            }
            const session = loaded.session;
            let why = '';
            if (session.expires && session.expires <= nowMs) {
              why = 'expired';
            } else {
              const ended = self.sessionEnded(session, nowMs);
              if (ended) {
                why = ended;
              }
            }
            if (!why) {
              return;
            }
            self.expireSession(store, session.id, session,
                               'the session sweep', why);
            gone++;
          });
        });
        return;
      }
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
    // Expiries first, so a row already queued is not also a capacity
    // victim. A realm with nothing expired still sheds. Both kinds are
    // in the count the job reports; the 0292 row tells a capacity end
    // from a lifetime.
    const shed = this.shedSubjectSurplus();
    if (gone) {
      log.info('authn: the session sweep ended ' + gone + ' expired ' +
               'session(s). Each one is an audit row and a CAEP ' +
               'session-revoked, which is the whole reason the sweep exists: ' +
               'an expiry noticed only when somebody comes back is an expiry ' +
               'nobody is ever told about.');
    }
    log.debug("Leaving Authn.sweepExpiredSessions(). " +
              (gone + shed) + " ended.");
    return gone + shed;
  }

  // ---------------------------------------------------------------------------
  // THE SIZE CAP (#345, #350): `authn.maxSessions` per realm, checked where a
  // session is CREATED, because a bound cannot wait for the expiry job.
  // Called by the doors that add a key — `startArrivalSession()`,
  // `startRelyingPartySession()`, `adoptRelyingPartySession()` and
  // `startSessionHere()` — before the set. A write of an id the store
  // already holds is not an insert. A restore or a change-log apply does
  // not come through here.
  //
  // **AT THE REALM CAP A NEW ROW IS REFUSED** (STS-AUTHN-0337). Nothing is
  // ended to make room for somebody else. One subject already at
  // `authn.maxSessionsPerSubject` loses their own oldest countable row
  // (STS-AUTHN-0292), one row, and the new row takes its place. An arrival
  // is not countable. The sign-on a relying-party row was just derived from
  // is not the victim.
  //
  // **OLDEST IS `lastSeenAt`, THEN `startedAt`.** A tie keeps the first row
  // in Map order while authn.sessionWindow is off. While it is on, the
  // index orders the same two columns and the map is not walked.
  //
  // **NOT LOCKED.** Two inserts at the same instant can each see room, so
  // the store can overshoot by one per concurrent inserter. Lowering a cap
  // does not mass-end: the next insert ends at most one own row, and each
  // realm's sweep ends at most that realm's `authn.sessionShedPerSweep`.
  // ---------------------------------------------------------------------------
  private sessionCapLoggedAt = 0;
  private sessionCapEnded = 0;
  private sessionRefuseLoggedAt = 0;
  private sessionRefuseCount = 0;

  // HOT PATH: asked of every resident row while one victim is chosen.
  // No Entering/Leaving pair — one would drown the log.
  private countsTowardSubject(session) {
    if (!session || session.chosen === false) {
      return false;
    }
    if (session.chosen === true) {
      return true;
    }
    // An old relying-party row omitted chosen. The merge treats that as a
    // real session, so the cap does too.
    return !!session.rpSurface;
  }

  // HOT PATH: compared once per resident row of one subject.
  // No Entering/Leaving pair — one would drown the log.
  // Strictly earlier. A tie is not earlier, so the first row in Map order
  // stays the victim.
  private earlierSession(a, b) {
    const aSeen = Number(a && a.lastSeenAt) || 0;
    const bSeen = Number(b && b.lastSeenAt) || 0;
    if (aSeen !== bSeen) {
      return aSeen < bSeen;
    }
    const aStart = Number(a && a.startedAt) || 0;
    const bStart = Number(b && b.startedAt) || 0;
    return aStart < bStart;
  }

  private subjectSessionCap() {
    const { log, config } = this.deps;
    log.debug("Entering Authn.subjectSessionCap().");
    let per = Math.floor(Number(
      config.value('authn.maxSessionsPerSubject')));
    const cap = Math.floor(Number(config.value('authn.maxSessions')));
    if (cap >= 1 && per > cap) {
      per = cap;
    }
    log.debug("Leaving Authn.subjectSessionCap().");
    return per;
  }

  // The stable id frozen on a chosen session: the urn:uuid sub when the
  // user has one, otherwise the username `sessionsOf()` compares. Not
  // holderKeyOf — that folds names the cap must keep apart.
  private subjectIdOf(user) {
    const { log } = this.deps;
    log.debug("Entering Authn.subjectIdOf().");
    const sub = user && user.sub ? String(user.sub) : '';
    if (/^urn:uuid:/i.test(sub)) {
      log.debug("Leaving Authn.subjectIdOf().");
      return sub;
    }
    const name = String((user && user.username) || '');
    log.debug("Leaving Authn.subjectIdOf().");
    return name;
  }

  private noteCapacityEnd(count) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.noteCapacityEnd().");
    this.sessionCapEnded += count;
    const now = Date.now();
    if (now - this.sessionCapLoggedAt >= 60000) {
      log.warn(errorCodes.tag('STS-AUTHN-0292') + 'authn: ' +
               this.sessionCapEnded + ' session(s) were ended at the ' +
               'per-subject session cap. Each was that subject\'s own ' +
               'oldest countable session, never another subject\'s and ' +
               'never an arrival. Each is an audit row.');
      this.sessionCapEnded = 0;
      this.sessionCapLoggedAt = now;
    }
    log.debug("Leaving Authn.noteCapacityEnd().");
  }

  private noteRealmRefusal() {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.noteRealmRefusal().");
    this.sessionRefuseCount += 1;
    const now = Date.now();
    if (now - this.sessionRefuseLoggedAt >= 60000) {
      log.warn(errorCodes.tag('STS-AUTHN-0337') + 'authn: ' +
               this.sessionRefuseCount + ' new session(s) were not ' +
               'admitted. The realm is at authn.maxSessions and the ' +
               'insert freed no row. An arrival continues with no ' +
               'cookie; a chosen sign-in is drawn again.');
      this.sessionRefuseCount = 0;
      this.sessionRefuseLoggedAt = now;
    }
    log.debug("Leaving Authn.noteRealmRefusal().");
  }

  private auditCapRefusal(username, via, application?, method?) {
    const { log, audit } = this.deps;
    log.debug("Entering Authn.auditCapRefusal().");
    audit.audit({
      action: 'session.refuse',
      actor: String(username || ''),
      errorCode: 'STS-AUTHN-0337',
      protocol: via || 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: '',
      summary: 'a session for ' + username + ' was refused: the realm is ' +
               'at authn.maxSessions',
      detail: Object.assign(this.attemptFacts(application, method), {
        why: 'the realm is at authn.maxSessions and this insert freed ' +
             'no row'
      })
    });
    log.debug("Leaving Authn.auditCapRefusal().");
  }

  // Ends one countable row of `incoming.subjectId`, the oldest by
  // lastSeenAt then startedAt, when that subject is already at the
  // per-subject cap. Skips `skipId` and `incoming.derivedFrom`. Returns
  // how many rows ended (0 or 1).
  private endOneOwn(store, incoming, skipId) {
    const { log, realms, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Authn.endOneOwn().");
    if (!store || !this.countsTowardSubject(incoming)) {
      log.debug("Leaving Authn.endOneOwn(). Not countable.");
      return 0;
    }
    const subject = String(incoming.subjectId || '');
    if (!subject) {
      log.debug("Leaving Authn.endOneOwn(). No subject.");
      return 0;
    }
    const cap = this.subjectSessionCap();
    if (!(cap >= 1)) {
      log.debug("Leaving Authn.endOneOwn(). No cap.");
      return 0;
    }
    const skip = skipId ? String(skipId) : '';
    const derived = incoming.derivedFrom ? String(incoming.derivedFrom) : '';
    // While the window is on the index is the authority. A failed read
    // ends nobody: ending from a partial map would pick the wrong row.
    if (this.windowOn()) {
      const realmId = realms.currentId();
      const subjectKey = keystore.keyedDigest('session-subject', subject);
      if (!subjectKey) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: the subject ' +
                  'digest is missing.');
        log.debug("Leaving Authn.endOneOwn(). Unread.");
        return 'error';
      }
      const rows = sessionWindow.oldest(realmId, subjectKey);
      if (rows === null) {
        log.debug("Leaving Authn.endOneOwn(). Unread.");
        return 'error';
      }
      const skipDigest = skip
        ? sessionWindow.sessionDigest(realmId, skip) : '';
      const derivedDigest = derived
        ? sessionWindow.sessionDigest(realmId, derived) : '';
      if ((skip && !skipDigest) || (derived && !derivedDigest)) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: the session ' +
                  'digest is missing.');
        log.debug("Leaving Authn.endOneOwn(). Unread.");
        return 'error';
      }
      let held = 0;
      let victim = '';
      rows.forEach(function (row) {
        const key = String((row && row.key) || '');
        if (!key || key === skipDigest) {
          return;
        }
        held += 1;
        if (derivedDigest && key === derivedDigest) {
          return;
        }
        if (!victim) {
          victim = key;
        }
      });
      if (held < cap || !victim) {
        log.debug("Leaving Authn.endOneOwn(). " + held + " held.");
        return 0;
      }
      const loaded = sessionWindow.loadByDigest(realmId, victim);
      if (!loaded.ok) {
        log.debug("Leaving Authn.endOneOwn(). The victim could not be " +
                  "read.");
        return 'error';
      }
      this.expireSession(store, loaded.session.id, loaded.session,
                         'the per-subject session cap', 'capacity');
      this.noteCapacityEnd(1);
      log.debug("Leaving Authn.endOneOwn(). Ended " +
                loaded.session.id + ".");
      return 1;
    }
    let count = 0;
    let oldest = null;
    // While authn.sessionWindow is off the scan is the whole resident map.
    store.forEach(function (row, id) {
      if (!self.countsTowardSubject(row)) {
        return;
      }
      if (String(row.subjectId || '') !== subject) {
        return;
      }
      const key = String(id);
      if (skip && key === skip) {
        return;
      }
      count += 1;
      if (derived && key === derived) {
        return;
      }
      if (oldest === null || self.earlierSession(row, oldest[1])) {
        oldest = [key, row];
      }
    });
    if (count < cap || !oldest) {
      log.debug("Leaving Authn.endOneOwn(). " + count + " held.");
      return 0;
    }
    this.expireSession(store, oldest[0], oldest[1],
                       'the per-subject session cap', 'capacity');
    this.noteCapacityEnd(1);
    log.debug("Leaving Authn.endOneOwn(). Ended " + oldest[0] + ".");
    return 1;
  }

  // True when the row may be stored. `replacingId` is a row this sign-in
  // will end once the new row is admitted; it counts as leaving so a realm
  // exactly at the cap still admits the switch, and it is not ended here.
  private makeRoomForSession(store, session, replacingId = '') {
    const { log, config, realms } = this.deps;
    log.debug("Entering Authn.makeRoomForSession().");
    if (!store || !session) {
      log.debug("Leaving Authn.makeRoomForSession(). No store.");
      return true;
    }
    const newId = session.id ? String(session.id) : '';
    if (this.windowOn()) {
      const realmId = realms.currentId();
      if (newId) {
        const held = sessionWindow.has(realmId, newId);
        if (held === 'error') {
          log.debug("Leaving Authn.makeRoomForSession(). Unread.");
          return 'error';
        }
        if (held === 'present') {
          log.debug("Leaving Authn.makeRoomForSession(). Already held.");
          return true;
        }
      }
      const ended = this.endOneOwn(store, session, '');
      if (ended === 'error') {
        log.debug("Leaving Authn.makeRoomForSession(). Unread.");
        return 'error';
      }
      const cap = Math.floor(Number(config.value('authn.maxSessions')));
      if (cap < 1) {
        // No cap: nothing to count (#754).
        log.debug("Leaving Authn.makeRoomForSession(). " + ended +
                  " ended, no cap.");
        return true;
      }
      let size = sessionWindow.countForAdmission(realmId, cap);
      if (size === null) {
        log.debug("Leaving Authn.makeRoomForSession(). Unread.");
        return 'error';
      }
      const leaving = replacingId ? String(replacingId) : '';
      if (leaving && leaving !== newId) {
        const leavingHeld = sessionWindow.has(realmId, leaving);
        if (leavingHeld === 'error') {
          log.debug("Leaving Authn.makeRoomForSession(). Unread.");
          return 'error';
        }
        if (leavingHeld === 'present') {
          size -= 1;
        }
      }
      if (size >= cap && ended === 0) {
        this.noteRealmRefusal();
        log.debug("Leaving Authn.makeRoomForSession(). Refused.");
        return false;
      }
      sessionWindow.noteAdmitted(realmId);
      log.debug("Leaving Authn.makeRoomForSession(). " + ended + " ended.");
      return true;
    }
    if (newId && store.has(newId)) {
      log.debug("Leaving Authn.makeRoomForSession(). Already held.");
      return true;
    }
    const ended = this.endOneOwn(store, session, '');
    const cap = Math.floor(Number(config.value('authn.maxSessions')));
    // A sign-in that will end this browser's previous session frees that
    // one row. Not locked. Two inserts at once can each see room and
    // overshoot by one per inserter. A victim already freed a row, so
    // this insert is admitted even when the realm is still over the cap.
    let size = store.size;
    const leaving = replacingId ? String(replacingId) : '';
    if (leaving && leaving !== newId && store.has(leaving)) {
      size -= 1;
    }
    if (cap >= 1 && size >= cap && ended === 0) {
      this.noteRealmRefusal();
      log.debug("Leaving Authn.makeRoomForSession(). Refused.");
      return false;
    }
    log.debug("Leaving Authn.makeRoomForSession(). " + ended + " ended.");
    return true;
  }

  // A console child marks the parent sign-on, in the parent's realm, so a
  // later merge can keep the flag. Only after the child was admitted.
  private noteBacksConsole(session) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Authn.noteBacksConsole().");
    if (!session || String(session.rpSurface || '') !== 'admin' ||
        !session.derivedFrom) {
      log.debug("Leaving Authn.noteBacksConsole(). Not a console child.");
      return;
    }
    const parentId = String(session.derivedFrom);
    const realmId = String(session.derivedFromRealm || realms.currentId());
    const realm = realms.get(realmId) || realms.current();
    realms.run(realm, function () {
      let parent = null;
      if (self.windowOn()) {
        const read = sessionWindow.get(realmId, parentId);
        if (!read.ok) {
          return;
        }
        parent = read.session;
      } else {
        parent = sessions.get(parentId);
      }
      if (!parent) {
        return;
      }
      parent.backsConsole = true;
      self.noteSessionChanged(parent);
    });
    log.debug("Leaving Authn.noteBacksConsole().");
  }

  // Each realm spends its own `authn.sessionShedPerSweep`, read while
  // that realm is ambient. One subject is brought down to their cap,
  // oldest first, before the next subject. Arrivals are not ended for
  // capacity, and a subject at or under their cap is not ended because
  // the realm is over authn.maxSessions.
  private shedSubjectSurplus() {
    const { log, realms, config } = this.deps;
    const self = this;
    log.debug("Entering Authn.shedSubjectSurplus().");
    // HOT PATH: ordered once per over-cap subject and once across them.
    // No Entering/Leaving pair — one would drown the log.
    const earlier = function (a, b) {
      if (self.earlierSession(a, b)) {
        return -1;
      }
      if (self.earlierSession(b, a)) {
        return 1;
      }
      return 0;
    };
    let shed = 0;
    realms.list().forEach(function (realm) {
      realms.run(realm, function () {
        const store = sessions.realmMap(realm.id);
        const budget = Math.floor(Number(
          config.value('authn.sessionShedPerSweep')));
        if (!(budget >= 1)) {
          return;
        }
        const per = self.subjectSessionCap();
        if (!(per >= 1)) {
          return;
        }
        // While the window is on the index is the shed authority. A failed
        // page skips the realm. A failed body ends nobody for that subject.
        // An absent row is not held, and the loop continues.
        if (self.windowOn()) {
          // Only the subjects over the cap, in one question (2026-10-21):
          // every chosen session paged synchronously was 634 questions a
          // sweep on 8081. At most `budget` subjects can lose one this
          // sweep, so no more are asked for.
          const grouped = sessionWindow.overCapBySubject(realm.id, per,
                                                         budget);
          if (grouped === null) {
            return;
          }
          const groups = [];
          grouped.forEach(function (group) {
            const list = group.rows.slice();
            if (list.length <= per) {
              return;
            }
            list.sort(function (a, b) {
              return earlier(a, b);
            });
            groups.push(list);
          });
          groups.sort(function (a, b) {
            return earlier(a[0], b[0]);
          });
          let left = budget;
          groups.forEach(function (rows) {
            let held = rows.length;
            for (let i = 0; i < rows.length && left > 0 &&
                 held > per; i++) {
              const loaded = sessionWindow.loadByDigest(realm.id,
                                                         rows[i].key);
              if (loaded.error) {
                return;
              }
              if (!loaded.ok) {
                held -= 1;
                continue;
              }
              self.expireSession(store, loaded.session.id, loaded.session,
                                 'the session sweep', 'capacity');
              shed += 1;
              held -= 1;
              left -= 1;
            }
          });
          return;
        }
        if (!store || !store.size) {
          return;
        }
        const groups = [];
        const bySubject = new Map();
        // While authn.sessionWindow is off the scan is the whole map.
        store.forEach(function (session, id) {
          if (!self.countsTowardSubject(session)) {
            return;
          }
          const subject = String(session.subjectId || '');
          if (!subject) {
            return;
          }
          let list = bySubject.get(subject);
          if (!list) {
            list = [];
            bySubject.set(subject, list);
          }
          list.push([id, session]);
        });
        bySubject.forEach(function (list) {
          if (list.length <= per) {
            return;
          }
          list.sort(function (a, b) {
            return earlier(a[1], b[1]);
          });
          groups.push(list);
        });
        groups.sort(function (a, b) {
          return earlier(a[0][1], b[0][1]);
        });
        let left = budget;
        groups.forEach(function (rows) {
          let held = rows.length;
          for (let i = 0; i < rows.length && left > 0 &&
               held > per; i++) {
            const id = rows[i][0];
            const live = store.get(id);
            if (!live) {
              held -= 1;
              continue;
            }
            self.expireSession(store, id, live, 'the session sweep',
                               'capacity');
            shed += 1;
            held -= 1;
            left -= 1;
          }
        });
      });
    });
    if (shed) {
      this.noteCapacityEnd(shed);
    }
    log.debug("Leaving Authn.shedSubjectSurplus(). " + shed + " ended.");
    return shed;
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
  //
  // **AND IT IS AN AUDIT ROW, `session.presented`, WHERE IT IS REPORTED.** The
  // Authentication attempts tabs (#954, #955) read the audit log's credential
  // rows, and single sign-on presents no credential, so a person who reached
  // an application on the session they already held appeared on neither the
  // application's tab nor their own. `application` is the protocol's name for
  // who the session was presented to — a client_id, an entityID, a wtrealm,
  // a GNAP client — and is what the application's tab matches; a caller with
  // no such name passes none, and the row is then on the person's tab only.
  // Written here and nowhere else, so it is exactly as often as the CAEP
  // event: the sign-in's own return trip writes no row, as it emits no event.
  // ---------------------------------------------------------------------------
  /**
   * Reports a session presented again for single sign-on (CAEP
   * `session-presented`), and writes the `session.presented` audit row.
   *
   * The first presentation of a brand-new session is the sign-in itself and is
   * not reported.
   *
   * @param session - the session
   * @param via - the protocol it was presented to
   * @param req - the request
   * @param application - the protocol's name for the application it was
   *   presented to, when the caller has one
   * @returns true when it was reported
   */
  notePresented(session, via, req, application?) {
    const { log, audit } = this.deps;
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
    const protocol = via || 'OAuth 2.0 / OIDC';
    const user = session.user || {};
    const username = String(user.username || '');
    const named = String(application || '');
    // No credential was presented, so `method` says what was instead. The
    // session's own amr and acr are what the application was given, and are
    // copied so the row reads as the tab's other rows do.
    audit.audit({
      action: 'session.presented',
      actor: username,
      protocol: protocol,
      channel: 'http',
      target: String(session.id || ''),
      summary: username + '\'s existing session ' + session.id +
               ' was presented through ' + protocol +
               (named ? ' to ' + named : ''),
      detail: Object.assign(this.attemptFacts(named, 'existing session'), {
        presented: username,
        sub: String(user.sub || ''),
        sessionId: String(session.id || ''),
        amr: (session.amr || []).join(', '),
        acr: String(session.acr || '')
      })
    });
    this.notifySession('presented', session, { via: protocol,
      req: req || null });
    log.debug("Leaving Authn.notePresented(). Reported.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // A PRESENTATION CONTINUED THROUGH THE CONSENT SCREEN (2026-10-26).
  //
  // An authorization request that needs consent reaches the endpoint twice:
  // once before the consent screen and once on the way back from it. Both
  // arrivals are ONE act, but notePresented() saw two. After a sign-in, the
  // first arrival spent the free presentation and the second read as single
  // sign-on; after a real single sign-on, the first was reported and the
  // second was reported again. Either way CAEP's `session-presented` and a
  // `session.presented` row on both Authentication attempts tabs said
  // something happened that had not. The authorization endpoint calls this
  // as it sends a request to the consent screen, whichever arrival that was,
  // so the trip back is not a presentation of its own: the sign-in's stays
  // the sign-in's, and a single sign-on is reported once, on the way in.
  //
  // It arms the same flag startSession() sets. A person who refuses consent
  // leaves it armed, and their next presentation of this session goes
  // unreported once. That is the same request coming back, in practice, and
  // a missed event costs less than a false one.
  // ---------------------------------------------------------------------------
  /**
   * Holds the next presentation of a session, because the request in flight
   * goes through the consent screen and comes back to the endpoint.
   *
   * @param session - the session the request is answered on
   */
  holdPresentation(session) {
    const { log } = this.deps;
    log.debug("Entering Authn.holdPresentation().");
    if (!session) {
      log.debug("Leaving Authn.holdPresentation(). No session.");
      return;
    }
    session.firstPresentationIsTheSignIn = true;
    // In the store as well, for notePresented()'s reason (#46).
    this.noteSessionChanged(session);
    log.debug("Leaving Authn.holdPresentation().");
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
  // WHO VOUCHED FOR AN AUTHENTICATION: this service, a federation partner,
  // or a Kerberos ticket. Its own function since #457, because the sign-in
  // mechanism question asks it of an authentication before its event exists.
  // THE CREDENTIAL FACTS OpenID Connect EAP's `phr` AND `phrh` ARE READ FROM
  // (#723), copied from what a door handed in: the ceremony, the key's
  // attestation trust and its backup eligibility. `eventContext()` records
  // the same three on the event; this is the copy the issuance policy is
  // asked with before the event exists.
  private phishingEvidenceOf(given) {
    const { log } = this.deps;
    log.debug("Entering Authn.phishingEvidenceOf().");
    const out: Record<string, any> = {};
    const g = given || {};
    if (g.ceremony === 'assertion' || g.ceremony === 'registration') {
      out.ceremony = g.ceremony;
    }
    if (typeof g.attestationTrusted === 'boolean') {
      out.attestationTrusted = g.attestationTrusted;
    }
    if (typeof g.backupEligible === 'boolean') {
      out.backupEligible = g.backupEligible;
    }
    log.debug("Leaving Authn.phishingEvidenceOf().");
    return out;
  }

  private authorityOf(detail) {
    const { log } = this.deps;
    log.debug("Entering Authn.authorityOf().");
    let authority: Record<string, string> = { kind: 'local' };
    if (detail.federation && detail.federation.id) {
      authority = { kind: 'federation', id: String(detail.federation.id),
                    peer: String(detail.federation.peer || ''),
                    subject: String(detail.federation.subject || ''),
                    // Consumer or enterprise, which provider, and whether
                    // the partner's address counts as verified (#565): what
                    // the issuance policy is told about a federated sign-in.
                    category: String(detail.federation.category ||
                                     'enterprise'),
                    provider: String(detail.federation.provider || ''),
                    emailVerified: detail.federation.mailVerified === false
                      ? 'false' : 'true' };
    } else if (detail.protocol === 'Kerberos v5' && detail.presented) {
      authority = { kind: 'kerberos', principal: String(detail.presented) };
    }
    log.debug("Leaving Authn.authorityOf(). " + authority.kind);
    return authority;
  }

  private authenticationEvent(amr, acr, via, extra, username?) {
    const { log, nowSec } = this.deps;
    log.debug("Entering Authn.authenticationEvent().");
    const detail = extra || {};
    const authority = this.authorityOf(detail);
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
      context: this.eventContext(detail),
      registeredDevice: this.registeredDeviceFor(detail, username)
    };
  }

  // ---------------------------------------------------------------------------
  // THE REGISTERED DEVICE THAT PROVED THIS AUTHENTICATION (#164 decision 1,
  // phase 2, 2026-09-26), or null: a linked WebAuthn credential that
  // answered, or the client certificate on this connection, recognised by
  // `common/device_recognition.ts`, which argues what counts. It is recorded
  // on the EVENT, beside `context`, as `registeredDevice` — `context.device`
  // is the browser fingerprint (#62 P6), a different thing — so every event
  // of a session says which device proved it, and later phases (compliance,
  // risk, policy, CAEP, token claims) read it from the session through
  // `registeredDeviceOf()`. A compromised device is recognised and says so.
  // A recogniser that throws records nothing and refuses nothing: a sign-in
  // is not the place a device register's defect should show.
  // ---------------------------------------------------------------------------
  //
  // `username` (#164 phase 5) is who is signing in, which sets the fact's
  // `ownerMatches`. ONE RECOGNITION PER REQUEST AND CREDENTIAL: a door that
  // assesses the sign-in's risk before the session exists (`assessSignIn()`)
  // asks here, and the session's event asks again a moment later for the
  // same request — the answer is remembered on the request, so the device's
  // last use moves once and Monitoring → Devices counts one recognition.
  // ---------------------------------------------------------------------------
  private registeredDeviceFor(detail, username?) {
    const { log, audit, deviceRecognition } = this.deps;
    log.debug("Entering Authn.registeredDeviceFor().");
    const given = detail.credential || {};
    const request = detail.request || audit.currentRequest();
    const credentialId = given.kind === 'webauthn' ? String(given.id || '')
                                                   : '';
    const memoKey = credentialId + '\u0000' + String(username || '');
    const memo = request && typeof request === 'object'
      ? recognitionMemo.get(request) : null;
    if (memo && memo.has(memoKey)) {
      log.debug("Leaving Authn.registeredDeviceFor(). Already recognised.");
      return memo.get(memoKey);
    }
    let fact = null;
    try {
      fact = deviceRecognition.recognize({
        request: request,
        webauthnCredentialId: credentialId,
        subject: username === undefined ? undefined : String(username),
        clientId: detail.application || undefined });
      if (request && typeof request === 'object') {
        const held = memo || new Map();
        held.set(memoKey, fact);
        recognitionMemo.set(request, held);
      }
    } catch (e) {
      log.error(this.deps.errorCodes.tag('STS-DEVICE-0029') + 'authn: ' +
                'recognising the device behind a sign-in threw: ' +
                ((e && e.stack) || e));
      fact = null;
    }
    log.debug("Leaving Authn.registeredDeviceFor(). " +
              (fact ? fact.id : 'none'));
    return fact;
  }

  // -------------------------------------------------------------------------
  // THE DEVICE ALONE, PUT TO THE ISSUANCE POLICY (#164 phase 6) for a door
  // that asked the rest before its credential was complete (`gated`). Asked
  // only where a device rule could refuse — the realm requires a compliant
  // device, or this one is compromised and the realm refuses one — so every
  // other gated sign-in costs nothing new. The role question is waived and
  // no risk facts are sent: both were asked already, and only a Deny about
  // the device refuses. True when it refused, with `refusedWith` and
  // `refusedWhy` on the caller's `detail`, as every refusal here writes.
  // -------------------------------------------------------------------------
  private refusedOnDevice(detail, username, via, method): boolean {
    const { log, gate, audit } = this.deps;
    log.debug("Entering Authn.refusedOnDevice().");
    const requirement = gate.deviceRequirementOf();
    const fact = this.registeredDeviceFor(detail, username);
    const matters = requirement.indexOf('compliant') >= 0 ||
      (!!fact && fact.status === 'compromised' &&
       requirement.indexOf('not-compromised') >= 0);
    if (!matters) {
      log.debug("Leaving Authn.refusedOnDevice(). No device rule applies.");
      return false;
    }
    const answer = gate.check({
      application: String(detail.application || ''),
      kind: gate.ISSUANCE.SESSION,
      subject: { kind: 'user', name: username,
                 authenticated: detail.authenticated !== false },
      claims: null, risk: null, rolesWaived: true, device: fact });
    if (answer.allowed || !answer.device) {
      log.debug("Leaving Authn.refusedOnDevice(). Allowed.");
      return false;
    }
    const code = answer.device.refusal === 'compromised' ? 'STS-DEVICE-0038'
                                                         : 'STS-DEVICE-0037';
    audit.audit({
      action: 'session.refuse', actor: username, errorCode: code,
      protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
      summary: 'a session for ' + username + ' was refused on its device ' +
               'at the ' + (via || 'sign-in') + ' door',
      detail: Object.assign(this.attemptFacts(detail.application, method), {
        why: answer.why,
        device: fact ? String(fact.id) : '',
        policy: answer.policy || ''
      }) });
    detail.refusedWith = code;
    detail.refusedWhy = answer.why;
    log.info('authn: a session for "' + username + '" was REFUSED on its ' +
             'device (' + answer.device.refusal + ').');
    log.debug("Leaving Authn.refusedOnDevice(). Refused.");
    return true;
  }

  // The registered device the session's LATEST authentication event
  // recognised, or null (#164 phase 2). What a later phase reads.
  /**
   * Returns the registered device the session's latest authentication event
   * recognised.
   *
   * @param session - the session
   * @returns the device, or null
   */
  registeredDeviceOf(session) {
    const { log } = this.deps;
    log.debug("Entering Authn.registeredDeviceOf().");
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const last = events.length ? events[events.length - 1] : null;
    log.debug("Leaving Authn.registeredDeviceOf().");
    return (last && last.registeredDevice) || null;
  }

  // ---------------------------------------------------------------------------
  // DID THIS FACTOR AUTHENTICATE THIS SESSION? (#722, 2026-10-19)
  //
  // Asked by `logout/logout.ts`'s `endFactorSessions()` when a person or an
  // administrator removes a credential: every session one of whose
  // authentication events names the credential ends, and every other
  // survives. It is asked HERE because the event is this module's record and
  // its shape is this module's to read — a second reader of
  // `context.credential` elsewhere would be a second answer to "what proved
  // this".
  //
  // `factor.kind` is one of four:
  //
  //   * `webauthn` with `credentialId`: an event whose credential is a
  //     WebAuthn one with that id's fingerprint (`eventContext()` keeps the
  //     fingerprint, never the id) — as the first factor (a passkey) or as a
  //     step after a password, at a sign-in or a re-authentication;
  //   * `totp`: an event the authenticator app's code completed;
  //   * `backup-code`: an event a recovery code completed;
  //   * `email`: an event the emailed code or link completed AS A SECOND
  //     FACTOR. Clearing that factor leaves the emailed FIRST factor (a
  //     sign-in link) alone, so its sessions stay: a first-factor event's
  //     `amr` is the one `otp` (`finishEmailFirstFactor()`), and a second
  //     factor's carries the first factor's beside it.
  //
  // EVERY EVENT IS READ, not the latest: a session that began with the key
  // being removed and then re-authenticated with another was still the
  // removed key's to begin with. `MAX_SESSION_EVENTS` keeps the first event
  // and the latest ones, so the event that BEGAN a session is never dropped;
  // a middle one can be, and that loses nothing an attacker could use —
  // reaching a middle event at all means holding the session already.
  // ---------------------------------------------------------------------------
  /**
   * Says whether one of a session's authentication events was completed by
   * the factor named (#722).
   *
   * @param session - the session
   * @param factor - `{ kind: 'webauthn', credentialId }`, or `{ kind }` for
   *   `totp`, `backup-code` or `email`
   * @returns true when an event names it
   */
  sessionNamesFactor(session, factor) {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Authn.sessionNamesFactor().");
    const kind = String((factor && factor.kind) || '');
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const print = kind === 'webauthn'
      ? stsCrypto.credentialFingerprint(String(factor.credentialId || ''))
      : '';
    if (!kind || (kind === 'webauthn' && !print)) {
      log.debug("Leaving Authn.sessionNamesFactor(). No factor named.");
      return false;
    }
    const named = events.some(function (event) {
      const given = (event && event.context && event.context.credential) ||
                    {};
      const was = String(given.kind || '');
      if (kind === 'webauthn') {
        return was === 'webauthn' && String(given.fingerprint || '') === print;
      }
      if (kind === 'email') {
        return was.indexOf('email-') === 0 &&
               Array.isArray(event.amr) && event.amr.length > 1;
      }
      return was === kind;
    });
    log.debug("Leaving Authn.sessionNamesFactor(). " + named);
    return named;
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
    // A FEDERATED SIGN-IN'S RELATIONSHIP (#565), by its id: not a secret, and
    // what an operator's per-relationship risk factor names.
    if (given.relationship) {
      credential.relationship = String(given.relationship);
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
    // The signature algorithm a WebAuthn ceremony was verified with
    // (2026-10-01).
    if (given.algorithm) {
      credential.algorithm = String(given.algorithm);
    }
    if (typeof given.coseAlg === 'number') {
      credential.coseAlg = given.coseAlg;
    }
    // And the passkey's lane (#643).
    if (given.lane === 'classical' || given.lane === 'pqc') {
      credential.lane = String(given.lane);
    }
    // WHICH WEBAUTHN CEREMONY, AND WHETHER THE KEY'S ATTESTATION IS TRUSTED
    // (#723): the evidence `common/phishing_resistance.ts` reads for OpenID
    // Connect EAP's `phr` and `phrh`, on the event so a later request for
    // either is answered from what this sign-in actually proved.
    if (given.ceremony === 'assertion' || given.ceremony === 'registration') {
      credential.ceremony = given.ceremony;
    }
    if (typeof given.attestationTrusted === 'boolean') {
      credential.attestationTrusted = given.attestationTrusted;
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
  /**
   * Returns when a session began: its first authentication event, else its
   * `authTime`.
   *
   * @param session - the session
   * @returns the instant in milliseconds, or 0
   */
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
  /**
   * Describes how a person is signed in, read from the sign-on session behind a
   * relying-party session while it is live.
   *
   * @param session - a relying-party or sign-on session
   * @returns `{ startedAt, authTime, amr, acr, authentications, fromParent }`
   */
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
      fromParent: fromParent,
      // Whether the sign-on session is bound to a browser key (#725).
      deviceBound: deviceBound.bindingOf(source)
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
    const event = this.authenticationEvent(amr, acr, via, extra, username);
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
      // Offered again where the session is not bound yet (#725).
      deviceBound.offer(res, session);
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
      detail: Object.assign(this.attemptFacts(extra.application,
        this.methodPhraseFor(event.amr)), {
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
      })
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
        registeredDevice: event.registeredDevice || null,
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
      // What THIS request proves about a registered device (#164 phase 5):
      // a client certificate on its connection, or nothing — a replayed
      // cookie proves no device, which is what the device signals then say.
      registeredDevice: this.registeredDeviceFor({ request: req },
        String(session.user.username || '')),
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
  /**
   * Replaces a live session's risk assessment in the ambient realm, through the
   * store.
   *
   * @param id - the session id
   * @param risk - the new assessment
   * @returns true when adopted, false when there is no live session
   */
  adoptSessionRisk(id: string, risk: any): boolean {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.adoptSessionRisk(). " + id);
    let session = null;
    if (this.windowOn()) {
      const read = sessionWindow.get(realms.currentId(), String(id || ''));
      if (!read.ok) {
        log.debug("Leaving Authn.adoptSessionRisk(). No live session.");
        return false;
      }
      session = read.session;
    } else {
      session = sessions.get(String(id || ''));
    }
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
  /**
   * Lists every live, person-held session that carries a risk, in every realm,
   * for the `risk.rescore` job.
   *
   * @returns `{ realm, id, session }` for each
   */
  sessionsForRisk(): any[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Authn.sessionsForRisk().");
    const out = [];
    realms.list().forEach(function (realm) {
      const store = sessions.realmMap(realm.id);
      let rows = null;
      if (self.windowOn()) {
        rows = self.indexedSessions(realm.id, store);
        if (rows === null) {
          return;
        }
      } else {
        if (!store || !store.size) {
          return;
        }
        rows = [];
        store.forEach(function (session, id) {
          rows.push({ id: id, session: session });
        });
      }
      rows.forEach(function (row) {
        const session = row.session;
        const id = row.id;
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
  /**
   * Ends a hosted surface's relying-party sessions for one person, in response
   * to a received signal.
   *
   * Each ends through the ordinary sign-out path, so it is audited and
   * announced.
   *
   * @param surfaceId - `admin` or `portal`
   * @param fromRealm - the realm the event arrived in
   * @param about - says whether a session's user is the one the event names
   * @param via - what ended them, for the audit row
   * @param initiatingEntity - CAEP's initiating entity
   * @returns how many sessions ended
   */
  endRelyingPartySessions(surfaceId: string, fromRealm: string,
                          about: (user: any, session?: any) => boolean,
                          via: string, initiatingEntity: string): number {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Authn.endRelyingPartySessions(). " + surfaceId);
    const partition = surfaceId === 'admin' ? realms.DEFAULT_ID : fromRealm;
    const store = sessions.realmMap(partition);
    const doomed: string[] = [];
    const matches = function (session, id) {
      log.debug("Entering matches().");
      const yes = !!(session && session.rpSurface === surfaceId &&
        String(session.derivedFromRealm || partition) === fromRealm &&
        session.user && about(session.user, session) && id);
      log.debug("Leaving matches().");
      return yes;
    };
    if (this.windowOn()) {
      const keys = sessionWindow.indexKeys('session.surface',
                                            [partition, surfaceId]);
      if (keys === null) {
        log.debug("Leaving Authn.endRelyingPartySessions(). 0 ended.");
        return 0;
      }
      const seen: Record<string, boolean> = {};
      keys.forEach(function (digest) {
        const loaded = sessionWindow.loadByDigest(partition, digest);
        if (!loaded.ok || !loaded.session) {
          return;
        }
        const id = String(loaded.session.id || '');
        if (!matches(loaded.session, id) || seen[id]) {
          return;
        }
        seen[id] = true;
        doomed.push(id);
      });
      // The held ones the index has not reached yet: only this surface's,
      // by the store's own index (#767), where this walked every session
      // the process held — once per signal a surface received, and each
      // password write sends one.
      if (store) {
        self.heldSurfaceSessions(store, surfaceId)
          .forEach(function (one: { id: string; session: any }): void {
          if (seen[one.id] || !matches(one.session, one.id)) {
            return;
          }
          doomed.push(one.id);
        });
      }
    } else if (store) {
      self.heldSurfaceSessions(store, surfaceId)
        .forEach(function (one: { id: string; session: any }): void {
        if (matches(one.session, one.id)) {
          doomed.push(one.id);
        }
      });
    }
    doomed.forEach(function (id: string): void {
      realms.run(realms.get(partition), function () {
        self.dropSession(id, via, false, null, initiatingEntity);
      });
    });
    log.debug("Leaving Authn.endRelyingPartySessions(). " + doomed.length +
              " ended.");
    return doomed.length;
  }

  // The sessions a realm's store holds for one hosted surface, by the
  // store's index (`sessions`' `indexBy`, #767). Each is read back, so a key
  // the index names is answered only while a session is there.
  private heldSurfaceSessions(store: any, surfaceId: string):
    { id: string; session: any }[] {
    const { log } = this.deps;
    log.debug("Entering Authn.heldSurfaceSessions(). " + surfaceId);
    const out: { id: string; session: any }[] = [];
    if (typeof store.lookup !== 'function') {
      // A store with no index (a test's stub): the walk, as before #767.
      store.forEach(function (session: any, id: string): void {
        out.push({ id: id, session: session });
      });
      log.debug("Leaving Authn.heldSurfaceSessions(). Walked.");
      return out;
    }
    (store.lookup('rp:' + String(surfaceId)) || [])
      .forEach(function (id: string): void {
      const session = store.get(id);
      if (session) {
        out.push({ id: id, session: session });
      }
    });
    log.debug("Leaving Authn.heldSurfaceSessions(). " + out.length);
    return out;
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
  /**
   * Scores a sign-in's risk before `startSession()`, for the issuance policy to
   * decide on.
   *
   * Never a refusal itself: a failure in the engine answers null.
   *
   * @param req - the request
   * @param username - who is signing in
   * @param via - the door
   * @param detail - what the door would hand `startSession()`
   * @returns the assessment, or null when there is no person to assess or no
   *   facts
   */
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
    // A NEWCOMER (#565): a federated sign-in that would CREATE the person has
    // no entry yet, and so no `sub` — and that is the sign-in the evidence
    // signals matter most for, since a consumer provider makes an account as
    // cheap as signing in. The door names a provisional subject for it, one
    // per partner subject, under which it is assessed as a first sign-in:
    // unscored on the model, decided on the evidence.
    const subject = user.sub ? String(user.sub)
      : String(d.provisionalSubject || '');
    if (!subject || !engine) {
      log.debug("Leaving Authn.assessSignIn(). Nobody to assess.");
      return null;
    }
    const headers = (req && req.headers) || {};
    const assessment = await engine.assess({
      realm: realms.currentId(), subject: subject,
      username: String(username), sessionId: '',
      door: String(via || ''), clientId: String(d.application || ''),
      context: this.eventContext(d),
      // THE REGISTERED DEVICE, recognised NOW (#164 phase 5) — before the
      // session and its event exist, because the risk engine scores it; the
      // event asks again for the same request and gets this same answer.
      registeredDevice: this.registeredDeviceFor(d, String(username)),
      // A WEBAUTHN CEREMONY MAY FOLLOW (#259): the door says so, and the
      // session's start amends this assessment with the device the
      // ceremony proved (`startSessionHere()`, `risk_engine.ts`'s
      // `amend()`).
      deviceAwaited: d.deviceAwaited === true,
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
  // Which mechanism, in which role, the authentication policy refuses for
  // this session — its code — or ''. See the paragraph in startSession().
  private authnPolicyRefusal(amr: any, credential: any): string {
    const { log, authnPolicy } = this.deps;
    log.debug("Entering Authn.authnPolicyRefusal().");
    const kind = String((credential && credential.kind) || '');
    const factors = Array.isArray(amr) ? amr.map(String) : [];
    const ONLY_FIRST: Record<string, string> = {
      certificate: 'certificate', kerberos: 'kerberos',
      federation: 'federation'
    };
    let mechanism = '';
    let role: 'primary' | 'second-factor' = factors.length <= 1
      ? 'primary' : 'second-factor';
    if (ONLY_FIRST[kind]) {
      mechanism = ONLY_FIRST[kind];
      role = 'primary';
    } else if (kind === 'password') {
      mechanism = 'password';
    } else if (kind === 'wallet') {
      mechanism = 'wallet';
    } else if (kind === 'email-code') {
      mechanism = 'emailCode';
    } else if (kind === 'email-link') {
      mechanism = 'emailLink';
    } else if (kind === 'webauthn' && factors.indexOf('pwd') < 0) {
      // A PASSKEY AS THE FIRST FACTOR, alone (`["hwk"]`) or with the
      // verification the authenticator performed (`["hwk","user"]`, #474):
      // either way no other first factor was presented, and a passkey is
      // what the policy is asked about.
      mechanism = 'passkey';
      role = 'primary';
    }
    // A held second factor is never refused here (see the caller).
    const refused = mechanism && !authnPolicy.allows(mechanism, role);
    const code = !refused ? ''
      : (role === 'primary' ? 'STS-AUTHN-0268' : 'STS-AUTHN-0269');
    log.debug("Leaving Authn.authnPolicyRefusal(). " + (code || 'allowed'));
    return code;
  }

  // THE PASSKEY QUESTION AT SIGN-IN (#536): whether the passkey that
  // answered may sign this person in, asked of the issuance policy with the
  // facts this line holds — the credential's BE flag as the door read it
  // (#528), and the minimum PIN length the key REPORTED at registration,
  // read off its row on the person's entry (#529), and its signature
  // algorithm with the lane it was made in (#718) — the ROW's, through
  // `keyAlgorithm()`, which also reads a row that recorded none; the
  // ceremony's own where no row was found. Whether that algorithm is
  // post-quantum is the question's to say. Null for anything but a
  // WebAuthn credential, or where the policy allows it.
  private passkeySignInRefusal(username: string, credential: any):
      { code: string; why: string; reason: string } | null {
    const { log, passkeyPolicy, credentials } = this.deps;
    log.debug("Entering Authn.passkeySignInRefusal().");
    if (!credential || String(credential.kind || '') !== 'webauthn') {
      log.debug("Leaving Authn.passkeySignInRefusal(). Not a passkey.");
      return null;
    }
    const id = String(credential.id || '');
    const key = credentials.keysOf(username).filter(function (one) {
      return String(one.credentialId) === id;
    })[0] || null;
    const facts: Record<string, any> = {
      username: username,
      minPinLength: key ? key.minPinLength : null
    };
    if (typeof credential.backupEligible === 'boolean') {
      facts.backupEligible = credential.backupEligible;
    }
    if (key) {
      const algorithm = credentials.keyAlgorithm(key);
      facts.algorithm = algorithm.name;
      facts.lane = algorithm.lane;
    } else if (credential.algorithm) {
      facts.algorithm = String(credential.algorithm);
      facts.lane = String(credential.lane || 'classical');
    }
    const out = passkeyPolicy.refusalFor('sign-in', facts);
    log.debug("Leaving Authn.passkeySignInRefusal(). " +
              (out ? out.code : 'allowed'));
    return out;
  }

  // THE ALGORITHM MISMATCH (#943): the key that signed, read off its ROW as
  // #718's question reads it, against every key the person holds; the
  // ceremony library decides whether it is one and writes the row. Never
  // throws, and decides nothing.
  private noteAlgorithmMismatch(username: string, credential: any,
                                via: string): void {
    const { log, credentials, passkeyPolicy } = this.deps;
    log.debug("Entering Authn.noteAlgorithmMismatch().");
    try {
      const keys = credentials.keysOf(username);
      const id = String(credential.id || '');
      const key = keys.filter(function (one) {
        return String(one.credentialId) === id;
      })[0] || null;
      this.deps.webauthnCeremonies.algorithmMismatch({
        username: username,
        used: key ? credentials.keyAlgorithm(key).name
                  : String(credential.algorithm || ''),
        held: keys.map(function (one) {
          return credentials.keyAlgorithm(one).name;
        }),
        required: passkeyPolicy.requiresPostQuantum('sign-in'),
        door: String(via || '') });
    } catch (e) {
      // Evidence, never the sign-in: a row that could not be written leaves
      // the session to start.
      log.debug("Caught in Authn.noteAlgorithmMismatch(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving Authn.noteAlgorithmMismatch().");
  }

  // THE PASSKEY STEP'S CEREMONY ROW (#943), at every way the step's act
  // ends: the browser's refusal, the RP ID, enrolment switched off, a check
  // that threw, and `finishWebauthn()` — verified or refused. What was
  // offered: for a registration the lane's algorithms as the verifier held
  // the credential to them (`expectedAlgorithms`), for an assertion the
  // algorithms of the person's keys of the step's role.
  private noteStepCeremony(req: any, body: any, step: any,
                           refusedWith: string, verdict?: any): void {
    const { log, credentials, webauthnPolicy } = this.deps;
    log.debug("Entering Authn.noteStepCeremony(). " +
              (refusedWith || 'completed'));
    try {
      const registration = String((body && body.mode) || '') === 'create';
      const role = step.passwordless ? 'primary' : 'mfa';
      const lane = String(step.lane || 'classical');
      const v = verdict || {};
      const posted = (body && body.posted) || {};
      const keys = credentials.keysOf(step.username);
      const named = String(posted.rawId || posted.id || '');
      const own = keys.filter(function (one) {
        return registration
          ? String(one.credentialId) === String(v.credentialId || '')
          : String(one.credentialId) === named;
      })[0] || null;
      this.deps.webauthnCeremonies.record({
        ceremony: registration ? 'registration' : 'assertion',
        door: 'sign-in-step', username: step.username, role: role,
        lane: registration ? lane
                           : (own ? credentials.keyLane(own) : ''),
        outcome: refusedWith ? 'refused' : 'success',
        errorCode: refusedWith,
        offered: registration ? webauthnPolicy.algorithmIds(lane)
          : keys.filter(function (one) {
            return one.role === role;
          }).map(function (one) {
            return credentials.keyAlgorithm(one).name;
          }),
        algorithm: String(v.algorithm ||
                          (own ? credentials.keyAlgorithm(own).name : '')),
        posted: posted,
        attestation: registration && own ? own.attestation : null,
        req: req });
    } catch (e) {
      // Evidence, never the ceremony.
      log.debug("Caught in Authn.noteStepCeremony(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving Authn.noteStepCeremony().");
  }

  // THE USERNAMELESS SIGN-IN'S CEREMONY ROW (#943), from what
  // `passkeySignIn()` learnt (`passkeyCeremonies`), once per response.
  private notePasskeyCeremony(res: any, refusedWith: string): void {
    const { log, credentials } = this.deps;
    log.debug("Entering Authn.notePasskeyCeremony().");
    const held = passkeyCeremonies.get(res);
    if (!held) {
      log.debug("Leaving Authn.notePasskeyCeremony(). No ceremony ran.");
      return;
    }
    passkeyCeremonies.delete(res);
    try {
      const known = held.known || null;
      this.deps.webauthnCeremonies.record({
        ceremony: 'assertion', door: 'usernameless',
        username: String(held.owner || ''), role: 'primary',
        lane: known ? credentials.keyLane(known) : '',
        outcome: refusedWith ? 'refused' : 'success',
        errorCode: refusedWith,
        offered: held.owner ? credentials.keysOf(held.owner)
          .filter(function (one) {
            return one.role === 'primary';
          }).map(function (one) {
            return credentials.keyAlgorithm(one).name;
          }) : [],
        algorithm: String(held.algorithm ||
                          (known ? credentials.keyAlgorithm(known).name
                                 : '')),
        posted: held.posted, req: held.req });
    } catch (e) {
      // Evidence, never the sign-in.
      log.debug("Caught in Authn.notePasskeyCeremony(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving Authn.notePasskeyCeremony().");
  }

  // A PASSKEY THE PASSKEY RULES REFUSED AT SIGN-IN FOR A REASON THAT
  // CHANGES ITS STANDING (#718, the post-quantum requirement): marked on
  // the key's row the first time per key and reason
  // (`credentials.noteKeyPolicyRefused()`), and only then a CAEP
  // credential-change by `policy`, as `attestationAtSignIn()` does for
  // #530. Never throws: a signal that cannot be sent leaves the refusal as
  // it is.
  private notePasskeyStanding(username: string, credential: any,
                              refusal: { code: string; why: string;
                                         reason: string }): void {
    const { log, credentials, accountSignals } = this.deps;
    log.debug("Entering Authn.notePasskeyStanding(). " + refusal.reason);
    try {
      const id = String((credential && credential.id) || '');
      const key = credentials.keysOf(username).filter(function (one) {
        return String(one.credentialId) === id;
      })[0] || null;
      if (!key || !credentials.noteKeyPolicyRefused(username, id,
                                                    refusal.reason,
                                                    refusal.code,
                                                    refusal.why)) {
        log.debug("Leaving Authn.notePasskeyStanding(). Nothing new.");
        return;
      }
      accountSignals.credentialChanged({
        username: username,
        credentialType: accountSignals.keyCredentialType(key),
        fido2Aaguid: credentials.Credentials.aaguidString(key.aaguid),
        friendlyName: String(key.label || ''),
        changeType: 'update', initiatingEntity: 'policy', via: 'sign-in',
        reasonAdmin: 'A passkey of ' + username + ' no longer meets this ' +
                     'realm\'s passkey policy: ' + refusal.why,
        reasonUser: 'One of your passkeys no longer meets this ' +
                    'service\'s rules and cannot sign you in.' });
      log.debug("Leaving Authn.notePasskeyStanding(). Signalled.");
    } catch (e) {
      // The refusal has been made and recorded already; a mark or a signal
      // that could not be sent must not turn it into an error page.
      log.debug("Caught in Authn.notePasskeyStanding(): " +
                ((e && e.message) || e));
      log.debug("Leaving Authn.notePasskeyStanding(). Threw.");
    }
  }

  // ---------------------------------------------------------------------------
  // THE RECOVERY QUESTION AT THE SESSION'S START (#724). A session for a
  // person who holds a passkey, when a recovery is PENDING on their entry (a
  // reset or activation link was spent, or an administrator gave out a
  // password, and no passkey has signed them in since) or when the
  // credential that answered is itself a recovery door (a recovery code, an
  // emailed code or link). The issuance policy decides (`recover-account`):
  // under the passkey policy's `recoveryAssurance` `not-weaker` such a
  // session reaches no application unless a passkey answered
  // (STS-AUTHN-0381), and under `operator-only` a self-service door is
  // refused outright (STS-AUTHN-0380). Asked only where there is a recovery
  // to ask about, so an ordinary sign-in costs one read of the entry and no
  // evaluation. Null where the policy allows it.
  // ---------------------------------------------------------------------------
  private recoveryRefusalAtSession(username: string, credential: any):
      { code: string; why: string; reason: string } | null {
    const { log, passkeyPolicy, credentials } = this.deps;
    log.debug("Entering Authn.recoveryRefusalAtSession().");
    // A key REGISTERED in the act is not a passkey that signed them in
    // (#901): it was enrolled on the strength of the recovery itself, so it
    // is named apart and the not-weaker rule, which asks for `webauthn`,
    // does not count it. EAP's `phr` treats it the same way.
    const registered = !!credential &&
      String(credential.kind || '') === 'webauthn' &&
      String(credential.ceremony || '') === 'registration';
    const kind = registered ? 'webauthn-registration'
      : String((credential && credential.kind) || '');
    const door = passkeyPolicy.RECOVERY_CREDENTIALS[kind] || '';
    const pending = credentials.recoveryPending(username);
    if (!pending && !door) {
      log.debug("Leaving Authn.recoveryRefusalAtSession(). No recovery.");
      return null;
    }
    const out = passkeyPolicy.recoveryRefusal({ username: username,
      door: door, at: 'session', credential: kind,
      covered: credentials.holdsPasskey(username), pending: !!pending });
    log.debug("Leaving Authn.recoveryRefusalAtSession(). " +
              (out ? out.code : 'allowed'));
    return out;
  }

  // A PASSKEY SIGNED THEM IN AFTER A RECOVERY (#724): the pending recovery
  // is cleared, and an audit row says so. Only a passkey that has passed
  // every passkey rule above reaches here, which is what "a passkey
  // satisfying the profile" means.
  private recoveryCompleted(username: string, extra: any): void {
    const { log, credentials, audit } = this.deps;
    log.debug("Entering Authn.recoveryCompleted().");
    // An ASSERTION only (#901): a key registered in the act proves nothing
    // the recovery did not already grant.
    if (!extra || !extra.credential ||
        String(extra.credential.kind || '') !== 'webauthn' ||
        String(extra.credential.ceremony || 'assertion') !== 'assertion') {
      log.debug("Leaving Authn.recoveryCompleted(). Not a passkey's " +
                "assertion.");
      return;
    }
    const pending = credentials.recoveryPending(username);
    if (!pending) {
      log.debug("Leaving Authn.recoveryCompleted(). None pending.");
      return;
    }
    credentials.setRecoveryPending(username, '');
    audit.audit({
      action: 'authn.recovery.completed', actor: username,
      target: username, channel: 'http', outcome: 'success',
      summary: 'a passkey signed ' + username + ' in after an account ' +
               'recovery (' + pending.door + '); the recovery is complete',
      detail: { door: pending.door, since: pending.at,
                application: String(extra.application || '') }
    });
    log.info('authn: a passkey signed "' + username + '" in after the ' +
             'recovery through ' + pending.door + '; it is no longer ' +
             'pending.');
    log.debug("Leaving Authn.recoveryCompleted().");
  }

  // Under a passkey policy that refuses self-service recovery to this
  // person (#724), a minted step offers neither a recovery code nor the
  // emailed factor. Asked of the issuance policy as the door would be.
  private closeSelfServiceRecovery(step: any): void {
    const { log, passkeyPolicy, credentials } = this.deps;
    log.debug("Entering Authn.closeSelfServiceRecovery().");
    const username = String(step.username || '');
    const covered = credentials.holdsPasskey(username);
    if (!covered) {
      log.debug("Leaving Authn.closeSelfServiceRecovery(). Holds no " +
                "passkey.");
      return;
    }
    const refuses = function (door: string): boolean {
      log.debug("Entering refuses(). " + door);
      const refused = !!passkeyPolicy.recoveryRefusal({ username: username,
        door: door, at: 'door', covered: true });
      log.debug("Leaving refuses(). " + refused);
      return refused;
    };
    if (step.backup && refuses('recovery-code')) {
      step.backup = false;
    }
    if (step.email && refuses(String(step.email) === 'link' ? 'email-link'
                                                            : 'email-code')) {
      step.email = '';
    }
    log.debug("Leaving Authn.closeSelfServiceRecovery().");
  }

  // ---------------------------------------------------------------------------
  // THE SESSION A RECOVERY LEADS TO, LIMITED TO REGISTERING A PASSKEY (#724).
  // `refusedSession()` calls it for STS-AUTHN-0381 at a door of the sign-in
  // screen, in place of drawing the refusal: the set-up step, offering ONLY
  // a passkey, minted `proved` (the recovery and the factor just given are
  // the proof; the person holds a passkey they cannot use) and `recovery`,
  // which makes the passkey page draw a REGISTRATION whatever keys they hold
  // and makes its finisher start NO session (`finishWebauthn()`): the
  // browser goes back to the application, which asks for a sign-in, and the
  // passkey just registered is what clears the recovery. The key goes
  // through `credentials.addKey()`, so the profile's registration rules
  // hold it. False where no passkey can be registered here, and the refusal
  // is drawn instead.
  // ---------------------------------------------------------------------------
  private recoveryEnrolment(res: any, record: any, username: string,
                            said: any): boolean {
    const { log, randomId, stsCrypto, audit, errorCodes } = this.deps;
    log.debug("Entering Authn.recoveryEnrolment().");
    const offered = this.enrolmentOfferedFor(['securityKey']);
    if (!offered.webauthn) {
      log.info(errorCodes.tag('STS-AUTHN-0383') + 'authn: a sign-in of "' +
               username + '" after an account recovery cannot register a ' +
               'passkey here (security keys are off, or not allowed as a ' +
               'second factor); refused.');
      log.debug("Leaving Authn.recoveryEnrolment(). Nothing to register.");
      return false;
    }
    const setupId = randomId(24);
    pendingMfa.set(setupId, {
      authn: record, username: username,
      challenge: stsCrypto.randomBytes(32).toString('base64url'),
      factor: 'enrol', alternate: '', backup: false, passwordless: false,
      requiredBy: 'recovery', proved: true, recovery: true,
      mfaAllowed: ['securityKey'], risk: said && said.risk,
      riskDecision: said && said.riskDecision,
      expires: Date.now() + this.mfaStepTtlMs()
    });
    audit.audit({
      action: 'authn.recovery.limited', outcome: 'success',
      errorCode: 'STS-AUTHN-0381', actor: username, target: username,
      channel: 'http', protocol: record && record.protocol,
      summary: 'a sign-in of ' + username + ' after an account recovery ' +
               'was limited to registering a passkey',
      detail: { credential: String((said && said.credential &&
                                    said.credential.kind) || ''),
                application: String((record && record.application) || '') }
    });
    log.info('authn: "' + username + '" signed in after an account ' +
             'recovery without a passkey; asking them to register one ' +
             'before anything is signed in.');
    errorCodes.mark(res, 'STS-AUTHN-0381');
    this.stepAnswer(res, 'mfa', 'enrol', setupId, MFA_SETUP_PATH, 'mfa');
    log.debug("Leaving Authn.recoveryEnrolment().");
    return true;
  }

  // THE ATTESTATION RULES AT SIGN-IN (#530): the key's recorded attestation
  // held to the rules in force now, where the passkey policy says so — the
  // issuance policy deciding since #536. A
  // refusal writes a `session.refuse` row and, the first time this key is
  // refused for this reason, a CAEP credential-change (#239's pattern: the
  // credential changed state, by policy). Asynchronous, because today's FIDO
  // metadata is a store lookup; never rejects.
  private async attestationAtSignIn(username: string, key: any,
      application?: string):
      Promise<{ code: string; why: string } | null> {
    // `audit` and `stsCrypto` from the deps too (#912), so a recording
    // audit dependency sees the refusal rows this writes.
    const { log, passkeyPolicy, webauthnAttestation, credentials,
      accountSignals, errorCodes, audit, stsCrypto } = this.deps;
    log.debug("Entering Authn.attestationAtSignIn().");
    if (!key) {
      log.debug("Leaving Authn.attestationAtSignIn(). No key.");
      return null;
    }
    try {
      // ASKED WHETHER OR NOT THE PASSKEY POLICY HOLDS SIGN-INS TO THE RULES
      // (#536): the issuance policy decides, and a realm's own may refuse on
      // the recorded attestation alone. The FIDO metadata is only looked up
      // while the passkey policy holds sign-ins to the rules.
      const verdict = await webauthnAttestation.signInVerdict(key, {
        username: username,
        enforced: passkeyPolicy.enforcesAttestationAtSignIn() });
      if (verdict.ok) {
        log.debug("Leaving Authn.attestationAtSignIn(). Allowed.");
        return null;
      }
      const code = errorCodes.codeOf(verdict) || 'STS-AUTHN-0316';
      const why = String(verdict.why || '');
      log.info('authn: a passkey of "' + username + '" was REFUSED at sign-' +
               'in by the attestation rules in force (' + code + '): ' + why);
      audit.audit({
        action: 'session.refuse', actor: String(username || ''),
        errorCode: code, protocol: 'WebAuthn', channel: 'http', target: '',
        summary: 'a passkey of ' + username + ' was refused at sign-in: ' +
                 'the attestation rules in force no longer accept it',
        detail: Object.assign(this.attemptFacts(application,
          'webauthn'), {
          credential: 'webauthn',
          credentialFingerprint: stsCrypto.credentialFingerprint(
            String(key.credentialId || '')),
          aaguid: credentials.Credentials.aaguidString(key.aaguid)
        })
      });
      // A KEY WHOSE ATTESTATION'S ALGORITHMS NO LONGER SATISFY THE PROFILE
      // (#941, STS-AUTHN-0412) changed standing as one #530 refuses did, so
      // it is marked and signalled the same way, once.
      if ((code === 'STS-AUTHN-0316' || code === 'STS-AUTHN-0412') &&
          credentials.noteKeyAttestationRefused(username, key.credentialId,
                                                code, why)) {
        accountSignals.credentialChanged({
          username: username,
          credentialType: accountSignals.keyCredentialType(key),
          fido2Aaguid: credentials.Credentials.aaguidString(key.aaguid),
          friendlyName: String(key.label || ''),
          changeType: 'update', initiatingEntity: 'policy', via: 'sign-in',
          reasonAdmin: 'A passkey of ' + username + ' no longer meets this ' +
                       'realm\'s attestation rules: ' + why,
          reasonUser: 'One of your passkeys no longer meets this ' +
                      'service\'s rules and cannot sign you in.' });
      }
      log.debug("Leaving Authn.attestationAtSignIn(). Refused.");
      return { code: code, why: why };
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0317') + 'authn: holding a ' +
                'passkey of "' + username + '" to the attestation rules ' +
                'threw: ' + ((e && e.stack) || e));
      log.debug("Leaving Authn.attestationAtSignIn(). Threw.");
      return { code: 'STS-AUTHN-0317',
               why: 'This passkey could not be checked against this ' +
                    'realm\'s rules. Try again.' };
    }
  }

  /**
   * Starts (or upgrades) the sign-on session for a person who has
   * authenticated, and sets its cookie.
   *
   * The one place every session is created. A refusal (a disabled account, the
   * authentication or issuance policy, a device, a realm being removed) answers
   * null and writes `refusedWith` and `refusedWhy` on `detail`.
   *
   * @param res - the response the cookie is set on
   * @param username - the person
   * @param amr - the authentication methods
   * @param acr - the authentication context class
   * @param via - the door, for the audit row and the event
   * @param detail - the request, credential, application and risk
   * @returns the session, or null when refused
   */
  startSession(res, username, amr, acr, via, detail) {
    const { log } = this.deps;
    log.debug("Entering Authn.startSession().");
    const session = this.startSessionHere(res, username, amr, acr, via,
                                          detail);
    // THE BROWSER IS PINNED TO THE CELL THAT HOLDS ITS SESSION (#98 D9), so
    // it keeps reaching this cell whichever cell DNS answers it with next —
    // a traveller moving between regions, or a balancer's health check
    // moving it. A no-op in single-cell mode.
    if (session && cells.isMulti()) {
      cellPlacement.setAffinity((detail && detail.request) || {}, res,
                                realms.currentId(), cells.id());
    }
    log.debug("Leaving Authn.startSession().");
    return session;
  }

  // What startSession() did before cells: every path that makes a session.
  // ---------------------------------------------------------------------------
  // A SIGN-IN WITH A MECHANISM THE APPLICATION DOES NOT ALLOW (#457). The
  // screen offered only the allowed ones; this is somebody who reached another
  // door anyway — a password posted to a screen that drew none, a link kept
  // from before, a direct URL. Refused, with the policy's sentence naming the
  // mechanisms, which `refusedSession()` draws the screen again with.
  // ---------------------------------------------------------------------------
  // A second factor the application does not allow (#475) is refused the
  // same way, under its own code: `answer.mechanism.secondFactor` says so.
  private refuseOnMechanism(extra, username, via, answer, method) {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering Authn.refuseOnMechanism().");
    const secondFactor = answer.mechanism.secondFactor === true;
    const code = secondFactor ? 'STS-AUTHN-0305' : 'STS-AUTHN-0298';
    log.info(errorCodes.tag(code) + 'authn: a session for "' +
             username + '" was REFUSED at the ' + (via || 'sign-in') +
             ' door: "' + String(extra.application || '') + '" allows ' +
             (secondFactor ? 'the second factors ' : '') +
             answer.mechanism.allowed.join(', ') + '.');
    audit.audit({
      action: 'session.refuse', actor: username,
      errorCode: code,
      protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
      summary: 'a session for ' + username + ' was refused at the ' +
               (via || 'sign-in') + ' door: the application does not allow ' +
               (secondFactor ? 'that second factor'
                             : 'that sign-in mechanism'),
      detail: Object.assign(this.attemptFacts(extra.application, method), {
        allowed: answer.mechanism.allowed,
        used: answer.mechanism.satisfied,
        policy: answer.policy || ''
      })
    });
    extra.refusedWith = code;
    extra.refusedWhy = answer.why;
    log.debug("Leaving Authn.refuseOnMechanism().");
    return null;
  }

  private startSessionHere(res, username, amr, acr, via, detail) {
    const { log, randomId, userFor, helpers, stats, gate, audit,
      errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Authn.startSessionHere(). username=" + username + ", acr=" +
              acr);
    const extra = detail || {};
    // What a session.refuse on this sign-in names (#954): the application
    // the door had, and the method the acceptance row will use. Ahead of
    // the reason in every detail below, so the twelve-key cap keeps them.
    const attemptMethod = extra.authenticated === false ? 'declined'
      : this.methodPhraseFor(amr);
    // THE PASSKEY POLICY FOR THIS PERSON AND APPLICATION (#535), which the
    // passkey refusals below read.
    this.deps.passkeyPolicy.select(username, extra.application);
    // -------------------------------------------------------------------------
    // A REALM BEING REMOVED STARTS NO SESSION (#262, 2026-09-26), from any
    // door, in either mode, authenticated or not — before everything below,
    // the disabled account included. `realms.retire()` has marked the realm
    // and is ending every session in it; one started now would be dropped by
    // the purge with no `session-revoked` and no Logout Token. The issuance
    // gate refuses the same, but the sign-in screen asks it ahead of time and
    // passes `gated: true`, so this line is what holds for every door.
    // -------------------------------------------------------------------------
    const retiring = realms.retiringRefusal();
    if (retiring) {
      log.info('authn: a session for "' + username + '" was REFUSED at the ' +
               (via || 'sign-in') + ' door: ' + retiring.why);
      audit.audit({
        action: 'session.refuse', actor: String(username || ''),
        errorCode: 'STS-CORE-0121',
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused at the ' +
                 (via || 'sign-in') + ' door: the realm is being removed',
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), { why: retiring.why })
      });
      extra.refusedWith = 'STS-CORE-0121';
      extra.refusedWhy = retiring.why;
      log.debug("Leaving Authn.startSessionHere(). The realm is being removed.");
      return null;
    }
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
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), {
          why: 'pwdAccountLockedTime is set on the entry'
        })
      });
      extra.refusedWith = 'STS-AUTHN-0201';
      log.debug("Leaving Authn.startSessionHere(). The account is disabled.");
      return null;
    }
    // -------------------------------------------------------------------------
    // A SERVICE ACCOUNT AT A BROWSER (#221), from any door that starts a
    // browser session — the password screen, a passkey, a certificate,
    // SPNEGO, a wallet, a federation partner — in either mode, where the
    // realm's service-account policy keeps `allowBrowserSignIn` off (the
    // default). A KEYED session (SCIM, the SPIRE Server API) is a program's
    // record and is not asked; an unauthenticated one names nobody.
    // -------------------------------------------------------------------------
    if (extra.authenticated !== false && !extra.key &&
        this.deps.credentials.serviceAccountRefusesDoor(username, 'browser')) {
      log.info('authn: a session for "' + username + '" was REFUSED at the ' +
               (via || 'sign-in') + ' door: it is a service account and this ' +
               'realm\'s service-account policy refuses it every browser ' +
               'sign-in.');
      audit.audit({
        action: 'session.refuse', actor: String(username || ''),
        errorCode: 'STS-SVCACCT-0010',
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused at the ' +
                 (via || 'sign-in') + ' door: a service account may not ' +
                 'sign in at a browser in this realm',
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), {
          why: 'stsServiceAccount is TRUE and the service-account ' +
               'policy\'s allowBrowserSignIn is off'
        })
      });
      extra.refusedWith = 'STS-SVCACCT-0010';
      log.debug("Leaving Authn.startSessionHere(). A service account at a " +
                "browser.");
      return null;
    }
    // -------------------------------------------------------------------------
    // THE AUTHENTICATION POLICY (#64), ASKED AT THE ONE LINE EVERY DOOR
    // REACHES. Which mechanism answered — the credential kind the door names —
    // and in which role: a first factor where this is the only `amr` value, or
    // where the mechanism can only ever be one (a certificate, a Kerberos
    // ticket, a federation partner); otherwise the second. A door that names
    // no credential is not asked. HELD second factors — an authenticator app,
    // a security key in the mfa role, a recovery code — are NOT refused
    // here: their rows stop new ones, never one already held (the contract
    // `totp.enabled` kept). A refusal is `null`, which every door already
    // draws as the policy's refusal.
    // -------------------------------------------------------------------------
    const policyCode = extra.authenticated === false ? ''
      : this.authnPolicyRefusal(amr, extra.credential);
    if (policyCode) {
      log.info('authn: a session for "' + username + '" was REFUSED at the ' +
               (via || 'sign-in') + ' door: this realm\'s authentication ' +
               'policy does not accept ' +
               String(extra.credential && extra.credential.kind) +
               ' there (' + policyCode + ').');
      audit.audit({
        action: 'session.refuse', actor: String(username || ''),
        errorCode: policyCode,
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused at the ' +
                 (via || 'sign-in') + ' door: the authentication policy ' +
                 'does not accept that mechanism in that role',
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), {
          credential: String(extra.credential && extra.credential.kind)
        })
      });
      extra.refusedWith = policyCode;
      log.debug("Leaving Authn.startSessionHere(). The policy refused.");
      return null;
    }
    // -------------------------------------------------------------------------
    // A SYNCED PASSKEY WHERE THE REALM TAKES ONLY DEVICE-BOUND ONES (#528),
    // asked here for the authentication policy's reason above: every door a
    // passkey signs somebody in through — the passkey step after a password,
    // the passwordless one, the usernameless sign-in — names its credential's
    // BE flag, and this is the line they all reach. BE never changes for a
    // credential, so this is what refuses a synced key enrolled before the
    // realm said no; `credentials.addKey()` refuses a new one. The same
    // question carries the key's reported minimum PIN length (#529), and
    // since #536 the ISSUANCE POLICY decides both (`passkeySignInRefusal()`).
    // -------------------------------------------------------------------------
    const syncedRefusal = extra.authenticated === false ? null
      : this.passkeySignInRefusal(username, extra.credential);
    if (syncedRefusal) {
      log.info('authn: a session for "' + username + '" was REFUSED at the ' +
               (via || 'sign-in') + ' door: the passkey policy refused the ' +
               'passkey that answered (' + syncedRefusal.code + '): ' +
               syncedRefusal.why);
      audit.audit({
        action: 'session.refuse', actor: String(username || ''),
        errorCode: syncedRefusal.code,
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused at the ' +
                 (via || 'sign-in') + ' door: ' +
                 (syncedRefusal.reason === 'pin-length'
                   ? 'the passkey\'s minimum PIN length is not what the ' +
                     'passkey policy requires'
                   : syncedRefusal.reason === 'backup-eligible'
                     ? 'a synced (backup-eligible) passkey, where the ' +
                       'passkey policy takes only device-bound ones'
                     : syncedRefusal.reason === 'post-quantum'
                       ? 'a passkey whose signature algorithm is not ' +
                         'post-quantum, where the passkey policy requires ' +
                         'a post-quantum one'
                       : 'the issuance policy refused the passkey'),
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), {
          credential: 'webauthn',
          credentialFingerprint: String(extra.credential &&
                                        extra.credential.id
            ? stsCrypto.credentialFingerprint(
                String(extra.credential.id)) : '')
        })
      });
      // A KEY THAT NO LONGER SIGNS ITS OWNER IN (#718): the first time per
      // key and reason, its row is marked and CAEP's credential-change goes
      // out by `policy` — #530's arrangement — so a relying party learns
      // the credential's standing changed once, not at every attempt.
      if (syncedRefusal.reason === 'post-quantum') {
        this.notePasskeyStanding(username, extra.credential, syncedRefusal);
      }
      extra.refusedWith = syncedRefusal.code;
      extra.refusedWhy = syncedRefusal.why;
      log.debug("Leaving Authn.startSessionHere(). The passkey policy " +
                "refused the passkey.");
      return null;
    }
    // A CLASSICAL PASSKEY FROM A PERSON WHO HOLDS A POST-QUANTUM ONE (#943),
    // where the policy above let it sign in — which it does only where
    // post-quantum is not required at sign-in. An assertion only: a key
    // registered in this act is the person's newest, not a fallback.
    if (extra.authenticated !== false && extra.credential &&
        String(extra.credential.kind || '') === 'webauthn' &&
        extra.credential.ceremony !== 'registration') {
      this.noteAlgorithmMismatch(username, extra.credential, via);
    }
    // -------------------------------------------------------------------------
    // ACCOUNT RECOVERY NO WEAKER THAN THE PASSKEY IT REPLACES (#724), asked
    // here for the passkey rules' reason: every door reaches this line. See
    // `recoveryRefusalAtSession()`. A keyed caller (SCIM, the SPIRE Server
    // API) is a program and is not asked; an unauthenticated session names
    // nobody. `recoveryLimited` tells `refusedSession()` to offer the
    // registration of a passkey rather than draw the refusal.
    // -------------------------------------------------------------------------
    const recoveryRefused = extra.authenticated === false || extra.key ? null
      : this.recoveryRefusalAtSession(username, extra.credential);
    if (recoveryRefused) {
      const limited = recoveryRefused.reason === 'recovery-enrol-first';
      log.info('authn: a session for "' + username + '" was REFUSED at the ' +
               (via || 'sign-in') + ' door: the passkey policy holds an ' +
               'account recovery to the passkey it replaces (' +
               recoveryRefused.code + ').');
      audit.audit({
        action: 'session.refuse', actor: String(username || ''),
        errorCode: recoveryRefused.code,
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused at the ' +
                 (via || 'sign-in') + ' door: ' + (limited
                   ? 'after an account recovery only a passkey reaches an ' +
                     'application'
                   : 'the passkey policy lets only an operator recover ' +
                     'this account'),
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), {
          credential: String(extra.credential && extra.credential.kind),
          reason: recoveryRefused.reason
        })
      });
      extra.refusedWith = recoveryRefused.code;
      extra.refusedWhy = recoveryRefused.why;
      extra.recoveryLimited = limited;
      log.debug("Leaving Authn.startSessionHere(). The recovery question " +
                "refused.");
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
    // The block below only REMEMBERS whatever session the browser was on.
    // The row is ended after the new one is admitted, because a sign-in is
    // a privilege change and leaving the old one usable would be a second
    // live session for the same browser — and ending it first signed the
    // browser out when the replacement was refused. A lowered cap does that
    // on purpose: deleting one row can still leave the realm over
    // authn.maxSessions. An ARRIVAL session is on that cookie too — so with
    // the lookup after the old session was deleted it found nothing, every
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
    const defaultFound = extra.request
      ? this.cookieSession(extra.request, SESSION_COOKIE) : null;
    if (defaultFound && defaultFound.error) {
      extra.refusedWith = 'STS-AUTHN-0338';
      log.debug("Leaving Authn.startSessionHere(). The session could not " +
                "be read.");
      return null;
    }
    // -------------------------------------------------------------------------
    // SEVERAL ACCOUNTS IN ONE BROWSER (#561). With `authn.multipleAccounts`
    // on, a browser's sign-in is checked against its ACCOUNT SET rather than
    // its one cookie: the same person already live in the set is a
    // re-authentication of THAT session (one live session per subject per
    // browser), whichever session the cookie happens to name; a different
    // person ADDS a session, so the previous one is not ended below. Only a
    // browser's own authenticated sign-in takes part — a keyed caller, a
    // caller that sets no cookie and the anonymous session behave as before.
    // -------------------------------------------------------------------------
    const multiAccount = !!(extra.request && !extra.key &&
      extra.cookie !== false && extra.authenticated !== false &&
      AccountSets.enabled());
    const accountSet = multiAccount ? this.accountSetOf(extra.request) : null;
    let current = defaultFound;
    if (multiAccount && !(defaultFound && defaultFound.session.user &&
        this.sameIdentity(defaultFound.session.user, username))) {
      const theirs = this.accountSessionFor(accountSet, username);
      if (theirs) {
        current = theirs;
      }
    }
    const reauthenticating = !!(current && !extra.key &&
      extra.authenticated !== false &&
      current.session.chosen !== false &&
      current.session.authenticated !== false &&
      !current.session.rpSurface && !current.session.credentialKey &&
      !this.sessionEnded(current.session) &&
      // A device-bound session is re-authenticated only from the browser
      // that holds its key (#725): from anywhere else the cookie is a copy,
      // and the sign-in starts a session of its own.
      deviceBound.honours(current.session, extra.request) &&
      current.session.user && this.sameIdentity(current.session.user,
                                                username));
    // A FULL SET REFUSES A NEW ACCOUNT (#561, the plan's D11): every place
    // `authn.maxBrowserAccounts` allows is held by a signed-in account, so
    // one must be signed out first. A remembered account would have been
    // dropped to make room; a live one never is.
    if (multiAccount && !reauthenticating) {
      const held = this.liveAccountCount(accountSet, defaultFound);
      if (held >= AccountSets.maxAccounts()) {
        const why = 'This browser is already signed in to ' + held +
          ' accounts, the most it may hold. Sign out of one of them first.';
        log.info(errorCodes.tag('STS-AUTHN-0340') + 'authn: a session for "' +
                 username + '" was REFUSED at the ' + (via || 'sign-in') +
                 ' door: its browser\'s account set is full (' + held +
                 ' signed in, authn.maxBrowserAccounts).');
        audit.audit({
          action: 'session.refuse', actor: String(username || ''),
          errorCode: 'STS-AUTHN-0340',
          protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
          summary: 'a session for ' + username + ' was refused at the ' +
                   (via || 'sign-in') + ' door: the browser is signed in ' +
                   'to as many accounts as it may hold',
          detail: Object.assign(this.attemptFacts(extra.application,
            attemptMethod), {
            accountSet: accountSet ? accountSet.id : '',
            signedIn: held
          })
        });
        extra.refusedWith = 'STS-AUTHN-0340';
        extra.refusedWhy = why;
        log.debug("Leaving Authn.startSessionHere(). The account set is " +
                  "full.");
        return null;
      }
    }
    // Ended after admission, below. Empty when this browser had no session,
    // when that session is the arrival being upgraded, or when this is the
    // same person re-authenticating.
    let replaceId = '';
    if (extra.request) {
      const previous = current ? current.id : '';
      // AN ARRIVAL SESSION IS NOT ENDED, it is upgraded — ending it would write
      // a sign-out audit row and a CAEP `session-revoked` for a session nobody
      // was ever in, every time anybody signed in. Nor is a session the same
      // person is re-authenticating on. NOR, with several accounts on (#561),
      // a different person's: their session stays in the browser's set.
      if (previous && !reauthenticating && !multiAccount &&
          !(arrived && arrived.id === previous)) {
        replaceId = previous;
      }
      // A DEVICE-BOUND SESSION OF THE SAME PERSON, FROM A BROWSER THAT DOES
      // NOT PROVE ITS KEY (#725 with #561). With the setting off it is the
      // previous session above, replaced. With several accounts on it would
      // stay in the set beside the new one — two live sessions of one
      // subject in one browser, which the set never holds, and a hint for
      // that person could choose the one this browser cannot use. So it is
      // replaced here too, exactly as with the setting off.
      if (multiAccount && previous && !reauthenticating &&
          current && current.session.user &&
          this.sameIdentity(current.session.user, username) &&
          !this.sessionEnded(current.session) &&
          !deviceBound.honours(current.session, extra.request) &&
          !(arrived && arrived.id === previous)) {
        replaceId = previous;
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
    // THE DEVICE THE CEREMONY PROVED, PUT INTO THE SCORE (#259). A door
    // that assessed before a WebAuthn ceremony could follow said so
    // (`deviceAwaited`), and this is the one funnel every finisher reaches:
    // the assessment is amended with the device this authentication
    // recognises — the same recognition the event below records — before
    // the policy is asked about it, so the decision, the session's risk and
    // the history all read the amended answer. Replaced on `extra`, so a
    // second reading of it amends nothing twice.
    if (extra.risk && extra.risk.deviceAwaited && riskEngine && !extra.key) {
      extra.risk = riskEngine.amend(extra.risk,
                                    this.registeredDeviceFor(extra, username),
                                    username);
    }
    const risk = extra.risk && riskEngine ? riskEngine.riskOf(extra.risk)
                                          : null;
    let riskDecision = String(extra.riskDecision || 'permit');
    // THE AUTHENTICATION AS AN EVENT (#457), what the session is about to
    // record — enough of one for `common/authn_mechanisms.ts` to say which
    // sign-in mechanism it was, for an application that allows only some. A
    // keyed API caller is not a browser sign-in.
    const mechanismEvent = extra.key ? null : {
      amr: (amr || []).map(String), acr: String(acr || ''),
      authenticated: extra.authenticated !== false,
      authority: this.authorityOf(extra),
      context: { credential: Object.assign({ kind: extra.credential &&
                               extra.credential.kind
                                 ? String(extra.credential.kind) : '' },
        // AND WHAT EAP'S `phr` AND `phrh` ARE READ FROM (#723), so the
        // gate's `urn:sts:xacml:phishing-resistance` fact for this sign-in
        // is the one the event will record.
        this.phishingEvidenceOf(extra.credential)) }
    };
    // Asked only of an application that allows only some: asking it of every
    // gated sign-in would put the session to the policy a second time, and
    // the policy's other rules (the console's alarm) answer every asking.
    // The second factors (#475) are the same kind of question, asked here on
    // the same terms: only of an application that allows only some.
    if (extra.gated === true && mechanismEvent && extra.application &&
        (this.declaredMechanismsFor(String(extra.application))
          .allowed.length ||
         this.mfaAllowedFor(String(extra.application)).length)) {
      // A DOOR THAT ASKED THE POLICY ITSELF (`gated: true`) asked it before
      // the authentication was complete — the password screen before its
      // second factor — so it could not ask about the MECHANISM, which needs
      // the whole of it: a `password-mfa` application would have refused
      // the password step. So the session's start asks that one question
      // here, with the role question waived (it was asked) and no risk or
      // device facts (asked too): only the mechanism rule can deny it.
      const mechanismAnswer = gate.check({
        application: String(extra.application),
        kind: gate.ISSUANCE.SESSION,
        subject: { kind: 'user', name: username,
                   authenticated: extra.authenticated !== false },
        claims: null, rolesWaived: true, deviceDeferred: true,
        authenticationEvent: mechanismEvent
      });
      if (!mechanismAnswer.allowed && mechanismAnswer.mechanism) {
        log.debug("Leaving Authn.startSessionHere(). The application does " +
                  "not allow that mechanism.");
        return this.refuseOnMechanism(extra, username, via, mechanismAnswer,
                                      attemptMethod);
      }
    }
    if (extra.gated !== true) {
      // THE APPLICATION IS THE CALLER'S TO NAME, and every screen's finisher
      // names `step.authn.application`. Until #226 (2026-09-26) the six
      // second-factor finishers named none, so after a step-up the policy was
      // asked about "": the console's `neverLockOut` rules never matched,
      // and a HIGH console sign-in that had just answered its step-up with a
      // security key was refused by the ordinary HIGH rule.
      const sessionAnswer = gate.check(Object.assign({
        application: String(extra.application || ''),
        kind: gate.ISSUANCE.SESSION,
        subject: { kind: 'user', name: username,
                   authenticated: extra.authenticated !== false },
        claims: null,
        // WHAT THE SESSION STANDS ON (#64), as facts for the policy: an
        // operator's rule may refuse a session on an emailed factor.
        authentication: extra.authenticated === false ? null
          : { amr: (amr || []).map(String), acr: String(acr || ''),
              kinds: extra.credential && extra.credential.kind
                ? [String(extra.credential.kind)] : [] },
        // The authentication as an event (#457), built above.
        authenticationEvent: mechanismEvent
      }, extra.key
        // A KEYED API CALLER (SCIM, SPIRE, the management API) is asked no
        // device question here (#164 phase 6): its credential is presented
        // per request, and the device rules decide the TOKEN that
        // credential was issued with, at the token endpoint.
        ? { deviceDeferred: true }
        // THE REGISTERED DEVICE THIS SIGN-IN PROVED (#164 phase 6) — the
        // same recognition the event below records — for the policy's two
        // device rules.
        : { device: this.registeredDeviceFor(extra, username) },
      extra.risk !== undefined && riskEngine
        ? { risk: riskEngine.factsOf(risk, amr, acr,
                                     extra.credential &&
                                     extra.credential.kind
                                       ? [String(extra.credential.kind)]
                                       : []) } : {}));
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
          detail: Object.assign(this.attemptFacts(extra.application,
            attemptMethod), {
            action: sessionAnswer.risk.action,
            factor: sessionAnswer.risk.factor,
            level: risk ? risk.level : '',
            assessment: risk ? risk.assessmentId : '',
            policy: sessionAnswer.policy || ''
          })
        });
        this.settleRisk(risk, { decision: riskDecision, errorCode: code,
                                policy: sessionAnswer.policy });
        extra.refusedWith = code;
        extra.riskStepUp = sessionAnswer.risk.factor || '';
        log.debug("Leaving Authn.startSessionHere(). Refused on risk.");
        return null;
      }
      if (!sessionAnswer.allowed && sessionAnswer.mechanism) {
        log.debug("Leaving Authn.startSessionHere(). The application does " +
                  "not allow that mechanism.");
        return this.refuseOnMechanism(extra, username, via, sessionAnswer,
                                      attemptMethod);
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
          detail: Object.assign(this.attemptFacts(extra.application,
            attemptMethod), {
            why: sessionAnswer.why,
            policy: sessionAnswer.policy || ''
          })
        });
        extra.refusedWith = sessionAnswer.device
          ? (sessionAnswer.device.refusal === 'compromised'
            ? 'STS-DEVICE-0038' : 'STS-DEVICE-0037')
          : 'STS-AUTHN-0010';
        extra.refusedWhy = sessionAnswer.why;
        log.debug("Leaving Authn.startSessionHere(). The issuance policy refused " +
                  "it.");
        return null;
      }
    } else if (!extra.key && this.refusedOnDevice(extra, username, via,
                                                 attemptMethod)) {
      // THE DEVICE QUESTION A GATED DOOR COULD NOT ASK (#164 phase 6). The
      // sign-in screen asks the policy BEFORE its credential is complete —
      // ahead of a WebAuthn ceremony that may be the very key naming the
      // device — so it leaves the device out (`deviceDeferred`), and the
      // question is asked here, of the credential the session actually
      // stands on, about the device alone.
      log.debug("Leaving Authn.startSessionHere(). Refused on the device.");
      return null;
    }

    // -------------------------------------------------------------------------
    // A POST-LOGIN ACTIVITY (#1096), asked LAST of the questions that may
    // refuse, so a sign-in held for one is a sign-in that would otherwise
    // have started: every rule above has already said yes.
    //
    // **THE SESSION IS HELD, NOT STARTED AND THEN INTERRUPTED.** A session
    // started first would be a live sign-on the person could take straight
    // to the application by opening it again, and a REQUIRED activity
    // (rcbj's answer 3: "block the sign-in") would be one click from being
    // skipped. So nothing is made here: the door that can draw the activity
    // — the sign-in screen's own, which mark `postLoginHold` on what they
    // hand this function — gets `extra.postLogin`, and `refusedSession()`
    // turns that into the step page; the step starts the session it held,
    // with the amr and acr it held, once the person has done it or skipped
    // it (`finishPostLogin()`).
    //
    // A DOOR THAT CANNOT DRAW IT — a federated, wallet, Kerberos or
    // certificate sign-in that finishes without this screen — is not
    // interrupted for an activity the person may still skip, and is REFUSED
    // for one that is required (STS-AUTHN-0473), with a sentence sending
    // them to the sign-in screen, where it will be asked.
    //
    // Asked of a person, interactively: never of a keyed caller (SCIM, the
    // SPIRE Server API), an unauthenticated session, a call with no request,
    // or the session the step itself starts (`postLoginDone`).
    // -------------------------------------------------------------------------
    const postLoginDue = extra.authenticated === false || extra.key ||
      extra.postLoginDone === true || !extra.request || !username
      ? null
      : this.deps.postLogin.dueFor(String(username),
                                   String(extra.application || ''));
    if (postLoginDue && extra.postLoginHold === true) {
      extra.postLogin = { due: postLoginDue, amr: (amr || []).slice(),
                          acr: String(acr || ''), via: String(via || '') };
      // What `refusedSession()` answers if no step can be drawn after all
      // (no pending sign-in to hold it on): the hold's own refusal.
      extra.refusedWith = 'STS-AUTHN-0473';
      extra.refusedWhy = 'You have to complete a step after signing in. ' +
        'Start the request again from the application that sent you here.';
      log.info('authn: the session for "' + username + '" is HELD at the ' +
               (via || 'sign-in') + ' door for a post-login activity (' +
               postLoginDue.activity + ', ' + postLoginDue.role + ', ' +
               (postLoginDue.required ? 'required' : 'skippable') + ').');
      log.debug("Leaving Authn.startSessionHere(). Held for a post-login " +
                "activity.");
      return null;
    }
    if (postLoginDue && postLoginDue.required) {
      const why = 'Before you can sign in this way you have to register a ' +
        'post-quantum passkey, and the time allowed for it has passed. ' +
        'Sign in at this service\'s sign-in screen, where you will be ' +
        'asked to register it.';
      log.info(errorCodes.tag('STS-AUTHN-0473') + 'authn: a session for "' +
               username + '" was REFUSED at the ' + (via || 'sign-in') +
               ' door: a required post-login activity (' +
               postLoginDue.activity + ') cannot be done there.');
      audit.audit({
        action: 'authn.post-login.held', actor: String(username),
        errorCode: 'STS-AUTHN-0473', outcome: 'failure',
        protocol: via || 'OAuth 2.0 / OIDC', channel: 'http', target: '',
        summary: 'a session for ' + username + ' was refused at the ' +
                 (via || 'sign-in') + ' door: a required post-login ' +
                 'activity is overdue and cannot be done there',
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), { activity: postLoginDue.activity,
                            role: postLoginDue.role,
                            profile: postLoginDue.profile })
      });
      extra.refusedWith = 'STS-AUTHN-0473';
      extra.refusedWhy = why;
      log.debug("Leaving Authn.startSessionHere(). A required post-login " +
                "activity this door cannot ask for.");
      return null;
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
      // The realm Map, not the facade. While the window is on the facade
      // pages the index, and this scan is the unflushed rows plus the
      // credential_key query below. The fingerprint stays in the clear:
      // it is not a digest.
      sessions.realmMap().forEach(function (held) {
        if (!found && held.credentialKey === wanted &&
            !self.sessionEnded(held)) {
          found = held;
        }
      });
      if (!found && this.windowOn()) {
        const realmId = this.deps.realms.currentId();
        const keys = sessionWindow.indexKeys('session.credential',
                                              [realmId, wanted]);
        if (keys === null) {
          extra.refusedWith = 'STS-AUTHN-0338';
          log.debug("Leaving Authn.startSessionHere(). The credential " +
                    "could not be read.");
          return null;
        }
        for (let i = 0; i < keys.length && !found; i++) {
          const loaded = sessionWindow.loadByDigest(realmId, keys[i]);
          if (loaded.ok && loaded.session &&
              loaded.session.credentialKey === wanted &&
              !self.sessionEnded(loaded.session)) {
            found = loaded.session;
          }
        }
      }
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
        // While the window is on, touches inside one second stay pinned.
        if (!(this.windowOn() && sessionWindow.holdTouch(
            this.deps.realms.currentId(), found.id, found))) {
          sessions.set(found.id, found);
        }
        // The name may sharpen between calls — a scheme that authenticated
        // anonymously first and by name later — and the creation instant
        // deliberately does not move.
        this.notifySession('presented', found, { via: via || found.via,
                                                 req: null });
        log.debug("Leaving Authn.startSessionHere(). The credential was " +
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
      this.recoveryCompleted(username, extra);
      if (multiAccount) {
        this.enrolInAccountSet(extra.request, res, again, defaultFound);
      }
      this.settleRisk(risk, { decision: riskDecision, sessionId: again.id,
                              context: extra.risk &&
                                       extra.risk.sessionContext });
      log.debug("Leaving Authn.startSessionHere(). " + username +
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
    const firstEvent = this.authenticationEvent(amr, acr, via, extra,
                                                username);
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
        ? this.defaultSignInNote()
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
        detail: Object.assign(this.attemptFacts(extra.application,
          attemptMethod), {
          why: 'no directory entry, so no subject',
          federation: (extra.federation && extra.federation.id) || '',
          autocreate: extra.federation
            ? String(extra.federation.autocreate !== false) : ''
        })
      });
      extra.refusedWith = 'STS-AUTHN-0180';
      log.debug("Leaving Authn.startSessionHere(). There is no entry to be the " +
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
      // Frozen here. A later rename does not rewrite it, and the per-subject
      // cap groups on this rather than on the username arrivals share.
      subjectId: this.subjectIdOf(user),
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
    // Room before the handle, so a refused row is not stored and has no
    // cookie. An upgraded arrival keeps its id and is not an insert: the
    // realm cap does not refuse it, and the subject cap ends one other
    // own row.
    const store = sessions.realmMap();
    let upgrading = false;
    if (arrived) {
      if (this.windowOn()) {
        const held = sessionWindow.has(this.deps.realms.currentId(),
                                        sessionId);
        if (held === 'error') {
          extra.refusedWith = 'STS-AUTHN-0338';
          log.debug("Leaving Authn.startSessionHere(). The session could " +
                    "not be read.");
          return null;
        }
        upgrading = held === 'present';
      } else {
        upgrading = store.has(sessionId);
      }
    }
    if (upgrading) {
      const ended = this.endOneOwn(store, session, session.id);
      if (ended === 'error') {
        extra.refusedWith = 'STS-AUTHN-0338';
        log.debug("Leaving Authn.startSessionHere(). The session index " +
                  "could not be read.");
        return null;
      }
    } else {
      const room = this.makeRoomForSession(store, session, replaceId);
      if (room === 'error') {
        extra.refusedWith = 'STS-AUTHN-0338';
        log.debug("Leaving Authn.startSessionHere(). The session store " +
                  "could not be read.");
        return null;
      }
      if (!room) {
        this.auditCapRefusal(username, via || 'OAuth 2.0 / OIDC',
                             extra.application, attemptMethod);
        extra.refusedWith = 'STS-AUTHN-0337';
        log.debug("Leaving Authn.startSessionHere(). The realm is at " +
                  "authn.maxSessions.");
        return null;
      }
    }
    // A FRESH HANDLE, EVEN FOR AN UPGRADED ARRIVAL ROW. The arrival session's
    // id survives the upgrade on purpose — it is the `sid` a flow was
    // correlated by from its first request — and until 2026-09-14 so did its
    // COOKIE, which made the cookie a browser was handed before anybody
    // authenticated the one that was authenticated afterwards. That is session
    // fixation, whatever the randomness of the id. Rotating the handle keeps
    // the correlation and ends the fixation.
    const cookieValue = this.mintSessionHandle(session);
    sessions.set(sessionId, session);
    // Only now: a refusal above left this browser's session in place.
    // `replaceId` counted as leaving, so a realm exactly at the cap still
    // admitted the switch. The via string is what CAEP's reason_admin says.
    let replacing = null;
    if (replaceId && replaceId !== sessionId) {
      if (this.windowOn()) {
        const read = sessionWindow.get(this.deps.realms.currentId(),
                                        replaceId);
        if (read.ok) {
          replacing = read.session;
        }
      } else if (sessions.get(replaceId)) {
        replacing = sessions.get(replaceId);
      }
    }
    if (replacing) {
      log.info('authn: ending the session this browser was already on (' +
               replaceId + ') because a new sign-in is replacing it. Every ' +
               'sign-in is a privilege change and the old session must not ' +
               'outlive it.');
      this.dropSession(replaceId, 'a new sign-in in the same browser', true,
                       extra.request, 'user');
    }
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
      // DEVICE BOUND SESSION CREDENTIALS (#725): where the realm binds
      // sessions, the same answer asks the browser for a key. Nothing is
      // written; a browser that does not speak DBSC ignores the header.
      deviceBound.offer(res, session);
    }
    // INTO THE BROWSER'S ACCOUNT SET (#561), after the session cookie: that
    // one is written by replacing, the set's is appended.
    if (multiAccount) {
      this.enrolInAccountSet(extra.request, res, session, defaultFound);
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
      detail: Object.assign(this.attemptFacts(extra.application,
        attemptMethod), {
        sessionId: sessionId,
        sub: session.user.sub,
        amr: (amr || []).join(', '),
        acr: acr || '',
        authTime: session.authTime,
        expiresAt: new Date(session.expires).toISOString(),
        // THE PASSKEY'S SIGNATURE ALGORITHM (2026-10-01), where a WebAuthn
        // ceremony — the only factor or the second — signed this session in.
        credentialAlgorithm: extra.credential && extra.credential.algorithm
          ? String(extra.credential.algorithm) +
            (extra.credential.coseAlg ? ' (' + extra.credential.coseAlg + ')'
                                      : '')
          : undefined,
        // AND ITS LANE (#643): `classical` or `pqc`.
        credentialLane: extra.credential && extra.credential.lane
          ? String(extra.credential.lane) : undefined,
        // The caller's own sentence where it has one. A federated sign-in's
        // "No password was checked" is true and useless — nothing was typed
        // here at all — and the row is the only place that distinction will
        // ever be recorded. Without one, the mode's (defaultSignInNote()).
        note: extra.note || this.defaultSignInNote()
      })
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
    // THE SESSION THIS RESPONSE STARTED (#94), for afterSignIn(): the
    // attribute sources read at sign-in are read between here and the
    // browser being sent back, which is before the first artifact. Not for
    // a keyed caller (SCIM, SPIRE), which is no person and has no browser.
    if (res && res.locals && !extra.key) {
      res.locals.stsStartedSession = {
        id: sessionId, username: String((user && user.username) ||
                                        username) };
    }
    // A PASSKEY AFTER A RECOVERY (#724) completes it.
    this.recoveryCompleted(username, extra);
    log.debug("Leaving Authn.startSessionHere(). " + username +
              " is signed in (amr " +
              (amr || []).join(',') + ").");
    return session;
  }

  // ---------------------------------------------------------------------------
  // THE SIGN-IN'S LAST STEP: THE ATTRIBUTE SOURCES (#94).
  //
  // A source whose mode is `sign-in` — or `once`, for a person it has not
  // read — is read AFTER the session exists (a first-time person has no
  // entry until startSession() made one) and BEFORE the browser is sent
  // back, which is before any artifact: every door here hands off with a
  // redirect, and the code, the ID Token or the assertion is minted on the
  // next request. So every door that leaves through returnToCaller() is
  // covered, and federation's and the certificate sign-in's own redirects
  // call this too.
  //
  // `go()` sends the browser on. A source that could not be read and says
  // `refuse` ENDS the session just started (initiated by `policy`) and calls
  // `refuse(why)` instead; any other failure proceeds, with what the entry
  // already holds — `attribute_sources.ts` has logged and coded it.
  // ---------------------------------------------------------------------------
  /**
   * Reads the attribute sources a sign-in reads, then sends the browser on,
   * or ends the session and refuses when a refusing source failed.
   *
   * @param res - the response whose startSession() made a session
   * @param go - sends the browser on
   * @param refuse - answers the refusal, given why
   */
  afterSignIn(res, go: () => void, refuse: (why: string) => void): void {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Authn.afterSignIn().");
    const started = res && res.locals ? res.locals.stsStartedSession : null;
    if (!started || !started.username) {
      log.debug("Leaving Authn.afterSignIn(). No session was started.");
      go();
      return;
    }
    delete res.locals.stsStartedSession;
    let sources: any = null;
    try {
      sources = require('../attribute-sources/attribute_sources');
    } catch (e) {
      log.debug("Caught in Authn.afterSignIn(): " + ((e && e.message) || e));
      // No attribute sources in this process: nothing is read at sign-in.
      sources = null;
    }
    if (!sources || typeof sources.refreshAtSignIn !== 'function') {
      log.debug("Leaving Authn.afterSignIn(). No attribute sources.");
      go();
      return;
    }
    Promise.resolve().then(function () {
      return sources.refreshAtSignIn(started.username);
    }).then(function (outcome) {
      if (outcome && outcome.refused) {
        errorCodes.mark(res, 'STS-ATTR-0012');
        self.dropSession(started.id, 'an attribute source at sign-in', true,
                         res.req, 'policy');
        refuse(String(outcome.why || 'An attribute source could not be ' +
                                     'read.'));
        return;
      }
      go();
    }, function (e) {
      log.debug("Caught in Authn.afterSignIn(): " + ((e && e.message) || e));
      // A failure outside any one source's policy — the register itself —
      // costs the refresh and never the sign-in.
      go();
    });
    log.debug("Leaving Authn.afterSignIn(). Reading the sources.");
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
  private dropSession(id, via, cookiePresented, req?, initiatingEntity?) {
    const { realms, log, stats, bcp } = this.deps;
    const self = this;
    log.debug("Entering Authn.dropSession(). id=" + (id || '(none)'));
    // WHO ENDED IT, SAID BY THE CALLER (#242). See initiatorOf().
    const entity = this.initiatorOf(initiatingEntity, via);
    // The read decides. A failure is not absence: nothing is deleted and
    // STS-AUTHN-0011 is not audited. Absence is still the no-session path.
    let session = null;
    let deleteAfter = false;
    if (id && this.windowOn()) {
      const read = sessionWindow.get(realms.currentId(), String(id));
      if (!read.ok && read.error) {
        log.debug("Leaving Authn.dropSession(). The session could not " +
                  "be read.");
        return null;
      }
      if (read.ok) {
        session = read.session;
        deleteAfter = true;
      } else {
        sessions.delete(id);
      }
    } else {
      session = id ? sessions.get(id) : null;
      if (id) {
        sessions.delete(id);
      }
    }
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
    // **AND ONE LEVEL FURTHER SINCE 2026-09-30**, which the paragraph above
    // said this service had no way to create: a portal session ADOPTED from a
    // console session (`adoptRelyingPartySession()`) is a relying party's
    // child of a relying party. The recursion below already reaches it — the
    // child's own `dropSession()` walks the child's children — and the one
    // thing it needed is where to look: a console session's adopted children
    // live in the realm the console session's person signed in through, which
    // is the console session's own `derivedFromRealm`, named here.
    if (id && session) {
      const children = this.derivedFrom(id, undefined,
                       session.rpSurface === 'admin'
                         ? session.derivedFromRealm : '');
      // Null is a children read that failed, already recorded as
      // STS-AUTHN-0338. The parent stays: deleting it would leave a
      // committed child signed in, with no cascade and no logout.
      if (children == null) {
        log.debug("Leaving Authn.dropSession(). The derived sessions " +
                  "could not be read.");
        return null;
      }
      // forEach cannot return from dropSession, and realms.run's return
      // is the child's. Null means that child's own children could not
      // be read (STS-AUTHN-0338 is already recorded there). The sign-on
      // is not revoked, deleted, or audited. A child already ended in
      // this loop stays ended.
      for (let i = 0; i < children.length; i++) {
        const child = children[i];
        log.info('authn: ending the ' + (child.session.rpSurface || 'relying ' +
            'party') +
                 ' session ' + child.id + ' (realm ' + child.realm + ') with ' +
                 'the sign-on session it was derived from (' + id + ').');
        const endChild = function () {
          log.debug("Entering endChild().");
          // The child ends for the parent's reason and by the parent's
          // hand, so it says the parent's initiating entity.
          const ended = self.dropSession(child.id,
                           'the end of the sign-on session it was derived ' +
                           'from (' + (via || 'an unknown door') + ')', false,
                           req, entity);
          log.debug("Leaving endChild().");
          return ended;
        };
        let ended = null;
        if (child.realm && child.realm !== realms.currentId()) {
          ended = realms.run(realms.get(child.realm), endChild);
        } else {
          ended = endChild();
        }
        if (ended == null) {
          log.debug("Leaving Authn.dropSession(). A derived session " +
                    "could not be ended.");
          return null;
        }
      }
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
         'issued on ended',
      // The grant each revoked token ends is reported by `stats.revoke()`'s
      // observer (#239) with the sign-out's own initiating entity (#242), so
      // a person signing out is `user` there too, not the observer's default.
      { initiatingEntity: entity },
      // Where the session's tokens are filed (#820 part 3): the register is
      // not held whole, and every sign-out would otherwise walk it.
      ['sid:' + id]);
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
    if (deleteAfter && id) {
      sessions.delete(id);
    }
    // THE ACCOUNT IS REMEMBERED AS SIGNED OUT in its browser's set (#561),
    // whoever ended the session: the picker offers it again, or forgets it.
    // Here, after the delete, and not where the session is first read: with
    // the window on (#350) a children read that fails returns above with the
    // session NOT ended, and its account must stay signed in in the set.
    this.accountSessionEnded(session);
    if (session) {
      const planned = this.planBackchannel(session, via || 'a sign-out',
                                           'sign-out');
      this.sessionEndOnce(session.id, function () {
        self.reportSignOut(session, id, via, cookiePresented, req, entity);
        self.dispatchBackchannel(planned);
      }, function () {
        self.reportSignOutAlreadyEnded(session, via, cookiePresented);
      });
    } else {
      this.reportSignOut(null, id, via, cookiePresented, req, entity);
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
  private reportSignOut(session, id, via, cookiePresented, req, entity) {
    const { log, audit } = this.deps;
    log.debug("Entering Authn.reportSignOut().");
    this.notifySession('revoked', session, { via: via || 'a sign-out endpoint',
      // STATED BY THE CALLER (#242), never read out of `via`: see
      // initiatorOf(). `byAdmin` is kept for an observer that reads it.
      initiatingEntity: entity,
      byAdmin: entity === 'admin',
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
  /**
   * Lists every session held for one username, newest first.
   *
   * The comparison is on the username exactly as typed.
   *
   * @param username - the username
   * @returns the sessions, or null when the index could not be read.
   *   Null is not an empty list and not the realm map.
   */
  sessionsOf(username) {
    const { log, realms, errorCodes } = this.deps;
    log.debug("Entering Authn.sessionsOf(). username=" + username);
    const wanted = String(username || '');
    const out = [];
    const seen: Record<string, boolean> = {};
    // The username as typed. Not subject_key: a urn:uuid subject digests
    // the sub, and not holderKeyOf, which moves when the person is renamed.
    const take = function (session) {
      log.debug("Entering take().");
      if (!session || seen[session.id]) {
        log.debug("Leaving take().");
        return;
      }
      const name = (session.user && session.user.username) || '';
      if (name !== wanted) {
        log.debug("Leaving take().");
        return;
      }
      seen[session.id] = true;
      out.push(session);
      log.debug("Leaving take().");
    };
    if (this.windowOn()) {
      const realmId = realms.currentId();
      const nameKey = keystore.keyedDigest('session-username', wanted);
      // A missing digest is not an empty username. The filter cannot run,
      // so the page is the walk. Returning nobody would hide the row.
      let page = false;
      if (!nameKey) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: the username ' +
                  'digest is missing.');
        page = true;
      } else {
        const keys = sessionWindow.indexKeys('session.username',
                                              [realmId, nameKey]);
        // null is a failed read. It is not a miss, and the realm map is
        // not every session of this username. Paging does not repair it.
        if (keys === null) {
          log.error(errorCodes.tag('STS-AUTHN-0338') +
                    'authn: a session could not be read: the username ' +
                    'index.');
          log.debug("Leaving Authn.sessionsOf(). Unread.");
          return null;
        }
        if (!keys.length) {
          page = true;
        } else {
          for (let i = 0; i < keys.length; i++) {
            const loaded = sessionWindow.loadByDigest(realmId, keys[i]);
            if (!loaded.ok && loaded.error) {
              log.error(errorCodes.tag('STS-AUTHN-0338') +
                        'authn: a session could not be read: a session ' +
                        'of ' + wanted + ' would not open.');
              log.debug("Leaving Authn.sessionsOf(). Unread.");
              return null;
            }
            if (loaded.ok && loaded.session) {
              take(loaded.session);
            }
          }
        }
      }
      if (page) {
        const rows = this.indexedSessions(realmId, null);
        if (!rows) {
          log.error(errorCodes.tag('STS-AUTHN-0338') +
                    'authn: a session could not be read: the page for ' +
                    wanted + '.');
          log.debug("Leaving Authn.sessionsOf(). Unread.");
          return null;
        }
        rows.forEach(function (row) {
          take(row.session);
        });
      }
      // Unflushed rows are not in the index yet. realmMap is those rows,
      // not the facade, whose forEach pages the index. Only after a read
      // that returned a key list.
      sessions.realmMap().forEach(function (session) {
        take(session);
      });
    } else {
      sessions.forEach(function (session) {
        take(session);
      });
    }
    out.sort(function (a, b) {
      return (b.authTime || 0) - (a.authTime || 0);
    });
    log.debug("Leaving Authn.sessionsOf(). " + out.length + " session(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // ONE PERSON'S SESSIONS FROM THE TWO COLUMNS THAT NAME THEM (#774).
  //
  // `logout.ts`'s `sessionsByKey()` read EVERY session of the realm to find
  // one person's, and resolved each one's subject through the directory; the
  // risk engine asks it at every sign-in whose level changes, which is every
  // person's first. With the session window on that is every sealed body
  // loaded and every subject asked of the store, synchronously: on 8081 at
  // 85,000 sessions, eighty seconds per sign-in after a restart, and the
  // service did not come back. A session is filed under its username
  // (`username_key`) and its subject (`subject_key`, the `urn:uuid:` sub
  // where the person has one — `subjectIdOf()`), so the sessions a caller
  // can mean are the union of two indexed reads, and the caller keeps its
  // own rule for which of them are the person's.
  //
  // Unlike `sessionsOf()` it never falls back to the page: an empty answer
  // is an answer. Null is a read that failed.
  // ---------------------------------------------------------------------------
  /**
   * Lists the ambient realm's sessions filed under a username or a subject
   * id, for a caller that applies its own rule to them (#774).
   *
   * @param username - the username, exactly as a session holds it
   * @param subjectId - the subject id (`urn:uuid:`), or ''
   * @returns the sessions, or null when an index could not be read
   */
  sessionsHeldUnder(username?, subjectId?) {
    const { log, realms, errorCodes } = this.deps;
    log.debug("Entering Authn.sessionsHeldUnder().");
    const name = String(username || '');
    const subject = String(subjectId || '');
    const out = [];
    const seen: Record<string, boolean> = {};
    const take = function (session) {
      if (!session || !session.id || seen[session.id]) {
        return;
      }
      const held = (name && session.user && session.user.username === name) ||
                   (subject && String(session.subjectId || '') === subject);
      if (held) {
        seen[session.id] = true;
        out.push(session);
      }
    };
    if (!this.windowOn()) {
      sessions.forEach(function (session) {
        take(session);
      });
      log.debug("Leaving Authn.sessionsHeldUnder(). " + out.length +
                ", in memory.");
      return out;
    }
    const realmId = realms.currentId();
    const digests: string[] = [];
    const asks: Array<[string, string, string]> = [];
    if (name) {
      asks.push(['session.username', 'session-username', name]);
    }
    if (subject) {
      asks.push(['session.subject', 'session-subject', subject]);
    }
    for (const ask of asks) {
      const digest = keystore.keyedDigest(ask[1], ask[2]);
      const keys = digest ? sessionWindow.indexKeys(ask[0], [realmId, digest])
                          : null;
      if (keys === null) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: ' + ask[0] + '.');
        log.debug("Leaving Authn.sessionsHeldUnder(). Unread.");
        return null;
      }
      keys.forEach(function (key) {
        if (digests.indexOf(key) < 0) {
          digests.push(key);
        }
      });
    }
    for (const key of digests) {
      const loaded = sessionWindow.loadByDigest(realmId, key);
      if (!loaded.ok && loaded.error) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: one held under ' +
                  name + ' would not open.');
        log.debug("Leaving Authn.sessionsHeldUnder(). Unread.");
        return null;
      }
      if (loaded.ok) {
        take(loaded.session);
      }
    }
    // Unflushed rows are not in the index yet; realmMap() is those rows.
    sessions.realmMap().forEach(function (session) {
      take(session);
    });
    log.debug("Leaving Authn.sessionsHeldUnder(). " + out.length + ".");
    return out;
  }

  // Sessions whose sealed fedPartnerSession names this relationship.
  // The column narrows the page; the body is still what the caller reads.
  // A second store of the partner object would be a second answer.
  /**
   * Lists sessions whose partner relationship is the one named.
   *
   * While the window is on, the index selects `partner_relationship` and
   * the sealed body is what the caller compares. While it is off, the walk
   * is the realm map.
   *
   * @param relationship - the federation relationship id
   * @returns the sessions, ended ones included, or null when the index
   *   could not be read. Null is not an empty list and not the realm map.
   */
  sessionsForRelationship(relationship) {
    const { log, realms, errorCodes } = this.deps;
    log.debug("Entering Authn.sessionsForRelationship(). " + relationship);
    const wanted = String(relationship || '');
    const out = [];
    const seen: Record<string, boolean> = {};
    const take = function (session) {
      log.debug("Entering take().");
      if (!session || !session.id || seen[session.id]) {
        log.debug("Leaving take().");
        return;
      }
      const held = session.fedPartnerSession;
      if (!held || String(held.relationship || '') !== wanted) {
        log.debug("Leaving take().");
        return;
      }
      seen[session.id] = true;
      out.push(session);
      log.debug("Leaving take().");
    };
    if (this.windowOn()) {
      const realmId = realms.currentId();
      const keys = sessionWindow.indexKeys('session.partner',
                                            [realmId, wanted]);
      // null is a failed read. The unflushed map is not the relationship.
      if (keys === null) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: the partner index ' +
                  'for ' + wanted + '.');
        log.debug("Leaving Authn.sessionsForRelationship(). Unread.");
        return null;
      }
      for (let i = 0; i < keys.length; i++) {
        const loaded = sessionWindow.loadByDigest(realmId, keys[i]);
        if (!loaded.ok && loaded.error) {
          log.error(errorCodes.tag('STS-AUTHN-0338') +
                    'authn: a session could not be read: a session of ' +
                    wanted + ' would not open.');
          log.debug("Leaving Authn.sessionsForRelationship(). Unread.");
          return null;
        }
        if (loaded.ok && loaded.session) {
          take(loaded.session);
        }
      }
      // A query that returned a list still adds rows not flushed yet.
      sessions.realmMap().forEach(function (session) {
        take(session);
      });
    } else {
      sessions.forEach(function (session) {
        take(session);
      });
    }
    log.debug("Leaving Authn.sessionsForRelationship(). " + out.length);
    return out;
  }

  // The index plus rows this process has not flushed. Null when the index
  // could not be read or a listed body would not open. The cache is not
  // merged into that failure: a partial page is not the whole store.
  private indexedSessions(realmId, store) {
    const { log } = this.deps;
    log.debug("Entering Authn.indexedSessions().");
    const keys = sessionWindow.keysOf(realmId);
    if (keys === null) {
      log.debug("Leaving Authn.indexedSessions(). Unread.");
      return null;
    }
    const out = [];
    const seen: Record<string, boolean> = {};
    for (let i = 0; i < keys.length; i++) {
      const loaded = sessionWindow.loadByDigest(realmId, keys[i]);
      if (!loaded.ok && loaded.error) {
        log.debug("Leaving Authn.indexedSessions(). Unread.");
        return null;
      }
      if (!loaded.ok || !loaded.session || !loaded.session.id) {
        continue;
      }
      const id = String(loaded.session.id);
      if (seen[id]) {
        continue;
      }
      seen[id] = true;
      out.push({ id: id, session: loaded.session });
    }
    if (store) {
      store.forEach(function (session, id) {
        if (!session || seen[id]) {
          return;
        }
        seen[id] = true;
        out.push({ id: String(id), session: session });
      });
    }
    log.debug("Leaving Authn.indexedSessions(). " + out.length + ".");
    return out;
  }

  // A forEach of the facade while the window is on. The realm Map then
  // holds unflushed rows only, so a caller that still walks it would see
  // who is cached. Paging the index is the walk. A failed page calls
  // nothing: the cache is not a stand-in for the rows that could not be
  // read, and it is not a reason to end some other row.
  /**
   * Walks every session of the ambient realm.
   *
   * While the window is off this is the realm map. While it is on it is
   * the index, plus rows not yet flushed.
   *
   * @param fn - `(session, id)`
   * @param thisArg - the value of `this` inside `fn`
   */
  forEachSession(fn, thisArg?) {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.forEachSession().");
    if (typeof fn !== 'function') {
      log.debug("Leaving Authn.forEachSession().");
      return;
    }
    if (!this.windowOn()) {
      sessions.realmMap().forEach(fn, thisArg);
      log.debug("Leaving Authn.forEachSession().");
      return;
    }
    const rows = this.indexedSessions(realms.currentId(),
                                       sessions.realmMap());
    if (!rows) {
      log.debug("Leaving Authn.forEachSession(). Unread.");
      return;
    }
    rows.forEach(function (row) {
      fn.call(thisArg, row.session, row.id);
    });
    log.debug("Leaving Authn.forEachSession().");
  }

  // WHO HOLDS A LIVE SIGN-ON SESSION, ASKED OF THE INDEX (2026-10-21), for
  // `/admin/users`: how many people hold one, and how many each of the named
  // people hold. The page counted them with `sessionsMatching()`, which while
  // the window is on reads and opens every session's sealed body — 67,000 on
  // 8081, synchronously, on the worker that serves sign-ins. The index holds
  // a digest of each session's username and subject, so the store counts
  // without anything being opened, on the driver's read pool. Null while the
  // window is off: the sessions are in memory, and the caller walks them.
  /**
   * Counts the ambient realm's live sign-on sessions in the index.
   *
   * @param usernames - the people whose own counts are wanted
   * @returns a promise of `{ people, byUsername }` (a Map), or of null
   */
  async liveSessionCountsAsync(usernames) {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.liveSessionCountsAsync().");
    if (!this.windowOn()) {
      log.debug("Leaving Authn.liveSessionCountsAsync(). Window off.");
      return null;
    }
    const realmId = realms.currentId();
    const nowMs = Date.now();
    const people = await sessionWindow.askAsync('session.liveSubjects',
                                                [realmId, nowMs]) as any;
    if (!people) {
      log.debug("Leaving Authn.liveSessionCountsAsync(). Unread.");
      return null;
    }
    const byKey = new Map();
    (usernames || []).forEach(function (username) {
      const digest = keystore.keyedDigest('session-username',
                                          String(username));
      if (digest) {
        byKey.set(digest, String(username));
      }
    });
    const byUsername = new Map();
    if (byKey.size) {
      const counted = await sessionWindow.askAsync('session.liveByUsername',
        [realmId, Array.from(byKey.keys()), nowMs]) as any;
      Object.keys(counted || {}).forEach(function (digest) {
        if (byKey.has(digest)) {
          byUsername.set(byKey.get(digest), Number(counted[digest]) || 0);
        }
      });
    }
    log.debug("Leaving Authn.liveSessionCountsAsync(). " + people.n +
              " people.");
    return { people: Number(people.n) || 0, byUsername: byUsername };
  }

  // THE CONSOLE'S LIVE SESSIONS, ONE PAGE AT A TIME (2026-10-22, #820).
  // Monitoring → Sessions, Monitoring → Metrics and a person's page built
  // their lists with `sessionsMatching()`, which while the window is on
  // opens every session's sealed body — one synchronous read each, about
  // 470,000 on 8081 — on the worker that serves sign-ins. That held the
  // worker for two minutes, and through read-your-write every other worker
  // waited behind it. This asks the index for the counts and one page,
  // newest first, on the driver's read pool, and opens only the page.
  //
  // **A SEARCH IS EXACT**: the index holds digests, so `q` matches a whole
  // username, subject or session id, not part of one. Null while the window
  // is off: the sessions are in memory, and the caller walks them.
  /**
   * One page of the ambient realm's live sessions from the index.
   *
   * @param options - `q` (an exact username, subject or session id),
   *   `authenticated` (true, false, or absent for both), `offset`, `limit`
   * @returns a promise of `{ authenticated, unauthenticated, total,
   *   sessions }`, of `{ unread: true }` when the index could not be read,
   *   or of null while the window is off
   */
  async liveSessionPageAsync(options?) {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.liveSessionPageAsync().");
    if (!this.windowOn()) {
      log.debug("Leaving Authn.liveSessionPageAsync(). Window off.");
      return null;
    }
    const o = options || {};
    const realmId = realms.currentId();
    const q = String(o.q || '').trim();
    // A search no digest can be made for matches nothing, not everything.
    const none = '\u0000';
    const byName = q ? (keystore.keyedDigest('session-username', q) || none)
      : '';
    const bySubject = q ? (keystore.keyedDigest('session-subject', q) || none)
      : '';
    const byId = q ? (sessionWindow.digestFor(realmId, q) || none) : '';
    const authenticated = o.authenticated === true ? 1
      : o.authenticated === false ? 0 : -1;
    const limit = Math.max(1, Math.min(500, Number(o.limit) || 50));
    const offset = Math.max(0, Number(o.offset) || 0);
    const args = [realmId, Date.now(), byName, bySubject, byId,
                  authenticated];
    const totals = await sessionWindow.askAsync('session.liveTotals',
                                                args) as any;
    const keys = await sessionWindow.askAsync('session.livePage',
      args.concat([limit, offset])) as any;
    if (!totals || !Array.isArray(keys)) {
      log.debug("Leaving Authn.liveSessionPageAsync(). Unread.");
      return { unread: true };
    }
    const opened = await Promise.all(keys.map(function (digest) {
      return sessionWindow.openAsync(realmId, String(digest));
    }));
    const sessions = opened.filter(function (session) {
      return session && session.id;
    });
    const a = Number(totals.authenticated) || 0;
    const u = Number(totals.unauthenticated) || 0;
    log.debug("Leaving Authn.liveSessionPageAsync(). " + sessions.length +
              " of " + (a + u) + ".");
    return { authenticated: a, unauthenticated: u, total: a + u,
             sessions: sessions };
  }

  /**
   * Whether the session store is windowed: the sessions are in the store,
   * not all in memory, and a walk of them is the index's (#820).
   *
   * @returns true while the window is on
   */
  sessionWindowOn() {
    const { log } = this.deps;
    log.debug("Entering Authn.sessionWindowOn().");
    log.debug("Leaving Authn.sessionWindowOn().");
    return this.windowOn();
  }

  // THE SESSIONS OF THIS REALM THAT `test` ACCEPTS (#189), without the cookie
  // and without expiring them. For a SAML attribute authority, which is asked
  // about a subject by the NameID a service provider was GIVEN — a transient
  // or an emailAddress NameID is not the username, so the question is which
  // live session gave that service provider that NameID, and nothing but the
  // session holds the answer. There is no NameID column, so the page is
  // every sealed body.
  /**
   * Lists the ambient realm's sessions a predicate accepts, without the cookie
   * and without expiring them.
   *
   * @param test - the predicate
   * @returns the matching sessions, or null when the page could not be
   *   read. Null is not an empty list, and the cache is not walked.
   */
  sessionsMatching(test) {
    const { log, realms, errorCodes } = this.deps;
    log.debug("Entering Authn.sessionsMatching().");
    const out = [];
    if (this.windowOn()) {
      const rows = this.indexedSessions(realms.currentId(),
                                         sessions.realmMap());
      if (!rows) {
        log.error(errorCodes.tag('STS-AUTHN-0338') +
                  'authn: a session could not be read: the page.');
        log.debug("Leaving Authn.sessionsMatching(). Unread.");
        return null;
      }
      rows.forEach(function (row) {
        if (test(row.session)) {
          out.push(row.session);
        }
      });
    } else {
      sessions.forEach(function (session) {
        if (test(session)) {
          out.push(session);
        }
      });
    }
    log.debug("Leaving Authn.sessionsMatching(). " + out.length +
              " session(s).");
    return out;
  }

  // One session by its id, without the cookie and without expiring it. Used by
  // /logout to draw a row for a session that is not the caller's; `sessionOf()`
  // stays the function that reads the cookie and sweeps what it finds expired.
  /**
   * Returns one session by its id, without the cookie and without expiring it.
   *
   * @param id - the session id
   * @returns the session, or null
   */
  sessionById(id) {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.sessionById().");
    const key = String(id || '');
    if (this.windowOn()) {
      const read = sessionWindow.get(realms.currentId(), key);
      log.debug("Leaving Authn.sessionById().");
      return read.ok ? read.session : null;
    }
    log.debug("Leaving Authn.sessionById().");
    return sessions.get(key) || null;
  }

  /**
   * Admits a session to the window ahead of a request that will read it,
   * asynchronously (#820; `SessionWindow.warmAsync()`). Nothing where the
   * window is off: the map holds every session.
   *
   * @param id - the session id
   * @returns a promise of whether it was admitted
   */
  warmSessionAsync(id) {
    const { log, realms } = this.deps;
    log.debug("Entering Authn.warmSessionAsync().");
    if (!id || !this.windowOn()) {
      log.debug("Leaving Authn.warmSessionAsync(). Nothing to warm.");
      return Promise.resolve(false);
    }
    log.debug("Leaving Authn.warmSessionAsync().");
    return sessionWindow.warmAsync(realms.currentId(), String(id));
  }

  // End one session named by its id. The protocol-independent logout's door,
  // and the console's. It does NOT touch the caller's cookie: the session being
  // ended is usually not the one the caller is holding, and clearing the cookie
  // of a browser that is signed in as somebody else would sign the operator out
  // instead of the person they asked about.
  /**
   * Ends one session named by its id, leaving the caller's cookie alone.
   *
   * @param id - the session id
   * @param via - what ended it, for the audit row
   * @param initiatingEntity - CAEP's initiating entity
   * @returns the ended session, or null when there was none
   */
  endSessionById(id, via, initiatingEntity?) {
    const { log } = this.deps;
    log.debug("Entering Authn.endSessionById(). id=" + id);
    const session = this.dropSession(String(id || ''), via, false, null,
                                     initiatingEntity);
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
  /**
   * Ends every session of one realm, each through the ordinary sign-out path.
   *
   * @param realmId - the realm; the default realm when unknown
   * @param via - what ended them
   * @param initiatingEntity - CAEP's initiating entity
   * @returns who was signed out
   */
  endEverySessionIn(realmId, via, initiatingEntity?) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering Authn.endEverySessionIn(). realm=" + realmId);
    const realm = realms.get(String(realmId || '')) ||
                  realms.get(realms.DEFAULT_ID);
    const store = sessions.realmMap(realm.id);
    const ids = [];
    const take = function (session, id) {
      log.debug("Entering take().");
      if (!session) {
        log.debug("Leaving take().");
        return;
      }
      // A row nobody signed in to (an arrival session, the anonymous
      // principal) is ended too, and answers no account: a caller that
      // tells RISC about the accounts must not tell it about `anonymous`
      // (#242).
      const somebody = session.chosen !== false &&
                       session.authenticated !== false;
      ids.push({ id: id,
                 username: somebody
                   ? String((session.user && session.user.username) || '')
                   : '' });
      log.debug("Leaving take().");
    };
    if (this.windowOn()) {
      const rows = this.indexedSessions(realm.id, store);
      if (rows) {
        rows.forEach(function (row) {
          take(row.session, row.id);
        });
      }
    } else if (store) {
      store.forEach(function (session, id) {
        take(session, id);
      });
    }
    const ended = realms.run(realm, function () {
      return ids.filter(function (one) {
        return !!self.dropSession(one.id, via, false, null,
                                  initiatingEntity);
      });
    });
    log.debug("Leaving Authn.endEverySessionIn(). " + ended.length +
              " ended.");
    return ended;
  }

  // ---------------------------------------------------------------------------
  // A TRUST REALM BEING REMOVED (#232): its sessions end through the ordinary
  // path before its stores are purged, so each is a `session.end` audit row, a
  // CAEP session-revoked (`initiating_entity` as the removal says — `admin`)
  // and its relying parties' back-channel Logout Tokens. Until #232 the
  // partition was dropped whole and nobody was told. `realms.retire()` calls
  // this in the realm, in its announce phase.
  // ---------------------------------------------------------------------------
  /**
   * Ends a trust realm's sessions as the announce phase of the realm's removal.
   *
   * @param realmId - the realm being removed
   * @param ctx - the removal's context: `via` and `initiatingEntity`
   * @returns how many sessions were ended
   */
  retireRealmSessions(realmId, ctx) {
    const { log } = this.deps;
    log.debug("Entering Authn.retireRealmSessions(). realm=" + realmId);
    const c = ctx || {};
    const ended = this.endEverySessionIn(realmId,
      String(c.via || 'the removal of the trust realm'),
      String(c.initiatingEntity || 'admin'));
    log.info('authn: the "' + realmId + '" realm is being removed; ' +
             ended.length + ' session(s) in it were ended first.');
    log.debug("Leaving Authn.retireRealmSessions(). " + ended.length);
    return ended.length;
  }

  // ...and its deliver phase: wait, until `ctx.deadline`, for every session
  // end to have won its cluster claim (`pendingEndReports()`) and for the
  // realm's outbound deliveries — the Logout Tokens above, and anything else
  // queued in `oauth-oidc/outbound_delivery.ts`'s kinds — to leave `pending`.
  // What is still pending is reported on `ctx.undelivered`. Never rejects.
  /**
   * Waits, until `ctx.deadline`, for a removed realm's session ends and
   * outbound deliveries to settle.
   *
   * What is still pending is reported on `ctx.undelivered`. Never rejects.
   *
   * @param realmId - the realm being removed
   * @param ctx - the removal's context
   */
  async settleRealmEnds(realmId, ctx) {
    const { log } = this.deps;
    log.debug("Entering Authn.settleRealmEnds(). realm=" + realmId);
    const c = ctx || {};
    const deadline = Number(c.deadline) || 0;
    const self = this;
    const pendingOutbound = function () {
      let total = 0;
      try {
        const report = require('../oauth-oidc/outbound_delivery')
          .kindReport({ limit: 1 });
        (report.kinds || []).forEach(function (kind) {
          total += Number((kind.counts || {}).pending) || 0;
        });
      } catch (e) {
        log.debug("Caught in Authn.settleRealmEnds(): " +
                  ((e && e.message) || e));
        total = 0;
      }
      return total;
    };
    let outbound = pendingOutbound();
    while (Date.now() < deadline &&
           (self.pendingEndReports() > 0 || outbound > 0)) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 50);
      });
      outbound = pendingOutbound();
    }
    if (Array.isArray(c.undelivered)) {
      c.undelivered.push({ what: 'session end(s) still waiting on their ' +
                                 'claim',
                           count: self.pendingEndReports() });
      c.undelivered.push({ what: 'outbound delivery(ies) (back-channel ' +
                                 'Logout Tokens, CIBA, provider commands)',
                           count: outbound });
    }
    log.debug("Leaving Authn.settleRealmEnds(). " + outbound + " pending.");
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
  /**
   * Clears a session cookie on a response, appending rather than replacing any
   * Set-Cookie already there.
   *
   * @param res - the response
   * @param cookieName - the cookie; the sign-on cookie by default
   */
  clearSessionCookie(res, cookieName?) {
    const { log, config, helpers } = this.deps;
    log.debug("Entering Authn.clearSessionCookie().");
    const value = String(cookieName || SESSION_COOKIE) +
                  '=; Path=/; Max-Age=0' +
                  (String(cookieName || SESSION_COOKIE) === SESSION_COOKIE
                    ? helpers.cookieDomainAttribute() : '') +
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
  /**
   * Ends the session the request's cookie names and clears the cookie.
   *
   * Only a cookie carrying the current handle ends anything. With
   * `authn.multipleAccounts` on (#561), `sid` may name another session of
   * this browser's account set, which the set's cookie proves the browser
   * holds — a bare sid is never enough — and that one is ended instead;
   * the cookie is then cleared only where the browser's default session
   * ended, and the next live account becomes the default
   * (`afterAccountSignOut()`). Off, `sid` is ignored.
   *
   * @param req - the request
   * @param res - the response
   * @param sid - a session of this browser's account set, or nothing
   * @returns the ended session, or null
   */
  endSession(req, res, sid?) {
    const { log } = this.deps;
    log.debug("Entering Authn.endSession().");
    if (AccountSets.enabled()) {
      const ended = this.endAccountSession(req, res, String(sid || ''));
      log.debug("Leaving Authn.endSession(). Several accounts.");
      return ended;
    }
    // ONLY A COOKIE CARRYING THE CURRENT HANDLE ENDS ANYTHING. The sid is not a
    // secret — every relying party that received an ID Token holds it — so a
    // sign-out endpoint that honoured `sts_session=<sid>` would let any of them
    // sign a person out from a forged cookie. A cookie that names nothing is
    // still recorded as a refused sign-out, by dropSession() below.
    const found = this.cookieSession(req, SESSION_COOKIE);
    if (found && found.error) {
      log.debug("Leaving Authn.endSession(). The session could not be read.");
      return null;
    }
    const id = found ? found.id : '';
    const presented = !!this.cookiesOf(req)[SESSION_COOKIE];
    const session = this.dropSession(id,
                                     'the sign-out endpoint for this browser',
                                     presented, req, 'user');
    this.clearSessionCookie(res);
    log.debug("Leaving Authn.endSession(). " +
              (session ? 'Dropped the session for ' + session.user.username +
               '.'
                                                  : 'There was no session to ' +
                                                    'drop.'));
    return session || null;
  }

  // ---------------------------------------------------------------------------
  // A SIGN-OUT IN A BROWSER HOLDING SEVERAL ACCOUNTS (#561, the plan's
  // section 5). `endSession()`'s body with the setting on: the session a
  // protocol named (`sid`) where it is live in THIS browser's set, else the
  // one the cookie names, as always; the cookie only where it was the
  // browser's default; the next live account made the default.
  // ---------------------------------------------------------------------------
  private endAccountSession(req, res, sid) {
    const { log } = this.deps;
    log.debug("Entering Authn.endAccountSession().");
    const row = sid ? this.accountSetOf(req) : null;
    const inSet = !!(row && row.sessions && row.sessions[sid] &&
                     this.accountSessionLive(sid));
    const found = inSet
      ? { id: sid, session: this.accountSessionRead(sid).session }
      : this.cookieSession(req, SESSION_COOKIE);
    const id = found ? found.id : '';
    const presented = inSet || !!this.cookiesOf(req)[SESSION_COOKIE];
    const session = this.dropSession(id,
                                     'the sign-out endpoint for this browser',
                                     presented, req, 'user');
    this.afterAccountSignOut(req, res);
    log.debug("Leaving Authn.endAccountSession(). " +
              (session ? 'Dropped ' + id + (inSet ? ', named in the set.'
                                                  : ', the cookie\'s.')
                       : 'Nothing to drop.'));
    return session || null;
  }

  /**
   * Puts a browser's cookies right after one or more of its accounts signed
   * out (#561): with the browser's default session (`sts_session`) ended,
   * the cookie is cleared and the most recently added live account of the
   * set becomes the default; with it still live, the cookie is left alone.
   * The OP browser states of OpenID Connect Session Management are written
   * again for the accounts still signed in. A no-op with
   * `authn.multipleAccounts` off.
   *
   * @param req - the request
   * @param res - the response
   * @returns `{ defaultEnded, defaultNow }`: whether the default had ended,
   *   and the sid that is the default now ('' for none)
   */
  afterAccountSignOut(req, res) {
    const { log } = this.deps;
    log.debug("Entering Authn.afterAccountSignOut().");
    if (!AccountSets.enabled() || !req || !res) {
      log.debug("Leaving Authn.afterAccountSignOut(). Off.");
      return { defaultEnded: false, defaultNow: '' };
    }
    const found = this.cookieSession(req, SESSION_COOKIE);
    const defaultLive = !!(found && this.accountSessionLive(found.id));
    const live = this.accountSessionsOf(req);
    let now = defaultLive ? found.id : '';
    if (!defaultLive) {
      this.clearSessionCookie(res);
      const next = live.length ? live[live.length - 1] : null;
      if (next) {
        this.appendDefaultSession(res, next);
        now = String(next.id);
      }
    }
    const library = this.sessionManagementLibrary();
    if (library && library.enabled() && typeof res.append === 'function') {
      library.writeCookie(res, library.browserStatesValue(
        live.map(library.browserStateOf)));
    }
    log.debug("Leaving Authn.afterAccountSignOut(). Default " +
              (defaultLive ? 'kept.' : (now ? 'moved.' : 'gone.')));
    return { defaultEnded: !defaultLive, defaultNow: now };
  }

  // The next default after a sign-out, its cookie APPENDED after the clear
  // (`clearSessionCookie()` appends too), so the later line is the one the
  // browser keeps. A fresh handle, as `makeDefaultSession()` mints one, and
  // its OP browser state kept, for that function's reason.
  private appendDefaultSession(res, session) {
    const { log } = this.deps;
    log.debug("Entering Authn.appendDefaultSession(). sid=" + session.id);
    const browserState = session.browserState;
    const value = this.mintSessionHandle(session);
    if (browserState) {
      session.browserState = browserState;
    }
    sessions.set(session.id, session);
    if (typeof res.append === 'function') {
      res.append('Set-Cookie', this.sessionCookieLine(SESSION_COOKIE, value));
    }
    log.debug("Leaving Authn.appendDefaultSession().");
  }

  /**
   * Hands a request an account KEY as its hint (#561): the key a page drew
   * an account by (`AccountSets.keyOf()`: its subject, or `name:<username>`
   * for one with none) — sign-out's account step, and the account a
   * protocol's sign-out page asked about. A no-op for an empty key.
   *
   * @param req - the request
   * @param key - the account's key
   */
  hintAccountKey(req, key) {
    const { log } = this.deps;
    log.debug("Entering Authn.hintAccountKey().");
    const k = String(key || '');
    if (k) {
      this.hintAccount(req, k.indexOf('name:') === 0
        ? { loginHint: k.slice(5) } : { sub: k });
    }
    log.debug("Leaving Authn.hintAccountKey().");
  }

  /**
   * The signed-in accounts of this browser's set, for a sign-out that asks
   * which (#561): each `{ key, sub, username, displayName, current, sid }`
   * — the sid for the server's own use (a protocol page's confirmation
   * value), never to be drawn. [] with `authn.multipleAccounts` off.
   *
   * @param req - the request
   * @returns the accounts, in the order they joined the set
   */
  signedInAccounts(req) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering Authn.signedInAccounts().");
    const found = req ? this.cookieSession(req, SESSION_COOKIE) : null;
    const out = this.accountSessionsOf(req).map(function (session) {
      const account = self.accountOf(session);
      return { key: AccountSets.keyOf(account), sub: account.sub,
               username: account.username,
               displayName: account.displayName || account.username,
               current: !!(found && found.id === session.id),
               sid: String(session.id) };
    });
    log.debug("Leaving Authn.signedInAccounts(). " + out.length);
    return out;
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
  // The one usable service-provider relationship whose fedHomeRealmDomain
  // holds `domainHint` (#148), or null — none, or more than one, which is
  // not a choice this service makes for the person.
  private homeRealmFor(domainHint) {
    const { log, federation } = this.deps;
    log.debug("Entering Authn.homeRealmFor().");
    const wanted = String(domainHint || '').trim().toLowerCase();
    if (!wanted) {
      log.debug("Leaving Authn.homeRealmFor(). No hint.");
      return null;
    }
    const ids = federation.list().filter(function (r) {
      return [].concat(r.fedHomeRealmDomain || []).map(function (d) {
        return String(d).toLowerCase();
      }).indexOf(wanted) >= 0;
    }).map(function (r) {
      return r.fedId;
    });
    const resolved = ids.length
      ? federation.usableServiceProviders(ids, 'A domain_hint')
      : { usable: [] };
    log.debug("Leaving Authn.homeRealmFor(). " + resolved.usable.length +
              " usable.");
    return resolved.usable.length === 1 ?
      resolved.usable[0].relationship : null;
  }

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
  // `appAuthnMechanism`, since #457 the LIST of mechanisms the application
  // ALLOWS, from the SAME closed table `fedAuthnMechanism` uses —
  // `federation.MECHANISM_IDS`. What it allows is ENFORCED by the issuance
  // policy (`common/authn_mechanisms.ts` has the facts); what is read here
  // is where the sign-in GOES: one usable mechanism routes as the one value
  // always did, several draw the screen with only those offered. One table
  // for both
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
  // ---------------------------------------------------------------------------
  // THE SECOND FACTORS AN APPLICATION ALLOWS (#475), its `appMfaMechanism` as
  // written — empty for none, which leaves the realm's authentication policy
  // as it is. Read where the second-factor step is chosen, on the way to the
  // screen and back from it, so the same reason as declaredMechanismsFor()'s
  // holds: a registry that throws costs the narrowing, never the sign-in,
  // and the issuance policy reads the same registry and decides.
  // ---------------------------------------------------------------------------
  private mfaAllowedFor(applicationId): string[] {
    const { log, applications, errorCodes } = this.deps;
    log.debug("Entering Authn.mfaAllowedFor(). application=" +
              (applicationId || '(none)'));
    const name = String(applicationId || '').trim();
    if (!name) {
      log.debug("Leaving Authn.mfaAllowedFor(). No application.");
      return [];
    }
    let allowed: string[] = [];
    try {
      const entry = applications.get(name);
      allowed = mfaLib.allowedOf(entry ? entry.fields : null);
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0016') +
                'authn: the application registry threw while reading ' +
                'appMfaMechanism for "' + name + '" and was ignored; the ' +
                'realm\'s second factors apply: ' + ((e && e.message) || e));
      allowed = [];
    }
    log.debug("Leaving Authn.mfaAllowedFor(). " +
              (allowed.join(', ') || 'the realm\'s'));
    return allowed;
  }

  private declaredMechanismsFor(applicationId) {
    const { log, federation, applications, config, errorCodes } = this.deps;
    log.debug("Entering Authn.declaredMechanismsFor(). application=" +
              (applicationId || '(none)'));
    let entry = null;
    try {
      entry = applications.get(String(applicationId || ''));
    } catch (e) {
      // Swallowed for federationFor()'s reason and no other: this runs on the
      // way to the sign-in screen, so a registry that throws must cost the
      // shortcut and never the screen. The issuance policy reads the same
      // registry and decides what it decides.
      log.error(errorCodes.tag('STS-AUTHN-0016') +
                'authn: the application registry threw while reading ' +
                'appAuthnMechanism for "' + applicationId + '" and was ' +
                'ignored; the sign-in screen itself is unaffected: ' +
                e.message);
      log.debug("Leaving Authn.declaredMechanismsFor(). The registry threw.");
      return { allowed: [], usable: [], problem: '' };
    }
    // THE LIST AS WRITTEN (#457) — what the issuance policy holds every
    // browser sign-in to — and the part of it this service can offer now.
    const allowed = mechanismLib.allowedOf(entry ? entry.fields : null);
    if (!allowed.length) {
      log.debug("Leaving Authn.declaredMechanismsFor(). That entry allows " +
                "every mechanism.");
      return { allowed: [], usable: [], problem: '' };
    }
    const problems: string[] = [];
    const usable = allowed.filter(function (declared) {
      if (federation.MECHANISM_IDS.indexOf(declared) === -1) {
        problems.push('The application "' + applicationId + '" allows the ' +
          'authentication mechanism "' + declared + '", which is not one ' +
          'this service has: they are ' +
          federation.MECHANISM_IDS.join(', ') + '.');
        return false;
      }
      // THE TWO MECHANISMS THAT CAN BE TURNED OFF SERVICE-WIDE. Configuration
      // pointing at a door that is shut is reported, and the door is not
      // offered: the person would meet a 403 halfway through a sign-in.
      if (declared === 'spnego' && !config.value('krb5.spnegoAuthentication')) {
        problems.push('The application "' + applicationId + '" allows ' +
          'signing in with a Kerberos ticket over SPNEGO, and ' +
          'krb5.spnegoAuthentication is off on this service, so that door ' +
          'is not offered.');
        return false;
      }
      if (declared === 'wallet' && !config.value('oid4vp.signIn')) {
        problems.push('The application "' + applicationId + '" allows ' +
          'signing in with a wallet, and oid4vp.signIn is off on this ' +
          'service, so that door is not offered.');
        return false;
      }
      return true;
    });
    if (!usable.length) {
      problems.push('None of the mechanisms "' + applicationId + '" allows ' +
        'can be offered here, so nobody can sign in to it until its ' +
        'appAuthnMechanism or this service\'s settings change.');
    }
    log.debug("Leaving Authn.declaredMechanismsFor(). Allowed " +
              allowed.join(', ') + '; usable ' +
              (usable.join(', ') || 'none') + ".");
    return { allowed: allowed, usable: usable, problem: problems.join(' ') };
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
      // The application's own list (#457) rides along: the policy holds the
      // sign-in to it whichever of the two routed it.
      return { mechanism: broker.mechanism || 'password',
               source: 'relationship', federation: home, via: broker.via,
               problem: broker.problem,
               allowed: this.declaredMechanismsFor(wanted).allowed };
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
    const declared = this.declaredMechanismsFor(wanted);
    const allowed = declared.allowed;
    const usable = declared.usable;
    // ONE USABLE MECHANISM, and not `federation`: where the sign-in goes, as
    // the one value always sent it.
    if (usable.length === 1 && usable[0] !== 'federation') {
      log.info('authn: "' + wanted + '" allows the authentication mechanism ' +
               '"' + usable[0] + '" on its entry under ou=applications, so ' +
               'that is what this sign-in does.');
      log.debug("Leaving Authn.mechanismFor(). The application entry " +
                "declared it.");
      return { mechanism: usable[0], source: 'application',
               federation: null, via: '', problem: declared.problem,
               allowed: allowed };
    }
    // SEVERAL (#457): the screen, drawing only what is allowed — partners
    // among them where `federation` is, as buttons rather than a redirect,
    // because the person is choosing between them and the rest.
    if (usable.length > 1) {
      const partners = usable.indexOf('federation') >= 0
        ? this.federationFor(wanted) : null;
      log.info('authn: "' + wanted + '" allows ' + usable.join(', ') +
               ', so the sign-in screen offers those.');
      log.debug("Leaving Authn.mechanismFor(). Several allowed.");
      return { mechanism: 'password', source: 'application',
               federation: partners
                 ? Object.assign({}, partners, { auto: false }) : null,
               via: '', problem: declared.problem, allowed: allowed };
    }
    // A LIST NOTHING ON WHICH CAN BE OFFERED: the screen, saying so, with
    // nothing on it the application allows — the issuance policy refuses
    // whatever is used.
    if (allowed.length && !usable.length) {
      log.debug("Leaving Authn.mechanismFor(). Nothing allowed is usable.");
      return { mechanism: 'password', source: 'application', federation: null,
               via: '', problem: declared.problem, allowed: allowed };
    }
    const home = this.federationFor(wanted);
    if (home) {
      log.debug("Leaving Authn.mechanismFor(). The application entry decided " +
                "it.");
      return { mechanism: 'federation', source: 'application', federation: home,
               via: '', problem: home.problem || declared.problem,
               allowed: allowed };
    }
    // ALLOWS ONLY `federation` AND NAMES NOTHING USABLE. federationFor()
    // returned null, which means the entry names no relationship at all or the
    // registry could not be read — and an entry that says its people are
    // federated while naming nobody is exactly the half-configured state this
    // whole function is careful to report rather than swallow.
    if (usable.length === 1 && usable[0] === 'federation') {
      log.debug("Leaving Authn.mechanismFor(). Declared federation and named " +
                "nobody.");
      return { mechanism: 'password', source: 'application', federation: null,
               via: '',
               problem: 'The application "' + wanted + '" authenticates its ' +
                        'users through a federation relationship and its ' +
                        'entry names none that this service can use. Set ' +
                        'appFederationRelationship on it.',
               allowed: allowed };
    }
    log.debug("Leaving Authn.mechanismFor(). Nothing configured; the screen " +
              "it is.");
    return { mechanism: 'password', source: 'default', federation: null,
             via: '', problem: '', allowed: allowed };
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
  //   phishingClass  `phrh` when this sign-in must earn hardware-protected
  //              phishing resistance (#739). The passkey step then offers
  //              only keys whose recorded evidence can, and says so before
  //              the ceremony when none can. '' otherwise, including `phr`
  //              beside `phrh` (either answers). `step_up.phishingClassFor()`.
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
  /**
   * Starts authentication for a protocol module and returns the path to
   * redirect the browser to.
   *
   * The path is the sign-in screen, the federation chooser, a federated flow's
   * entry point or the Kerberos door; the caller cannot tell which. The options
   * are `returnTo`, `details`, `hint`, `forceMfa`, `forceKey`,
   * `phishingClass`, `protocol` and `application`.
   *
   * @param opts - the options, described above
   * @returns a path on this service
   * @throws an Error when `returnTo` is not a path on this service
   */
  beginAuthentication(opts) {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering Authn.beginAuthentication(). protocol=" +
              (opts.protocol || '(unnamed)'));
    if (!AccountSets.enabled()) {
      const target = this.beginAuthenticationHere(opts);
      log.debug("Leaving Authn.beginAuthentication().");
      return target;
    }
    // -----------------------------------------------------------------------
    // SEVERAL ACCOUNTS IN ONE BROWSER (#561): THE PICKER COMES FIRST WHERE
    // THERE IS A CHOICE TO MAKE, and the caller still cannot tell.
    //
    // `opts.accountChoice` is the caller's word on it: `always` (OpenID
    // Connect's prompt=select_account) shows the picker whenever the
    // browser holds any account; `never` (prompt=login, which asks for a
    // fresh sign-in) never does; absent, the picker is shown when
    // `accountChoiceNeeded()` says the request is AMBIGUOUS. The request is
    // `opts.request`, or the one being answered (`audit.currentRequest()`),
    // so a protocol module passes nothing new. Where a single account
    // resolved and no hint was given, its name is filled in — a re-sign-in
    // for a step-up is for the account the flow chose.
    // -----------------------------------------------------------------------
    const req = opts.request || audit.currentRequest();
    const choice = String(opts.accountChoice || '');
    let pick = '';
    let unmatched = '';
    if (req && choice !== 'never') {
      if (choice === 'always') {
        const row = this.freshAccountSet(req);
        pick = row && AccountSets.size(row) ? 'select_account'
          : (req.stsAccountSetUnread ? 'unread' : '');
      } else {
        const need = this.accountChoiceNeeded(req);
        if (need && need.reason === 'ambiguous') {
          pick = 'ambiguous';
        } else if (need && need.reason === 'unread') {
          // THE SET COULD NOT BE READ (rcbj's decision 3 on #561): to the
          // picker, which answers 503 with Retry-After until it can be —
          // never the sign-in screen, which would add a second session for
          // an account the browser may already hold.
          pick = 'unread';
        } else if (need && need.reason === 'hint-unmatched') {
          unmatched = String(need.hint || '');
          log.info(errorCodes.tag('STS-AUTHN-0341') + 'authn: a hint named ' +
                   'an account with no live session in this browser; the ' +
                   'person is sent to sign in rather than given another ' +
                   'account.');
        }
      }
    }
    let given = opts;
    if (req && choice !== 'never' && !opts.hint && !opts.lockedUsername) {
      const resolved = this.resolveAccount(req, false);
      const chosen = resolved.sid
        ? this.accountSessionRead(resolved.sid).session : null;
      if (chosen && chosen.user && chosen.user.username) {
        given = Object.assign({}, opts, { hint: chosen.user.username });
      } else if (unmatched) {
        // THE ACCOUNT A HINT OR A SPENT TICKET NAMED and that is not live
        // here (#731): the screen fills its name in. A protocol's own
        // `login_hint` arrives as `opts.hint` already; a ticket whose
        // session ended in flight has nowhere else to say whom it chose.
        given = Object.assign({}, opts, { hint: unmatched });
      }
    }
    const target = this.beginAuthenticationHere(given);
    if (!pick) {
      log.debug("Leaving Authn.beginAuthentication(). No choice to make.");
      return target;
    }
    const picker = this.routeToAccounts(given, target, pick, req);
    log.debug("Leaving Authn.beginAuthentication(). The account picker.");
    return picker;
  }

  // ---------------------------------------------------------------------------
  // THE PICKER'S RECORD (#561). Where the sign-in would have gone to a page
  // of this service with a pending record (the screen, the chooser, the
  // Kerberos and wallet doors), that record is the picker's too, marked
  // `accountChoice` and given `afterAccounts`, the address Use another
  // account continues to. Where it would have left at once (a federation
  // partner chosen by configuration) a record is minted for the picker
  // alone, `accountsOnly`, which `pendingFor()` refuses — so it can never be
  // drawn as a sign-in screen the application did not allow.
  // ---------------------------------------------------------------------------
  private routeToAccounts(opts, target, why, req) {
    const { log, randomId, audit, stats } = this.deps;
    log.debug("Entering Authn.routeToAccounts(). " + why);
    const named = /[?&]authn=([^&]+)/.exec(String(target));
    let record = null;
    if (named) {
      try {
        record = pending.get(decodeURIComponent(named[1]));
      } catch (e) {
        // A target this function did not make; a record of its own below.
        log.debug("Caught in Authn.routeToAccounts(): " +
                  ((e && e.message) || e));
        record = null;
      }
    }
    if (!record) {
      record = { id: randomId(18), accountsOnly: true,
                 returnTo: String(opts.returnTo || ''),
                 details: Array.isArray(opts.details) ? opts.details : [],
                 hint: '', protocol: opts.protocol || 'OAuth 2.0 / OIDC',
                 application: String(opts.application || ''),
                 uiLocales: String(opts.uiLocales || '').slice(0, 256),
                 expires: Date.now() + this.pendingTtlMs() };
    }
    record.accountChoice = true;
    record.accountChoiceReason = why;
    record.afterAccounts = String(target);
    pending.set(record.id, record);
    if (why === 'unread') {
      // Not a choice anybody failed to make: the picker's 503 is the
      // record (STS-AUTHN-0338, -0344), and no `account.ambiguous` row.
      log.debug("Leaving Authn.routeToAccounts(). The set is unread.");
      return ACCOUNTS_PATH + '?authn=' + encodeURIComponent(record.id);
    }
    const row = this.accountSetOf(req);
    stats.recordAccountChoice('ambiguous');
    audit.audit({
      action: 'account.ambiguous', actor: '',
      protocol: record.protocol || '', channel: 'http',
      target: row ? row.id : '',
      summary: why === 'select_account'
        ? 'the relying party asked for the account picker ' +
          '(prompt=select_account)'
        : 'a request from a browser with several signed-in accounts ' +
          'named none of them; the account picker was shown',
      detail: { accountSet: row ? row.id : '', reason: why,
                application: String(record.application || ''),
                signedIn: row ? Object.keys(row.sessions || {}).length : 0 }
    });
    log.debug("Leaving Authn.routeToAccounts().");
    return ACCOUNTS_PATH + '?authn=' + encodeURIComponent(record.id);
  }

  // What `beginAuthentication()` did before #561, whole: the federation
  // partner, the chooser, the Kerberos and wallet doors, or the screen.
  private beginAuthenticationHere(opts) {
    const { log, randomId, federation } = this.deps;
    log.debug("Entering Authn.beginAuthenticationHere(). protocol=" +
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
    // ENTERPRISE EXTENSIONS SECTION 3.1 (#148): a `domain_hint` names the
    // person's home realm, and a relationship whose fedHomeRealmDomain holds
    // it is where their sign-in happens — asked only when the application
    // names no partner of its own to go to, which is the more specific
    // configuration.
    const hinted = (home && home.relationship && home.auto) ? null :
      this.homeRealmFor(opts.domainHint);
    if (hinted) {
      log.info('authn: domain_hint "' + String(opts.domainHint) + '" names ' +
               'the home realm of the federation relationship "' +
               hinted.fedId + '", so this sign-in goes straight there.');
      log.debug("Leaving Authn.beginAuthenticationHere(). Home realm.");
      return federation.PATHS.login + '/' + encodeURIComponent(hinted.fedId) +
        '?returnTo=' + encodeURIComponent(returnTo) +
        '&application=' + encodeURIComponent(String(opts.application || '')) +
        this.restartParameter(returnTo);
    }
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
        '&application=' + encodeURIComponent(String(opts.application || '')) +
        this.restartParameter(returnTo);
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
      log.debug("Leaving Authn.beginAuthenticationHere(). Federated to " +
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
    // SEVERAL ALLOWED (#457) take the screen's shape from what is on the
    // list: two factors where `password-mfa` is the only screen mechanism
    // allowed, a passwordless key where `webauthn` is. The doors and links
    // the list leaves out are not drawn (loginPage()).
    const allowedMechanisms: string[] = (chosen.allowed || []).slice();
    const allows = function (id: string): boolean {
      log.debug("Entering allows().");
      log.debug("Leaving allows().");
      return allowedMechanisms.indexOf(id) >= 0;
    };
    const several = allowedMechanisms.length > 1 &&
      chosen.mechanism === 'password';
    const forceMfa = !!opts.forceMfa || chosen.mechanism === 'password-mfa' ||
      (several && allows('password-mfa') && !allows('password') &&
       !allows('webauthn'));
    let forcePasswordless = chosen.mechanism === 'webauthn' ||
      (several && allows('webauthn') && !allows('password') &&
       !allows('password-mfa'));
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
      // WHERE THIS FLOW STARTED, for a restart at the person's home cell
      // (#98 D9). Null in single-cell mode.
      restart: this.restartOrigin(),
      returnTo: returnTo,
      details: Array.isArray(opts.details) ? opts.details : [],
      hint: lockedUsername || String(opts.hint || ''),
      lockedUsername: lockedUsername,
      // THE MECHANISMS THE APPLICATION ALLOWS (#457), empty for every one:
      // what loginPage() offers. Not the enforcement — the issuance policy
      // refuses a session made with anything else at startSessionHere().
      allowedMechanisms: allowedMechanisms,
      forceMfa: forceMfa,
      // A SECURITY KEY DEMANDED (2026-09-17) — alone or after a password; see
      // the entry point's header. On the record for `forcePasswordless`'s
      // reason: the POST at the other end is an answer, not the question.
      forceKey: forceKey,
      // `phrh` WHEN THE SIGN-IN MUST EARN IT (#739), so the passkey step
      // narrows `allowCredentials` to keys whose recorded evidence can.
      // Anything else is '', including a request `phr` would also answer.
      phishingClass: opts.phishingClass === 'phrh' ? 'phrh' : '',
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
      // OpenID Connect Core 1.0 section 3.1.2.1's `ui_locales` (#539): the
      // languages the relying party asked this screen to be drawn in, ahead
      // of the person's own and the browser's (`common/page_locale.ts`).
      uiLocales: String(opts.uiLocales || '').slice(0, 256),
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
      log.debug("Leaving Authn.beginAuthenticationHere(). " + record.id +
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
      log.debug("Leaving Authn.beginAuthenticationHere(). " + record.id +
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
      log.debug("Leaving Authn.beginAuthenticationHere(). " + record.id +
                " goes to the wallet door.");
      return WALLET_PATH + '?authn=' + encodeURIComponent(record.id);
    }
    log.debug("Leaving Authn.beginAuthenticationHere(). " + record.id +
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
  // (#572: a problem answered, which the step's view and its acts each send
  // in their own shape.)
  private keyDemandProblem(step, what): any {
    const { log } = this.deps;
    log.debug("Entering Authn.keyDemandProblem().");
    // A demand made on RISK (`step.riskKey`, #899) is refused the same way
    // as one a relying party made: the step that records it hides the code
    // links, and without this a code posted to the act's URL still passed.
    if (!step || ((!step.authn || !step.authn.forceKey) && !step.riskKey)) {
      log.debug("Leaving Authn.keyDemandProblem(). No key was demanded.");
      return null;
    }
    log.info('authn: ' + what + ' was offered for "' + step.username + '" ' +
             'where the sign-in demands a security key; refused.');
    log.debug("Leaving Authn.keyDemandProblem(). Refused.");
    return { code: 'STS-AUTHN-0204',
             why: 'This sign-in demands a passkey, and ' + what + ' does not ' +
                  'answer that. Use your passkey on the previous screen.' };
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
  // A REMEMBERED BROWSER AFTER A SIGN-IN-SCREEN SESSION STARTS (#265): its
  // token issued again with the next generation, or the browser registered
  // where the person ticked "Remember this browser", or a copied or
  // unreadable cookie cleared. Every door on this screen ends in
  // refusedSession() with the pending record in hand, which is why it is
  // asked there. It never fails the sign-in.
  private afterBrowserSignIn(res, record, username, session, detail) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.afterBrowserSignIn().");
    // NOBODY SIGNED IN: "continue without signing in" leaves a remembered
    // browser alone rather than reading it as somebody else's cookie.
    if (username === ANONYMOUS_USERNAME ||
        (session && session.authenticated === false)) {
      log.debug("Leaving Authn.afterBrowserSignIn(). Anonymous.");
      return;
    }
    const said = detail || {};
    const request = said.request || this.deps.audit.currentRequest();
    try {
      const bd = this.deps.browserDevices();
      bd.afterSignIn(request, res, {
        username: username,
        recognized: this.registeredDeviceOf(session),
        secondFactor: bd.hasSecondFactor(session && session.amr),
        remember: !!(record && record.rememberBrowser)
      });
    } catch (e) {
      log.warn(errorCodes.tag('STS-DEVICE-0045') + 'authn: the remembered ' +
               'browser could not be settled after a sign-in: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving Authn.afterBrowserSignIn().");
  }

  // ---------------------------------------------------------------------------
  // THE POST-LOGIN STEP (#1096): `startSessionHere()` held the session; this
  // mints the step that asks for the activity, on the pending sign-in the
  // door held (`authn`), with what the session is to be started with when
  // the step ends (`held`): the amr, acr and door, the credential, the
  // application and the risk the door assessed. The first invitation is
  // recorded here, which is when the allotted time starts.
  // ---------------------------------------------------------------------------
  private postLoginStep(res: any, record: any, username: string,
                        said: any): boolean {
    const { log, randomId, stsCrypto, audit, postLogin } = this.deps;
    log.debug("Entering Authn.postLoginStep().");
    const hold = said.postLogin || {};
    const due = hold.due;
    if (!due) {
      log.debug("Leaving Authn.postLoginStep(). Nothing held.");
      return false;
    }
    const row = postLogin.noteAsked(username, due);
    // The end of the allotted time, from the first invitation just recorded
    // where this is it; none where the activity is never required.
    const deadline = due.enforceable === true && Number(due.graceDays) > 0
      ? Number(row.invitedAt) + Number(due.graceDays) * 24 * 60 * 60 * 1000
      : 0;
    const stepId = randomId(24);
    pendingMfa.set(stepId, {
      authn: record, username: username,
      challenge: stsCrypto.randomBytes(32).toString('base64url'),
      factor: 'post-login', alternate: '', backup: false,
      passwordless: due.role === 'primary', proved: true,
      postLogin: {
        activity: String(due.activity), role: String(due.role),
        reason: String(due.reason), required: due.required === true,
        snoozeDays: Number(due.snoozeDays) || 1,
        graceDays: Number(due.graceDays) || 0,
        deadline: deadline,
        profile: String(due.profile || '') },
      held: {
        amr: Array.isArray(hold.amr) ? hold.amr : [],
        acr: String(hold.acr || ''), via: String(hold.via || ''),
        application: String(said.application || ''),
        credential: said.credential || null, gated: said.gated === true,
        method: said.method ? String(said.method) : '' },
      risk: said.risk, riskDecision: said.riskDecision,
      expires: Date.now() + this.mfaStepTtlMs()
    });
    audit.audit({
      action: 'authn.post-login.asked', outcome: 'success',
      actor: username, target: username, channel: 'http',
      protocol: record && record.protocol,
      summary: username + ' was asked, after signing in, to register a ' +
               'post-quantum passkey' + (due.role === 'mfa'
                 ? ' as a second factor' : ' to sign in with') +
               (due.required ? '; it is required' : ''),
      detail: { activity: String(due.activity), role: String(due.role),
                reason: String(due.reason), required: due.required === true,
                profile: String(due.profile || ''),
                application: String((record && record.application) || '') }
    });
    log.info('authn: "' + username + '" signed in and is asked for a ' +
             'post-login activity (' + due.activity + ', ' + due.role +
             (due.required ? ', required' : '') + ') before the session ' +
             'starts.');
    this.stepAnswer(res, 'mfa', 'post-login', stepId, POST_LOGIN_PATH, 'mfa');
    log.debug("Leaving Authn.postLoginStep().");
    return true;
  }

  // THE SESSION THE POST-LOGIN STEP HELD, STARTED (#1096): as the door would
  // have started it — its amr and acr, its credential, its application and
  // its risk — and marked `postLoginDone` so it is not held again. The
  // passkey registered in the step is NOT an authentication of this
  // sign-in: it is what the person was asked to do after one.
  private finishPostLogin(req: any, res: any, base: string,
                          step: any): void {
    const { log } = this.deps;
    log.debug("Entering Authn.finishPostLogin().");
    const held = step.held || {};
    const said: any = { request: req, postLoginDone: true,
                        gated: held.gated === true,
                        application: String(held.application || ''),
                        credential: held.credential || { kind: 'password' },
                        risk: step.risk, riskDecision: step.riskDecision };
    if (held.method) {
      said.method = String(held.method);
    }
    const started = this.startSession(res, step.username,
      Array.isArray(held.amr) ? held.amr : [], String(held.acr || '1'),
      String(held.via || (step.authn && step.authn.protocol) || ''), said);
    if (this.refusedSession(res, base, step.authn, step.username, started,
                            said)) {
      log.debug("Leaving Authn.finishPostLogin(). Refused.");
      return;
    }
    this.returnToCaller(res, step.authn, null, null);
    log.debug("Leaving Authn.finishPostLogin(). Signed in.");
  }

  // ---------------------------------------------------------------------------
  // `POST /authn-api/mfa/{id}/post-login/…` — THE POST-LOGIN STEP'S TWO ACTS
  // (#1096):
  //
  //   * `register` — the passkey page's registration, in the activity's role
  //     and with ML-DSA only (`webauthnFacts()`); its finish starts the held
  //     session. Where the realm can no longer make one (a setting changed
  //     since the step was minted) the activity cannot be done here, and the
  //     held session is started without it (STS-AUTHN-0475): a sign-in is
  //     never held for something that cannot be done.
  //   * `skip` — refused where the activity is required (STS-AUTHN-0474);
  //     otherwise it is put off for the profile's `snoozeDays` and the held
  //     session starts.
  // ---------------------------------------------------------------------------
  /**
   * Answers an act at the post-login step.
   *
   * @param req - the request
   * @param res - the response
   * @param stepId - the step's id
   * @param action - `register` or `skip`
   * @returns nothing; the answer is sent
   */
  postLoginAct(req: any, res: any, stepId: string, action: string): void {
    const { log, baseUrlOf, audit, errorCodes, postLogin } = this.deps;
    log.debug("Entering Authn.postLoginAct(). " + action);
    const base = baseUrlOf(req);
    const found = this.stepProblem('post-login', stepId);
    if (found.problem) {
      errorCodes.mark(res, found.problem.code);
      this.stepRefused(res, found.problem.why);
      log.debug("Leaving Authn.postLoginAct(). No step.");
      return;
    }
    const step = found.step;
    const due = step.postLogin;
    this.deps.passkeyPolicy.select(String(step.username),
      String((step.held && step.held.application) || ''));
    if (action === 'skip') {
      const skipped = due.required ? { ok: false }
        : postLogin.noteSkipped(step.username, due);
      if (!skipped.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0474');
        this.stepRefused(res, 'The time allowed for this has passed, so ' +
          'it cannot be skipped any more. Register the passkey to finish ' +
          'signing in.');
        log.debug("Leaving Authn.postLoginAct(). Required.");
        return;
      }
      pendingMfa.delete(String(stepId));
      audit.audit({
        action: 'authn.post-login.skipped', outcome: 'success',
        actor: step.username, target: step.username, channel: 'http',
        protocol: step.authn && step.authn.protocol,
        summary: step.username + ' put off registering a post-quantum ' +
                 'passkey for ' + due.snoozeDays + ' day(s)',
        detail: { activity: String(due.activity), role: String(due.role),
                  snoozedUntil: new Date(Number(skipped.snoozedUntil))
                    .toISOString(),
                  profile: String(due.profile || '') }
      });
      this.finishPostLogin(req, res, base, step);
      log.debug("Leaving Authn.postLoginAct(). Skipped.");
      return;
    }
    if (!postLogin.canRegister(String(due.role))) {
      pendingMfa.delete(String(stepId));
      log.info(errorCodes.tag('STS-AUTHN-0475') + 'authn: the post-login ' +
               'passkey of "' + step.username + '" cannot be registered ' +
               'here any more (the realm makes no ML-DSA passkey in that ' +
               'role); the held session is started without it.');
      errorCodes.mark(res, 'STS-AUTHN-0475');
      this.finishPostLogin(req, res, base, step);
      log.debug("Leaving Authn.postLoginAct(). Cannot be done here.");
      return;
    }
    // THE PASSKEY PAGE'S REGISTRATION FROM HERE, as the set-up step's
    // `webauthn` does: the role off the activity, the lane the post-quantum
    // passkey is made in, a handle minted for it when the ceremony is armed.
    step.factor = 'webauthn';
    step.atSignIn = true;
    step.passwordless = due.role === 'primary';
    step.lane = postLogin.lane();
    step.userHandle = '';
    step.classicalOnly = false;
    pendingMfa.set(String(stepId), step);
    this.stepAnswer(res, 'mfa', 'webauthn', String(stepId), WEBAUTHN_PATH,
                    'mfa');
    log.debug("Leaving Authn.postLoginAct(). To the registration.");
  }

  private refusedSession(res, base, record, username, started, detail) {
    const { log, accountState, errorCodes } = this.deps;
    log.debug("Entering Authn.refusedSession().");
    if (started) {
      this.afterBrowserSignIn(res, record, username, started, detail);
      log.debug("Leaving Authn.refusedSession(). Not refused.");
      return false;
    }
    const said = detail || {};
    if (said.refusedWith === 'STS-AUTHN-0338') {
      if (res && !res.headersSent) {
        this.refuseUnread(res);
      } else {
        errorCodes.mark(res, 'STS-AUTHN-0338');
      }
      log.debug("Leaving Authn.refusedSession(). The session could not " +
                "be read.");
      return true;
    }
    // AFTER AN ACCOUNT RECOVERY (#724): the registration of a passkey, in
    // place of the refusal, where one can be registered here.
    if (said.recoveryLimited && record &&
        this.recoveryEnrolment(res, record, username, said)) {
      log.debug("Leaving Authn.refusedSession(). To the recovery " +
                "enrolment.");
      return true;
    }
    // A SESSION HELD FOR A POST-LOGIN ACTIVITY (#1096): its step, in place
    // of the refusal.
    if (said.postLogin && record &&
        this.postLoginStep(res, record, username, said)) {
      log.debug("Leaving Authn.refusedSession(). To the post-login step.");
      return true;
    }
    // A REMEMBERED BROWSER'S COOKIE THAT CAUSED OR SHARED THE REFUSAL (#265)
    // — a copy, somebody else's, or a device since marked compromised — is
    // cleared, so the next attempt from this browser is not refused on it
    // again. The device stays compromised; only the cookie goes.
    try {
      const fact = this.registeredDeviceFor({ request: said.request },
                                            username);
      if (fact && fact.via === 'browser-cookie' &&
          (fact.status === 'compromised' || (fact.browserToken &&
           (fact.browserToken.replayed || fact.browserToken.foreign)))) {
        this.deps.browserDevices().clear(res);
      }
    } catch (e) {
      log.debug("Caught in Authn.refusedSession(): " +
                ((e && e.message) || e));
    }
    const code = said.refusedWith ||
      (accountState.isDisabled(username) ? 'STS-AUTHN-0201'
                                         : 'STS-AUTHN-0010');
    const message = (code === 'STS-AUTHN-0010' ||
                     code === 'STS-AUTHN-0298' ||
                     code === 'STS-AUTHN-0305' ||
                     code === 'STS-AUTHN-0313' ||
                     code === 'STS-AUTHN-0315' ||
                     // A classical passkey where a post-quantum one is
                     // required (#718): the sentence names the algorithm
                     // and the row, and what to do instead.
                     code === 'STS-AUTHN-0356' ||

                     // After an account recovery (#724).
                     code === 'STS-AUTHN-0380' ||
                     code === 'STS-AUTHN-0381' ||
                     // A required post-login activity (#1096).
                     code === 'STS-AUTHN-0473') && said.refusedWhy
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
    void base;
    // A CLASSICAL PASSKEY WHERE A POST-QUANTUM ONE IS REQUIRED, REFUSED AFTER
    // ITS CEREMONY (#946): the usernameless sign-in, and under
    // `list-and-refuse` the passkey step. The screen draws a panel of its
    // own over the sentence — what the application requires and where to
    // get such a passkey — in the page's language, where a platform's
    // "no credential found" said nothing of this service's reason. The
    // refused assertion is NO authentication event: the session's start
    // refused it above, before any session, event or `session.start` row.
    // (Its signature counter is spent, as every verified assertion's is, so
    // it cannot be replayed.)
    this.screenRefused(res, record, message,
                       { postQuantumRequired: code === 'STS-AUTHN-0356' });
    log.debug("Leaving Authn.refusedSession(). Answered.");
    return true;
  }

  // ===========================================================================
  // WHAT THE SIGN-IN SCREEN'S ACTS ANSWER, SINCE #571: JSON TO `/authn-api`,
  // A REDIRECT TO A FORM.
  //
  // Until #571 every act at the screen answered with a PAGE — the screen
  // again with a sentence on it, the one-time code screen, the security-key
  // ceremony, the set-up step, the forced password change — drawn in answer
  // to the form's POST. The screen is a static surface now, and its acts
  // are `/authn-api`'s operations, which answer the NEXT STEP as JSON:
  //
  //   { ok: true,  next: 'redirect', location }      back to the caller
  //   { ok: true,  next: 'mfa', step, id, location } a second-factor page
  //   { ok: true,  next: 'password-change', id, location }
  //   { ok: true,  next: 'home-cell', form }         #98's restart at home
  //   { ok: false, next: 'refused', errors: [why] }  the screen again
  //
  // **THE LOGIC DID NOT MOVE, ONLY THE ANSWER.** `finishPasswordSignIn()`,
  // `passkeySignIn()`, `refusedSession()`, `returnToCaller()` and
  // `sendHome()` decide exactly what they decided; each asks
  // `answersJson(res)` — set by `authn/authn_api.ts` on the responses it
  // owns (`res.locals.authnApi`) — at the one line where a page used to be
  // sent. A second copy of the sign-in for the API would be two answers to
  // what a sign-in requires, and the second factor is the half a copy forgets.
  //
  // **THE SECOND-FACTOR STEPS ARE THE API'S TOO SINCE #572** (`mfa*Act()`,
  // below), and a session refused at the end of one is drawn on the SCREEN:
  // the sentence goes on the pending record (`screenError`), which the
  // screen's view answers, and the answer names the screen
  // (`res.locals.authnStep`, `screenRefused()`). A door that is still a FORM
  // (the wallet's, until #574) gets the same sentence behind a 303 to the
  // screen, and a next step as a 303 to its page — what a form expects.
  //
  // NO ERROR CODE IS EVER IN AN ANSWER: codes are recorded, never sent.
  // ===========================================================================
  /**
   * Whether this response belongs to `/authn-api`, and so answers JSON.
   *
   * @param res - the response
   * @returns whether the act answers JSON
   */
  answersJson(res): boolean {
    const { log } = this.deps;
    log.debug("Entering Authn.answersJson().");
    log.debug("Leaving Authn.answersJson().");
    return !!(res && res.locals && res.locals.authnApi);
  }

  // THE ADDRESS AN ANSWER NAMES IS THE ONE A REDIRECT WOULD HAVE SENT:
  // `common/app.js` wraps `res.location()` to put the realm's prefix on a
  // root-relative target and to move one to the listener that answers it
  // (#472), and a 303 went through that. A JSON answer does not, so its
  // `location` is made by the same wrapper — set, read back and taken off —
  // rather than by a second copy of either rule.
  /**
   * The address `res.location()` would have sent a browser to.
   *
   * @param res - the response
   * @param target - the address as a redirect would be given it
   * @returns the address, in the realm and on its listener
   */
  locationOf(res, target: string): string {
    const { log } = this.deps;
    log.debug("Entering Authn.locationOf().");
    res.location(String(target));
    const out = String(res.get('Location') || target);
    res.removeHeader('Location');
    log.debug("Leaving Authn.locationOf().");
    return out;
  }

  /**
   * Sends one of `/authn-api`'s answers.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the answer
   * @returns nothing
   */
  answerJson(res, status: number, body: any): void {
    const { log } = this.deps;
    log.debug("Entering Authn.answerJson(). " + status);
    res.status(status).type('application/json')
      .set('Cache-Control', 'no-store').send(JSON.stringify(body));
    log.debug("Leaving Authn.answerJson().");
  }

  // A CREDENTIAL REFUSED AT A SIGN-IN (#954). The acceptance funnel counts,
  // and a refusal is not an acceptance, so this writes authentication.refused
  // and moves no counter. The password is never an argument. A session.refuse
  // written later, after a credential was accepted and the session was then
  // refused, is a different act and is not written here. `pendingRecord` is
  // the sign-in itself, or a second-factor step whose `authn` is one.
  /**
   * Records an authentication attempt that was refused, for the application
   * the pending sign-in names.
   *
   * @param pendingRecord - the pending sign-in, or a step whose `authn` is
   *   one
   * @param username - who presented the credential
   * @param method - the factor
   * @param errorCode - the refusal's code
   * @param note - a short reason, never the credential
   * @returns nothing
   */
  noteRefusedAuthentication(pendingRecord, username: string, method: string,
                            errorCode: string, note: string): void {
    const { log } = this.deps;
    log.debug("Entering Authn.noteRefusedAuthentication().");
    const pending = pendingRecord || {};
    const authn = pending.authn || pending;
    stats.recordRefusedAuthentication({
      presented: String(username || ''),
      protocol: String(authn.protocol || ''),
      method: method,
      application: String(authn.application || ''),
      errorCode: errorCode,
      note: note,
      channel: 'http'
    });
    log.debug("Leaving Authn.noteRefusedAuthentication().");
  }

  // THE SCREEN AGAIN, WITH A SENTENCE: what every refusal at the screen was.
  // The record is put back while it has time left (`refusedSession()`'s
  // argument: the next act must find it). `extra` carries what a refused
  // passkey tells the browser — a credential nobody holds, to signal, and
  // that the autofill is not armed again. The sentence is English (#539).
  /**
   * Refuses an act at the sign-in screen: the sentence, as JSON to the API
   * or on the record behind a 303 to the screen for a form.
   *
   * @param res - the response
   * @param record - the pending sign-in
   * @param message - the sentence, English
   * @param extra - `{ status, unknownCredential, noAutofill,
   *   postQuantumRequired }` — the last (#946) draws the screen's panel for
   *   a classical passkey refused where a post-quantum one is required
   * @returns nothing
   */
  screenRefused(res, record, message: string,
    extra?: { status?: number, unknownCredential?: string,
    noAutofill?: boolean, postQuantumRequired?: boolean }): void {
    const { log } = this.deps;
    log.debug("Entering Authn.screenRefused().");
    const asked = extra || {};
    const json = this.answersJson(res);
    // A SESSION REFUSED AT THE END OF A SECOND-FACTOR STEP (#572): the step
    // is spent and the pending sign-in put back, so the refusal is drawn on
    // the SCREEN, where the person can sign in again — the sentence on the
    // record, which the screen's view answers, and the screen's address in
    // the answer for the step's page to go to.
    const fromStep = json && !!(res && res.locals && res.locals.authnStep);
    const live = !!(record && record.id && !(record.expires < Date.now()));
    if (live) {
      record.screenError = json && !fromStep ? '' : String(message || '');
      // THE PANEL (#946) is the record's, like the sentence, so the screen's
      // view draws it whichever way the refusal reached the screen; every
      // refusal sets it afresh, so the next one without it clears it.
      record.postQuantumRequired = !!asked.postQuantumRequired;
      pending.set(record.id, record);
    }
    if (json) {
      const body: any = { ok: false, next: 'refused',
                          errors: [String(message || 'Refused.')] };
      if (fromStep && live) {
        body.location = this.locationOf(res, realms.currentPrefix() +
          LOGIN_PATH + '?authn=' + encodeURIComponent(String(record.id)));
      }
      if (asked.unknownCredential || asked.noAutofill) {
        body.passkey = { unknownCredential: asked.unknownCredential || '',
                         autofill: !asked.noAutofill };
      }
      this.answerJson(res, asked.status || 400, body);
      log.debug("Leaving Authn.screenRefused(). JSON.");
      return;
    }
    res.set('Cache-Control', 'no-store');
    res.redirect(303, realms.currentPrefix() + LOGIN_PATH + '?authn=' +
                      encodeURIComponent(String((record && record.id) || '')));
    log.debug("Leaving Authn.screenRefused(). Back to the screen.");
  }

  // A NEXT STEP ON A PAGE OF ITS OWN: a second factor, the set-up step, the
  // forced password change. The page is the one that step has always been
  // drawn on, asked for by its own GET.
  /**
   * Answers a next step: JSON to the API, a 303 to its page for a form.
   *
   * @param res - the response
   * @param next - `mfa` or `password-change`
   * @param step - the step's kind (`totp`, `webauthn`, `enrol`, …)
   * @param id - the step's id
   * @param path - the page that draws it
   * @param query - the query parameter carrying the id
   * @returns nothing
   */
  stepAnswer(res, next: string, step: string, id: string, path: string,
             query: string): void {
    const { log } = this.deps;
    log.debug("Entering Authn.stepAnswer(). " + next + " " + step);
    const location = realms.currentPrefix() + path + '?' + query + '=' +
                     encodeURIComponent(id);
    if (this.answersJson(res)) {
      this.answerJson(res, 200, { ok: true, next: next, step: step, id: id,
                                  location: this.locationOf(res, location) });
      log.debug("Leaving Authn.stepAnswer(). JSON.");
      return;
    }
    res.set('Cache-Control', 'no-store');
    res.redirect(303, location);
    log.debug("Leaving Authn.stepAnswer(). A redirect.");
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
    //
    // A SUCCESSFUL SIGN-IN READS ITS ATTRIBUTE SOURCES FIRST (#94), and a
    // refusing source that failed turns the success into the caller's own
    // access_denied — the same refusal a cancelled sign-in sends back.
    // TO `/authn-api` (#571) the same 303 is an answer naming where to go,
    // and the browser goes there with a GET — which is what a 303 did.
    const self = this;
    const leave = function (): void {
      log.debug("Entering leave().");
      if (self.answersJson(res)) {
        self.answerJson(res, 200, { ok: true, next: 'redirect',
                                    location: self.locationOf(res, target) });
        log.debug("Leaving leave(). JSON.");
        return;
      }
      res.redirect(303, target);
      log.debug("Leaving leave().");
    };
    // THE FLOW RESUMES AS THE SESSION THIS SIGN-IN STARTED (#561): a
    // selection ticket for it, where the session joined a browser's account
    // set. Nothing changes with several accounts off.
    if (!error) {
      target = this.ticketedReturn(res, record, target);
    }
    if (error) {
      leave();
    } else {
      this.afterSignIn(res, function () {
        leave();
      }, function (why) {
        // error-code: none — afterSignIn() marked STS-ATTR-0012 on `res`
        self.returnToCaller(res, record, 'access_denied', why);
      });
    }
    log.debug("Leaving Authn.returnToCaller(). Sending the browser to " +
              target + " with a 303.");
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
  /**
   * Returns a pending second-factor step, read-only; an expired step is dropped
   * on the way past.
   *
   * @param id - the step id
   * @returns the step, or null
   */
  mfaStepFor(id: unknown, accepts?: string): any {
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
    // A POST-LOGIN STEP (#1096) IS NOT A SECOND-FACTOR STEP, and no other
    // step's act may finish it: the person is already authenticated, so a
    // one-time code, a recovery code or a wallet posted to its id would
    // start the held session WITHOUT the activity — the way round a required
    // one. It is answered only to its own page (`post-login`), to the
    // passkey page once Register has made it that ceremony, and to the acts
    // that end any step (`any`: Start over, the API's page lookup).
    if (step.postLogin && accepts !== 'any' && accepts !== 'post-login' &&
        !(accepts === 'webauthn' && step.factor === 'webauthn')) {
      log.debug("Leaving Authn.mfaStepFor(). A post-login step, not " +
                "answered to " + (accepts || 'this act') + ".");
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
  /**
   * Finishes a second-factor step with a verified wallet presentation for the
   * same person.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step id
   * @param outcome - `vc_verifier.ts`'s `signInOutcome()`
   * @returns the session, or `{ refused, why }`
   */
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
               'one factor. Use your authenticator app, your passkey or your ' +
               'password.' };
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
    // A PROOF BEFORE AN ENROLMENT (#475): no session yet; the set-up
    // screen, offering what the application allows.
    if (step.thenEnrol) {
      this.enrolAfterProof(res, step, amr);
      log.debug("Leaving Authn.finishWithWallet(). To the set-up screen.");
      return { enrolling: true };
    }
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
  //     (`record.forceMfa`), no requirement applies (the authentication policy,
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
  //
  // **AND AFTER AN EMAILED FIRST FACTOR (#64)**, with `opts.first` `email`:
  // the same decision, except that the emailed factor is never the second
  // factor after itself — one mailbox proved twice is one factor — and the
  // password fallback is offered only where the authentication policy
  // accepts a password as a second factor.
  /**
   * Asks for a second factor after a wallet or emailed first factor, where one
   * is needed.
   *
   * Where none is needed it answers `{ handled: false }` and the door starts
   * the session itself.
   *
   * @param req - the request
   * @param res - the response
   * @param record - the pending sign-in record
   * @param username - the person
   * @param outcome - the first factor's outcome
   * @param assessment - the sign-in's risk assessment
   * @param opts - `first: 'email'` after an emailed first factor
   * @returns whether it took over the response
   */
  // ---------------------------------------------------------------------------
  // A SECOND FACTOR HERE, AFTER A FEDERATION PARTNER (#565, the risk design's
  // decision 1). A federated sign-in the policy answers with a step-up used
  // to be refused outright — the partner authenticated the person, and this
  // door could ask for nothing — and a consumer provider asserts no second
  // factor this service believes. So the partner's verified answer is the
  // FIRST factor, exactly as a wallet presentation is: a pending record is
  // minted for the person, locked to their name and returning to the
  // federation module's step-up address, and `beginSecondFactorAfterWallet()`
  // asks for what they hold HERE — never enrolling one, because an elevated
  // risk suspects exactly the person who would enrol their own. The
  // federation module, not this one, then starts the federated session: this
  // module requires nothing of it (4b).
  // ---------------------------------------------------------------------------
  /**
   * Asks for a second factor this service holds for a person a federation
   * partner signed in, where the issuance policy asked for a step-up.
   *
   * @param req - the request
   * @param res - the response
   * @param spec - `username`, `returnTo` (a path on this service), `via`,
   *   `details` for the step's page, and `assessment`, the sign-in's risk
   * @returns `{ handled }`, or `{ handled: false, refused, errorCode }`
   */
  beginSecondFactorAfterFederation(req: any, res: any, spec: any): any {
    const { log } = this.deps;
    log.debug("Entering Authn.beginSecondFactorAfterFederation(). " +
              "username=" + spec.username);
    const target = this.beginAuthentication({
      returnTo: String(spec.returnTo || ''),
      protocol: String(spec.via || 'Federation step-up'),
      lockedUsername: String(spec.username || ''),
      application: '',
      details: spec.details || []
    });
    const id = new URL(String(target), 'http://step.invalid')
      .searchParams.get('authn') || '';
    const record = id ? pending.get(id) : null;
    if (!record) {
      log.debug("Leaving Authn.beginSecondFactorAfterFederation(). No " +
                "pending record.");
      return { handled: false, refused: 'Authentication failed.',
               errorCode: 'STS-RISK-0018' };
    }
    log.debug("Leaving Authn.beginSecondFactorAfterFederation().");
    return this.beginSecondFactorAfterWallet(req, res, record,
      String(spec.username), { amr: ['federated'], acr: '' },
      spec.assessment, { first: 'federation' });
  }

  beginSecondFactorAfterWallet(req: any, res: any, record: any,
                               username: string, outcome: any,
                               assessment?: any,
                               opts?: { first?: string }): any {
    const { log, randomId, gate, credentials, stsCrypto, config } = this.deps;
    const firstIsEmail = !!(opts && opts.first === 'email');
    const firstIsFederation = !!(opts && opts.first === 'federation');
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
        risk: engine.factsOf(risk, outcome.amr || ['pop'], outcome.acr || '1'),
        // The session's start asks about the device (#164 phase 6).
        deviceDeferred: true
      });
      if (!riskAnswer.allowed && riskAnswer.risk &&
          !riskAnswer.risk.observed) {
        // Only an mfa-role key answers (#898); the step offers no other.
        const holdsKey = enrolled.mfaKeys > 0;
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
    // AFTER A FEDERATION PARTNER (#565) the step-up is answered with a factor
    // the person holds HERE — an authenticator app or a security key — and
    // never with a password, which a consumer provider's newcomer does not
    // have and which would prove nothing about the partner's sign-in.
    // Holding neither is a refusal, never an enrolment.
    if (firstIsFederation && riskFactor &&
        !(enrolled.totp || enrolled.mfaKeys + enrolled.primaryKeys > 0)) {
      this.settleRisk(risk, { decision: 'step-up', errorCode: 'STS-RISK-0018',
                              policy: '' });
      log.debug("Leaving Authn.beginSecondFactorAfterWallet(). After a " +
                "partner, nothing held answers the step-up.");
      return { handled: false, refused: 'Authentication failed.',
               onRisk: true, errorCode: 'STS-RISK-0018' };
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
      // The roles alone: the risk was asked above, and the session's start
      // asks about the device (#164 phase 6).
      risk: null,
      deviceDeferred: true
    });
    if (!roleAnswer.allowed) {
      log.debug("Leaving Authn.beginSecondFactorAfterWallet(). Refused.");
      return { handled: false, refused: roleAnswer.why };
    }
    const base = this.deps.baseUrlOf(req);
    const firstAmr = [].concat(outcome.amr || ['pop']).map(String);
    pending.delete(record.id);
    let configured = riskFactor === 'security-key' ? 'webauthn'
      : (enrolled.secondFactor || '');
    if (firstIsEmail && String(configured).indexOf('email-') === 0) {
      configured = '';
    }
    // AN EMAIL DOES NOT ANSWER A STEP-UP ON RISK (D1), so a person whose one
    // second factor is the email is not handed it when risk asked.
    if (riskFactor && String(configured).indexOf('email-') === 0) {
      configured = '';
    }
    // -----------------------------------------------------------------------
    // THE APPLICATION'S SECOND FACTORS (#475), as at the password screen
    // (`narrowSecondFactor()`), with the password as one more factor the
    // list may or may not allow. A held factor it does not allow gives way
    // to another held one, then to the password; only where neither is
    // allowed is it PROVED and an allowed one enrolled after it.
    // `narrowedAway` keeps that person off the enrolment below, which is for
    // somebody who holds nothing: enrolling for them unproved is the bypass.
    // -----------------------------------------------------------------------
    const mfaAllowed = this.mfaAllowedFor(String(record.application || ''));
    const passwordSecond = !firstIsFederation &&
      this.deps.authnPolicy.allows('password', 'second-factor') &&
      mfaLib.allowsStepFactor(mfaAllowed, 'password');
    let thenEnrol = false;
    let narrowedAway = false;
    if (mfaAllowed.length && configured &&
        !mfaLib.allowsStepFactor(mfaAllowed, configured)) {
      const demand = riskFactor === 'security-key' ? 'key'
        : (riskFactor ? 'any' : '');
      const held = demand === 'key' ? ''
        : this.allowedHeldFactor(mfaAllowed, enrolled);
      if (held) {
        configured = held;
      } else if (passwordSecond && demand !== 'key') {
        configured = '';
        narrowedAway = true;
      } else {
        const narrowed = this.narrowSecondFactor(username, mfaAllowed,
                                                 enrolled, configured, demand);
        if (narrowed.refused) {
          log.debug("Leaving Authn.beginSecondFactorAfterWallet(). No " +
                    "second factor the application allows.");
          return { handled: false, refused: narrowed.why,
                   errorCode: narrowed.refused };
        }
        configured = narrowed.factor;
        thenEnrol = narrowed.thenEnrol;
      }
    }
    if (requirement.required && !configured && !riskFactor && !narrowedAway) {
      const offered = this.enrolmentOfferedFor(mfaAllowed);
      if (offered.totp || offered.webauthn) {
        const setupId = randomId(24);
        pendingMfa.set(setupId, {
          authn: record, username: username,
          challenge: stsCrypto.randomBytes(32).toString('base64url'),
          factor: 'enrol', alternate: '', backup: false, passwordless: false,
          requiredBy: requirement.byUser ? 'account' : 'realm',
          firstAmr: firstAmr, mfaAllowed: mfaAllowed,
          // The sign-in's assessment (#906), for the finisher's session, as
          // the step below and the password screen's set-up step carry it.
          risk: assessment || undefined,
          expires: Date.now() + this.mfaStepTtlMs()
        });
        // The set-up step's page (#572), by its address.
        this.stepAnswer(res, 'mfa', 'enrol', setupId, MFA_SETUP_PATH, 'mfa');
        log.debug("Leaving Authn.beginSecondFactorAfterWallet(). Enrolment.");
        return { handled: true };
      }
    }
    const factor = configured || (passwordSecond ? 'password' : '');
    if (!factor) {
      log.info('authn: "' + username + '" needs a second factor and holds ' +
               'none this sign-in can ask for, and the authentication ' +
               'policy does not accept a password as one; refused.');
      log.debug("Leaving Authn.beginSecondFactorAfterWallet(). Nothing to " +
                "ask for.");
      return { handled: false, refused: 'A second factor is needed and none ' +
               'that this realm accepts is available for this account.',
               errorCode: 'STS-AUTHN-0256' };
    }
    const mfaId = randomId(24);
    pendingMfa.set(mfaId, {
      authn: record, username: username,
      challenge: stsCrypto.randomBytes(32).toString('base64url'),
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
      passwordAlternate: factor !== 'password' && passwordSecond &&
                         riskFactor !== 'security-key',
      // The emailed factor as a way round (#64), never after itself and
      // never on risk.
      email: firstIsEmail || riskFactor ||
             String(factor).indexOf('email-') === 0
        ? '' : (enrolled.mailFactor ? enrolled.mailFactor.held : ''),
      // The sign-in's assessment (#62 P3), for the finisher's session.
      risk: assessment || undefined,
      // A security key demanded on risk, for keyDemandProblem() (#899).
      riskKey: riskFactor === 'security-key',
      // The application's second factors (#475), as at the password screen.
      mfaAllowed: mfaAllowed,
      thenEnrol: thenEnrol,
      expires: Date.now() + this.mfaStepTtlMs()
    });
    this.narrowStep(pendingMfa.get(mfaId));
    void config;
    log.info('authn: "' + username + '" signed in with ' +
             (opts && opts.first === 'federation' ? 'a federation partner'
               : (opts && opts.first === 'certificate'
                 ? 'a TLS client certificate' : 'a wallet')) +
             ' and a second ' +
             'factor is needed (' + (record.forceMfa ? 'the request demands ' +
             'two' : requirement.required ? 'required of them' :
             'they hold one') + '); asking for ' + factor + '.');
    // THE STEP'S PAGE, BY ITS ADDRESS (#572): a 303 to the wallet door's
    // form, the next step to `/authn-api`'s act — `stepAnswer()` decides.
    // An emailed factor's first message is sent first, as it always was,
    // and a message that could not be sent is said on its page.
    const self = this;
    if (factor === 'email-code' || factor === 'email-link') {
      const path = factor === 'email-code' ? EMAIL_CODE_PATH : EMAIL_LINK_PATH;
      Promise.resolve(this.emailDoor().armSecondFactor(req, res, mfaId))
        .catch(function (e) {
          log.debug("Caught in Authn.beginSecondFactorAfterWallet(): " +
                    ((e && e.message) || e));
          // The page says nothing was sent, and offers the other factors.
          return null;
        })
        .then(function () {
          self.stepAnswer(res, 'mfa', factor, mfaId, path, 'mfa');
        });
    } else if (factor === 'totp') {
      this.stepAnswer(res, 'mfa', 'totp', mfaId, TOTP_PATH, 'mfa');
    } else if (factor === 'webauthn') {
      // THE CEREMONY THIS STEP WAS MINTED FOR (#574): drawn by the passkey
      // page, as the sign-in screen's is (#571).
      const minted = pendingMfa.get(mfaId);
      if (minted) {
        minted.atSignIn = true;
        pendingMfa.set(mfaId, minted);
      }
      this.stepAnswer(res, 'mfa', 'webauthn', mfaId, WEBAUTHN_PATH, 'mfa');
    } else {
      this.stepAnswer(res, 'mfa', 'password', mfaId, PASSWORD_FACTOR_PATH,
                      'mfa');
    }
    void base;
    log.debug("Leaving Authn.beginSecondFactorAfterWallet(). " + factor + ".");
    return { handled: true };
  }

  // ===========================================================================
  // THE SECOND-FACTOR STEPS ARE PAGES OF THE SIGN-IN SURFACE (#572,
  // 2026-10-12).
  //
  // `/authn/totp`, `/authn/webauthn`, `/authn/backup-code`,
  // `/authn/password-factor` and `/authn/mfa-setup` were drawn here, each a
  // page with a form posting back to its own path. Since #572 each path
  // answers the sign-in surface's shell, the browser draws the page from
  // `GET /authn-api/mfa/{id}?page=<page>` — `mfaView()` below, every
  // decision the markup was drawn under as a fact and no words — and every
  // act is `/authn-api`'s (`mfaTotpAct()` and its siblings, further down),
  // whose answer is the next step in #571's shape.
  //
  // **WHAT A PAGE MAY BE DRAWN FOR DID NOT CHANGE**: `stepProblem()` is what
  // each GET refused before it drew anything — a step that expired, a code
  // page for somebody with no authenticator app, a passkey page for
  // somebody holding no key of the step's role (except the enrolment
  // ceremony the screen minted the step for), a recovery-code page for
  // somebody with no unspent code, a password page after a password — and
  // both the shell's GET (as the 400 it always answered) and the view ask
  // it. The step id is a bearer capability, as `?mfa=` always was: it is
  // never logged, and `common/audit.js` redacts it from a row's path.
  // ===========================================================================

  /**
   * The page a second-factor step is drawn on, by the name `/authn-api`
   * gives it.
   *
   * @param page - `totp`, `webauthn`, `backup-code`, `password` or `setup`
   * @returns the path, or '' for a name that is not a page
   */
  stepPagePath(page: string): string {
    const { log } = this.deps;
    log.debug("Entering Authn.stepPagePath(). " + page);
    const out = STEP_PAGES[page] || '';
    log.debug("Leaving Authn.stepPagePath().");
    return out;
  }

  /**
   * Whether a step's page may be drawn: the step, or the refusal its GET
   * always answered (`{ problem: { code, why } }`).
   *
   * @param page - the page's name (`stepPagePath()`)
   * @param mfaId - the step's id
   * @returns `{ step }` or `{ problem }`
   */
  stepProblem(page: string, mfaId: string): any {
    const { log, credentials } = this.deps;
    log.debug("Entering Authn.stepProblem(). " + page);
    const restart = ' Start the request again from the application that ' +
                    'sent you here.';
    if (page === 'setup') {
      const setup = pendingMfa.get(mfaId);
      if (!setup || setup.expires < Date.now() ||
          ['enrol', 'enrol-totp'].indexOf(setup.factor) < 0) {
        if (setup && setup.expires < Date.now()) {
          pendingMfa.delete(mfaId);
        }
        log.debug("Leaving Authn.stepProblem(). No set-up step.");
        return { problem: { code: 'STS-AUTHN-0173',
          why: 'This second-factor set-up has expired or does not exist.' +
               restart } };
      }
      log.debug("Leaving Authn.stepProblem(). The set-up step.");
      return { step: setup };
    }
    const step = this.mfaStepFor(mfaId, page);
    if (page === 'post-login') {
      if (!step || step.factor !== 'post-login' || !step.postLogin) {
        log.debug("Leaving Authn.stepProblem(). No post-login step.");
        return { problem: { code: 'STS-AUTHN-0019',
          why: 'This step after signing in has expired or does not ' +
               'exist.' + restart } };
      }
      log.debug("Leaving Authn.stepProblem(). The post-login step.");
      return { step: step };
    }
    if (page === 'password') {
      if (!step || this.firstAmrOf(step).indexOf('pwd') >= 0) {
        log.debug("Leaving Authn.stepProblem(). No password step.");
        return { problem: { code: 'STS-AUTHN-0019',
          why: 'There is no sign-in waiting for a password as its second ' +
               'factor.' + restart } };
      }
      log.debug("Leaving Authn.stepProblem(). The password step.");
      return { step: step };
    }
    if (!step) {
      log.debug("Leaving Authn.stepProblem(). The step had expired.");
      return { problem: { code: 'STS-AUTHN-0019',
        why: 'This second-factor step has expired.' + restart } };
    }
    if (page === 'totp') {
      const demanded = this.keyDemandProblem(step, 'a one-time code');
      if (demanded) {
        log.debug("Leaving Authn.stepProblem(). A key was demanded.");
        return { problem: demanded };
      }
      if (!credentials.mechanismsFor(step.username).totp) {
        log.info('authn: a one-time code screen was asked for "' +
                 step.username + '", who has no authenticator enrolled. ' +
                 'Refused.');
        log.debug("Leaving Authn.stepProblem(). Nothing is enrolled.");
        return { problem: { code: 'STS-AUTHN-0076',
          why: 'No authenticator app is enrolled for that account, so ' +
               'there is no code to ask for.' } };
      }
    } else if (page === 'backup-code') {
      const held = credentials.mechanismsFor(step.username).backupCodes;
      if (!held || !held.remaining) {
        log.info('authn: a recovery code screen was asked for "' +
                 step.username + '", who has ' + ((held && held.total)
                   ? 'spent every code in their set' : 'no recovery codes') +
                 '. Refused.');
        log.debug("Leaving Authn.stepProblem(). Nothing left to present.");
        return { problem: (held && held.total)
          ? { code: 'STS-AUTHN-0088',
              why: 'Every recovery code on that account has been used. A ' +
                   'set is issued once and is never topped up, so an ' +
                   'administrator has to clear it before a new one can be ' +
                   'issued.' }
          : { code: 'STS-AUTHN-0087',
              why: 'No recovery codes have been issued for that account, ' +
                   'so there is nothing to ask for.' } };
      }
    } else if (page === 'webauthn') {
      // THE KEYS OF THE STEP'S ROLE (#534): a passwordless step is drawn for
      // somebody holding a PRIMARY key, a second-factor step for somebody
      // holding an mfa key — EXCEPT THE ENROLMENT CEREMONY THE SCREEN (or
      // the set-up step) MINTED THIS STEP FOR (#571, `step.atSignIn`). A
      // hand-made address must not draw an enrolment for somebody whose
      // account is configured for another factor: register a fresh key,
      // skip the configured factor — the bypass `/authn/mfa-setup` refuses.
      const held = step.passwordless
        ? credentials.mechanismsFor(step.username).primaryKeys
        : credentials.mechanismsFor(step.username).mfaKeys;
      if (held < 1 && !(step.atSignIn && step.factor === 'webauthn')) {
        log.info('authn: a security-key screen was asked for "' +
                 step.username + '", who holds no key marked as a second ' +
                 'factor. Refused.');
        log.debug("Leaving Authn.stepProblem(). No key is enrolled.");
        return { problem: { code: 'STS-AUTHN-0025',
          why: 'No passkey is registered as a second factor for that ' +
               'account.' } };
      }
    }
    log.debug("Leaving Authn.stepProblem(). Drawn for " + step.username +
              ".");
    return { step: step };
  }

  // THE WAYS ROUND THE FACTOR A PAGE ASKS FOR, as each page drew them: the
  // other mechanism the person holds (`alternate`, resolved when the step
  // was minted so a link cannot offer a factor they have not enrolled), the
  // wallet after a password and the password after a wallet, the emailed
  // factor (#64), and — last, because the codes are finite and issued
  // once — a recovery code.
  private stepLinks(page: string, step: any): any {
    const { log, config } = this.deps;
    log.debug("Entering Authn.stepLinks(). " + page);
    const links = { totp: false, webauthn: false, wallet: false,
                    password: false, email: '', backup: false };
    if (page === 'password') {
      links.totp = step.alternate === 'totp';
      log.debug("Leaving Authn.stepLinks(). The password page.");
      return links;
    }
    if (page !== 'totp' && page !== 'webauthn') {
      log.debug("Leaving Authn.stepLinks(). None on this page.");
      return links;
    }
    links.totp = page === 'webauthn' && step.alternate === 'totp';
    links.webauthn = page === 'totp' && step.alternate === 'webauthn';
    links.wallet = this.firstAmrOf(step).indexOf('pop') < 0 &&
      !step.passwordless && !!config.value('oid4vp.signIn') &&
      this.stepAllowsWallet(step);
    links.password = !!step.passwordAlternate;
    // A LINK TO A PAGE, not a send: the page it leads to asks before
    // anything is mailed, because a GET must not be what sends mail.
    links.email = step.email === 'code' || step.email === 'link'
      ? String(step.email) : '';
    links.backup = !!step.backup;
    log.debug("Leaving Authn.stepLinks().");
    return links;
  }

  /**
   * A second-factor step's view for its page: facts and no words.
   *
   * @param req - the request
   * @param page - the page's name (`stepPagePath()`)
   * @param mfaId - the step's id
   * @param key - the passkey a person chose, on the passkey page (#534)
   * @returns `{ view, uiLocales, preferredLanguage }`, or `{ problem }`
   */
  mfaView(req: any, page: string, mfaId: string, key?: string): any {
    const { log, baseUrlOf, credentials } = this.deps;
    log.debug("Entering Authn.mfaView(). " + page);
    const found = this.stepProblem(page, mfaId);
    if (found.problem) {
      log.debug("Leaving Authn.mfaView(). Refused.");
      return found;
    }
    const step = found.step;
    const base = baseUrlOf(req);
    const view: any = { page: page, id: String(mfaId),
                        username: String(step.username),
                        passwordless: !!step.passwordless,
                        links: this.stepLinks(page, step) };
    if (page === 'totp') {
      // What the AUTHENTICATOR was told, off the person's own enrolment, so
      // the field asks for the right number of digits.
      const detail = credentials.mechanismsFor(step.username).totpDetail;
      view.totp = { digits: (detail && detail.digits) || 6,
                    period: (detail && detail.period) || 30 };
    } else if (page === 'password') {
      view.amr = this.firstAmrOf(step).concat(['pwd']);
    } else if (page === 'backup-code') {
      // The COUNT and never the codes, off the store rather than the step:
      // a code may have been spent since the step was minted. WHICH
      // MECHANISM it stands in for, as a kind (#539: a phrase dropped into a
      // sentence does not decline in most of the page's languages).
      const status = credentials.mechanismsFor(step.username).backupCodes ||
                     { remaining: 0, total: 0 };
      const factor = String(step.factor || '');
      view.backup = {
        factor: factor === 'webauthn' ? 'passkey'
          : (factor.indexOf('email-') === 0
            ? (factor === 'email-code' ? 'code' : 'link') : 'app'),
        back: ['webauthn', 'email-code', 'email-link'].indexOf(factor) >= 0
          ? factor : 'totp',
        remaining: Number(status.remaining) || 0,
        total: Number(status.total) || 0,
        low: status.remaining > 0 && status.remaining <= 3 };
    } else if (page === 'webauthn') {
      const facts = this.webauthnFacts(base, String(mfaId), step, key);
      delete facts.ceremony;
      view.webauthn = facts;
    } else if (page === 'setup') {
      view.setup = this.mfaSetupFacts(base, step);
    } else if (page === 'post-login') {
      // WHAT IS ASKED (#1096), as facts: the activity, the role, why, and
      // whether Skip is offered and for how long.
      const due = step.postLogin || {};
      view.postLogin = {
        activity: String(due.activity || ''), role: String(due.role || ''),
        reason: String(due.reason || ''), required: due.required === true,
        canSkip: due.required !== true,
        snoozeDays: Number(due.snoozeDays) || 0,
        deadline: Number(due.deadline) > 0
          ? new Date(Number(due.deadline)).toISOString() : '' };
    }
    const own = this.preferredLanguageOf(String(step.username));
    log.debug("Leaving Authn.mfaView().");
    return { view: view,
             uiLocales: String((step.authn && step.authn.uiLocales) || ''),
             preferredLanguage: own || null };
  }

  // A REFUSAL OF A STEP'S ACT, drawn on the step's own page, which keeps the
  // step: a wrong code, a ceremony that did not verify, a rate limit. The
  // sentence is English (#539) and carries no code.
  /**
   * Refuses an act at a second-factor step; the page draws it.
   *
   * @param res - the response
   * @param why - the sentence
   * @param status - the HTTP status, 400 where left out
   * @returns nothing
   */
  stepRefused(res: any, why: string, status?: number): void {
    const { log } = this.deps;
    log.debug("Entering Authn.stepRefused(). " + (status || 400));
    this.answerJson(res, status || 400, { ok: false, next: 'refused',
                                          errors: [String(why)] });
    log.debug("Leaving Authn.stepRefused().");
  }

  /**
   * Spends a pending record and redirects (303) back to whatever was
   * interrupted.
   *
   * @param res - the response
   * @param record - the pending record
   */
  completeAuthentication(res, record) {
    const { log } = this.deps;
    log.debug("Entering Authn.completeAuthentication(). id=" + record.id);
    pending.delete(record.id);
    this.returnToCaller(res, record, null, null);
    log.debug("Leaving Authn.completeAuthentication(). Sent them back to " +
              record.returnTo + ".");
  }

  // ===========================================================================
  // THE EMAILED CODE AND LINK'S HOLD ON A SIGN-IN (#64).
  //
  // `authn/email_factor.ts` draws the screens and checks the secrets; what it
  // needs from here is the one register of sign-ins waiting for a factor
  // (`pendingMfa`) and the ways out of one — the same needs the wallet door
  // has, answered the same way: a few functions, and never the store itself.
  // ===========================================================================

  // The door, loaded when first used: it is required after this module.
  /**
   * Returns `authn/email_factor.ts`, loaded when first used.
   *
   * @returns the email door module
   */
  emailDoor(): any {
    const { log } = this.deps;
    log.debug("Entering Authn.emailDoor().");
    log.debug("Leaving Authn.emailDoor().");
    return require('./email_factor');
  }

  // A new step, stored; answers its id.
  /**
   * Stores a new second-factor step.
   *
   * @param step - the step
   * @returns its id
   */
  mintMfaStep(step: any): string {
    const { log, randomId } = this.deps;
    log.debug("Entering Authn.mintMfaStep().");
    const id = randomId(24);
    pendingMfa.set(id, step);
    log.debug("Leaving Authn.mintMfaStep().");
    return id;
  }

  // A step written back after it changed (a code sent, an attempt counted).
  /**
   * Writes a second-factor step back after it changed.
   *
   * @param id - the step id
   * @param step - the step
   */
  saveMfaStep(id: string, step: any): void {
    const { log } = this.deps;
    log.debug("Entering Authn.saveMfaStep().");
    pendingMfa.set(String(id), step);
    log.debug("Leaving Authn.saveMfaStep().");
  }

  /**
   * Deletes a second-factor step.
   *
   * @param id - the step id
   */
  dropMfaStep(id: string): void {
    const { log } = this.deps;
    log.debug("Entering Authn.dropMfaStep().");
    pendingMfa.delete(String(id));
    log.debug("Leaving Authn.dropMfaStep().");
  }

  // ===========================================================================
  // START OVER (rcbj, 2026-10-12): "each MFA screen during login should have
  // a back button to start the login over in a graceful manner".
  //
  // A step after the sign-in screen — a second factor, the set-up step, an
  // emailed factor, the forced password change — CARRIES the pending sign-in
  // it was minted from (`step.authn`), which was taken out of `pending` when
  // the step began. Starting over is the reverse, and nothing else:
  //
  //   * the step is ENDED: deleted from its store, and with it whatever it
  //     held — an emailed code's hash, a link's token, an enrolment's secret
  //     in progress, the first factor's `amr` and risk assessment. No session
  //     is started and no factor is counted: the first factor is spent with
  //     the step, and the person proves it again.
  //   * the ORIGINAL pending sign-in is put back under its SAME id with a
  //     fresh expiry and nothing of the attempt on it (no sentence, no armed
  //     passkey challenge, no "remember this browser" ticked), so the
  //     relying party's request — its returnTo, its demands, its client —
  //     completes after the person signs in again.
  //   * the answer is the sign-in screen for that record, the address every
  //     refusal at a step's end already sends the browser to
  //     (`screenRefused()`).
  //
  // A STEP WITH NO RECORD TO RETURN TO cannot come about — every step is
  // minted with its `authn` — but if one did, there would be no request to
  // continue and `/authn/login` is not a destination without one: the step
  // is still ended and the browser sent to the realm's front door, which
  // offers a way in, rather than to a sign-in screen that can only refuse.
  //
  // It is not a protocol endpoint and changes none: what reaches a relying
  // party is exactly what a sign-in that had not been interrupted sends.
  // ===========================================================================
  /**
   * Puts a step's pending sign-in back and answers the sign-in screen for
   * it (the step itself is already taken out of its store by the caller).
   *
   * @param res - the response
   * @param step - the step, ended
   * @param kind - what the step was, for the audit row
   * @returns nothing
   */
  private restartFrom(res: any, step: any, kind: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering Authn.restartFrom(). " + kind);
    const record = step && step.authn;
    const username = String((step && step.username) || '');
    const back = !!(record && record.id);
    if (back) {
      record.screenError = '';
      delete record.postQuantumRequired;
      delete record.passkeyChallenge;
      record.rememberBrowser = false;
      record.expires = Date.now() + this.pendingTtlMs();
      pending.set(record.id, record);
    }
    audit.audit({
      action: 'authn.sign-in.started-over', outcome: 'success',
      actor: username || 'anonymous', target: username, channel: 'http',
      protocol: (record && record.protocol) || 'Authentication',
      summary: (username || 'somebody') + ' left the ' + kind +
               ' step and started the sign-in over' +
               (back ? '' : '; it had no request to return to'),
      detail: { step: kind, returned: back }
    });
    const target = back
      ? realms.currentPrefix() + LOGIN_PATH + '?authn=' +
        encodeURIComponent(String(record.id))
      : realms.currentPrefix() + '/';
    this.answerJson(res, 200, { ok: true, next: 'redirect',
                                location: this.locationOf(res, target) });
    log.debug("Leaving Authn.restartFrom(). " +
              (back ? 'Back to the screen.' : 'To the front door.'));
  }

  /**
   * `POST /authn-api/mfa/{id}/start-over`: ends a second-factor, set-up or
   * emailed-factor step and puts its pending sign-in back.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step id
   * @returns nothing
   */
  mfaStartOver(req: any, res: any, mfaId: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.mfaStartOver().");
    void req;
    const step = this.mfaStepFor(mfaId, 'any');
    if (!step) {
      errorCodes.mark(res, 'STS-AUTHN-0331');
      this.answerJson(res, 400, { ok: false, next: 'refused', errors: [
        'This sign-in step has already ended. Start the request again ' +
        'from the application that sent you here.'] });
      log.debug("Leaving Authn.mfaStartOver(). No step.");
      return;
    }
    pendingMfa.delete(String(mfaId));
    this.restartFrom(res, step, String(step.factor || 'second-factor'));
    log.debug("Leaving Authn.mfaStartOver().");
  }

  /**
   * `POST /authn-api/password-change/{id}/start-over`: ends the forced
   * password change, changing nothing, and puts its pending sign-in back.
   *
   * @param req - the request
   * @param res - the response
   * @param changeId - the step id
   * @returns nothing
   */
  passwordChangeStartOver(req: any, res: any, changeId: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.passwordChangeStartOver().");
    void req;
    const step = pendingPasswordChange.get(String(changeId || ''));
    if (!step || step.expires < Date.now()) {
      pendingPasswordChange.delete(String(changeId || ''));
      errorCodes.mark(res, 'STS-AUTHN-0331');
      this.answerJson(res, 400, { ok: false, next: 'refused', errors: [
        'This sign-in step has already ended. Start the request again ' +
        'from the application that sent you here.'] });
      log.debug("Leaving Authn.passwordChangeStartOver(). No step.");
      return;
    }
    pendingPasswordChange.delete(String(changeId));
    this.restartFrom(res, step, 'password-change');
    log.debug("Leaving Authn.passwordChangeStartOver().");
  }

  // The pending sign-in record a first factor is minted from, spent: the
  // step carries it from here on, as a password step's does.
  /**
   * Spends the pending sign-in record a first factor's step is minted from.
   *
   * @param record - the pending record
   */
  takePending(record: any): void {
    const { log } = this.deps;
    log.debug("Entering Authn.takePending().");
    pending.delete(record.id);
    log.debug("Leaving Authn.takePending().");
  }

  /**
   * Returns the `amr` of a step's first factor.
   *
   * @param step - the step
   * @returns the methods; `['pwd']` by default
   */
  firstAmrFor(step: any): string[] {
    const { log } = this.deps;
    log.debug("Entering Authn.firstAmrFor().");
    log.debug("Leaving Authn.firstAmrFor().");
    return this.firstAmrOf(step);
  }

  // The sign-in screen again, with a sentence on it, for the email door's
  // refusals of a first factor — the same page every refusal there draws.
  /**
   * Refuses an act at the sign-in screen with a sentence (`screenRefused()`):
   * JSON to `/authn-api` (#571).
   *
   * @param res - the response
   * @param record - the pending record
   * @param error - the sentence
   * @param status - the HTTP status, 400 where left out
   * @returns nothing
   */
  refuseAtScreen(res: any, record: any, error: string,
                 status?: number): void {
    const { log } = this.deps;
    log.debug("Entering Authn.refuseAtScreen().");
    this.screenRefused(res, record, error, { status: status || 400 });
    log.debug("Leaving Authn.refuseAtScreen().");
  }

  // AN EMAILED SECOND FACTOR, VERIFIED: the step's first factor and `otp`
  // (D2 — RFC 8176 registers nothing for email, and a single-use secret sent
  // to the person is what `otp` names), `acr` `mfa` (D1), and the credential
  // kind saying which it was. Answers whether a session was started.
  /**
   * Finishes a sign-in whose emailed second factor verified: the first factor's
   * `amr` plus `otp`, `acr` `mfa`.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step id
   * @param step - the step
   * @param kind - `code` or `link`
   * @returns whether a session was started
   */
  finishEmailSecondFactor(req: any, res: any, mfaId: string, step: any,
                          kind: string): boolean {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering Authn.finishEmailSecondFactor(). " + kind);
    pendingMfa.delete(String(mfaId));
    const amr = this.firstAmrOf(step).concat(
      this.firstAmrOf(step).indexOf('otp') >= 0 ? [] : ['otp']);
    if (step.thenEnrol) {
      // A proof before an enrolment (#475): the set-up screen, no session.
      this.enrolAfterProof(res, step, amr);
      log.debug("Leaving Authn.finishEmailSecondFactor(). To the set-up " +
                "screen.");
      return false;
    }
    const said = { postLoginHold: true,
                   request: req, risk: step.risk,
                   application: String(step.authn.application || ''),
                   credential: { kind: 'email-' + kind } };
    const started = this.startSession(res, step.username, amr, 'mfa',
                                      step.authn.protocol, said);
    if (this.refusedSession(res, baseUrlOf(req), step.authn, step.username,
                            started, said)) {
      log.debug("Leaving Authn.finishEmailSecondFactor(). Refused.");
      return false;
    }
    this.returnToCaller(res, step.authn, null, null);
    log.debug("Leaving Authn.finishEmailSecondFactor(). Signed in.");
    return true;
  }

  // AN EMAILED FIRST FACTOR, VERIFIED: the wallet's shape exactly — the risk
  // assessed, a second factor asked for where one is needed (never the email
  // again), and otherwise a session of one factor, `amr ["otp"]`, `acr "1"`.
  // Answers `{ handled: true }` when it wrote the response, or `{ refused,
  // why, errorCode }` for the door to draw.
  /**
   * Finishes a sign-in whose emailed first factor verified, asking for a second
   * factor where one is needed.
   *
   * @param req - the request
   * @param res - the response
   * @param step - the step
   * @param kind - `code` or `link`
   * @returns `{ handled: true }` when it wrote the response, or `{ refused,
   *   why, errorCode }` for the door to draw
   */
  async finishEmailFirstFactor(req: any, res: any, step: any,
                               kind: string): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering Authn.finishEmailFirstFactor(). " + kind);
    const record = step.authn;
    const username = step.username;
    const credential = { kind: 'email-' + kind };
    const assessed = await this.assessSignIn(req, username, record.protocol,
      { application: String(record.application || ''),
        credential: credential,
        // A key may answer as the second factor (#259).
        deviceAwaited: true });
    const second = this.beginSecondFactorAfterWallet(req, res, record,
      username, { amr: ['otp'], acr: '1' }, assessed, { first: 'email' });
    if (second.refused) {
      log.debug("Leaving Authn.finishEmailFirstFactor(). Refused.");
      return { refused: true, why: second.onRisk ? 'Authentication failed.'
                                                 : second.refused,
               errorCode: second.errorCode || 'STS-AUTHN-0009' };
    }
    if (second.handled) {
      log.debug("Leaving Authn.finishEmailFirstFactor(). Second factor.");
      return { handled: true };
    }
    const said = { postLoginHold: true,
                   request: req, credential: credential,
                   risk: assessed || undefined,
                   application: String(record.application || '') };
    const started = this.startSession(res, username, ['otp'], '1',
                                      record.protocol, said);
    if (this.refusedSession(res, this.deps.baseUrlOf(req), record, username,
                            started, said)) {
      log.debug("Leaving Authn.finishEmailFirstFactor(). Refused.");
      return { handled: true };
    }
    this.returnToCaller(res, record, null, null);
    log.debug("Leaving Authn.finishEmailFirstFactor(). Signed in.");
    return { handled: true };
  }

  // The record a request names, or null — expired ones are dropped on the way
  // past, which is the only cleanup this store needs beyond the sweep above.
  /**
   * Returns the pending sign-in record a request names; an expired one is
   * dropped on the way past.
   *
   * @param id - the record id
   * @returns the record, or null
   */
  pendingFor(id) {
    const { log } = this.deps;
    // The id is a bearer capability over the sign-in (#571): not logged.
    log.debug("Entering Authn.pendingFor(). " + (id ? 'An id.' : 'No id.'));
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
    // A RESTART-ONLY RECORD (#98 D9, restartParameter()) is not a sign-in
    // anybody may continue: it holds where a flow started and nothing else.
    if (record.restartOnly) {
      log.debug("Leaving Authn.pendingFor(). A restart-only record.");
      return null;
    }
    // A PICKER-ONLY RECORD (#561, `routeToAccounts()`) is not a sign-in
    // either: the flow it holds goes to a federation partner, and drawing a
    // screen for it would offer a mechanism the application does not allow.
    if (record.accountsOnly) {
      log.debug("Leaving Authn.pendingFor(). A picker-only record.");
      return null;
    }
    log.debug("Leaving Authn.pendingFor(). Found it.");
    return record;
  }

  /**
   * The pending sign-in the account picker is drawn for (#561): a record
   * waiting on an account choice, picker-only ones included, or null.
   *
   * @param id - the pending sign-in's id
   * @returns the record, or null
   */
  pendingForAccounts(id) {
    const { log } = this.deps;
    log.debug("Entering Authn.pendingForAccounts().");
    const record = pending.get(String(id || ''));
    if (!record || record.expires < Date.now() || record.restartOnly ||
        !record.accountChoice) {
      log.debug("Leaving Authn.pendingForAccounts(). None waiting.");
      return null;
    }
    log.debug("Leaving Authn.pendingForAccounts(). Found it.");
    return record;
  }

  // The partner buttons, or nothing at all. Nothing at all is the ordinary
  // state — a service with no federation configured must have a sign-in screen
  // byte for byte the one it always had, which is why this returns null
  // rather than an empty section with a heading. Since #571 it answers the
  // list as DATA for the screen's view — `{ kind, options }`, `kind` naming
  // the sentence over the buttons (`own-one`, `own-many`, `any`) — and the
  // browser draws it (`web_authn_login.ts`).
  private partnersOf(record) {
    const { log, federation, config, errorCodes } = this.deps;
    log.debug("Entering Authn.partnersOf().");
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
      const own = { kind: many ? 'own-many' : 'own-one',
        options: this.partnerLinks(record,
          home.usable.map(function (one) { return one.option; })) };
      log.debug("Leaving Authn.partnersOf(). " + home.usable.length +
                " partner(s) this application names.");
      return own;
    }
    if (!config.value('federation.loginButtons')) {
      log.debug("Leaving Authn.partnersOf(). " +
                "federation.loginButtons is off.");
      return null;
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
      log.debug("Leaving Authn.partnersOf(). It threw.");
      return null;
    }
    if (!options.length) {
      log.debug("Leaving Authn.partnersOf(). No usable partner is " +
                "configured.");
      return null;
    }
    // EVERY USABLE RELATIONSHIP IN THE REGISTER, WHICH IS NOT THIS
    // APPLICATION'S LIST — so no application is named on these hrefs,
    // deliberately. Somebody who picks one off here has signed in through a
    // partner nothing configured for this application, and counting that as a
    // use of the pair would put a number on /admin/federation/map that means
    // something other than what the page says it means.
    const any = { kind: 'any', options: this.partnerLinks(record, options) };
    log.debug("Leaving Authn.partnersOf(). " + options.length + " " +
        "partner(s) offered.");
    return any;
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
  //
  // SINCE #571 THE LINKS ARE DATA — `{ id, label, protocolLabel, peer, href }`
  // — and the words over them are the browser's; the hrefs are built here
  // still, once, for the reason above.
  private partnerLinks(record, options, application?) {
    const { log } = this.deps;
    log.debug("Entering Authn.partnerLinks(). " + options.length +
              " option(s).");
    // The whole original request rides along, so that whatever brought the
    // person here resumes once the partner has answered. It is
    // `record.returnTo`, which beginAuthentication() has already checked is a
    // path on this service.
    const back = encodeURIComponent(record.returnTo);
    const forApplication = String(application || '')
      ? '&application=' + encodeURIComponent(String(application))
      : '';
    // AND THIS RECORD'S ID, in a service deployed as cells (#98 D9): a
    // partner may assert a person homed in another cell, and the assertion
    // consumer then restarts THIS flow there from the start the record
    // holds (`restartPendingAtHome()`). It names a record and carries
    // nothing else; single-cell mode adds nothing.
    const forRestart = cells.isMulti() && record && record.id
      ? '&authn=' + encodeURIComponent(String(record.id)) : '';
    const links = options.map(function (one) {
      return { id: String(one.id), label: String(one.label || ''),
               protocolLabel: String(one.protocolLabel || ''),
               peer: String(one.peer || ''),
               // Consumer or enterprise, and which provider (#565), so the
               // screen draws the consumer providers as a group of their own.
               category: String(one.category || 'enterprise'),
               provider: String(one.provider || ''),
               href: '/federation/login/' + encodeURIComponent(one.id) +
                     '?returnTo=' + back + forApplication + forRestart };
    });
    log.debug("Leaving Authn.partnerLinks().");
    return links;
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
  // SINCE #571 AS DATA — `{ state, href }`, `state` `offered`,
  // `withheld-key` or `withheld-mfa` — which the browser draws.
  private kerberosOption(record) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.kerberosOption().");
    if (!config.value('krb5.spnegoAuthentication') ||
        !config.value('krb5.spnegoLoginButton')) {
      log.debug("Leaving Authn.kerberosOption(). Not offered.");
      return null;
    }
    if (record.forceKey && !record.forceMfa) {
      log.debug("Leaving Authn.kerberosOption(). Withheld: a security " +
                "key was demanded.");
      return { state: 'withheld-key', href: '' };
    }
    if (record.forceMfa) {
      log.debug("Leaving Authn.kerberosOption(). Withheld: two factors " +
                "were demanded.");
      return { state: 'withheld-mfa', href: '' };
    }
    log.debug("Leaving Authn.kerberosOption(). Offered.");
    return { state: 'offered',
             href: SPNEGO_PATH + '?authn=' + encodeURIComponent(record.id) };
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
  // SINCE #571 AS DATA — `{ state, mfaNote, href, siop }` — which the
  // browser draws.
  private walletOption(record) {
    const { log, config } = this.deps;
    log.debug("Entering Authn.walletOption().");
    if (!config.value('oid4vp.signIn')) {
      log.debug("Leaving Authn.walletOption(). Not offered.");
      return null;
    }
    if (record.forceKey) {
      log.debug("Leaving Authn.walletOption(). Withheld: a security key " +
                "was demanded.");
      return { state: 'withheld', mfaNote: false, href: '', siop: '' };
    }
    const href = WALLET_PATH + '?authn=' + encodeURIComponent(record.id);
    log.debug("Leaving Authn.walletOption(). Offered.");
    return { state: 'offered', mfaNote: !!record.forceMfa, href: href,
             // SIOPv2 (#129): the wallet's own key, enrolled on the
             // person's portal. Its own switch, off by default.
             siop: config.value('oid4vp.signInSelfIssued')
               ? href + '&siop=1' : '' };
  }

  // ---------------------------------------------------------------------------
  // THE CERTIFICATE ON THE CONNECTION (#1051, 2026-10-27; rcbj's decision on
  // #520): every browser protocol reaches this screen, so a TLS client
  // certificate is offered HERE, once, rather than by each protocol. Where
  // the connection presented one the identity gate accepts for this
  // sign-in's realm, the screen offers "Continue as <name> with your
  // certificate"; the act (`certificateSignIn()`) completes the pending
  // sign-in on it as a first factor — the event `GET /tls/sign-in` records,
  // `amr ["swk"]`, `acr "1"`, credential kind `certificate` — subject to the
  // authentication policy like any other first factor.
  //
  // NOT OFFERED, and the act refuses it the same way (`certificateNotHere()`):
  //
  //   * where the authentication policy does not take a certificate as a
  //     first factor (`certificatePrimary`);
  //   * on a linking sign-in (#109), which rests on the password;
  //   * where the application names the mechanisms it allows (#457): a TLS
  //     client certificate is not one an application can name, so an
  //     application naming any would re-prompt the session it made;
  //   * where a security key or a passwordless passkey is demanded, or the
  //     passkey policy requires a passkey with no username (#608): a
  //     certificate is neither;
  //   * where the connection carries no certificate that names a PERSON here
  //     — none, one that did not verify, one of this service's that is not an
  //     identity, an application's, or one from another realm's authority.
  //
  // UNDER A DEMAND FOR TWO FACTORS it is offered with a note: one factor,
  // after which the second is asked for as after a wallet.
  // ---------------------------------------------------------------------------
  /**
   * Why a certificate is not taken at this sign-in, or '' where it may be.
   *
   * @param record - the pending sign-in
   * @returns the reason, for the log, or ''
   */
  private certificateNotHere(record): string {
    const { log, authnPolicy } = this.deps;
    log.debug("Entering Authn.certificateNotHere().");
    const restricted: string[] = Array.isArray(record.allowedMechanisms)
      ? record.allowedMechanisms : [];
    const why = !authnPolicy.allows('certificate', 'primary')
      ? 'the authentication policy does not take a certificate as a first ' +
        'factor'
      : (record.lockedUsername ? 'a linking sign-in rests on the password'
      : (restricted.length ? 'the application names the mechanisms it ' +
                             'allows'
      : (record.forceKey || record.forcePasswordless
        ? 'a security key or a passkey is demanded'
      : (this.usernamelessRequired(record)
        ? 'the passkey policy requires a passkey with no username' : ''))));
    log.debug("Leaving Authn.certificateNotHere(). " + (why || 'Taken.'));
    return why;
  }

  /**
   * The screen's certificate offer: `{ name, mfaNote }`, or null.
   *
   * @param req - the request for the view, whose connection is read
   * @param record - the pending sign-in
   * @returns the offer, or null
   */
  private certificateOption(req, record): any {
    const { log } = this.deps;
    log.debug("Entering Authn.certificateOption().");
    if (this.certificateNotHere(record)) {
      log.debug("Leaving Authn.certificateOption(). Not taken here.");
      return null;
    }
    const door = this.deps.certificateDoor();
    const offer = door ? door.screenCertificateOffer(req) : null;
    if (!offer || !offer.username) {
      log.debug("Leaving Authn.certificateOption(). No certificate.");
      return null;
    }
    log.debug("Leaving Authn.certificateOption(). Offered.");
    return { name: String(offer.username), mfaNote: !!record.forceMfa };
  }

  // THE ACT (#1051): the first factor the screen offered, checked again in
  // full — the view is not the enforcement. The certificate's own refusals
  // are `tls_server.js`'s (`screenCertificateHolder()`), the rest is the
  // emailed first factor's shape: a person homed in another cell restarted
  // there, the risk assessed, a second factor asked for where one is needed
  // (`beginSecondFactorAfterWallet()`), and otherwise a session of one
  // factor and back to the protocol that sent the person here.
  private async certificateSignIn(req, res, base, record): Promise<void> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.certificateSignIn().");
    const notHere = this.certificateNotHere(record);
    if (notHere) {
      log.info('authn: a certificate sign-in was refused at the screen: ' +
               notHere + '.');
      log.debug("Leaving Authn.certificateSignIn(). Not taken here.");
      errorCodes.mark(res, 'STS-AUTHN-0467');
      return this.screenRefused(res, record,
        'Signing in with a certificate is not offered for this sign-in.');
    }
    const door = this.deps.certificateDoor();
    const holder = door ? await door.screenCertificateHolder(req)
      : { ok: false, code: 'STS-AUTHN-0463',
          why: 'Signing in with a certificate is not available here.' };
    if (!holder.ok) {
      log.debug("Leaving Authn.certificateSignIn(). The certificate was " +
                "refused.");
      errorCodes.mark(res, holder.code || 'STS-AUTHN-0463');
      return this.screenRefused(res, record, String(holder.why));
    }
    const username = String(holder.username);
    // A PERSON HOMED IN ANOTHER CELL (#98 D9), as the password door does,
    // before anything is counted here: the sign-in restarts at home, where
    // the screen offers the certificate again.
    if (cells.isMulti() && !req.stsCellRelay) {
      const home = await cellRouting.homeOf(realms.currentId(), 'name',
                                            username);
      if (home && home !== cells.id() && cells.get(home)) {
        if (!cellPlacement.CellPlacement.servePermitted(realms.currentId(),
                                                        home, res)) {
          pending.delete(record.id);
          log.debug("Leaving Authn.certificateSignIn(). Geofenced.");
          return undefined;
        }
        await this.restartAtHome(req, res, record, home);
        log.debug("Leaving Authn.certificateSignIn(). Restarted at home.");
        return undefined;
      }
    }
    const application = String(record.application || '');
    const credential = { kind: 'certificate',
                         id: String(holder.credentialId || '') };
    const assessed = await this.assessSignIn(req, username, record.protocol,
      { application: application, credential: credential,
        // A key may answer as the second factor (#259).
        deviceAwaited: true });
    const second = this.beginSecondFactorAfterWallet(req, res, record,
      username, { amr: ['swk'], acr: '1' }, assessed,
      { first: 'certificate' });
    if (second.refused) {
      log.debug("Leaving Authn.certificateSignIn(). Refused.");
      errorCodes.mark(res, second.errorCode || 'STS-AUTHN-0009');
      return this.screenRefused(res, record,
        second.onRisk ? 'Authentication failed.' : String(second.refused));
    }
    if (second.handled) {
      holder.recordVerification();
      log.debug("Leaving Authn.certificateSignIn(). A second factor.");
      return undefined;
    }
    // `amr ["swk"]` and `acr "1"`: `GET /tls/sign-in`'s event, and its
    // reason — one factor, whose private key sits in a file.
    const said = { postLoginHold: true,
                   request: req, application: application,
                   risk: assessed || undefined, credential: credential,
                   method: 'a TLS client certificate on the connection' };
    pending.delete(record.id);
    const started = this.startSession(res, username, ['swk'], '1',
                                      record.protocol, said);
    if (this.refusedSession(res, base, record, username, started, said)) {
      log.debug("Leaving Authn.certificateSignIn(). The session was " +
                "refused.");
      return undefined;
    }
    holder.recordVerification();
    this.returnToCaller(res, record, null, null);
    log.debug("Leaving Authn.certificateSignIn(). " + username +
              " continued with a certificate.");
    return undefined;
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

  // WHAT IS WRONG WITH THE CONFIGURATION THAT SENT THIS SIGN-IN HERE, as the
  // screen shows it (#571: once on the GET that drew the page, now in its
  // view). English: each sentence is an operator's.
  /**
   * The configuration problems the sign-in screen shows for a record.
   *
   * @param record - the pending sign-in
   * @returns the sentences, joined, or ''
   */
  screenProblem(record): string {
    const { log } = this.deps;
    log.debug("Entering Authn.screenProblem().");
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
    log.debug("Leaving Authn.screenProblem().");
    return problem;
  }

  // ===========================================================================
  // THE SIGN-IN SCREEN'S VIEW (#571): EVERYTHING `loginPage()` DECIDED, AS
  // FACTS AND NO WORDS.
  //
  // Until #571 this function drew the screen. The screen is a static surface
  // now (`web_authn_login.ts` draws it in the browser's language, from the
  // `authn` catalog namespace #539 wrote for this page, word for word), and
  // what is left here is every DECISION the page made — which doors are
  // offered, which boxes are checked and disabled and why, which partner
  // buttons, what this mode checks — answered to `GET /authn-api/pending/{id}`.
  // **The decisions did not change**: each line below is the condition the
  // markup was drawn under, and none of it is the enforcement, which is
  // still the act's (`screenAct()`): the record decides, the view only shows.
  //
  // A PASSKEY'S CHALLENGE IS NOT IN THE VIEW: the view is a GET a page may
  // ask twice, and the challenge is minted by `POST …/passkey/options`
  // (`passkeyOptions()`), whose answer the ceremony uses at once.
  // ===========================================================================
  /**
   * The sign-in screen's view: what it offers for a pending sign-in, as
   * facts the browser draws in its own language.
   *
   * @param req - the request for it
   * @param record - the pending sign-in
   * @param problem - the configuration's problems to show (English)
   * @returns the view
   */
  screenView(req, record, problem?: string): any {
    const { log, config, webauthnPolicy, baseUrlOf } = this.deps;
    log.debug("Entering Authn.screenView(). protocol=" + record.protocol);
    // THE PASSKEY POLICY FOR THE APPLICATION (#535), where a door has not
    // already selected one for a person: the screen offers what it says.
    if (!this.deps.passkeyPolicy.hasSelection()) {
      this.deps.passkeyPolicy.select('', record.application);
    }
    // What this realm will let a security key BE: `/admin/webauthn` sets it,
    // and the act checks the same three answers.
    const keyPolicy = webauthnPolicy.settings();
    // A sign-in as one named person (#109): the name drawn fixed, and nothing
    // offered that is not a password — see beginAuthentication().
    const locked = String(record.lockedUsername || '');
    // THE AUTHENTICATION POLICY'S FIRST FACTORS (#64): a password field only
    // where a password is one, and the two emailed ones only where they are
    // ACTIVE — allowed, and this realm able to send mail. Not on a linking
    // sign-in (a password, by #109), nor where a key or a passwordless key is
    // demanded: an email answers neither.
    const policy = this.deps.authnPolicy;
    // THE MECHANISMS THE APPLICATION ALLOWS (#457), empty for every one: a
    // door or a link it leaves out is not drawn. Not the enforcement — the
    // issuance policy refuses a session made with anything else — but a
    // screen offering a door that will refuse is a screen that lies.
    const restricted: string[] = Array.isArray(record.allowedMechanisms)
      ? record.allowedMechanisms : [];
    const offers = function (id: string): boolean {
      log.debug("Entering offers().");
      log.debug("Leaving offers().");
      return !restricted.length || restricted.indexOf(id) >= 0;
    };
    const screenOffered = offers('password') || offers('password-mfa') ||
      offers('webauthn');
    const passwordFirst = policy.allows('password', 'primary') &&
      (offers('password') || offers('password-mfa'));
    // A PASSKEY AND NO USERNAME (#474), where `passkeyOffered()` says so and
    // the screen's form is drawn at all.
    const passkey = screenOffered && this.passkeyOffered(record).ok;
    const usernameless = passkey && this.usernamelessRequired(record);
    const emailFirst = locked || record.forceKey || record.forcePasswordless ||
      restricted.length
      ? { code: false, link: false }
      : { code: !!policy.active('emailCode', 'primary'),
          link: !!policy.active('emailLink', 'primary') };
    // The sentences the screen shows over everything else: the
    // configuration's problems, then what the last act's refusal left on the
    // record for a form that could not be answered in JSON (a second-factor
    // page's refusal, `screenRefused()`). English, as every refusal (#539).
    const error = [String(problem || ''), String(record.screenError || '')]
      .filter(Boolean).join(' ');
    const view = {
      id: String(record.id),
      base: baseUrlOf(req),
      protocol: String(record.protocol || ''),
      application: String(record.application || ''),
      error: error,
      locked: locked,
      hint: String(record.hint || ''),
      // The form: drawn at all, and with a password field.
      screen: screenOffered,
      password: passwordFirst,
      // WHAT THE `webauthn.*` POLICY LEAVES ON THIS SCREEN (2026-09-10): a
      // box taken away is DISABLED AND LABELLED rather than removed, and the
      // browser draws it so.
      keys: { enabled: !!keyPolicy.enabled,
              mfaAllowed: !!keyPolicy.mfaAllowed,
              primaryAllowed: !!keyPolicy.primaryAllowed },
      // What the calling protocol demanded and what an operator configured:
      // they check, disable and explain the two boxes.
      demands: { mfa: !!record.forceMfa, key: !!record.forceKey,
                 passwordless: !!record.forcePasswordless,
                 via: String(record.mechanismVia || '') },
      // "REMEMBER THIS BROWSER" (#265), where the realm offers it.
      remember: !!this.deps.browserDevices().enabled() && !locked,
      // THE THIRD BUTTON, "Continue without signing in" (2026-09-05), only
      // while `authn.unauthenticatedSessions` is on.
      anonymous: !!config.value('authn.unauthenticatedSessions') &&
                 !locked && !restricted.length,
      passkey: passkey,
      // A PASSKEY WITH NO USERNAME, REQUIRED (#608): no username field and
      // no Sign In, the passkey button the way in.
      usernameless: usernameless,
      email: emailFirst,
      // THE CERTIFICATE ON THIS CONNECTION (#1051): "Continue as <name>
      // with your certificate", where `certificateOption()` says so.
      certificate: screenOffered && !usernameless
        ? this.certificateOption(req, record) : null,
      // A CLASSICAL PASSKEY REFUSED WHERE A POST-QUANTUM ONE IS REQUIRED
      // (#946): the panel's links, while the last refusal was that one.
      postQuantumRequired: record.postQuantumRequired
        ? this.postQuantumHelp() : null,
      // FORGOT YOUR PASSWORD? (#63): the portal's self-service reset, where
      // `common/mail_uses.ts` says it is offered, never for a locked name.
      // Root-relative: the browser puts the realm's prefix on it.
      forgot: !locked && this.offersPasswordReset()
        ? '/portal/forgot-password' : '',
      // The partners, the Kerberos door and the wallet, none on a linking
      // sign-in (#109) and each only where the application allows it.
      partners: locked || !offers('federation') ? null
                                                : this.partnersOf(record),
      kerberos: locked || !offers('spnego') ? null
                                            : this.kerberosOption(record),
      wallet: locked || !offers('wallet') ? null : this.walletOption(record),
      // WHAT THIS SCREEN CHECKS, BY MODE (2026-09-21).
      verifiesCredentials: !!mode.verifiesCredentials(),
      // THE BROWSER FINGERPRINT (#62 P6), off by default.
      fingerprint: this.fingerprinting(),
      // The calling protocol's own rows: parameter names and values, not
      // prose, so drawn as they are.
      details: (Array.isArray(record.details) ? record.details : [])
        .map(function (d) {
          return { label: String(d.label || ''),
                   value: d.value == null ? '' : String(d.value),
                   note: d.note ? String(d.note) : '' };
        })
    };
    log.debug("Leaving Authn.screenView().");
    return view;
  }

  // THE LANGUAGE OF A PAGE DRAWN FOR ONE PERSON (#539's order): a linking
  // sign-in is locked to a person, and a forced password change is for one,
  // so their own `preferredLanguage` ranks above the chooser — the shape
  // `WebI18n.load()` takes as `own`. Asked lazily of the locale policy, a
  // library; nothing is answered for nobody.
  /**
   * A person's own language for a static page, as `{ value, populated }`.
   *
   * @param username - the person, or ''
   * @returns their language, or null
   */
  preferredLanguageOf(username: string): any {
    const { log } = this.deps;
    log.debug("Entering Authn.preferredLanguageOf().");
    if (!username) {
      log.debug("Leaving Authn.preferredLanguageOf(). Nobody.");
      return null;
    }
    let own: any = null;
    try {
      own = require('../common/locale_policy').languageOf(username);
    } catch (e) {
      log.debug("Caught in Authn.preferredLanguageOf(): " +
                ((e && e.message) || e));
      own = null;
    }
    log.debug("Leaving Authn.preferredLanguageOf().");
    return own && own.value ? { value: String(own.value),
                                populated: !!own.populated } : null;
  }

  // THE PASSKEY CEREMONY'S OPTIONS (#474, an operation since #571): the
  // challenge minted on the pending record — single-use, taken by the act
  // whatever happens — the RP ID and the request's options. Conditional
  // mediation asks for these as the page loads.
  /**
   * Arms the pending sign-in's passkey ceremony and answers its options.
   *
   * @param req - the request
   * @param record - the pending sign-in
   * @returns `{ ok, challenge, rpId, options }`, or `{ ok: false, why }`
   */
  passkeyOptions(req, record): any {
    const { log, webauthnPolicy, baseUrlOf } = this.deps;
    log.debug("Entering Authn.passkeyOptions().");
    this.deps.passkeyPolicy.select('', record.application);
    const offered = this.passkeyOffered(record);
    if (!offered.ok) {
      log.debug("Leaving Authn.passkeyOptions(). Not offered.");
      return offered;
    }
    // A fresh challenge for every ceremony asked for, as every drawing of
    // the screen armed one.
    delete record.passkeyChallenge;
    const rpId = this.rpIdOf(baseUrlOf(req));
    const out = { ok: true, challenge: this.passkeyChallengeFor(record),
                  rpId: rpId,
                  options: webauthnPolicy.discoverableRequestOptions(rpId) };
    log.debug("Leaving Authn.passkeyOptions().");
    return out;
  }

  // ===========================================================================
  // A PERSON HOMED IN ANOTHER CELL RESTARTS THEIR FLOW THERE (#98 D9).
  //
  // The sign-in screen is the first place a request says WHO it is about, and
  // what a flow has made so far — the protocol's pending request, this
  // record, the consent screen's — is held by the cell that made it. So a
  // person homed elsewhere is not signed in here: the browser is PINNED to
  // their home cell (`cell_placement.ts`'s affinity cookie) and sent back to
  // the request that started the flow, which that cell then serves from the
  // beginning — its own records, its own sign-in screen, its own second
  // factor, all against the entry only it holds. Nothing personal crosses:
  // not the typed password (never read here), not the entry.
  //
  // `restartOrigin()` records the starting request when the flow begins:
  //
  //   * the request as it arrived — a GET's URL, or a POST's URL and form
  //     (a SAML HTTP-POST binding, an authorization request by POST), which
  //     is re-posted from a page with a real button and no script;
  //   * EXCEPT for this service's own hosted surfaces (`common/oidc_rp.ts`),
  //     whose authorization request is itself step two of a flow the surface
  //     started: the restart is the surface's root, which starts its own
  //     flow at home rather than resuming one whose state is here.
  //
  // A pushed authorization request (RFC 9126) the start names is HANDED to
  // the home cell first (`adopt-pushed-request`, `oauth-oidc/par.ts`), since
  // its reference names this cell and the pinned browser reaches home.
  // ===========================================================================
  /**
   * Records the request a sign-in flow started from, for a restart at the
   * person's home cell.
   *
   * @returns `{ method, url, form }`, or null in single-cell mode or outside
   *   a request
   */
  private restartOrigin(): { method: string; url: string;
                             form: Record<string, string> | null } | null {
    const { log } = this.deps;
    log.debug("Entering Authn.restartOrigin().");
    if (!cells.isMulti()) {
      log.debug("Leaving Authn.restartOrigin(). Single-cell.");
      return null;
    }
    const req = require('../common/jose_certificate_header').currentRequest();
    if (!req) {
      log.debug("Leaving Authn.restartOrigin(). No request.");
      return null;
    }
    const method = String(req.method || 'GET').toUpperCase();
    let form: Record<string, string> | null = null;
    if (method === 'POST') {
      const parsed = this.deps.parseBody(req) || {};
      form = {};
      Object.keys(parsed).slice(0, 64).forEach(function (k) {
        form[k] = String(parsed[k] === undefined ? '' : parsed[k])
          .slice(0, 65536);
      });
    }
    const url = String(req.originalUrl || req.url || '/');
    const clientId = String((req.query && req.query.client_id) ||
                            (form && form.client_id) || '');
    const surface = ({ 'sts-admin-console': '/admin',
                       'sts-user-portal': '/portal',
                       'sts-report': '/report' } as Record<string, string>)[
      clientId];
    log.debug("Leaving Authn.restartOrigin().");
    if (surface) {
      return { method: 'GET', url: realms.currentPrefix() + surface,
               form: null };
    }
    return { method: method, url: url, form: form };
  }

  /**
   * Sends a browser whose person is homed in another cell back to the start
   * of its flow, pinned to that cell.
   *
   * @param req - the sign-in POST
   * @param res - the response
   * @param record - the pending sign-in
   * @param home - the person's home cell
   * @returns a promise settled when the answer is sent
   */
  private async restartAtHome(req, res, record, home: string): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering Authn.restartAtHome(). home=" + home);
    const origin = record.restart;
    pending.delete(record.id);
    log.debug("Leaving Authn.restartAtHome().");
    return this.sendHome(req, res, origin, home, record);
  }

  // ---------------------------------------------------------------------------
  // WHERE A FLOW SENT STRAIGHT TO A PARTNER STARTED (#98 D9). Home realm
  // discovery by configuration or by `domain_hint` sends the browser to a
  // federation partner without drawing this screen, so there is no pending
  // record — and the assertion consumer may find the person homed in another
  // cell and have to restart the flow there. In a service deployed as cells
  // this mints a RESTART-ONLY record (`restartOnly`: `pendingFor()` refuses
  // it, so nobody can continue a sign-in on it) holding `restartOrigin()`,
  // and answers the `&authn=` parameter naming it. Single-cell mode mints
  // nothing and answers ''.
  // ---------------------------------------------------------------------------
  private restartParameter(returnTo: string): string {
    const { log, randomId } = this.deps;
    log.debug("Entering Authn.restartParameter().");
    const restart = cells.isMulti() ? this.restartOrigin() : null;
    if (!restart) {
      log.debug("Leaving Authn.restartParameter(). Nothing to record.");
      return '';
    }
    const id = randomId(18);
    pending.set(id, { id: id, restartOnly: true, restart: restart,
                      returnTo: returnTo,
                      expires: Date.now() + this.pendingTtlMs() });
    log.debug("Leaving Authn.restartParameter().");
    return '&authn=' + encodeURIComponent(id);
  }

  /**
   * Restarts, at the person's home cell, the sign-in flow a pending record
   * names — for a door that found the person's home only after the sign-in
   * screen let them through (federation's assertion consumer, #98 D9). The
   * record is spent; with no such record the browser is sent to `fallback`,
   * a path on this service, pinned home all the same.
   *
   * @param req - the request that found the home
   * @param res - the response
   * @param pendingId - the pending record the flow's sign-in screen held
   * @param fallback - where to send the browser when there is no record
   * @param home - the person's home cell
   * @returns a promise settled when the answer is sent
   */
  async restartPendingAtHome(req, res, pendingId: string, fallback: string,
                             home: string): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering Authn.restartPendingAtHome(). home=" + home);
    // A hard geofence refuses rather than sending the browser home (D4),
    // exactly as the sign-in screen's own restart does.
    if (!cellPlacement.CellPlacement.servePermitted(realms.currentId(), home,
                                                    res)) {
      if (pendingId) {
        pending.delete(String(pendingId));
      }
      log.debug("Leaving Authn.restartPendingAtHome(). Geofenced.");
      return;
    }
    const held = pendingId ? pending.get(String(pendingId)) : null;
    const record = held && held.expires >= Date.now() ? held : null;
    if (held && !record) {
      pending.delete(held.id);
    }
    if (record && record.restart) {
      log.debug("Leaving Authn.restartPendingAtHome(). The flow's start.");
      return this.restartAtHome(req, res, record, home);
    }
    if (record) {
      pending.delete(record.id);
    }
    const url = /^\/(?!\/)/.test(String(fallback || ''))
      ? String(fallback) : realms.currentPrefix() + '/';
    log.debug("Leaving Authn.restartPendingAtHome(). The return address.");
    return this.sendHome(req, res, { method: 'GET', url: url, form: null },
                         home);
  }

  /**
   * Pins a browser to its person's home cell and sends it to the start of a
   * flow: a redirect for a GET start, a re-post from a page with a real
   * button for a POST one. A pushed request the start names is handed home
   * first.
   *
   * @param req - the request
   * @param res - the response
   * @param origin - `{ method, url, form }`, as `restartOrigin()` records it
   * @param home - the person's home cell
   * @returns a promise settled when the answer is sent
   */
  // `record`, where there is one, is only for the language the re-post page
  // is drawn in (#539).
  private async sendHome(req, res, origin, home: string,
                         record?: any): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering Authn.sendHome(). home=" + home);
    const realmId = realms.currentId();
    // A pushed request the start names goes home first.
    const named = String(origin && origin.url && /request_uri=([^&]+)/
      .exec(origin.url) ? decodeURIComponent(/request_uri=([^&]+)/
        .exec(origin.url)[1]) : (origin && origin.form &&
                                 origin.form.request_uri) || '');
    if (named) {
      try {
        await require('../oauth-oidc/par').handOver(realmId, named, home);
      } catch (e) {
        log.warn(errorCodes.tag('STS-CELL-0041') + 'authn: the pushed ' +
                 'authorization request of a flow restarting at cell "' +
                 home + '" could not be handed over (' +
                 ((e && e.message) || e) + '); the flow restarts without it ' +
                 'and the client will be told the request_uri is unknown.');
      }
    }
    cellPlacement.setAffinity(req, res, realmId, home);
    log.info('authn: the person signing in is homed in cell "' + home +
             '"; the browser is pinned there and sent back to the start of ' +
             'its flow (#98 D9).');
    res.set('Cache-Control', 'no-store');
    // TO `/authn-api` (#571) THE START IS ANSWERED AS A FORM the browser
    // sends exactly as the re-post page below did — its method, its address
    // and its fields, nothing added — the affinity cookie set on this
    // answer. A GET start is the same form with no fields: the browser goes
    // there, as it followed the 303.
    if (this.answersJson(res)) {
      const post = !!(origin && origin.method === 'POST' && origin.form);
      this.answerJson(res, 200, { ok: true, next: 'home-cell', form: {
        method: post ? 'POST' : 'GET',
        action: origin ? String(origin.url) : realms.currentPrefix() + '/',
        fields: post ? origin.form : {} } });
      log.debug("Leaving Authn.sendHome(). JSON.");
      return;
    }
    if (!origin || origin.method !== 'POST' || !origin.form) {
      log.debug("Leaving Authn.sendHome(). A redirect.");
      res.redirect(303, origin ? origin.url : realms.currentPrefix() + '/');
      return;
    }
    // A POST START IS RE-POSTED FROM A PAGE WITH A REAL BUTTON, the way a
    // federation partner's HTTP-POST binding is sent: no script (the service's
    // policy is script-src 'none'), the fields as hidden inputs.
    const esc = function (v: string) {
      return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    };
    const fields = Object.keys(origin.form).map(function (k) {
      return '<input type="hidden" name="' + esc(k) + '" value="' +
        esc(origin.form[k]) + '">';
    }).join('');
    // THE LANGUAGE (#539), from the pending sign-in where there is one. NO
    // CHOOSER on this page, deliberately: it carries a POST that no GET can
    // draw again, so a chooser's return would lose the request it re-posts.
    const t = PageLocale.forPage({
      application: record ? record.application : '',
      uiLocales: record ? record.uiLocales : '' });
    log.debug("Leaving Authn.sendHome(). A re-post.");
    res.status(200).type('html').send(
      '<!DOCTYPE html><html' + PageLocale.htmlAttributes(t) +
      '><head><meta charset="utf-8">' +
      '<title>' + esc(t.text('authn.home.title')) + '</title></head><body>' +
      '<p>' + t.html('authn.home.text') + '</p>' +
      '<form method="post" action="' + esc(origin.url) + '">' + fields +
      '<button type="submit">' + t.html('authn.home.continue') +
      '</button></form></body></html>');
  }

  // ===========================================================================
  // THE SIGN-IN SURFACE'S SHELL (#571): what `/authn/login`,
  // `/authn/select-idp` and `/authn/password-change` answer now, through
  // `common/shell_document.ts` (3cl's recipe). The browser draws the page
  // from `/authn-api` with `SIGNIN_SCRIPT_PATH`.
  //
  // SCRIPT IS REQUIRED (rcbj on #569 and #571): no form is drawn here for a
  // browser without it — the `<noscript>` says so — and no submit button
  // stands in for the script. The policy is the shell's: `script-src
  // 'self'` (the bundle, and `/authn/fingerprint.js` where the realm turns
  // the fingerprint on), `connect-src 'self'` (the API, `/web` and the
  // language chooser are this service's own paths on this listener: `/authn`
  // and `/authn-api` are one application, #472), `style-src 'self'` (the
  // card from `/web/card.css`, nothing inline), `frame-ancestors` re-added by
  // `app.contentSecurityPolicy()` whatever is asked. A WebAuthn ceremony
  // needs nothing more.
  //
  // `application` is the pending sign-in's, for the locale policy's default
  // (`PageLocale.shellAttributes()`): the screen is drawn for the
  // application that sent the person here, as it always was.
  // ===========================================================================
  /**
   * Sends the sign-in surface's shell document.
   *
   * @param req - the request
   * @param res - the response
   * @param application - the application the sign-in is for, or ''
   * @returns nothing
   */
  signInShell(req, res, application: string): void {
    const { log, app } = this.deps;
    log.debug("Entering Authn.signInShell().");
    const html = ShellDocument.document({
      title: 'Sign in — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()]] as
                   Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, application || '')),
      stylesheets: ['/web/card.css'],
      script: SIGNIN_SCRIPT_PATH,
      open: '<div class="card">',
      close: '</div>',
      noscript: '<h1>Sign in</h1><div class="err">This sign-in page is a ' +
        'script that runs in your browser, and with scripts blocked there ' +
        'is nothing it can show. Allow scripts for this page to sign in.' +
        '</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    ShellDocument.serve(app, req, res, html,
                        { csp: { 'style-src': "'self'" } });
    log.debug("Leaving Authn.signInShell().");
  }

  /**
   * The sign-in surface's bundle and its precompressed forms, read once. A
   * tree that was never built has none, and the shell then loads a script
   * that says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  signInBundle(): any {
    const { log } = this.deps;
    log.debug("Entering Authn.signInBundle().");
    if (!this.bundleFile) {
      this.bundleFile = ShellDocument.readFile(__dirname, SIGNIN_BUNDLE_FILE,
        'document.body.textContent = "This service has no sign-in script ' +
        '(authn/' + SIGNIN_BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving Authn.signInBundle().");
    return this.bundleFile;
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
  // SINCE #571 THE CHOOSER IS DATA, answered to `GET
  // /authn-api/pending/{id}/partners`, and drawn by `web_authn_select.ts`:
  // the partners (this application's own, so the pair is named on every
  // href, as the screen's first branch does), the problems (English, an
  // operator's), and the protocol's own rows.
  /**
   * The federation chooser's view for a pending sign-in.
   *
   * @param req - the request
   * @param record - the pending sign-in, its partner list refreshed
   * @returns the view
   */
  selectIdpView(req, record): any {
    const { log, baseUrlOf } = this.deps;
    const home = record.federation || {};
    const usable = home.usable || [];
    log.debug("Entering Authn.selectIdpView(). " + usable.length +
              " partner(s).");
    const view = {
      id: String(record.id),
      base: baseUrlOf(req),
      protocol: String(record.protocol || ''),
      application: String(record.application || ''),
      problems: (home.problems || []).map(String),
      partners: this.partnerLinks(record,
        usable.map(function (one) { return one.option; }),
        // THIS APPLICATION'S OWN PARTNERS BY CONSTRUCTION — the page is not
        // drawn at all for any other list.
        record.application),
      details: (Array.isArray(record.details) ? record.details : [])
        .map(function (d) {
          return { label: String(d.label || ''),
                   value: d.value == null ? '' : String(d.value),
                   note: d.note ? String(d.note) : '' };
        })
    };
    log.debug("Leaving Authn.selectIdpView().");
    return view;
  }

  // ===========================================================================
  // THE ACCOUNT PICKER (#561): `/authn/accounts?authn=<id>`, drawn by the
  // sign-in surface from `GET /authn-api/pending/{id}/accounts` and acted on
  // through `POST …/accounts/select`, `…/another` and `…/forget`. It belongs
  // to the pending flow, as the chooser does: every account is named by its
  // KEY (`AccountSets.keyOf()`: the subject), never by a sid, and every
  // choice is checked again on the server — the page is not a boundary.
  // ===========================================================================
  /**
   * Answers the account picker 503 with Retry-After where this browser's
   * account set, or a session it lists, could not be read (rcbj's decision
   * 3 on #561) — as #350 answers a failed session read (`refuseUnread()`),
   * and never a picker drawn from what could be read, or a redirect to sign
   * in: either would let a store outage stand for an account signed out.
   * `STS-AUTHN-0344` for the set's own row, `STS-AUTHN-0338` for a session
   * it lists. Nothing is written and the cookie stays.
   *
   * @param req - the request
   * @param res - the response
   * @returns true when it answered
   */
  refuseAccountsUnread(req, res) {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Authn.refuseAccountsUnread().");
    if (!AccountSets.enabled() || !req || !res) {
      log.debug("Leaving Authn.refuseAccountsUnread(). Off.");
      return false;
    }
    const row = this.accountSetOf(req);
    const code = !row && req.stsAccountSetUnread ? 'STS-AUTHN-0344'
      : row && Object.keys(row.sessions || {}).some(function (sid) {
        return !!self.accountSessionRead(sid).error;
      }) ? 'STS-AUTHN-0338' : '';
    if (!code) {
      log.debug("Leaving Authn.refuseAccountsUnread(). Readable.");
      return false;
    }
    // At debug: the read's own failure was logged where it happened, and a
    // line per refused request is the log the no-per-event rule keeps out.
    log.debug(errorCodes.tag(code) + 'authn: the account picker answered ' +
              '503: this browser\'s account set could not be read.');
    if (!res.headersSent && typeof res.status === 'function') {
      errorCodes.mark(res, code);
      res.set('Retry-After', '5');
      this.answerJson(res, 503, {
        ok: false, error: 'unavailable',
        error_description: 'This browser\'s accounts could not be read. ' +
                           'Try again.',
        errors: ['This browser\'s accounts could not be read just now. ' +
                 'Try again in a moment.'] });
    } else {
      errorCodes.mark(res, code);
    }
    log.debug("Leaving Authn.refuseAccountsUnread(). 503.");
    return true;
  }

  /**
   * The account picker's view for a pending sign-in (#561): the browser's
   * accounts (key, names, state, times), whether Use another account is
   * open, and the protocol's rows. Never a sid.
   *
   * @param req - the request
   * @param record - the pending sign-in, waiting on an account choice
   * @returns the view
   */
  accountsView(req, record): any {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering Authn.accountsView().");
    const row = this.freshAccountSet(req);
    const accounts = this.accountRows(row, req);
    const live = accounts.filter(function (one) {
      return one.state === 'signed-in';
    }).length;
    const view = {
      id: String(record.id),
      base: baseUrlOf(req),
      protocol: String(record.protocol || ''),
      application: String(record.application || ''),
      reason: String(record.accountChoiceReason || ''),
      accounts: accounts,
      another: { open: live < AccountSets.maxAccounts() },
      max: AccountSets.maxAccounts(),
      details: (Array.isArray(record.details) ? record.details : [])
        .map(function (d) {
          return { label: String(d.label || ''),
                   value: d.value == null ? '' : String(d.value),
                   note: d.note ? String(d.note) : '' };
        })
    };
    log.debug("Leaving Authn.accountsView(). " + accounts.length +
              " account(s).");
    return view;
  }

  // A refusal at the picker: the sentence, English, and the picker drawn
  // again by the page from a fresh view.
  private accountsRefused(res, status, code, why) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.accountsRefused(). " + code);
    errorCodes.mark(res, code);
    this.answerJson(res, status, { ok: false, next: 'refused',
                                   errors: [String(why)] });
    log.debug("Leaving Authn.accountsRefused().");
  }

  // Back to the flow, as the session chosen: the record is spent and the
  // address carries a ticket for that session in this set.
  private resumeAs(res, record, row, sid) {
    const { log } = this.deps;
    log.debug("Entering Authn.resumeAs().");
    pending.delete(record.id);
    const ticket = AccountSets.mintTicket(row.id, sid,
                                          String(record.returnTo)
                                            .split('?')[0],
                                          record.id);
    const target = AccountSets.withTicket(record.returnTo, ticket);
    this.answerJson(res, 200, { ok: true, next: 'redirect',
                                location: this.locationOf(res, target) });
    log.debug("Leaving Authn.resumeAs().");
  }

  // On to the sign-in the picker stood in front of, with `hint` filled in
  // (or cleared): the screen, the chooser, the Kerberos or wallet door, or
  // a federation partner for a picker-only record, which is spent.
  private onToSignIn(res, record, hint) {
    const { log } = this.deps;
    log.debug("Entering Authn.onToSignIn().");
    const after = String(record.afterAccounts ||
                         LOGIN_PATH + '?authn=' +
                         encodeURIComponent(record.id));
    if (record.accountsOnly) {
      pending.delete(record.id);
    } else {
      record.accountChoice = false;
      record.hint = String(hint || '');
      pending.set(record.id, record);
    }
    this.answerJson(res, 200, { ok: true, next: 'redirect',
                                location: this.locationOf(res, after) });
    log.debug("Leaving Authn.onToSignIn().");
  }

  /**
   * One act at the account picker (#561): `select` continues the flow as a
   * signed-in account (or signs a signed-out one in again), `another` goes
   * on to the sign-in for a new account, `forget` forgets a signed-out
   * account. Each is checked again here; the answer is `/authn-api`'s next
   * step.
   *
   * @param req - the API's request
   * @param res - its response
   * @param record - the pending sign-in, waiting on an account choice
   * @param body - `{ action, account }`
   */
  accountsAct(req, res, record, body): void {
    const { log, audit, stats, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering Authn.accountsAct(). " + body.action);
    if (this.refuseAccountsUnread(req, res)) {
      log.debug("Leaving Authn.accountsAct(). The set could not be read.");
      return;
    }
    // A SET COOKIE THAT OPENS NOTHING, AT THE PICKER, IS ANOTHER TAB'S
    // SELECTION (#561, with rcbj's decision 1 that every selection rotates
    // the handle): this request left before that answer arrived, so it
    // carries the handle the other selection retired. Making a set around
    // the session cookie here (D12) would split the browser into two sets
    // and leave one tab's ticket for a set the browser no longer holds. So
    // the act is refused and the picker drawn again, from the cookie the
    // browser holds by then. A browser with NO set cookie is D12's case
    // and goes on below.
    if (this.cookiesOf(req)[AccountSets.cookieName()] &&
        !this.accountSetOf(req)) {
      stats.recordAccountChoice('selectFailed');
      log.info(errorCodes.tag('STS-AUTHN-0348') + 'authn: an act at the ' +
               'account picker carried an account set cookie that opens ' +
               'no set — another selection rotated it — and was refused.');
      this.accountsRefused(res, 409, 'STS-AUTHN-0348',
        'The accounts in this browser changed in another tab. Choose ' +
        'again.');
      log.debug("Leaving Authn.accountsAct(). A stale set cookie.");
      return;
    }
    const row = this.freshAccountSet(req);
    const key = String(body.account || '');
    const liveSid = row
      ? Object.keys(row.sessions || {}).filter(function (sid) {
        return AccountSets.keyOf(row.sessions[sid]) === key &&
          self.accountSessionLive(sid);
      })[0] || ''
      : '';
    if (body.action === 'another') {
      const live = row ? this.liveAccountCount(row, null) : 0;
      if (live >= AccountSets.maxAccounts()) {
        this.accountsRefused(res, 409, 'STS-AUTHN-0340',
          'This browser is already signed in to ' + live + ' accounts, the ' +
          'most it may hold. Sign out of one of them first.');
        log.debug("Leaving Authn.accountsAct(). Full.");
        return;
      }
      this.onToSignIn(res, record, '');
      log.debug("Leaving Authn.accountsAct(). Use another account.");
      return;
    }
    if (body.action === 'forget') {
      if (liveSid) {
        this.accountsRefused(res, 409, 'STS-AUTHN-0347',
          'That account is still signed in. Sign it out first; only a ' +
          'signed-out account can be forgotten.');
        log.debug("Leaving Authn.accountsAct(). Live.");
        return;
      }
      const entry = row && row.remembered ? row.remembered[key] : null;
      if (!row || !AccountSets.forget(row, key)) {
        this.accountsRefused(res, 409, 'STS-AUTHN-0345',
          'That account is not one this browser remembers.');
        log.debug("Leaving Authn.accountsAct(). Not remembered.");
        return;
      }
      AccountSets.save(row);
      stats.recordAccountChoice('forgotten');
      audit.audit({
        action: 'account.forget',
        actor: String((entry && entry.username) || ''),
        protocol: 'Authentication', channel: 'http', target: row.id,
        summary: String((entry && entry.username) || 'an account') +
                 ' was forgotten by account set ' + row.id,
        detail: { accountSet: row.id, sub: String((entry && entry.sub) || ''),
                  sessionId: '' }
      });
      this.answerJson(res, 200, { ok: true, next: 'stay' });
      log.debug("Leaving Authn.accountsAct(). Forgotten.");
      return;
    }
    // SELECT. A signed-out account signs in again, its name filled in.
    if (!liveSid) {
      const remembered = row && row.remembered ? row.remembered[key] : null;
      if (remembered) {
        this.onToSignIn(res, record, String(remembered.username || ''));
        log.debug("Leaving Authn.accountsAct(). Signs in again.");
        return;
      }
      stats.recordAccountChoice('selectFailed');
      this.accountsRefused(res, 409, 'STS-AUTHN-0345',
        'That account is no longer signed in here. Choose it again to sign ' +
        'in, or choose another.');
      log.debug("Leaving Authn.accountsAct(). Not live.");
      return;
    }
    // THE SESSION IS HELD TO EVERYTHING `sessionOf()` HOLDS IT TO, now: it
    // may have ended between the page and the click, or its account been
    // disabled.
    const session = this.honouredSession(req, liveSid,
                                         this.accountSessionRead(liveSid).session);
    if (!session) {
      stats.recordAccountChoice('selectFailed');
      this.accountsRefused(res, 409, 'STS-AUTHN-0345',
        'That account\'s session has just ended. Choose it again to sign ' +
        'in, or choose another.');
      log.debug("Leaving Authn.accountsAct(). Ended meanwhile.");
      return;
    }
    // A DEMAND THE SESSION DOES NOT MEET IS A RE-AUTHENTICATION OF IT, NEVER
    // A WAY PAST IT: two factors demanded (acr_values, RequestedAuthnContext,
    // wauth) of a one-factor session send the person to sign in again as
    // that account. Everything else the protocol asks — `max_age`, RFC
    // 9470's acr — it asks again on the request this resumes, of this
    // session, as of any other.
    if (record.forceMfa && String(session.acr || '') !== 'mfa') {
      this.onToSignIn(res, record, String(session.user.username || ''));
      log.debug("Leaving Authn.accountsAct(). Two factors demanded.");
      return;
    }
    const before = this.cookieSession(req, SESSION_COOKIE);
    const switched = !before || before.id !== liveSid;
    if (switched) {
      this.makeDefaultSession(res, session);
    }
    row.lastActiveSid = liveSid;
    // THE SET'S HANDLE ROTATES ON EVERY SELECTION (rcbj's decision 1 on
    // #561), not only when an account is added: choosing an account is a
    // change of who the browser acts as, so a `sts_accounts` value copied
    // before it goes stale at the next choice the person makes. Appended
    // AFTER `makeDefaultSession()`, which writes the session cookie by
    // replacing; the attributes are `AccountSets.cookieLine()`'s, as at a
    // sign-in. The ticket below is minted for the set's id, which a
    // rotation does not change, and the resumed request carries the new
    // handle. Two selections in flight at once cost what two sign-ins do
    // (`authn/CLAUDE.md`, *At once, and under failure*).
    const rotated = AccountSets.rotate(row);
    AccountSets.save(row);
    AccountSets.writeCookie(res, rotated);
    req.stsAccountSetId = row.id;
    stats.recordAccountChoice('selected');
    const detail = { accountSet: row.id, sessionId: liveSid,
                     sub: String(session.user.sub || ''),
                     protocol: String(record.protocol || ''),
                     application: String(record.application || '') };
    audit.audit({
      action: 'account.select', actor: String(session.user.username || ''),
      protocol: String(record.protocol || ''), channel: 'http',
      target: liveSid,
      summary: session.user.username + ' was chosen at the account picker ' +
               'of account set ' + row.id,
      detail: detail
    });
    if (switched) {
      stats.recordAccountChoice('switched');
      audit.audit({
        action: 'account.switch', actor: String(session.user.username || ''),
        protocol: String(record.protocol || ''), channel: 'http',
        target: liveSid,
        summary: 'the browser\'s default account became ' +
                 session.user.username,
        detail: Object.assign({}, detail,
                              { previousSessionId: before ? before.id : '' })
      });
    }
    this.resumeAs(res, record, row, liveSid);
    log.debug("Leaving Authn.accountsAct(). Selected.");
  }

  // THE LIST IS RESOLVED AGAIN when the chooser is asked for — the GET's
  // argument below, which the shell and the API both make — and the
  // record's copy replaced, so the screen it falls back to agrees.
  /**
   * Resolves a pending sign-in's partners again and answers how many are
   * usable.
   *
   * @param record - the pending sign-in
   * @returns the number of usable partners
   */
  refreshPartners(record): number {
    const { log } = this.deps;
    log.debug("Entering Authn.refreshPartners().");
    const fresh = record.mechanismSource === 'relationship'
      ? record.federation
      : this.federationFor(record.application);
    record.federation = fresh;
    if (record.id && pending.has(record.id)) {
      pending.set(record.id, record);
    }
    const usable = ((fresh || {}).usable || []).length;
    log.debug("Leaving Authn.refreshPartners(). " + usable);
    return usable;
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
    const { stsCrypto, log, randomId, gate, credentials, audit,
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
      return this.screenRefused(res, record,
        'Authentication failed for ' + username + '.');
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
                                                          : 'password' },
                         // A key may answer next, in either role (#259).
                         deviceAwaited: true });
    const riskEngine = assessment ? this.riskEngine() : null;
    const risk = riskEngine ? riskEngine.riskOf(assessment) : null;
    const roleAnswer = gate.check(Object.assign({
      application: String(record.application || ''),
      kind: gate.ISSUANCE.SESSION,
      subject: { kind: 'user', name: username, authenticated: true },
      claims: null,
      // NOT THE DEVICE, YET (#164 phase 6): the key that may name it — a
      // passwordless or second-factor WebAuthn ceremony — has not been
      // presented. The session's start asks about it (`refusedOnDevice()`
      // for the password-only path, the policy for the rest).
      deviceDeferred: true
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
      return this.screenRefused(res, record,
        'Authentication failed for ' + username + '.');
    }
    if (!roleAnswer.allowed && roleAnswer.risk && !roleAnswer.risk.observed) {
      riskFactor = roleAnswer.risk.factor;
    } else if (!roleAnswer.allowed) {
      log.info('authn: the issuance policy refused a session for "' + username +
               '" at "' + String(record.application) + '". ' + roleAnswer.why);
      log.debug("Leaving the authentication endpoint. The issuance policy " +
                "refused the session.");
      // A realm being removed (#262) is its own code; the policy's is 0009.
      errorCodes.mark(res, roleAnswer.retiring ? 'STS-CORE-0121'
                                               : 'STS-AUTHN-0009');
      log.debug("Leaving Authn.finishPasswordSignIn().");
      return this.screenRefused(res, record,
        roleAnswer.why);
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
    // Only an mfa-role key answers (#898): the step minted below offers only
    // those, so a primary passkey counted here handed its holder the
    // enrolling ceremony this paragraph refuses.
    const holdsKey = enrolled.mfaKeys > 0;
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
      return this.screenRefused(res, record,
        'Authentication failed for ' + username + '.');
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
    // A primary passkey is no answer (#898): the step offers mfa-role keys
    // only, so counting one here handed its holder the enrolling ceremony.
    if (record.forceKey && !passwordless && enrolled.mfaKeys === 0 &&
        enrolled.mfaRequired) {
      log.info('authn: a security key was demanded of "' + username + '", ' +
               'who holds a second factor and no key; refused.');
      errorCodes.mark(res, 'STS-AUTHN-0204');
      log.debug("Leaving Authn.finishPasswordSignIn(). No key to present.");
      return this.screenRefused(res, record,
        'This request needs a passkey, and this account holds none. Add ' +
        'one at /portal/keys and sign in again.');
    }
    let factor = passwordless || record.forceKey ||
                 riskFactor === 'security-key'
      ? 'webauthn'
      : (configuredFactor || riskChoice || (secondFactor ? 'webauthn' : ''));

    // ---------------------------------------------------------------------
    // THE SECOND FACTORS THE APPLICATION ALLOWS (#475) narrow the one asked
    // for — never the passwordless path, which is a first factor.
    // `narrowSecondFactor()` argues the four outcomes: the factor as it was,
    // another the person holds, a held one PROVED and then an allowed one
    // ENROLLED (`thenEnrol`), or a refusal.
    // ---------------------------------------------------------------------
    const mfaAllowed = this.mfaAllowedFor(String(record.application || ''));
    let thenEnrol = false;
    if (mfaAllowed.length && factor && !passwordless) {
      const narrowed = this.narrowSecondFactor(username, mfaAllowed, enrolled,
        factor, record.forceKey || riskFactor === 'security-key' ? 'key'
          : (riskFactor ? 'any' : ''));
      if (narrowed.refused) {
        if (risk) {
          this.settleRisk(risk, { decision: riskDecision,
                                  errorCode: narrowed.refused,
                                  policy: roleAnswer.policy });
        }
        errorCodes.mark(res, narrowed.refused);
        log.debug("Leaving Authn.finishPasswordSignIn(). No second factor " +
                  "the application allows.");
        return this.screenRefused(res, record,
          narrowed.why);
      }
      factor = narrowed.factor;
      thenEnrol = narrowed.thenEnrol;
    }

    // ---------------------------------------------------------------------
    // A REMEMBERED BROWSER IN PLACE OF THE SECOND FACTOR (#265), and ONLY in
    // place of the person's CONFIGURED one: never one a relying party
    // demanded (`forceMfa`, `forceKey`), never one risk asked for, never the
    // security key the person ticked themselves, and never a factor required
    // of an administrator. `browser_devices.ts`'s `skipsSecondFactor()`
    // holds the rest — the realm's policy, the browser recognised and
    // current and theirs, the second factor given on it within the policy's
    // days, the admin console, portal and debugger excluded, risk below
    // MEDIUM. The session is then ONE factor (`["pwd"]`, acr 1) and says so.
    // ---------------------------------------------------------------------
    let skippedSecondFactor = '';
    if (factor && factor === configuredFactor && !passwordless && !thenEnrol &&
        !secondFactor && !record.forceMfa && !record.forceKey &&
        !riskFactor && !requirementForAdministrator(credentials, username)) {
      const answer = this.deps.browserDevices().skipsSecondFactor({
        fact: this.registeredDeviceFor({ request: req,
          application: String(record.application || '') }, username),
        username: username,
        clientId: String(record.application || ''),
        riskLevel: risk ? risk.level : '' });
      if (answer.skip) {
        skippedSecondFactor = factor;
        factor = '';
        audit.audit({
          action: 'authn.second-factor.skipped', outcome: 'success',
          actor: username, target: username, channel: 'http',
          protocol: record.protocol,
          summary: username + ' was not asked for their ' +
                   skippedSecondFactor + ': ' + answer.why,
          detail: { factor: skippedSecondFactor } });
        log.info('authn: "' + username + '" signs in without their ' +
                 skippedSecondFactor + ' on a remembered browser.');
      }
    }

    // ---------------------------------------------------------------------
    // A SECOND FACTOR REQUIRED OF THIS PERSON (2026-09-13) — by their own entry
    // (`stsMfaRequired`, set from /admin/users) or by the realm
    // (the authentication policy's `requireSecondFactor`).
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
      return this.screenRefused(res, record,
        'A second factor is required ' + (requirement.byUser
          ? 'for this account' : 'in this realm') + ', and a security key on ' +
        'its own is one factor. Sign in with your password; you will be ' +
        'asked for your second factor, or to set one up.');
    }
    if (requirement.required && !factor && !skippedSecondFactor) {
      // Only the ones the application allows (#475).
      const offered = this.enrolmentOfferedFor(mfaAllowed);
      if (!offered.totp && !offered.webauthn && mfaAllowed.length) {
        log.info(errorCodes.tag('STS-AUTHN-0306') + 'authn: a second ' +
                 'factor is required of "' + username + '", who holds none, ' +
                 'and none of the ones "' + String(record.application) +
                 '" allows (' + mfaAllowed.join(', ') + ') can be set up at ' +
                 'sign-in; refused.');
        errorCodes.mark(res, 'STS-AUTHN-0306');
        log.debug("Leaving Authn.finishPasswordSignIn(). Nothing the " +
                  "application allows can be enrolled.");
        return this.screenRefused(res, record,
          'A second factor is required, and none that this application ' +
          'accepts can be set up here. Ask an administrator.');
      }
      if (!offered.totp && !offered.webauthn) {
        log.warn(errorCodes.tag('STS-AUTHN-0172') +
                 'authn: a second factor is ' +
                 'required of "' + username + '", who holds none, and ' +
                 'neither mechanism can be enrolled in this realm ' +
                 '(the authentication policy on Directory > Policies, ' +
                 'webauthn.enabled, webauthn.mfaAllowed). The ' +
                 'sign-in is REFUSED rather than let through on one factor.');
        errorCodes.mark(res, 'STS-AUTHN-0172');
        log.debug("Leaving Authn.finishPasswordSignIn(). Nothing can be " +
                  "enrolled.");
        return this.screenRefused(res, record,
          'A second factor is required for this account and none can be set ' +
          'up here: authenticator apps and security keys are both switched ' +
          'off in this realm. Ask an administrator.');
      }
      pending.delete(record.id);
      const setupId = randomId(24);
      pendingMfa.set(setupId, {
        authn: record, username: username,
        challenge: stsCrypto.randomBytes(32).toString('base64url'),
        // `enrol` until a mechanism is chosen; `enrol-totp` once an
        // authenticator app's secret has been shown; `webauthn` once a security
        // key is chosen, which is then the ordinary ceremony — it registers a
        // key in the `mfa` role for somebody who holds none.
        factor: 'enrol', alternate: '', backup: false, passwordless: false,
        requiredBy: requirement.byUser ? 'account'
          : (requirement.byRealm ? 'realm' : 'administrator'),
        // What the application allows (#475), which the set-up screen
        // offers from.
        mfaAllowed: mfaAllowed,
        // The sign-in's assessment (#246): the finisher decides the session
        // on it, as every other step's does. Until #246 this step carried
        // none, and an enrolment's session was decided with no risk at all.
        risk: assessment || undefined,
        expires: Date.now() + this.mfaStepTtlMs()
      });
      this.noteEnrolmentAtRisk(username, assessment, 'required');
      audit.audit({
        action: 'authn.mfa.enrolment.required', outcome: 'success',
        actor: username, target: username, channel: 'http',
        protocol: record.protocol,
        summary: username + ' holds no second factor and one is required; ' +
                 'asked to set one up before signing in',
        detail: { requiredBy: requirement.byUser ? 'account'
          : (requirement.byRealm ? 'realm' : 'administrator') }
      });
      log.info('authn: "' + username + '" holds no second factor and one is ' +
               'required; asking them to set one up.');
      log.debug("Leaving Authn.finishPasswordSignIn(). Enrolment step.");
      return this.stepAnswer(res, 'mfa', 'enrol', setupId, MFA_SETUP_PATH,
                             'mfa');
    }

    // ---------------------------------------------------------------------
    // A SECOND FACTOR OFFERED TO AN ADMINISTRATOR (#246): the authentication
    // policy's `requireSecondFactorForAdministrators` is `offer` (the default
    // for now), or `always` for the default realm's built-in administrator.
    // The same set-up step, minted `optional`, with an Ignore button that
    // finishes this sign-in on the password — rcbj's "we can offer it, but
    // they can decline". Offered at every sign-in until one is set up.
    // Nothing is offered where nothing can be enrolled, and never to a
    // passwordless sign-in, which is not asked for a second factor.
    // ---------------------------------------------------------------------
    const enrolable = requirement.offered && !factor && !passwordless &&
                      !skippedSecondFactor
      ? this.enrolmentOfferedFor(mfaAllowed) : null;
    if (enrolable && (enrolable.totp || enrolable.webauthn)) {
      pending.delete(record.id);
      const offerId = randomId(24);
      pendingMfa.set(offerId, {
        authn: record, username: username,
        challenge: stsCrypto.randomBytes(32).toString('base64url'),
        factor: 'enrol', alternate: '', backup: false, passwordless: false,
        requiredBy: 'administrator', optional: true, mfaAllowed: mfaAllowed,
        risk: assessment || undefined, riskDecision: riskDecision,
        expires: Date.now() + this.mfaStepTtlMs()
      });
      this.noteEnrolmentAtRisk(username, assessment, 'offered');
      audit.audit({
        action: 'authn.mfa.enrolment.offered', outcome: 'success',
        actor: username, target: username, channel: 'http',
        protocol: record.protocol,
        summary: username + ' holds an administrator role and no second ' +
                 'factor; offered one before signing in',
        detail: { requiredBy: 'administrator' }
      });
      log.info('authn: "' + username + '" is an administrator with no ' +
               'second factor; offering to set one up.');
      log.debug("Leaving Authn.finishPasswordSignIn(). Offered a factor.");
      return this.stepAnswer(res, 'mfa', 'enrol', offerId, MFA_SETUP_PATH,
                             'mfa');
    }

    if (factor) {
      pending.delete(record.id);
      const mfaId = randomId(24);
      pendingMfa.set(mfaId, {
        authn: record, username: username,
        challenge: stsCrypto.randomBytes(32).toString('base64url'),
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
        // THE EMAILED FACTOR AS A WAY ROUND THE ONE ASKED FOR (#64): `code`
        // or `link` where the person holds it and it is not already the
        // factor asked for. Never under a demand for a key, and never on
        // risk — an email answers neither (D1).
        email: record.forceKey || riskFactor ||
               String(factor).indexOf('email-') === 0
          ? '' : (enrolled.mailFactor ? enrolled.mailFactor.held : ''),
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
        // A security key demanded ON RISK, for `keyDemandProblem()`'s
        // reason: the POST at the other end is an answer, not the question.
        riskKey: riskFactor === 'security-key',
        // THE APPLICATION'S SECOND FACTORS (#475): what the step may offer,
        // and whether the factor asked for is only a PROOF, after which an
        // allowed one is enrolled (`enrolAfterProof()`).
        mfaAllowed: mfaAllowed,
        thenEnrol: thenEnrol,
        expires: Date.now() + this.mfaStepTtlMs()
      });
      this.narrowStep(pendingMfa.get(mfaId));
      pendingMfa.forEach(function (v, k) {
        if (v.expires < Date.now()) pendingMfa.delete(k);
      });
      if (factor === 'totp') {
        log.debug("Leaving the authentication endpoint. " + username +
                  " passed the password step; asking for the one-time code.");
        log.debug("Leaving Authn.finishPasswordSignIn().");
        return this.stepAnswer(res, 'mfa', 'totp', mfaId, TOTP_PATH, 'mfa');
      }
      if (factor === 'email-code' || factor === 'email-link') {
        log.debug("Leaving Authn.finishPasswordSignIn(). Mailing the " +
                  factor + ".");
        // The first message is sent now, as it always was; the page the
        // step is drawn on then shows it sent (`email_factor.ts`, #571).
        await this.emailDoor().armSecondFactor(req, res, mfaId);
        return this.stepAnswer(res, 'mfa', factor, mfaId,
                               factor === 'email-code' ? EMAIL_CODE_PATH
                                                       : EMAIL_LINK_PATH,
                               'mfa');
      }
      // THE CEREMONY IS DRAWN BY `GET /authn/webauthn` SINCE #571, which
      // until then drew only the assertion for a person holding a key: an
      // enrolment ceremony (a person holding no second factor, or
      // development's passwordless first use) was drawn only in answer to
      // the screen's POST. The step says it was minted here for this
      // ceremony, which is what lets that GET draw it — never for a step
      // minted for another factor (the bypass its header argues).
      const minted = pendingMfa.get(mfaId);
      if (minted) {
        minted.atSignIn = true;
        pendingMfa.set(mfaId, minted);
      }
      log.debug("Leaving the authentication endpoint. " + username +
                (passwordless ? " asked for a passwordless sign-in; asking " +
                                "for the security key."
                              : " passed the password step; asking for the " +
                                "security key."));
      log.debug("Leaving Authn.finishPasswordSignIn().");
      return this.stepAnswer(res, 'mfa', 'webauthn', mfaId, WEBAUTHN_PATH,
                             'mfa');
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
    // The application named (#457), for the sign-in mechanism question
    // startSession() still asks of a gated door.
    const said = { postLoginHold: true,
                   request: req, gated: true,
                   application: String(record.application || ''),
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
  // SINCE #571 THE FORCED PASSWORD CHANGE IS A PAGE OF THE SIGN-IN SURFACE
  // (`web_authn_password.ts`), drawn from `GET
  // /authn-api/password-change/{id}`: whose password it is, and why the
  // change is asked for now where there is a reason (a breached password).
  // IT STILL CHANGES NOTHING UNTIL THE NEW PASSWORD IS STORED: the step
  // carries the pending sign-in, and `passwordChangeAct()` resumes it.
  /**
   * The forced password change's view.
   *
   * @param changeId - the step's id
   * @param step - the step
   * @returns the view
   */
  passwordChangeView(changeId, step): any {
    const { log } = this.deps;
    log.debug("Entering Authn.passwordChangeView().");
    const view = { id: String(changeId), username: String(step.username),
                   notice: String(step.notice || '') };
    log.debug("Leaving Authn.passwordChangeView().");
    return view;
  }

  // The step, or null with the refusal already sent.
  passwordChangeStep(res, changeId) {
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

  // ---------------------------------------------------------------------------
  // THE SECOND FACTORS AN APPLICATION ALLOWS, AT THE STEP (#475).
  //
  // `enrolmentOfferedFor()` is enrolmentOffered() narrowed to the list: a
  // security key only where `securityKey` is on it, an authenticator app only
  // where `totp` is. Nothing else can be enrolled at sign-in.
  //
  // `narrowSecondFactor()` decides what the step asks for when the factor
  // chosen above is not on the list — rcbj's decisions, 2026-10-07:
  //
  //   * **Another the person holds** and the list allows, preferring a key,
  //     then an app, then an emailed factor the realm can send.
  //   * **None held at all**: nothing is asked here. A second factor
  //     required of them is enrolled by the requirement step, which offers
  //     only allowed ones; the security-key box, ticked to enrol a key an
  //     application does not allow, enrols nothing.
  //   * **Held, but none allowed: PROVE ONE, THEN ENROL** (`thenEnrol`). The
  //     step asks for the factor they hold, and its finisher hands over to
  //     the set-up screen (`enrolAfterProof()`) instead of starting a
  //     session. Enrolling BEFORE that proof is the bypass the header of
  //     the set-up screen refuses: anybody who knows the password could
  //     register their own key and never meet the factor the account has.
  //   * **Refused** where nothing allowed can be enrolled (STS-AUTHN-0306),
  //     and where the factor was DEMANDED — a security key by the relying
  //     party or on risk, or any factor on risk — and the list leaves the
  //     person nothing that answers it (STS-AUTHN-0307): a step-up never
  //     enrols (#62 P3), and a demand the application's own list forbids
  //     cannot be met at all.
  // ---------------------------------------------------------------------------
  private enrolmentOfferedFor(allowed: string[]) {
    const { log } = this.deps;
    log.debug('Entering Authn.enrolmentOfferedFor().');
    const out = this.enrolmentOffered();
    if (!Array.isArray(allowed) || !allowed.length) {
      log.debug('Leaving Authn.enrolmentOfferedFor(). The realm\'s.');
      return out;
    }
    const narrowed = {
      totp: out.totp && allowed.indexOf('totp') >= 0,
      webauthn: out.webauthn && allowed.indexOf('securityKey') >= 0
    };
    log.debug('Leaving Authn.enrolmentOfferedFor(). totp=' + narrowed.totp +
              ', webauthn=' + narrowed.webauthn);
    return narrowed;
  }

  private allowedHeldFactor(allowed: string[], enrolled: any): string {
    const { log, authnPolicy } = this.deps;
    log.debug('Entering Authn.allowedHeldFactor().');
    const mail = enrolled && enrolled.mailFactor
      ? String(enrolled.mailFactor.held || '') : '';
    let out = '';
    if (enrolled && enrolled.mfaKeys > 0 &&
        allowed.indexOf('securityKey') >= 0) {
      out = 'webauthn';
    } else if (enrolled && enrolled.totp && allowed.indexOf('totp') >= 0) {
      out = 'totp';
    } else if (mail === 'code' && allowed.indexOf('emailCode') >= 0 &&
               authnPolicy.active('emailCode', 'second-factor')) {
      out = 'email-code';
    } else if (mail === 'link' && allowed.indexOf('emailLink') >= 0 &&
               authnPolicy.active('emailLink', 'second-factor')) {
      out = 'email-link';
    }
    log.debug('Leaving Authn.allowedHeldFactor(). ' + (out || 'none'));
    return out;
  }

  private narrowSecondFactor(username: string, allowed: string[],
                             enrolled: any, factor: string,
                             demand: string) {
    const { log, errorCodes } = this.deps;
    log.debug('Entering Authn.narrowSecondFactor(). ' + factor);
    const answer = { factor: factor, thenEnrol: false, refused: '', why: '' };
    if (mfaLib.allowsStepFactor(allowed, factor)) {
      log.debug('Leaving Authn.narrowSecondFactor(). Allowed as it is.');
      return answer;
    }
    const held = demand === 'key' ? '' : this.allowedHeldFactor(allowed,
                                                                enrolled);
    if (held) {
      answer.factor = held;
      log.debug('Leaving Authn.narrowSecondFactor(). ' + held + ' instead.');
      return answer;
    }
    if (demand) {
      log.info(errorCodes.tag('STS-AUTHN-0307') + 'authn: a ' +
               (demand === 'key' ? 'security key' : 'second factor') +
               ' was demanded of "' + username + '", and the application ' +
               'allows only ' + allowed.join(', ') + ', none of which they ' +
               'hold to answer it; refused.');
      answer.refused = 'STS-AUTHN-0307';
      answer.why = 'This sign-in needs a second factor that this ' +
        'application does not accept, or one you have not set up. Ask an ' +
        'administrator.';
      log.debug('Leaving Authn.narrowSecondFactor(). A demand it cannot ' +
                'meet.');
      return answer;
    }
    if (!enrolled || !enrolled.mfaRequired) {
      answer.factor = '';
      log.debug('Leaving Authn.narrowSecondFactor(). They hold none.');
      return answer;
    }
    const offered = this.enrolmentOfferedFor(allowed);
    if (!offered.totp && !offered.webauthn) {
      log.info(errorCodes.tag('STS-AUTHN-0306') + 'authn: "' + username +
               '" holds no second factor the application allows (' +
               allowed.join(', ') + '), and none of those can be set up at ' +
               'sign-in; refused.');
      answer.refused = 'STS-AUTHN-0306';
      answer.why = 'This application accepts a second factor you have not ' +
        'set up, and none that it accepts can be set up here. Ask an ' +
        'administrator.';
      log.debug('Leaving Authn.narrowSecondFactor(). Nothing to enrol.');
      return answer;
    }
    answer.thenEnrol = true;
    log.debug('Leaving Authn.narrowSecondFactor(). Prove ' + factor +
              ', then enrol.');
    return answer;
  }

  // The links a minted step offers beside its factor, narrowed to the
  // application's list (#475) — unless the step is a PROOF before an
  // enrolment, where any factor the person holds proves who they are.
  private narrowStep(step: any): void {
    const { log } = this.deps;
    log.debug('Entering Authn.narrowStep().');
    // NO SELF-SERVICE RECOVERY OFFERED WHERE THE PASSKEY POLICY REFUSES IT
    // (#724): the recovery-code and emailed links are not drawn for a
    // passkey holder under `operator-only`. `startSessionHere()` refuses
    // either anyway; this keeps the step from offering a door that fails.
    if (step && (step.backup || step.email)) {
      this.closeSelfServiceRecovery(step);
    }
    const allowed = step && Array.isArray(step.mfaAllowed)
      ? step.mfaAllowed : [];
    if (!step || !allowed.length || step.thenEnrol) {
      log.debug('Leaving Authn.narrowStep(). Nothing to narrow.');
      return;
    }
    if (step.alternate && !mfaLib.allowsStepFactor(allowed, step.alternate)) {
      step.alternate = '';
    }
    if (step.backup && !mfaLib.allowsStepFactor(allowed, 'backup')) {
      step.backup = false;
    }
    if (step.email && !mfaLib.allowsStepFactor(allowed, step.email)) {
      step.email = '';
    }
    if (step.passwordAlternate &&
        !mfaLib.allowsStepFactor(allowed, 'password')) {
      step.passwordAlternate = false;
    }
    log.debug('Leaving Authn.narrowStep().');
  }

  // Whether a step may draw the wallet as its second factor (#475): the
  // links above are minted; this one is decided when the page is drawn.
  private stepAllowsWallet(step: any): boolean {
    const { log } = this.deps;
    log.debug('Entering Authn.stepAllowsWallet().');
    const allowed = step && Array.isArray(step.mfaAllowed)
      ? step.mfaAllowed : [];
    const out = !!(step && step.thenEnrol) ||
      mfaLib.allowsStepFactor(allowed, 'wallet');
    log.debug('Leaving Authn.stepAllowsWallet(). ' + out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // A HELD FACTOR PROVED, AN ALLOWED ONE ENROLLED (#475). Called by every
  // second-factor finisher, in place of starting the session, for a step
  // minted `thenEnrol`: the person has just proved the factor they hold,
  // which is what makes enrolling one for them safe. The set-up step it
  // mints is marked `proved`, which is what lets the set-up screen enrol
  // for somebody who holds a factor, and carries the proof's `amr` as its
  // first factors, so the session finally started says both were given.
  // It offers only what the application allows.
  // ---------------------------------------------------------------------------
  private enrolAfterProof(res: any, step: any, amr: string[]): void {
    const { log, randomId, stsCrypto, audit, oauthError, errorCodes } =
      this.deps;
    log.debug('Entering Authn.enrolAfterProof(). username=' + step.username);
    const allowed = Array.isArray(step.mfaAllowed) ? step.mfaAllowed : [];
    const offered = this.enrolmentOfferedFor(allowed);
    if (!offered.totp && !offered.webauthn) {
      // The realm switched both off since the step was minted.
      log.debug('Leaving Authn.enrolAfterProof(). Nothing to enrol now.');
      const why = 'This application accepts a second factor you have not ' +
        'set up, and none that it accepts can be set up here. Ask an ' +
        'administrator.';
      errorCodes.mark(res, 'STS-AUTHN-0306');
      if (this.answersJson(res)) {
        this.stepRefused(res, why, 400);
      } else {
        errorCodes.mark(res, 'STS-AUTHN-0306');
        oauthError(res, 400, 'access_denied', why);
      }
      return;
    }
    const first: string[] = [];
    (amr || []).map(String).forEach(function (one) {
      if (first.indexOf(one) < 0) {
        first.push(one);
      }
    });
    const setupId = randomId(24);
    pendingMfa.set(setupId, {
      authn: step.authn, username: step.username,
      challenge: stsCrypto.randomBytes(32).toString('base64url'),
      factor: 'enrol', alternate: '', backup: false, passwordless: false,
      requiredBy: 'application', proved: true, mfaAllowed: allowed,
      firstAmr: first, risk: step.risk, riskDecision: step.riskDecision,
      expires: Date.now() + this.mfaStepTtlMs()
    });
    audit.audit({
      action: 'authn.mfa.enrolment.required', outcome: 'success',
      actor: step.username, target: step.username, channel: 'http',
      protocol: step.authn && step.authn.protocol,
      summary: step.username + ' gave a second factor the application ' +
               'does not allow; asked to set up one it does',
      detail: { requiredBy: 'application',
                application: String((step.authn || {}).application || ''),
                allowed: allowed }
    });
    log.info('authn: "' + step.username + '" proved a second factor "' +
             String((step.authn || {}).application || '') + '" does not ' +
             'allow; asking them to set up one it does (' +
             allowed.join(', ') + ').');
    // The set-up step's page (#572), by its address.
    this.stepAnswer(res, 'mfa', 'enrol', setupId, MFA_SETUP_PATH, 'mfa');
    log.debug('Leaving Authn.enrolAfterProof().');
  }

  // ENROLMENT AT ELEVATED RISK (#246, rcbj's decision 3): an administrator
  // with no second factor, signing in at HIGH or MEDIUM, is still sent to the
  // set-up step — the console is never locked out (#226) — and this is the
  // alarm that says a factor may be enrolled by whoever holds the password.
  private noteEnrolmentAtRisk(username, assessment, how) {
    const { log, audit, errorCodes } = this.deps;
    log.debug("Entering Authn.noteEnrolmentAtRisk().");
    const level = assessment ? String(assessment.level || '') : '';
    if (level !== 'HIGH' && level !== 'MEDIUM') {
      log.debug("Leaving Authn.noteEnrolmentAtRisk(). Not elevated.");
      return;
    }
    audit.audit({
      action: 'authn.mfa.enrolment.at-risk', outcome: 'success',
      errorCode: 'STS-RISK-0039', actor: username, target: username,
      channel: 'http',
      summary: username + ' was ' + how + ' a second factor to set up at a ' +
               'sign-in whose risk is ' + level,
      detail: { level: level, assessment: String(assessment.id || '') }
    });
    log.warn(errorCodes.tag('STS-RISK-0039') + 'authn: "' + username + '" ' +
             'was ' + how + ' a second factor to set up at a sign-in whose ' +
             'risk is ' + level + '. Whoever holds the password could enrol ' +
             'it; confirm with them.');
    log.debug("Leaving Authn.noteEnrolmentAtRisk().");
  }

  // THE SET-UP STEP'S FACTS (#572): the choice — an authenticator app or a
  // security key, whichever this realm and the application offer (#475) —
  // and, once an app was chosen, its secret: the `otpauth:` URI, which the
  // browser draws as a QR code (`common/web_qr.ts`), and the secret typed
  // out, as the page always showed it. No picture crosses the API.
  // `optional` (#246): the step was OFFERED rather than required, and the
  // page draws an Ignore button. `proved` (#475): the application's own.
  private mfaSetupFacts(base: string, step: any): any {
    const { log, credentials, totp } = this.deps;
    log.debug('Entering Authn.mfaSetupFacts().');
    const out: any = {
      state: 'choose',
      offered: this.enrolmentOfferedFor(step.mfaAllowed || []),
      optional: !!step.optional, proved: !!step.proved,
      // AFTER AN ACCOUNT RECOVERY (#724): the page says why only a passkey
      // is offered, and that nothing is signed in afterwards.
      recovery: !!step.recovery, totp: null };
    const held = step.factor === 'enrol-totp'
      ? credentials.pendingTotpFor(step.username) : null;
    if (held) {
      out.state = 'totp';
      out.totp = {
        uri: totp.otpauthUri({ issuer: totp.issuerFor(base),
          account: step.username, secret: held.secret,
          algorithm: held.algorithm, digits: held.digits,
          period: held.period }),
        secret: totp.grouped(held.secret),
        algorithm: 'HMAC-' + String(held.algorithm).replace(/^SHA/, 'SHA-'),
        digits: held.digits, period: held.period };
    }
    log.debug('Leaving Authn.mfaSetupFacts(). ' + out.state);
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHICH ENROLLED KEY AN ASSERTION IS TO BE CHECKED AGAINST (2026-09-10).
  //
  // A FUNCTION rather than four lines in the handler, because it is a RULE and
  // the handler is where it would quietly stop being one. It is also the only
  // shape in which it can be tested: a person holding TWO keys is the state
  // that tells "check the one the browser named" from "check the first one you
  // find", and no door in this service can currently enrol a second key — see
  // `tests/protocol/sts_webauthn_second_factor.js`'s header.
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
  /**
   * Picks the enrolled security key a WebAuthn assertion is checked against:
   * the one it names.
   *
   * @param username - the person
   * @param role - the key's role, primary or second factor
   * @param presentedId - the credential id the assertion names
   * @returns `{ key, usable }`, or `{ key: null, usable, why }` marked with the
   *   error code of the refusal
   */
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

  // WHERE A PERSON GETS A POST-QUANTUM PASSKEY (#946), for the panel the
  // sign-in screen and the passkey step draw when a classical one is
  // refused: the account page's passkeys, root-relative so the browser
  // puts the realm's prefix on it, where passkeys may be registered here at
  // all — whether the person can reach it depends on the portal's own
  // passkey profile, which the panel's words say — and #939's upgrade,
  // which is '' until `postQuantumUpgradeOffered()` answers true.
  /**
   * The links of the post-quantum panel (#946).
   *
   * @returns `{ register, upgrade }`, each a path or ''
   */
  postQuantumHelp(): { register: string; upgrade: string } {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering Authn.postQuantumHelp().");
    const out = {
      register: webauthnPolicy.offered() ? '/portal/keys' : '',
      // #939: drawn when this realm offers the upgrade.
      upgrade: webauthnPolicy.postQuantumUpgradeOffered()
        ? '/portal/keys?upgrade=post-quantum' : ''
    };
    log.debug("Leaving Authn.postQuantumHelp(). " +
              (out.register ? 'register' : 'none') +
              (out.upgrade ? ', upgrade' : ''));
    return out;
  }

  // THE PASSKEY STEP'S FACTS (#572), which `webauthnPage()` drew as markup
  // and data attributes until then: what the page says and, as `ceremony`,
  // what `POST /authn-api/mfa/{id}/webauthn/options` hands the browser's
  // ceremony. Nothing in it is secret and nothing in it is trusted on the
  // way back: it is a REQUEST to the browser, and every security property
  // is checked against the pending step and the origin when the result
  // arrives.
  /**
   * The passkey step's facts: the page's, and the ceremony's options.
   *
   * @param base - the realm's base URL
   * @param mfaId - the step's id
   * @param step - the step
   * @param chosenKey - the passkey chosen (#534), if any
   * @param lane - the lane a registration is to be made in (#643), as the
   *   person chose it when the ceremony was armed; kept on the step
   * @returns the facts
   */
  webauthnFacts(base: string, mfaId: string, step: any,
                chosenKey?: string, lane?: string): any {
    const { log, credentials, webauthnPolicy } = this.deps;
    const username = String(step.username);
    log.debug("Entering Authn.webauthnFacts(). username=" + username);
    // -------------------------------------------------------------------
    // WHICH KEYS THIS PERSON HOLDS, FROM THE ONE STORE (2026-09-10), AND
    // ONLY THE KEYS THAT ANSWER THIS ROLE. A `primary` key signs somebody
    // in on its own and an `mfa` key is a second factor beside a password;
    // offering both in one ceremony would let a person satisfy a
    // second-factor step with a credential this service considers a way IN.
    // -------------------------------------------------------------------
    const passwordless = !!step.passwordless;
    const wantedRole = passwordless ? 'primary' : 'mfa';
    // THE PASSKEY POLICY FOR THIS PERSON AND APPLICATION (#535): the
    // ceremony's options read it.
    this.deps.passkeyPolicy.select(username,
                                   step.authn && step.authn.application);
    const held = credentials.keysOf(username).filter(function (one) {
      return one.role === wantedRole;
    });
    // ONLY THE POST-QUANTUM KEYS WHILE THE PROFILE REQUIRES ONE AT SIGN-IN
    // (#718, rcbj's decision 3), by the question's own reading of each
    // key's algorithm (`postQuantumRefusal()`), so `allowCredentials` never
    // offers an authenticator a key the policy would refuse after the
    // ceremony. A person who holds keys of this role and none of them
    // post-quantum is told before any ceremony (`postQuantumRefused`
    // below, refused at `mfaWebauthnOptions()`) — and is NOT offered an
    // enrolment instead: the mode is decided on what they hold.
    const pqRequired = this.deps.passkeyPolicy.requiresPostQuantum('sign-in');
    const pqHeld = pqRequired ? held.filter((one) => {
      return !this.deps.passkeyPolicy.postQuantumRefusal(
        credentials.keyAlgorithm(one), 'sign-in');
    }) : held;
    // LIST AND REFUSE (#946), the alternative to narrowing: the realm's
    // `webauthn.postQuantumAllowCredentials`, or the selected profile's
    // row of that name. `narrow` (the default) is #718's filter above;
    // `list-and-refuse` names EVERY key of the role, so a platform asked
    // for a person's passkeys does not answer "no credential found" for
    // the classical one they hold, and a classical assertion is refused
    // after the ceremony by this service, in its own words, at the
    // session's start (STS-AUTHN-0356 — the panel `refusedSession()` adds).
    // The trade-off is the ticket's: the person may pick a key that will be
    // refused. Either way a person holding NO post-quantum key is told
    // before any ceremony (below): no choice of theirs could succeed, so
    // there is nothing for a ceremony to find out.
    const listAll = pqRequired &&
      this.deps.passkeyPolicy.postQuantumAllowCredentials() ===
        'list-and-refuse';
    const known = listAll ? held : pqHeld;
    // A RECOVERY ENROLMENT (#724) is a registration, so it is not refused
    // for the keys already held; the new key meets the registration rules.
    const pqRefusal = !step.recovery && !step.postLogin && pqRequired &&
      held.length &&
      !pqHeld.length
      ? this.deps.passkeyPolicy.postQuantumRefusal(
          credentials.keyAlgorithm(held[0]), 'sign-in')
      : null;
    // A RECOVERY ENROLMENT (#724) REGISTERS, whatever keys the person holds:
    // the step exists because they cannot use the one they have.
    // AND SO DOES A POST-LOGIN STEP (#1096): it exists to add a passkey
    // beside the ones the person holds.
    const mode = step.recovery || step.postLogin ? 'create'
      : (held.length ? 'get' : 'create');
    // `phrh` NARROWED (#739): the sign-in must earn hardware-protected
    // phishing resistance, so `allowCredentials` names only keys whose
    // RECORDED attestation is trusted and whose BE flag is clear — the same
    // two facts `phishing_resistance.ts` reads off an assertion. A person
    // who holds keys of this role and none of them qualify is told before
    // any ceremony, and is not offered an enrolment: a registration in this
    // act earns neither class. A discoverable (usernameless) ceremony has
    // no list to narrow and is not this step; it is refused after, as
    // STS-OAUTH-0971. `phr` beside `phrh` is either, and is not narrowed.
    const phrhAsked = String((step.authn || {}).phishingClass || '') ===
                      'phrh' && mode === 'get' && !pqRefusal;
    let hardwareKnown = known;
    let hardwareRefusal: { code: string, why: string } | null = null;
    if (phrhAsked) {
      const leaf = require('../common/phishing_resistance');
      hardwareKnown = known.filter(function (one) {
        return leaf.storedKeyEarnsHardware(one);
      });
      if (known.length && !hardwareKnown.length) {
        hardwareRefusal = { code: 'STS-AUTHN-0459',
          why: 'This sign-in asks for a hardware-protected ' +
               'phishing-resistant passkey, and none of the passkeys held ' +
               'for this step can earn it. A synced passkey, or one whose ' +
               'attestation is not trusted, is not enough.' };
      }
    }
    const offered = hardwareRefusal ? [] : hardwareKnown;
    // ONE CHOICE PER PASSKEY (#534), where the passkey policy says so and
    // there is more than one to choose from: until one is chosen the page
    // lists them, and once one is, the ceremony names only it. A chosen id
    // that is not one of this step's keys is not a choice.
    const separate = mode === 'get' && offered.length > 1 &&
                     !this.deps.passkeyPolicy.aggregatesDevices();
    const chosen = separate ? offered.filter(function (one) {
      return one.credentialId === String(chosenKey || '');
    })[0] || null : null;
    const choosing = separate && !chosen;
    const allowed = chosen ? [chosen] : offered;
    // THE LANE A REGISTRATION IS MADE IN (#643), ON THE STEP like the role:
    // chosen when the ceremony is armed (`mfaWebauthnOptions()` has asked
    // `laneRefusal()` of it), and read back from the step — never from the
    // browser's answer — by the registration branch. A new choice before
    // the ceremony ran takes a new handle, the lane's own.
    // WHILE A POST-QUANTUM PASSKEY IS REQUIRED AT REGISTRATION AND BOTH
    // LANES ARE ON (#718), the post-quantum lane is the only one
    // (`enrolmentLane()`): a classical choice, or none, becomes it, so the
    // credential is made under the lane's own handle and replaces nothing.
    // A post-login step's lane is the activity's, never the page's (#1096).
    const chosenLane = mode === 'create' && lane && !step.postLogin
      ? webauthnPolicy.enrolmentLane(String(lane)) : '';
    if (chosenLane && chosenLane !== String(step.lane || 'classical')) {
      step.lane = chosenLane;
      step.userHandle = '';
      pendingMfa.set(mfaId, step);
    } else if (mode === 'create' && !step.lane &&
               webauthnPolicy.enrolmentLane('') !== 'classical') {
      step.lane = webauthnPolicy.enrolmentLane('');
      step.userHandle = '';
      pendingMfa.set(mfaId, step);
    }
    const stepLane = String(step.lane || 'classical');
    // THE USER HANDLE THE CREDENTIAL IS CREATED UNDER (#474), on the step
    // so the registration branch records the one the browser was given —
    // the lane's (#643).
    if (mode === 'create' && !step.userHandle) {
      step.userHandle = credentials.userHandleOf(username,
                                                 { mint: true,
                                                   lane: stepLane }) ||
                        credentials.newUserHandle();
      pendingMfa.set(mfaId, step);
    }
    // Read ONCE: rpIdOf() logs when it refuses a configured value.
    const rpId = this.rpIdOf(base);
    const options = webauthnPolicy.settings();
    // THE CLASSICAL RETRY (#944), where a registration is drawn: whether
    // the ceremony asks for ML-DSA at all (`asksPostQuantum`, so the page
    // has guidance to give when the device cannot make one), whether a
    // retry with the classical algorithms only may be offered here
    // (`classical`), and whether this ceremony IS that retry. On the page's
    // facts and on the ceremony's, language-free.
    // A POST-LOGIN STEP (#1096) ASKS FOR ML-DSA ONLY, and has no classical
    // retry: a classical passkey is the thing it exists not to make. The
    // algorithms are #939's upgrade's (`upgradeAlgorithms()`), in the lane
    // the step was given.
    const postLoginAlgs = mode === 'create' && step.postLogin
      ? webauthnPolicy.upgradeAlgorithms() : null;
    const fallback = postLoginAlgs
      ? { asksPostQuantum: true, classical: false, retrying: false }
      : mode === 'create' ? {
      asksPostQuantum: webauthnPolicy.asksPostQuantum(stepLane,
                                                      !!step.classicalOnly),
      classical: !step.classicalOnly &&
        webauthnPolicy.classicalFallbackOffered(stepLane, 'sign-in'),
      retrying: !!step.classicalOnly } : null;
    const out = {
      mode: mode, passwordless: passwordless,
      choices: choosing ? offered.map(function (one) {
        return { id: String(one.credentialId),
                 name: String(credentials.keyName(one)) };
      }) : [],
      chosen: chosen ? { id: String(chosen.credentialId),
                         name: String(credentials.keyName(chosen)) } : null,
      // In product mode an RP ID that does not fit is said on the page as
      // well as refused at the act: a ceremony drawn under a refusal would
      // be a browser prompt whose answer is thrown away.
      problem: String(this.rpIdProblem(base) ||
                      (pqRefusal ? pqRefusal.why : '') ||
                      (hardwareRefusal ? hardwareRefusal.why : '') || ''),
      // NO POST-QUANTUM KEY WHERE ONE IS REQUIRED (#718): the refusal the
      // ceremony would end in, said before it runs.
      postQuantumRefused: pqRefusal ? { code: pqRefusal.code,
                                        why: pqRefusal.why } : null,
      // NO KEY THAT CAN EARN `phrh` (#739), said before the ceremony.
      hardwareRefused: hardwareRefusal,
      // AND WHERE TO GET ONE (#946): the panel's links, drawn in the page's
      // language — the refusal above stays English (#539).
      postQuantumHelp: pqRefusal ? this.postQuantumHelp() : null,
      // How `allowCredentials` was built while one is required (#946):
      // `narrow` or `list-and-refuse`; '' while nothing is required.
      postQuantumAllowCredentials: pqRequired
        ? (listAll ? 'list-and-refuse' : 'narrow') : '',
      fallback: fallback,
      // The technical fold (#470): what this ceremony asks for. The
      // ceremony's own names stay as they are; what is said ABOUT them is
      // in the page's language (#539).
      rpId: rpId, widened: !!options.rpId,
      challenge: String(step.challenge || ''),
      attestation: String(options.attestation || ''),
      // The lane's algorithms where a registration is drawn (#643); the
      // configured list otherwise, and with the switch off.
      algorithms: (postLoginAlgs || (mode === 'create'
        ? webauthnPolicy.algorithmsOffered(stepLane, !!step.classicalOnly)
        : (options.algorithms || []))).map(String),
      // WHAT A POST-LOGIN STEP ASKS (#1096), for the page's words.
      postLogin: step.postLogin ? { role: String(step.postLogin.role),
                                    required: step.postLogin.required ===
                                              true } : null,
      // THE LANES A REGISTRATION MAY BE MADE IN (#643): both while the
      // switch is on, which is when the page asks which; the one chosen.
      lanes: postLoginAlgs ? [stepLane]
        : (mode === 'create' ? webauthnPolicy.lanes() : []),
      lane: mode === 'create' ? stepLane : '',
      userVerification: String(options.userVerification || ''),
      residentKey: String(options.residentKey || ''),
      attachment: String(options.authenticatorAttachment || ''),
      ceremony: {
        mode: mode, challenge: String(step.challenge || ''), rpId: rpId,
        // THE NAME THE PROMPT SHOWS (#533): the passkey policy's
        // userDisplayName, else the username. The handle (#474): 64 random
        // bytes, never the username.
        // THE POST-QUANTUM LANE'S NAME (#643): `<username>+ml-dsa`, which a
        // credential manager shows and nobody signs in with.
        user: Object.assign(credentials.laneUser(username,
          String(this.deps.passkeyPolicy.displayNameFor(username, username)),
          mode === 'create' ? stepLane : 'classical'),
          { id: String(step.userHandle || '') }),
        // EVERY key of this role, because a person may hold several and the
        // authenticator picks; empty on the enrolment path.
        allow: allowed.map(function (one) {
          return String(one.credentialId);
        }),
        // EVERY key they hold IN THIS LANE (#643), of EITHER role, so an
        // authenticator already registered here cannot be registered again
        // on the enrolment path — and one holding their classical passkey
        // can take the post-quantum one. Every key while the switch is off.
        exclude: credentials.keysOf(username).filter(function (one) {
          return credentials.keyLane(one) === stepLane;
        }).map(function (one) {
          return String(one.credentialId);
        }),
        options: postLoginAlgs
          ? Object.assign(webauthnPolicy.creationOptions(rpId, undefined,
                                                         stepLane, false),
                          { algorithms: webauthnPolicy.upgradeAlgorithmIds() })
          : mode === 'create'
          ? webauthnPolicy.creationOptions(rpId, undefined, stepLane,
                                           !!step.classicalOnly)
          : webauthnPolicy.requestOptions(rpId),
        // The retry's facts (#944), for the script — and any caller of the
        // API that runs the ceremony itself.
        fallback: fallback } };
    log.debug("Leaving Authn.webauthnFacts(). mode=" + mode);
    return out;
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
  /**
   * Returns the origin of a base URL, which in a realm is not the base URL
   * itself.
   *
   * @param base - the base URL
   * @returns the origin
   */
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
  /**
   * Says why a configured `webauthn.rpId` cannot be used for this address,
   * where the mode refuses unregistered addresses.
   *
   * @param base - the base URL
   * @returns the problem, or '' when there is none
   */
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

  /**
   * Returns the origin a WebAuthn ceremony's client data is verified against.
   *
   * With `webauthn.allowedOrigins` empty it is the base's origin; otherwise the
   * browser's claimed origin when on the list, else the list's first entry, so
   * the verifier refuses.
   *
   * @param base - the base URL
   * @param credential - the browser's credential
   * @returns the expected origin
   */
  expectedOriginFor(base, credential) {
    const { log } = this.deps;
    log.debug("Entering Authn.expectedOriginFor().");
    let list = this.allowedOrigins();
    // EACH CELL'S OWN CONSOLE ADDRESS (#361, 2026-09-30). With no list, the
    // base's origin was the only one — the shared public name wherever
    // `global.publicBaseUrl` is pinned — so a passkey used at a cell's own
    // console address (`cells.consoleUrl`, `https://cac1.<public name>`) was
    // refused as another origin, even though its RP ID, the public name, is
    // a valid parent of that host for the browser. Those addresses are
    // configuration, so with no list of its own the base's origin and every
    // configured cell console origin are accepted; a list, where set, is
    // still the whole answer.
    const implicit = !list.length;
    if (implicit) {
      const cells = require('../common/cells');
      list = [this.originOf(base)].concat(cells.all().map(function (one) {
        return String(one.consoleUrl || '');
      }).filter(Boolean));
      if (list.length === 1) {
        log.debug("Leaving Authn.expectedOriginFor(). Derived from the " +
                  "base.");
        return list[0];
      }
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
              "verifier refuses." + (implicit ? " (The base's origin and " +
              "the cells' console origins.)" : ''));
    return list[0];
  }

  /**
   * Returns the WebAuthn RP ID for a base URL: `webauthn.rpId` when it is a
   * registrable suffix of the host, else the host.
   *
   * @param base - the base URL
   * @returns the RP ID
   */
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

  // ===========================================================================
  // A PASSKEY AND NO USERNAME (#474): the sign-in screen's *Sign in with a
  // passkey* button and the username field's autofill.
  //
  // **THE ACCOUNT IS NAMED BY THE PASSKEY.** The browser is asked for any
  // discoverable credential of this RP (`allowCredentials` empty, WebAuthn
  // Level 3 section 5.4), and the authenticator answers with the credential
  // id and the `userHandle` it was created under. The handle is looked up
  // (`credentials.ownerOfUserHandle()`), and from there it is the ordinary
  // assertion: the key the credential id names among that person's PRIMARY
  // keys, section 7.2 step 6 (the handle must be the key's), the signature,
  // the challenge spent across the cluster, the counter.
  //
  // **WHAT IT DOES NOT DO, and each is a decision:**
  //
  //   * **It enrols nothing.** There is no name to enrol under; a passkey is
  //     added at `/portal/keys` or by an activation link.
  //   * **It accepts no key registered before #474.** Those were created
  //     under the username's bytes, which identify nobody here (rcbj's
  //     decision): the person is told to type their username, where that key
  //     still works, or to register it again.
  //   * **It takes no step of the pending record.** The challenge is minted
  //     on the RECORD when the screen is drawn (`passkeyChallengeFor()`),
  //     because conditional mediation starts the ceremony as the page loads,
  //     before anybody presses anything; it is single-use, taken off the
  //     record by the POST whatever the outcome, and a redrawn screen mints
  //     the next.
  //
  // **USER VERIFICATION IS REQUIRED** (`discoverableRequestOptions()`), so
  // the session is `amr ["hwk","user"]`, `acr "mfa"` — rcbj's decision on
  // #474; `webauthn_policy.ts`'s `usernamelessOffered()` argues it. Every
  // other decision about the session — the issuance policy, risk, the
  // device, the application's mechanisms, a disabled account — is
  // `startSession()`'s, ungated, which is what the passkey step after a typed
  // username already relies on.
  //
  // **A REFUSAL SAYS ONE THING** whatever failed before the account is
  // known, so the screen cannot be used to learn which handles exist; the
  // reason is in the log and the code on the response.
  // ===========================================================================
  /**
   * Says whether this sign-in screen offers a passkey sign-in with no
   * username, and why not.
   *
   * @param record - the pending sign-in
   * @returns `{ ok: true }`, or `{ ok: false, why }` marked with its code
   */
  private passkeyOffered(record) {
    const { log, webauthnPolicy, errorCodes } = this.deps;
    log.debug("Entering Authn.passkeyOffered().");
    const offered = webauthnPolicy.usernamelessOffered();
    if (!offered.ok) {
      log.debug("Leaving Authn.passkeyOffered(). The realm's settings.");
      return offered;
    }
    const restricted: string[] = Array.isArray(record.allowedMechanisms)
      ? record.allowedMechanisms : [];
    const why = record.lockedUsername
      ? 'Linking an account signs in with its password, so a passkey on ' +
        'its own is not offered here.'
      : (!this.deps.authnPolicy.allows('passkey', 'primary')
        ? 'This realm\'s authentication policy does not accept a passkey ' +
          'as a first factor.'
        : (restricted.length && restricted.indexOf('webauthn') < 0
          ? 'This application does not allow a passkey sign-in.' : ''));
    log.debug("Leaving Authn.passkeyOffered(). " + (why ? 'No.' : 'Yes.'));
    return why ? errorCodes.mark({ ok: false, why: why }, 'STS-AUTHN-0301')
               : { ok: true };
  }

  // ===========================================================================
  // A PASSKEY SIGN-IN WITH NO USERNAME, REQUIRED (#608, rcbj 2026-10-13).
  //
  // The passkey policy's `requireUsernameless` takes the username field off
  // the screen and refuses a sign-in that names somebody — but only where
  // all of these hold, and this is the one place they are asked:
  //
  //   * THE APPLICATION SIGNS IN WITH A PASSKEY ALONE: its own
  //     `appAuthnMechanism` is `webauthn` and nothing else, so the record is
  //     passwordless by the application's declaration (`mechanismSource`
  //     `application`). A relationship's `webauthn`, a demand for two factors
  //     that overrode it (`forcePasswordless` false) or a list with anything
  //     beside it is not this case: rcbj's "only webauthn selected".
  //   * A passkey with no username is OFFERED here (`passkeyOffered()`): the
  //     realm's settings, the authentication policy, not a linking sign-in.
  //     Required and not offered would be a screen that signs nobody in.
  //   * THE PROFILE THAT SELECTS THIS APPLICATION says so — chosen by the
  //     application alone (the screen knows nobody yet), read by name, so
  //     the ambient selection of some other door cannot answer it.
  //   * AND NOT A HOSTED SURFACE THROUGH `default` (rcbj): the admin
  //     console, the debugger and the portal are held to it only by a named
  //     profile that selects the application itself, so a realm-wide switch
  //     cannot change how an administrator gets in
  //     (`applications.HOSTED_SURFACE_CLIENT_IDS`).
  // ===========================================================================
  /**
   * Says whether this sign-in must be a passkey sign-in with no username.
   *
   * @param record - the pending sign-in
   * @returns true where the screen asks for no username
   */
  usernamelessRequired(record): boolean {
    const { log, passkeyPolicy } = this.deps;
    log.debug("Entering Authn.usernamelessRequired().");
    const allowed: string[] = Array.isArray(record.allowedMechanisms)
      ? record.allowedMechanisms : [];
    const passkeyAlone = !!record.forcePasswordless &&
      record.mechanismSource === 'application' &&
      record.mechanism === 'webauthn' &&
      allowed.every(function (one) {
        return one === 'webauthn';
      });
    if (!passkeyAlone || record.lockedUsername) {
      log.debug("Leaving Authn.usernamelessRequired(). The application " +
                "does not sign in with a passkey alone.");
      return false;
    }
    const application = String(record.application || '');
    let name = 'default';
    let required = false;
    try {
      name = passkeyPolicy.selectionFor('', application);
      required = passkeyPolicy.requiresUsernameless(passkeyPolicy.read(name));
    } catch (e) {
      // A policy that cannot be read requires nothing new: the screen is
      // the one it was, with its username field, and every other rule still
      // holds.
      log.debug("Caught in Authn.usernamelessRequired(): " +
                ((e && e.message) || e));
      required = false;
    }
    if (required && name === passkeyPolicy.DEFAULT_PROFILE &&
        applications.HOSTED_SURFACE_CLIENT_IDS.indexOf(application) >= 0) {
      log.debug("Leaving Authn.usernamelessRequired(). A hosted surface " +
                "under the default profile.");
      return false;
    }
    const out = required && this.passkeyOffered(record).ok;
    log.debug("Leaving Authn.usernamelessRequired(). " + (out ? 'Yes.'
                                                               : 'No.'));
    return out;
  }

  // The challenge the screen's passkey ceremony is armed with: minted on the
  // pending record when the screen is drawn and kept there until a POST
  // takes it. Persisted with the record, so any node answers the POST.
  private passkeyChallengeFor(record) {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering Authn.passkeyChallengeFor().");
    if (!record.passkeyChallenge) {
      record.passkeyChallenge = stsCrypto.randomBytes(32).toString('base64url');
      if (record.id && pending.has(record.id)) {
        pending.set(record.id, record);
      }
    }
    log.debug("Leaving Authn.passkeyChallengeFor().");
    return record.passkeyChallenge;
  }

  // The screen again, with the passkey refusal on it. `unknownId` is a
  // credential this realm holds for nobody, which the page tells the
  // credential manager about (`signalUnknownCredential()`, section 5.1.10).
  private passkeyRefused(res, base, record, code, logged, shown,
                         unknownId?) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.passkeyRefused(). " + code);
    log.info('authn: a passkey sign-in with no username was refused (' +
             code + '): ' + logged);
    // The ceremony's row (#943), where a ceremony was posted.
    this.notePasskeyCeremony(res, code);
    if (record && record.id && !pending.has(record.id) &&
        !(record.expires < Date.now())) {
      pending.set(record.id, record);
    }
    errorCodes.mark(res, code);
    // The passkey button stays; the autofill is not armed again, or an
    // authenticator that answers it unasked would loop (the script's
    // data-autofill note).
    this.screenRefused(res, record, shown,
                       { unknownCredential: unknownId || '',
                         noAutofill: true });
    log.debug("Leaving Authn.passkeyRefused().");
  }

  // A credential id this realm may tell the browser it does not know.
  // **ONLY WITH ONE TRUST REALM AND ONE CELL**: every realm answers on the
  // same host and so the same RP ID, and a credential this realm cannot
  // place may be another realm's — or, across cells, a person homed
  // elsewhere — and the signal would hide it from the person's credential
  // manager for good.
  private signalsUnknown(credentialId) {
    const { log } = this.deps;
    log.debug("Entering Authn.signalsUnknown().");
    const ok = !!credentialId && /^[A-Za-z0-9_-]{1,1400}$/.test(credentialId) &&
               !realms.active() && !cells.isMulti();
    log.debug("Leaving Authn.signalsUnknown(). " + ok);
    return ok ? credentialId : '';
  }

  /**
   * Signs a person in with a passkey and no username: the screen's button or
   * its autofill posted a discoverable credential's assertion.
   *
   * @param req - the sign-in POST
   * @param res - the response
   * @param base - the base URL
   * @param record - the pending sign-in
   * @param body - the posted form
   * @returns a promise settled when the answer is sent
   */
  private async passkeySignIn(req, res, base, record, body): Promise<void> {
    const { log, credentials, webauthnPolicy, errorCodes,
      webauthnVerifier } = this.deps;
    log.debug("Entering Authn.passkeySignIn().");
    const SAID = 'That passkey could not sign you in.';
    // The application's passkey policy until the account is known (#535).
    this.deps.passkeyPolicy.select('', record.application);
    const offered = this.passkeyOffered(record);
    if (!offered.ok) {
      log.debug("Leaving Authn.passkeySignIn(). Not offered.");
      return this.passkeyRefused(res, base, record,
        errorCodes.codeOf(offered) || 'STS-AUTHN-0301', offered.why,
        offered.why);
    }
    // THE CHALLENGE IS TAKEN NOW, whatever follows: single-use, and the
    // screen drawn next arms a new one.
    const challenge = String(record.passkeyChallenge || '');
    delete record.passkeyChallenge;
    pending.set(record.id, record);
    let credential: any = {};
    try {
      credential = JSON.parse(String(body.passkey_credential || '{}')) || {};
    } catch (e) {
      log.debug("Caught in Authn.passkeySignIn(): " +
                ((e && e.message) || e));
      log.debug("Leaving Authn.passkeySignIn(). Not JSON.");
      return this.passkeyRefused(res, base, record, 'STS-AUTHN-0021',
        'the posted credential was not JSON',
        'The browser returned something this server could not read.');
    }
    // THE CEREMONY IN HAND (#943), for its row: what was posted, and below
    // whose it is, which key, and what it signed with.
    const ceremony: any = { req: req, posted: credential, owner: '',
                            known: null, algorithm: '' };
    passkeyCeremonies.set(res, ceremony);
    if (credential.error || !credential.response) {
      // THE REAL BUTTON (the root CLAUDE.md's rule): pressed with the script
      // blocked it posts no credential, and is told why.
      log.debug("Leaving Authn.passkeySignIn(). No ceremony ran.");
      return this.passkeyRefused(res, base, record, 'STS-AUTHN-0022',
        credential.error ? 'the browser refused: ' + credential.error
                         : 'the browser ran no ceremony',
        credential.error
          ? 'Your browser did not use a passkey (' + credential.error + ').'
          : 'Your browser did not run the ceremony. Signing in with a ' +
            'passkey needs JavaScript — a passkey is used by the browser and ' +
            'no form can do it. Allow scripts for this page, or type your ' +
            'username.');
    }
    if (!challenge) {
      log.debug("Leaving Authn.passkeySignIn(). No challenge was armed.");
      return this.passkeyRefused(res, base, record, 'STS-AUTHN-0019',
        'the screen armed no challenge, or it was spent',
        'That passkey request has expired. Try again.');
    }
    const rpRefusal = this.rpIdProblem(base);
    if (rpRefusal) {
      log.debug("Leaving Authn.passkeySignIn(). The RP ID does not fit.");
      return this.passkeyRefused(res, base, record, 'STS-AUTHN-0023',
                                 rpRefusal, rpRefusal);
    }
    const credentialId = String(credential.rawId || credential.id || '');
    const handle = String(credential.response.userHandle || '');
    // WHOSE IS IT. A handle this service minted, held by a person's entry.
    const owner = credentials.ownerOfUserHandle(handle);
    // And the person's, once the handle names them (#535).
    if (owner) {
      this.deps.passkeyPolicy.select(owner, record.application);
      ceremony.owner = owner;
    }
    if (!owner) {
      // A KEY REGISTERED BEFORE #474 hands back the username's bytes. Told
      // apart from a credential nobody holds, so its holder is told to type
      // their name rather than that it is unknown — and so the credential
      // manager is not told to forget it.
      const legacyName = handle && !credentials.isUserHandle(handle)
        ? Buffer.from(handle, 'base64url').toString('utf8') : '';
      const legacy = legacyName && credentials.keysOf(legacyName)
        .some(function (one) {
          return String(one.credentialId) === credentialId && !one.userHandle;
        });
      if (legacy) {
        log.debug("Leaving Authn.passkeySignIn(). A key from before #474.");
        return this.passkeyRefused(res, base, record, 'STS-AUTHN-0304',
          'a key registered before #474 under the username',
          'This passkey was registered before passkeys could sign in ' +
          'without a username. Type your username to use it, or register ' +
          'it again at /portal/keys.');
      }
      log.debug("Leaving Authn.passkeySignIn(). The handle names nobody.");
      return this.passkeyRefused(res, base, record, 'STS-AUTHN-0302',
        handle ? 'the user handle is held by nobody in this realm'
               : 'the authenticator returned no user handle', SAID,
        handle ? this.signalsUnknown(credentialId) : '');
    }
    const picked = this.keyForAssertion(owner, 'primary', credentialId);
    if (!picked.key) {
      log.debug("Leaving Authn.passkeySignIn(). Not a primary key of theirs.");
      return this.passkeyRefused(res, base, record,
        errorCodes.codeOf(picked) || 'STS-AUTHN-0026', picked.why, SAID);
    }
    const known = picked.key;
    ceremony.known = known;
    const handled = credentials.userHandleRefusal(owner, known, handle, true);
    if (!handled.ok) {
      log.debug("Leaving Authn.passkeySignIn(). Section 7.2 step 6.");
      return this.passkeyRefused(res, base, record,
        errorCodes.codeOf(handled) || 'STS-AUTHN-0303', handled.why,
        errorCodes.codeOf(handled) === 'STS-AUTHN-0304'
          ? 'This passkey was registered before passkeys could sign in ' +
            'without a username. Type your username to use it, or ' +
            'register it again at /portal/keys.'
          : SAID);
    }
    let verdict;
    try {
      verdict = webauthnVerifier.verifyAssertion({
        authenticatorData: credential.response.authenticatorData,
        clientDataJSON: credential.response.clientDataJSON,
        signature: credential.response.signature,
        publicKeyJwk: known.publicKeyJwk,
        expectedChallenge: challenge,
        expectedOrigin: this.expectedOriginFor(base, credential),
        expectedRpId: this.rpIdOf(base),
        // REQUIRED HERE WHATEVER THE SETTING (#474): see the header.
        requireUserVerification: true,
        previousSignCount: known.signCount,
        allowInsecure: webauthnPolicy.insecureAlgorithmsAllowed()
      });
    } catch (e) {
      log.debug("Leaving Authn.passkeySignIn(). Verification threw.");
      return this.passkeyRefused(res, base, record,
        errorCodes.codeOf(e) || 'STS-AUTHN-0027',
        'verification threw: ' + ((e && e.message) || e), SAID);
    }
    if (credentials.Credentials.clonedKeyVerdict(verdict)) {
      credentials.noteKeyCloned(owner, known.credentialId,
        'signature counter ' + verdict.signCount + ', last recorded ' +
        known.signCount);
    }
    if (!verdict.ok) {
      this.noteRefusedAuthentication(record, owner, 'webauthn',
        webauthnPolicy.failureCodeFor(verdict) || 'STS-AUTHN-0027',
        'assertion-did-not-verify');
      log.debug("Leaving Authn.passkeySignIn(). The assertion did not " +
                "verify.");
      return this.passkeyRefused(res, base, record,
        webauthnPolicy.failureCodeFor(verdict),
        'the assertion did not verify — ' +
        (verdict.failed || []).join('; '), SAID);
    }
    const spent = await credentials.spendAssertion({
      username: owner, credentialId: known.credentialId,
      signCount: verdict.signCount, flags: verdict.flags,
      challenge: challenge, ttlMs: this.mfaStepTtlMs() });
    if (!spent.ok) {
      log.debug("Leaving Authn.passkeySignIn(). Not spent.");
      return this.passkeyRefused(res, base, record,
        errorCodes.codeOf(spent) || 'STS-AUTHN-0182',
        String(spent.detail || spent.reason), SAID);
    }
    // THE ATTESTATION RULES IN FORCE (#530). The account is known by now,
    // so the refusal may say why.
    const attestationRefused = await this.attestationAtSignIn(owner,
      known, record.application);
    if (attestationRefused) {
      log.debug("Leaving Authn.passkeySignIn(). The attestation rules " +
                "refused the key.");
      return this.passkeyRefused(res, base, record, attestationRefused.code,
        attestationRefused.why, attestationRefused.why);
    }
    const flags = verdict.flags || {};
    // The ceremony completed (#943): its row now, whatever the session's
    // own decision below, which writes rows of its own.
    ceremony.algorithm = String(verdict.algorithm || '');
    this.notePasskeyCeremony(res, '');
    const said = { postLoginHold: true,
                   request: req, application: String(record.application ||
                                                       ''),
      risk: await this.assessSignIn(req, owner, record.protocol,
        { application: String(record.application || ''),
          credential: { kind: 'webauthn' } }),
      credential: {
        kind: 'webauthn', id: known.credentialId,
        aaguid: known.aaguid
          ? credentials.Credentials.aaguidString(known.aaguid) : '',
        backupEligible: typeof flags.be === 'boolean' ? flags.be : undefined,
        backupState: typeof flags.bs === 'boolean' ? flags.bs : undefined,
        algorithm: String(verdict.algorithm || ''),
        coseAlg: Number(verdict.coseAlg) || undefined,
        // Its lane (#643).
        lane: credentials.keyLane(known),
        // AN ASSERTION BY A KEY WHOSE STORED ATTESTATION IS OR IS NOT
        // TRUSTED (#723): what `common/phishing_resistance.ts` reads for
        // EAP's `phr` and `phrh`.
        ceremony: 'assertion',
        attestationTrusted: !!(known.attestation &&
                               known.attestation.trusted === true) } };
    pending.delete(record.id);
    // `hwk` the key and `user` the authenticator's verification of the
    // person (RFC 8176), and acr `mfa`, because those are two factors.
    const started = this.startSession(res, owner, ['hwk', 'user'], 'mfa',
                                      record.protocol, said);
    if (this.refusedSession(res, base, record, owner, started, said)) {
      log.debug("Leaving Authn.passkeySignIn(). The session was refused.");
      return;
    }
    this.returnToCaller(res, record, null, null);
    log.debug("Leaving Authn.passkeySignIn(). " + owner + " signed in with " +
              "a passkey and no username.");
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
    // The ceremony's row (#943): verified, or refused with its code.
    this.noteStepCeremony(req, body, step, verdict.ok ? ''
      : (errorCodes.codeOf(verdict) ||
         webauthnPolicy.failureCodeFor(verdict)), verdict);

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
      this.noteRefusedAuthentication(step, step.username, 'webauthn',
        errorCodes.codeOf(verdict) ||
        webauthnPolicy.failureCodeFor(verdict),
        'assertion-did-not-verify');
      log.debug("Leaving Authn.finishWebauthn(). Refused: " +
                failed.join('; '));
      return this.stepRefused(res, 'The second factor did not verify — ' +
                              failed.join('; ') + '.');
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
    // `hwk` once: a step after a proof (#475) may already carry it.
    const amr = step.passwordless ? ['hwk'] :
                this.firstAmrOf(step).filter(function (one) {
                  return one !== 'hwk';
                }).concat(['hwk']);
    const acr = step.passwordless ? '1' : 'mfa';
    // A POST-QUANTUM PASSKEY REGISTERED AT A POST-LOGIN STEP (#1096): the
    // activity is done, and the session the step held starts as the door
    // would have started it — the amr and acr above describe the
    // registration, not the sign-in, and are not used.
    if (step.postLogin) {
      this.deps.postLogin.noteDone(step.username, step.postLogin);
      this.deps.audit.audit({
        action: 'authn.post-login.done', outcome: 'success',
        actor: step.username, target: step.username, channel: 'http',
        protocol: step.authn && step.authn.protocol,
        summary: step.username + ' registered a post-quantum passkey ' +
                 (step.postLogin.role === 'mfa' ? 'as a second factor'
                                                : 'to sign in with') +
                 ' after signing in',
        detail: { activity: String(step.postLogin.activity),
                  role: String(step.postLogin.role),
                  algorithm: String(verdict.algorithm || ''),
                  lane: String(step.lane || 'classical'),
                  profile: String(step.postLogin.profile || '') }
      });
      this.finishPostLogin(req, res, base, step);
      log.debug("Leaving Authn.finishWebauthn(). A post-login passkey " +
                "registered; the held session started.");
      return;
    }
    // A PASSKEY REGISTERED AFTER AN ACCOUNT RECOVERY (#724): NO SESSION. The
    // browser goes back to the caller, whose request asks for a sign-in, and
    // the passkey just registered is what signs the person in and completes
    // the recovery (`recoveryCompleted()`). The registration's CAEP
    // credential-change was sent where it was written.
    if (step.recovery) {
      this.deps.audit.audit({
        action: 'authn.mfa.enrolled', outcome: 'success',
        actor: step.username, target: step.username, channel: 'http',
        protocol: step.authn && step.authn.protocol,
        summary: step.username + ' registered a passkey after an account ' +
                 'recovery; nothing is signed in until it is used',
        detail: { requiredBy: 'recovery' }
      });
      this.returnToCaller(res, step.authn, null, null);
      log.debug("Leaving Authn.finishWebauthn(). A recovery passkey " +
                "registered; back to sign in with it.");
      return;
    }
    // A PROOF BEFORE AN ENROLMENT (#475): no session yet; the set-up
    // screen, offering what the application allows.
    if (step.thenEnrol && !step.passwordless) {
      this.enrolAfterProof(res, step, amr);
      log.debug("Leaving Authn.finishWebauthn(). To the set-up screen.");
      return;
    }
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
    // WHICH CEREMONY (#723): an assertion by a stored key, or a key
    // REGISTERED in this act — which EAP ACR Values 1.0 section 4 counts as
    // provisioned on the strength of whatever came before it, so it earns
    // no `phr` (`common/phishing_resistance.ts`).
    const registered = String(body.mode) === 'create';
    const flags = verdict.flags || {};
    const said = { postLoginHold: true,
                   request: req, risk: step.risk,
      application: String(step.authn.application || ''), credential: {
        kind: 'webauthn', id: answered.id || '',
        aaguid: answered.aaguid
          ? credentials.Credentials.aaguidString(answered.aaguid) : '',
        backupEligible: typeof flags.be === 'boolean' ? flags.be : undefined,
        backupState: typeof flags.bs === 'boolean' ? flags.bs : undefined,
        // THE SIGNATURE ALGORITHM THIS CEREMONY WAS VERIFIED WITH
        // (2026-10-01): the registration's or the assertion's, which is
        // the key's. On the event and the session.start row.
        algorithm: String(verdict.algorithm || ''),
        coseAlg: Number(verdict.coseAlg) || undefined,
        // AND ITS LANE (#643): the stored key's, or the step's for a key
        // just registered.
        lane: String(answered.lane || step.lane || 'classical'),
        ceremony: registered ? 'registration' : 'assertion',
        attestationTrusted: !registered && answered.attestationTrusted ===
                            true } };
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
  // IT HAD NO SCRIPT UNTIL #572, and argued it beside the passkey page,
  // which needed one: a person reads six digits off a phone and types them.
  // Since #572 every step is a page of the sign-in surface, which is a
  // script (rcbj's decision on #569: script is required), so the argument
  // is moot rather than reversed — the page is drawn by `web_authn_mfa.ts`
  // and its code is sent to `POST /authn-api/mfa/{id}/totp`.
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
      errorCodes.mark(res, errorCodes.codeOf(verdict) || 'STS-AUTHN-0105');
      this.noteRefusedAuthentication(step, step.username, 'totp',
        errorCodes.codeOf(verdict) || 'STS-AUTHN-0105',
        String(verdict.reason || 'refused'));
      log.debug('Leaving Authn.finishTotp(). Refused: ' + verdict.reason + '.');
      return this.stepRefused(res, verdict.detail);
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
    // A PROOF BEFORE AN ENROLMENT (#475): no session yet; the set-up
    // screen, offering what the application allows.
    if (step.thenEnrol) {
      this.enrolAfterProof(res, step, amr);
      log.debug('Leaving Authn.finishTotp(). To the set-up screen.');
      return;
    }
    const said = { postLoginHold: true,
                   request: req, risk: step.risk,
                   application: String(step.authn.application || ''),
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
  // IT HAD NO SCRIPT UNTIL #572, as `/authn/totp` had none; both are
  // pages of the sign-in surface since (`POST
  // /authn-api/mfa/{id}/backup-code`).
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
      errorCodes.mark(res, errorCodes.codeOf(verdict) || 'STS-AUTHN-0092');
      this.noteRefusedAuthentication(step, step.username, 'backup-code',
        errorCodes.codeOf(verdict) || 'STS-AUTHN-0092',
        String(verdict.reason || 'refused'));
      log.debug('Leaving the recovery code endpoint. Refused: ' +
                verdict.reason + '.');
      log.debug("Leaving Authn.finishBackupCode().");
      return this.stepRefused(res, verdict.detail);
    }
    // Not awaited, for finishTotp()'s reason.
    websecurity.succeededShared('mfa-code', req, step.username);
    pendingMfa.delete(mfaId);

    logArtifact('recovery code', 'as verified and spent by this server',
                { username: step.username, remaining: verdict.remaining,
                  total: verdict.total });
    // A RECOVERY CODE SPENT IS TWO RISC EVENTS (#235, rcbj's decision): the
    // set shrank, which is recovery-information-changed (section 2.10) on
    // every use and not only the last; and the code IS the recovery
    // mechanism being exercised, which is recovery-activated (2.9). Both
    // through `account_signals.ts`, so `risc.autoEmitTypes` and the opt-out
    // gate decide them as they do every other act. No mail notice: the
    // person is signing in, and nothing mailed about a code they just typed
    // was asked for.
    this.deps.accountSignals.recoveryInformationChanged({
      username: step.username, initiatingEntity: 'user', via: 'sign-in',
      reasonAdmin: step.username + ' spent a recovery code at sign-in; ' +
                   verdict.remaining + ' of ' + verdict.total + ' remain.',
      reasonUser: 'You used one of your recovery codes.' });
    this.deps.accountSignals.recoveryActivated({ username: step.username,
      initiatingEntity: 'user', via: 'sign-in', mailNotice: false,
      reasonAdmin: step.username + ' signed in with a recovery code in ' +
                   'place of their second factor.',
      reasonUser: 'You signed in with a recovery code.' });

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
    // A PROOF BEFORE AN ENROLMENT (#475): no session yet; the set-up
    // screen, offering what the application allows.
    if (step.thenEnrol) {
      this.enrolAfterProof(res, step, amr);
      log.debug('Leaving Authn.finishBackupCode(). To the set-up screen.');
      return;
    }
    const said = { postLoginHold: true,
                   request: req, risk: step.risk,
                   application: String(step.authn.application || ''),
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
  /**
   * Names the person a request's sign-on cookie belongs to, for the audit log,
   * even when the session has expired.
   *
   * @param req - the request
   * @returns the username, or ''
   */
  auditActorOf(req) {
    const { log } = this.deps;
    log.debug("Entering Authn.auditActorOf().");
    // THE ACCOUNT THE REQUEST ACTED AS (#561), with several in the browser:
    // resolved in `sessionOf()`'s order, with nothing made or swept, so a
    // row names the account the request was answered for — '' where the
    // request could not tell which (the picker's own rows say so).
    if (AccountSets.enabled() && req) {
      const resolved = this.resolveAccount(req, false);
      if (!resolved.fallback) {
        const chosen = resolved.sid
          ? this.accountSessionRead(resolved.sid).session : null;
        log.debug("Leaving Authn.auditActorOf(). The account set's.");
        return chosen && chosen.user ? String(chosen.user.username || '')
                                     : '';
      }
    }
    const found = this.cookieSession(req, SESSION_COOKIE);
    const session = found && !found.error ? found.session : null;
    if (!session) {
      log.debug("Leaving Authn.auditActorOf().");
      return '';
    }
    log.debug("Leaving Authn.auditActorOf().");
    return session.user.username;
  }

  // ===========================================================================
  // THE SIGN-IN SCREEN'S ACTS (#571): what `POST /authn/login` did, moved
  // here whole when the form's handler was deleted, and called by
  // `authn/authn_api.ts` once it has checked the operation's body, its CSRF
  // binding and its pending id. `body` is the form's fields as they were —
  // `action` among `login`, `cancel`, `anonymous`, `email-code`,
  // `email-link`, `passkey` and `certificate` (#1051), set by the
  // operation — and every answer goes
  // through `screenRefused()`, `stepAnswer()`, `returnToCaller()` or
  // `sendHome()`, which answer JSON on the API's responses.
  // ===========================================================================
  /**
   * Performs one act at the sign-in screen for a pending sign-in.
   *
   * @param req - the API's request
   * @param res - its response, marked as the API's
   * @param record - the pending sign-in
   * @param body - the act's fields, `action` naming it
   * @returns a promise settled when the answer is sent
   */
  async screenAct(req, res, record, body): Promise<void> {
    const { log, baseUrlOf, randomId, config, gate, credentials,
      websecurity, mode, errorCodes, webauthnPolicy } = this.deps;
    log.debug("Entering Authn.screenAct(). " +
              String(body.action || 'login'));
    const base = baseUrlOf(req);
    // A sentence the screen was showing belongs to the act before this one,
    // and so does #946's panel.
    delete record.screenError;
    delete record.postQuantumRequired;

    if (String(body.action || '') === 'cancel') {
      pending.delete(record.id);
      log.debug("Leaving Authn.screenAct(). The user cancelled.");
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
        claims: null,
        // Asked at the session's start (#164 phase 6).
        deviceDeferred: true
      });
      if (!anonRoleAnswer.allowed) {
        log.info('authn: the issuance policy refused an unauthenticated ' +
                 'session at ' +
                 '"' + String(record.application) + '". ' +
                 anonRoleAnswer.why);
        log.debug("Leaving Authn.screenAct(). The issuance " +
                  "policy refused the anonymous session.");
        errorCodes.mark(res, 'STS-AUTHN-0005');
        return this.screenRefused(res, record,
          anonRoleAnswer.why);
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
      // The application named (#457): an application that allows only
      // some sign-in mechanisms allows no anonymous session.
      const anonymousSaid = { request: req, authenticated: false,
                              gated: true,
                              application: String(record.application ||
                                                  '') };
      const anonymous = this.startSession(res, ANONYMOUS_USERNAME, [], '0',
                                          record.protocol, anonymousSaid);
      if (this.refusedSession(res, base, record, ANONYMOUS_USERNAME,
                              anonymous, anonymousSaid)) {
        log.debug("Leaving Authn.screenAct(). The anonymous " +
                  "session was refused.");
        return undefined;
      }
      this.returnToCaller(res, record, null, null);
      log.debug("Leaving Authn.screenAct(). An unauthenticated " +
                "session was started; back to " +
                record.returnTo + ".");
      return undefined;
    }

    // THE PERSON'S "REMEMBER THIS BROWSER" (#265), carried on the pending
    // record so that whichever step finishes the sign-in — this one or a
    // second factor's — registers the browser (refusedSession()).
    record.rememberBrowser = String(body.remember_browser || '') === '1';
    // THE CERTIFICATE ON THE CONNECTION (#1051): the certificate names the
    // account, so no username is read. See certificateSignIn().
    if (String(body.action || '') === 'certificate') {
      log.debug("Leaving Authn.screenAct(). Continuing with a certificate.");
      return this.certificateSignIn(req, res, base, record);
    }
    // A PASSKEY AND NO USERNAME (#474), before a username is asked for:
    // the passkey names the account. See passkeySignIn().
    if (String(body.action || '') === 'passkey') {
      log.debug("Leaving Authn.screenAct(). A passkey with no " +
                "username.");
      return this.passkeySignIn(req, res, base, record, body);
    }
    // A PASSKEY WITH NO USERNAME, REQUIRED (#608): the screen drew no
    // username field, and a POST naming somebody anyway is refused here —
    // the screen's shape is not what enforces it.
    if (this.usernamelessRequired(record)) {
      log.info('authn: a sign-in naming a person was refused: the passkey ' +
               'policy requires a passkey sign-in with no username for "' +
               String(record.application || '') + '".');
      log.debug("Leaving Authn.screenAct(). A username where none is " +
                "asked for.");
      errorCodes.mark(res, 'STS-AUTHN-0333');
      return this.screenRefused(res, record,
        'This application signs in with a passkey and no username. Use ' +
        'Sign in with a passkey.');
    }
    // A LOCKED RECORD'S NAME IS THE RECORD'S (#109): see
    // beginAuthentication(). Whatever was typed is not read.
    const username = record.lockedUsername ||
                     String(body.username || '').trim();
    // The only two ways to fail: no username to put in the tokens, and the
    // reserved password the rest of this mock also refuses.
    if (!username) {
      log.debug("Leaving Authn.screenAct(). No username was " +
                "entered, so the form is shown again.");
      errorCodes.mark(res, 'STS-AUTHN-0006');
      return this.screenRefused(res, record,
        'Enter a username. It does not have to exist — it is the identity ' +
        'the issued tokens will describe.');
    }
    // A POST-QUANTUM PASSKEY'S NAME IS NOT A SIGN-IN NAME (#643, rcbj): a
    // credential manager lists a person's post-quantum passkey as
    // `alice+ml-dsa` or `alice+ml-dsa-65`, and somebody who types what it
    // shows is told so rather than signed in — in development as somebody
    // new — under a name that is not theirs. Refused in every mode and
    // whether or not the realm offers the lanes; a locked record's name is
    // the record's and is not typed.
    if (!record.lockedUsername &&
        credentials.Credentials.isLaneName(username)) {
      log.info('authn: a sign-in naming "' + username + '" was refused: ' +
               'that is a passkey\'s name in a credential manager, not a ' +
               'username.');
      log.debug("Leaving Authn.screenAct(). A passkey lane's name.");
      errorCodes.mark(res, 'STS-AUTHN-0354');
      return this.screenRefused(res, record,
        'That is the name your password manager shows for a post-quantum ' +
        'passkey, not a username. Type your username without the part ' +
        'after the "+".');
    }
    // A PERSON HOMED IN ANOTHER CELL (#98 D9), before anything is verified,
    // counted or spent here: see restartAtHome(). A name nobody knows is
    // served here, as a name nobody knows always was.
    if (cells.isMulti() && !req.stsCellRelay) {
      const home = await cellRouting.homeOf(realms.currentId(), 'name',
                                            username);
      if (home && home !== cells.id() && cells.get(home)) {
        // A hard geofence refuses rather than restarting at home (D4).
        if (!cellPlacement.CellPlacement.servePermitted(realms.currentId(),
                                                        home, res)) {
          pending.delete(record.id);
          log.debug("Leaving Authn.screenAct(). Geofenced.");
          return undefined;
        }
        await this.restartAtHome(req, res, record, home);
        log.debug("Leaving Authn.screenAct(). Restarted at " +
                  "home.");
        return undefined;
      }
    }
    // ---------------------------------------------------------------------
    // AN EMAILED FIRST FACTOR (#64): the username alone, and the code or the
    // link goes to the address on that account — `authn/email_factor.ts`
    // decides everything from here, including the answer a name with no
    // verified address gets, which is the SAME page as one with one.
    const act = String(body.action || '');
    if (act === 'email-code' || act === 'email-link') {
      log.debug("Leaving Authn.screenAct(). An emailed first " +
                "factor was asked for.");
      return this.emailDoor().beginFirstFactor(req, res, base, record,
        username, act === 'email-code' ? 'code' : 'link');
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
      log.debug("Leaving Authn.screenAct(). Passwordless at a " +
                "linking sign-in.");
      errorCodes.mark(res, 'STS-AUTHN-0212');
      return this.screenRefused(res, record,
        'Linking an account signs in with its password — and its second ' +
        'factor, where it has one — so a security key on its own is not ' +
        'offered here.');
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
        log.debug("Leaving Authn.screenAct(). The security-key " +
                  "path is switched off in this realm.");
        errorCodes.mark(res, errorCodes.codeOf(allowed) || 'STS-AUTHN-0044');
        return this.screenRefused(res, record,
          allowed.why);
      }
    }

    // A caller that demanded a second factor does not get the passwordless
    // path. The checkbox is rendered disabled for this reason and THIS is the
    // check that matters: `disabled` is a property of a browser, not of an
    // HTTP request, and the whole value of acr_values and wauth is that the
    // answer cannot be chosen by whoever is answering.
    if (passwordless && record.forceMfa) {
      log.debug("Leaving Authn.screenAct(). Passwordless was " +
                "asked " +
                "for where the caller demands a second factor, so the form " +
                "is shown again.");
      errorCodes.mark(res, 'STS-AUTHN-0007');
      return this.screenRefused(res, record,
        'This request asked for a second factor, so a passkey on its own ' +
        'cannot answer it — one factor is one factor. Sign in with a ' +
        'password and the passkey together.');
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
      log.debug("Leaving Authn.screenAct(). No primary key to " +
                "sign in with, and product mode enrols none here.");
      errorCodes.mark(res, 'STS-AUTHN-0206');
      return this.screenRefused(res, record,
        'There is no passkey registered for signing in to this account. ' +
        'Sign in with your password, then add a passkey at ' +
        '/portal/keys.');
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
    // A PASSWORD AS THE FIRST FACTOR IS THE AUTHENTICATION POLICY'S TO ALLOW
    // (#64). Refused before it is checked, with the same page either way,
    // so it says nothing about the account.
    if (!passwordless &&
        !this.deps.authnPolicy.allows('password', 'primary')) {
      log.info('authn: a password sign-in for "' + username + '" was ' +
               'refused: this realm\'s authentication policy does not ' +
               'accept a password as a first factor.');
      errorCodes.mark(res, 'STS-AUTHN-0255');
      this.noteRefusedAuthentication(record, username, 'password',
        'STS-AUTHN-0255', 'password-not-a-first-factor');
      return this.screenRefused(res, record,
        'This realm does not accept a password as a first factor. Use one ' +
        'of the other ways of signing in below.');
    }

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
        log.debug("Leaving Authn.screenAct(). Rate limited.");
        errorCodes.mark(res, 'STS-AUTHN-0008');
        this.noteRefusedAuthentication(record, username, 'password',
          'STS-AUTHN-0008', String(allowed.kind || 'rate-limit'));
        return this.screenRefused(res, record, allowed.detail,
                                  { status: 429 });
      }
      // `allowPasswordReset`: this is the one door that can ask for a new
      // password, so a password flagged `pwdReset` is accepted HERE and the
      // change step below is drawn instead of a session. See credentials.js.
      // `secondFactor: 'asked-next'` (#101): this screen asks for the second
      // factor right after, so the password-only-door refusal does not
      // apply. It passes no `door`, so an app password is NEVER accepted
      // here.
      // ON LIBUV'S THREAD POOL (#756): the synchronous door held a request
      // worker for the whole scrypt (about 70 ms), a fifth of a worker under
      // a sign-in load. The answer is `verify()`'s; the rate limit above was
      // already awaited, so the await adds no interleaving that was not there.
      const credential = await credentials.verifyAsync(username,
        String(body.password || ''),
        { via: 'the sign-in screen', allowPasswordReset: true,
          secondFactor: 'asked-next' });
      if (!credential.ok) {
        log.info('authn: the sign-in for "' + username + '" was refused (' +
                 credential.reason + '): ' + credential.detail);
        log.debug("Leaving Authn.screenAct(). The credential was " +
                  "refused, so the form is shown again.");
        errorCodes.mark(res, errorCodes.codeOf(credential) ||
                             'STS-AUTHN-0054');
        // The reason token, not credential.detail and not the password.
        this.noteRefusedAuthentication(record, username, 'password',
          errorCodes.codeOf(credential) || 'STS-AUTHN-0054',
          String(credential.reason || 'refused'));
        return this.screenRefused(res, record,
          'Authentication failed for ' + username + '.');
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
          // THE PASSWORD IS COMPROMISED, AND THE CHANGE IS REQUIRED (#231):
          // RISC `credential-compromise` (`password`) and
          // `account-credential-change-required`, through the account
          // signals funnel, so `risc.autoEmitTypes` and the opt-out gate
          // hold. Sent once per demand — a person who abandons the change
          // step and signs in again with the same password is not a
          // second finding while `pwdReset` still stands.
          const alreadyRequired =
            credentials.passwordResetRequired(username);
          credentials.setPasswordResetRequired(username, true);
          breachedAtSignIn = true;
          if (!alreadyRequired) {
            this.deps.accountSignals.credentialCompromised({
              username: username, credentialType: 'password',
              initiatingEntity: 'system', via: 'sign-in',
              reasonAdmin: 'The password ' + username + ' signed in with ' +
                           'has appeared in a data breach; it must be ' +
                           'changed before the sign-in finishes.',
              reasonUser: 'The password you signed in with has appeared ' +
                          'in a data breach. Choose a new one.' });
            this.deps.accountSignals.credentialChangeRequired({
              username: username,
              reasonAdmin: 'The password of ' + username + ' has ' +
                           'appeared in a data breach and must be ' +
                           'changed.' });
          }
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
        // WHY, where the screen has a reason to give (#62 P6): the page the
        // step is drawn on says it — English, as every refusal (#539).
        notice: breachedAtSignIn
          ? 'The password you signed in with has appeared in a data ' +
            'breach, so it has to be changed now. Choose one you have ' +
            'not used anywhere else.' : '',
        expires: Date.now() + this.mfaStepTtlMs()
      });
      pendingPasswordChange.forEach(function (v, k) {
        if (v.expires < Date.now()) {
          pendingPasswordChange.delete(k);
        }
      });
      log.info('authn: "' + username + '" must change their password ' +
               'before this sign-in continues (pwdReset).');
      log.debug("Leaving Authn.screenAct(). Asking for a new " +
                "password.");
      return this.stepAnswer(res, 'password-change', 'password-change',
                             changeId, PASSWORD_CHANGE_PATH, 'change');
    }

    await this.finishPasswordSignIn(req, res, base, record, username,
                                    passwordless, secondFactor);
    log.debug("Leaving Authn.screenAct().");
    return undefined;
  }

  // THE FORCED PASSWORD CHANGE'S ACT (#571): what `POST
  // /authn/password-change` did, called by `authn/authn_api.ts` with the
  // step it found and the body it checked.
  /**
   * Stores the new password a forced change asked for and resumes the
   * sign-in.
   *
   * @param req - the API's request
   * @param res - its response, marked as the API's
   * @param changeId - the step's id
   * @param step - the step
   * @param body - `{ new_password, confirm_password }`
   * @returns a promise settled when the answer is sent
   */
  async passwordChangeAct(req, res, changeId, step, body): Promise<void> {
    const { log, baseUrlOf, credentials, audit, errorCodes } = this.deps;
    log.debug('Entering Authn.passwordChangeAct().');
    const base = baseUrlOf(req);
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
      log.debug('Leaving Authn.passwordChangeAct(). ' + problem);
      return this.passwordChangeRefused(res, problem);
    }
    // Screened against Pwned Passwords first (#62 P6).
    await require('../common/breached_passwords').screen(chosen);
    const written = credentials.setPassword(step.username, chosen,
                                            { via: 'the forced password ' +
                                                'change' });
    if (!written.ok) {
      errorCodes.mark(res, errorCodes.codeOf(written) || 'STS-AUTHN-0146');
      log.debug('Leaving Authn.passwordChangeAct(). The store refused ' +
                'it.');
      return this.passwordChangeRefused(res,
        (written.errors || []).join(' ') ||
        'The new password was not accepted.');
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
    log.debug('Leaving Authn.passwordChangeAct().');
    return undefined;
  }

  // A refusal of the new password, English (#539): the step is kept.
  /**
   * Refuses a forced password change's new password; the step is kept.
   *
   * @param res - the response
   * @param why - the sentence
   * @returns nothing
   */
  passwordChangeRefused(res, why: string): void {
    const { log } = this.deps;
    log.debug('Entering Authn.passwordChangeRefused().');
    this.answerJson(res, 400, { ok: false, next: 'refused',
                                errors: [String(why)] });
    log.debug('Leaving Authn.passwordChangeRefused().');
  }

  // ===========================================================================
  // THE SECOND-FACTOR STEPS' ACTS (#572): `/authn-api`'s operations on a
  // step, each what its page's form POST did, moved whole — the rate limits,
  // the checks, the spends, the audit rows and the session are exactly what
  // they were. What changed is the answer (`authn_api.ts` sets
  // `res.locals.authnApi` and `res.locals.authnStep`):
  //
  //   * a refusal of the step's own credential — a wrong code, a ceremony
  //     that did not verify, a rate limit — is `stepRefused()`, and the
  //     step's own page draws it, the step kept, as the page redrawn with a
  //     sentence did;
  //   * a session refused at the end (`refusedSession()`) is drawn on the
  //     SIGN-IN SCREEN: the step is spent, the pending sign-in put back, and
  //     the answer names the screen's address (`screenRefused()`);
  //   * a next step — the set-up step, the passkey ceremony after "set up a
  //     passkey" — is `stepAnswer()`'s `next: mfa`; a finished sign-in is
  //     `returnToCaller()`'s `next: redirect`, the session cookie set on
  //     that answer.
  // ===========================================================================

  // The step a code act answers, or null with the refusal sent: live, and
  // not under a demand for a key, which neither code answers.
  private codeStepOf(res: any, mfaId: string, what: string): any {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Authn.codeStepOf().");
    const step = this.mfaStepFor(mfaId);
    if (!step) {
      errorCodes.mark(res, 'STS-AUTHN-0019');
      this.stepRefused(res, 'This second-factor step has expired. Start the ' +
        'request again from the application that sent you here.');
      log.debug("Leaving Authn.codeStepOf(). The step had expired.");
      return null;
    }
    const demanded = this.keyDemandProblem(step, what);
    if (demanded) {
      errorCodes.mark(res, demanded.code);
      this.stepRefused(res, demanded.why);
      log.debug("Leaving Authn.codeStepOf(). A key was demanded.");
      return null;
    }
    log.debug("Leaving Authn.codeStepOf().");
    return step;
  }

  // ---------------------------------------------------------------------------
  // `POST /authn-api/mfa/{id}/totp` — the code, checked for real.
  //
  // **RATE LIMITED, AND THIS IS THE DOOR IN THIS SERVICE WHERE THAT MATTERS
  // MOST.** A six-digit code has a MILLION values, it is checked properly in
  // both modes, and the window forgives a step either side, so an
  // unthrottled door here is roughly a one-in-333,000 chance per attempt.
  // `security.rateLimitPerIdentity` gives it five a minute, by identity AND
  // by address, the sign-in screen's pair and for the same reason.
  //
  // **A REFUSED CODE KEEPS THE STEP**: mistyping six digits is the ordinary
  // case, and throwing away a password step that succeeded would make the
  // commonest mistake the most expensive one. The step still expires, and
  // the rate limiter bounds the attempts inside it. **SPENT ON SUCCESS AND
  // ONLY ON SUCCESS**, in the store as well as on the entry since #46
  // (`credentials.verifyTotpAsync()`).
  // ---------------------------------------------------------------------------
  /**
   * Checks a one-time code for a second-factor step and finishes it.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param body - `{ code }`
   * @returns a promise settled when the answer is sent
   */
  async mfaTotpAct(req: any, res: any, mfaId: string,
                   body: any): Promise<void> {
    const { log, baseUrlOf, websecurity, credentials, errorCodes } =
      this.deps;
    log.debug('Entering Authn.mfaTotpAct().');
    const base = baseUrlOf(req);
    const step = this.codeStepOf(res, mfaId, 'a one-time code');
    if (!step) {
      log.debug('Leaving Authn.mfaTotpAct(). Refused.');
      return;
    }
    const allowed = await websecurity.attemptShared('mfa-code', req,
                                                    step.username);
    if (!allowed.ok) {
      log.warn('authn: too many one-time code attempts for "' +
               step.username + '" (' + allowed.kind + ' bucket). Refusing ' +
               'for ' + allowed.retryAfterS + 's.');
      errorCodes.mark(res, 'STS-AUTHN-0040');
      this.stepRefused(res, allowed.detail, 429);
      log.debug('Leaving Authn.mfaTotpAct(). Rate limited.');
      return;
    }
    let verdict: any = null;
    try {
      verdict = await credentials.verifyTotpAsync(step.username,
                                                  String(body.code || ''));
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0182') + 'authn: checking a ' +
                'one-time code for "' + step.username + '" threw: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-AUTHN-0182');
      this.stepRefused(res, 'That code could not be checked. Try the next ' +
                            'one.');
      log.debug('Leaving Authn.mfaTotpAct(). It threw.');
      return;
    }
    this.finishTotp(req, res, base, mfaId, step, verdict);
    log.debug('Leaving Authn.mfaTotpAct().');
  }

  // ---------------------------------------------------------------------------
  // `POST /authn-api/mfa/{id}/backup-code` — a recovery code, checked for
  // real and SPENT. Rate limited through the same buckets as the one-time
  // code, because this door answers "is this one of your codes" and an
  // unthrottled one would let somebody walk a list at network speed. A
  // refused code keeps the step. **A FAILED SPEND IS A REFUSAL**
  // (`common/credentials.ts`): a recovery code that cannot be marked spent
  // works for ever. Asynchronous because a wrong code is compared against
  // every scrypt hash in the set, on libuv's thread pool.
  // ---------------------------------------------------------------------------
  /**
   * Checks and spends a recovery code for a second-factor step, and finishes
   * it.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param body - `{ code }`
   * @returns a promise settled when the answer is sent
   */
  async mfaBackupCodeAct(req: any, res: any, mfaId: string,
                         body: any): Promise<void> {
    const { log, baseUrlOf, websecurity, credentials, errorCodes } =
      this.deps;
    log.debug('Entering Authn.mfaBackupCodeAct().');
    const base = baseUrlOf(req);
    const step = this.codeStepOf(res, mfaId, 'a recovery code');
    if (!step) {
      log.debug('Leaving Authn.mfaBackupCodeAct(). Refused.');
      return;
    }
    const allowed = await websecurity.attemptShared('mfa-code', req,
                                                    step.username);
    if (!allowed.ok) {
      log.warn('authn: too many recovery code attempts for "' +
               step.username + '" (' + allowed.kind + ' bucket). Refusing ' +
               'for ' + allowed.retryAfterS + 's.');
      errorCodes.mark(res, 'STS-AUTHN-0042');
      this.stepRefused(res, allowed.detail, 429);
      log.debug('Leaving Authn.mfaBackupCodeAct(). Rate limited.');
      return;
    }
    let verdict: any = null;
    try {
      verdict = await credentials.verifyBackupCodeAsync(step.username,
        String(body.code || ''));
    } catch (e) {
      log.error(errorCodes.tag('STS-AUTHN-0043') + 'authn: checking a ' +
                'recovery code for "' + step.username + '" threw: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-AUTHN-0043');
      this.stepRefused(res, 'That code could not be checked. Try again.');
      log.debug('Leaving Authn.mfaBackupCodeAct(). It threw.');
      return;
    }
    this.finishBackupCode(req, res, base, mfaId, step, verdict);
    log.debug('Leaving Authn.mfaBackupCodeAct().');
  }

  // ---------------------------------------------------------------------------
  // `POST /authn-api/mfa/{id}/password` — a password after a wallet (#38's
  // follow-ups), checked with `credentials.verify()` and rate limited on the
  // sign-in bucket. `asked-next` (#101): here the password IS the second
  // factor, so the password-only-door refusal is not this door's, and there
  // is no `door`, so no app password.
  // ---------------------------------------------------------------------------
  /**
   * Checks a password as a step's second factor and finishes the step.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param body - `{ password }`
   * @returns a promise settled when the answer is sent
   */
  async mfaPasswordAct(req: any, res: any, mfaId: string,
                       body: any): Promise<void> {
    const { log, baseUrlOf, websecurity, credentials, errorCodes } =
      this.deps;
    log.debug('Entering Authn.mfaPasswordAct().');
    const found = this.stepProblem('password', mfaId);
    if (found.problem) {
      errorCodes.mark(res, found.problem.code);
      this.stepRefused(res, found.problem.why);
      log.debug('Leaving Authn.mfaPasswordAct(). No such step.');
      return;
    }
    const step = found.step;
    const allowed = await websecurity.attemptShared('sign-in', req,
                                                    step.username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0008');
      this.stepRefused(res, allowed.detail, 429);
      log.debug('Leaving Authn.mfaPasswordAct(). Rate limited.');
      return;
    }
    // On the thread pool, as the sign-in screen's check (#756).
    const credential = await credentials.verifyAsync(step.username,
      String(body.password || ''),
      { via: 'the password-factor screen', secondFactor: 'asked-next' });
    if (!credential.ok) {
      log.info('authn: the password second factor for "' + step.username +
               '" was refused (' + credential.reason + ').');
      errorCodes.mark(res, errorCodes.codeOf(credential) ||
                           'STS-AUTHN-0196');
      this.stepRefused(res, 'That password is not right.');
      log.debug('Leaving Authn.mfaPasswordAct(). Refused.');
      return;
    }
    await websecurity.succeededShared('sign-in', req, step.username);
    pendingMfa.delete(mfaId);
    const amr = this.firstAmrOf(step).concat(['pwd']);
    // A PROOF BEFORE AN ENROLMENT (#475): no session yet; the set-up step.
    if (step.thenEnrol) {
      this.enrolAfterProof(res, step, amr);
      log.debug('Leaving Authn.mfaPasswordAct(). To the set-up step.');
      return;
    }
    // The account may have been disabled after the wallet step (#62 P0).
    const said = { postLoginHold: true,
                   request: req, risk: step.risk,
                   application: String(step.authn.application || ''),
                   credential: { kind: 'password' } };
    const started = this.startSession(res, step.username, amr, 'mfa',
                                      step.authn.protocol, said);
    if (this.refusedSession(res, baseUrlOf(req), step.authn, step.username,
                            started, said)) {
      log.debug('Leaving Authn.mfaPasswordAct(). Refused.');
      return;
    }
    this.returnToCaller(res, step.authn, null, null);
    log.debug('Leaving Authn.mfaPasswordAct(). Signed in.');
  }

  // ---------------------------------------------------------------------------
  // `POST /authn-api/mfa/{id}/webauthn/options` (#572): arms the passkey
  // step's ceremony — the challenge, the RP ID, the user, the keys allowed
  // and excluded, and the policy's options — which the page carried as data
  // attributes for `/authn/webauthn.js`. Refused where the page could not be
  // drawn, and while a person has still to choose one of several passkeys
  // (#534).
  // ---------------------------------------------------------------------------
  /**
   * Arms a passkey step's ceremony.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param key - the passkey chosen (#534), or ''
   * @param lane - the lane a registration is to be made in (#643), or ''
   * @param algorithms - `classical` for the classical retry of a
   *   registration that failed on the device (#944), or ''
   * @returns nothing; the answer is sent
   */
  mfaWebauthnOptions(req: any, res: any, mfaId: string, key: string,
                     lane?: string, algorithms?: string): void {
    // `audit` from the deps (#912), as every other writer of its rows.
    const { log, baseUrlOf, errorCodes, webauthnPolicy, audit } = this.deps;
    log.debug('Entering Authn.mfaWebauthnOptions().');
    const found = this.stepProblem('webauthn', mfaId);
    if (found.problem) {
      errorCodes.mark(res, found.problem.code);
      this.stepRefused(res, found.problem.why);
      log.debug('Leaving Authn.mfaWebauthnOptions(). No step.');
      return;
    }
    // A LANE THE REALM DOES NOT OFFER (#643) is refused before the ceremony
    // is armed, as `beginKeyEnrolment()` refuses it on the portal; the write
    // asks again (`credentials.addKey()`).
    // A POST-LOGIN STEP (#1096) is armed in the activity's lane, ML-DSA
    // only: a lane or a classical retry asked for by the page is refused.
    if (found.step.postLogin && (lane || String(algorithms || '') ===
                                 'classical')) {
      errorCodes.mark(res, 'STS-AUTHN-0420');
      this.stepRefused(res, 'This step registers a post-quantum passkey ' +
                            'only; a classical one cannot be made here.');
      log.debug('Leaving Authn.mfaWebauthnOptions(). Not on a post-login ' +
                'step.');
      return;
    }
    if (lane) {
      const laneAllowed = webauthnPolicy.laneRefusal(String(lane));
      if (!laneAllowed.ok) {
        errorCodes.mark(res, errorCodes.codeOf(laneAllowed) ||
                             'STS-AUTHN-0351');
        this.stepRefused(res, laneAllowed.why);
        log.debug('Leaving Authn.mfaWebauthnOptions(). The lane is not ' +
                  'offered.');
        return;
      }
    }
    // THE CLASSICAL RETRY (#944), ASKED AT THE DOOR AND NOT ON THE PAGE: the
    // page offers it only where `classicalFallbackOffered()` says so, and a
    // body sent by hand asking for it where the realm forbids a classical
    // passkey is refused here, before any challenge is armed. Allowed, it is
    // carried on the step like the lane — `classicalOnly`, read back by the
    // registration branch for section 7.1's offered-algorithm check — and
    // the lane is the classical one while both lanes are on. An ordinary
    // request after a retry puts the step back on the realm's own list.
    const retry = String(algorithms || '') === 'classical';
    let stepLane = String(lane || '');
    if (retry) {
      this.deps.passkeyPolicy.select(String(found.step.username || ''),
        found.step.authn && found.step.authn.application);
      const retryAllowed = webauthnPolicy.classicalRetryRefusal('sign-in');
      if (!retryAllowed.ok) {
        errorCodes.mark(res, errorCodes.codeOf(retryAllowed) ||
                             'STS-AUTHN-0420');
        this.stepRefused(res, retryAllowed.why);
        log.debug('Leaving Authn.mfaWebauthnOptions(). The classical retry ' +
                  'is refused here.');
        return;
      }
      stepLane = webauthnPolicy.classicalRetryLane(
        stepLane || String(found.step.lane || ''));
    }
    if (!!found.step.classicalOnly !== retry) {
      found.step.classicalOnly = retry;
      pendingMfa.set(mfaId, found.step);
    }
    const facts = this.webauthnFacts(baseUrlOf(req), mfaId, found.step, key,
                                     stepLane);
    // NO POST-QUANTUM KEY WHERE THE PROFILE REQUIRES ONE (#718): refused
    // before the ceremony is armed, so nobody touches a key the policy
    // would refuse — and recorded as the refusal it is, a session refused.
    if (facts.postQuantumRefused) {
      const refusal = facts.postQuantumRefused;
      audit.audit({
        action: 'session.refuse', actor: String(found.step.username || ''),
        errorCode: refusal.code,
        protocol: String((found.step.authn && found.step.authn.protocol) ||
                         'OAuth 2.0 / OIDC'), channel: 'http', target: '',
        summary: 'a session for ' + String(found.step.username || '') +
                 ' was refused before the passkey step\'s ceremony: the ' +
                 'passkey policy requires a post-quantum passkey and they ' +
                 'hold none',
        detail: Object.assign(this.attemptFacts(
          found.step.authn && found.step.authn.application, 'webauthn'), {
          credential: 'webauthn'
        })
      });
      errorCodes.mark(res, refusal.code);
      this.stepRefused(res, refusal.why);
      log.debug('Leaving Authn.mfaWebauthnOptions(). No post-quantum key.');
      return;
    }
    // NO KEY THAT CAN EARN `phrh` (#739): the same, before the ceremony is
    // armed. A registration would not earn it either.
    if (facts.hardwareRefused) {
      const refusal = facts.hardwareRefused;
      audit.audit({
        action: 'session.refuse', actor: String(found.step.username || ''),
        errorCode: refusal.code,
        protocol: String((found.step.authn && found.step.authn.protocol) ||
                         'OAuth 2.0 / OIDC'), channel: 'http', target: '',
        summary: 'a session for ' + String(found.step.username || '') +
                 ' was refused before the passkey step\'s ceremony: phrh ' +
                 'was required and no held key can earn it',
        detail: Object.assign(this.attemptFacts(
          found.step.authn && found.step.authn.application, 'webauthn'), {
          credential: 'webauthn'
        })
      });
      errorCodes.mark(res, refusal.code);
      this.stepRefused(res, refusal.why);
      log.debug('Leaving Authn.mfaWebauthnOptions(). No phrh key.');
      return;
    }
    if (facts.choices.length) {
      errorCodes.mark(res, 'STS-AUTHN-0329');
      this.stepRefused(res, 'Choose one of your passkeys first.');
      log.debug('Leaving Authn.mfaWebauthnOptions(). Not chosen.');
      return;
    }
    // WHAT THIS REGISTRATION OFFERS (#940), under the profile selected for
    // the step's person and application, recorded on the step: the finish
    // holds the credential to it as well as to the list then
    // (`webauthnPolicy.heldToOffer()`), so nothing the browser posts and no
    // profile changed in between widens what was asked for.
    if (facts.mode === 'create') {
      found.step.offered = ((facts.ceremony.options || {}).algorithms || [])
        .map(Number);
      pendingMfa.set(mfaId, found.step);
    }
    this.answerJson(res, 200, Object.assign({ ok: true }, facts.ceremony));
    log.debug('Leaving Authn.mfaWebauthnOptions(). ' + facts.mode);
  }

  // ---------------------------------------------------------------------------
  // `POST /authn-api/mfa/{id}/setup/…` — THE SET-UP STEP'S ACTS (#572),
  // what `POST /authn/mfa-setup` did by its `action`:
  //
  //   * `totp` — begin an authenticator app's enrolment; the next step is
  //     this page again, drawing the secret (`next: mfa`, step `enrol-totp`);
  //   * `confirm` — the code from the app, rate limited; a session of two
  //     factors (`otp`, `mfa`) where it is right;
  //   * `webauthn` — a passkey's registration: the next step is the
  //     ordinary passkey page, the step marked for its enrolment ceremony
  //     (`atSignIn`, which `stepProblem()` honours);
  //   * `skip` — Ignore (#246), only on a step that was OFFERED: the sign-in
  //     finished on the password, as `finishPasswordSignIn()` would have.
  //
  // THE PERSON MUST STILL HOLD NOTHING, except on a step minted after a
  // proof (#475, `enrolAfterProof()`): a factor enrolled in another tab
  // since the step was minted makes this an ordinary sign-in again.
  // ---------------------------------------------------------------------------
  /**
   * An act at the second-factor set-up step.
   *
   * @param req - the request
   * @param res - the response
   * @param setupId - the step's id
   * @param action - `totp`, `confirm`, `webauthn` or `skip`
   * @param body - `{ code }` for `confirm`
   * @returns a promise settled when the answer is sent
   */
  async mfaSetupAct(req: any, res: any, setupId: string, action: string,
                    body: any): Promise<void> {
    const { log, baseUrlOf, credentials, websecurity, audit,
      errorCodes } = this.deps;
    log.debug('Entering Authn.mfaSetupAct(). ' + action);
    const base = baseUrlOf(req);
    const found = this.stepProblem('setup', setupId);
    if (found.problem) {
      errorCodes.mark(res, found.problem.code);
      this.stepRefused(res, found.problem.why);
      log.debug('Leaving Authn.mfaSetupAct(). No step.');
      return;
    }
    const step = found.step;
    // Only what the application allows (#475).
    const offered = this.enrolmentOfferedFor(step.mfaAllowed || []);
    if (!step.proved &&
        credentials.mechanismsFor(step.username).mfaRequired) {
      pendingMfa.delete(setupId);
      errorCodes.mark(res, 'STS-AUTHN-0175');
      this.stepRefused(res, 'A second factor is already set up for this ' +
        'account. Start the request again from the application that sent ' +
        'you here and sign in with it.');
      log.debug('Leaving Authn.mfaSetupAct(). They hold one now.');
      return;
    }

    // IGNORE (#246): only on a step that was OFFERED. On a required one it
    // is refused, since skipping would be the requirement not asked.
    if (action === 'skip') {
      if (!step.optional) {
        errorCodes.mark(res, 'STS-AUTHN-0270');
        this.stepRefused(res, 'A second factor is required for this ' +
                              'account; it cannot be ignored.');
        log.debug('Leaving Authn.mfaSetupAct(). Ignore on a required step.');
        return;
      }
      pendingMfa.delete(setupId);
      audit.audit({
        action: 'authn.mfa.enrolment.declined', outcome: 'success',
        actor: step.username, target: step.username, channel: 'http',
        protocol: step.authn && step.authn.protocol,
        summary: step.username + ' ignored the offer of a second factor ' +
                 'and signed in with a password',
        detail: { requiredBy: step.requiredBy || '' }
      });
      // THE PASSWORD SIGN-IN, FINISHED AS `finishPasswordSignIn()` WOULD
      // HAVE: the issuance policy was asked there, with this assessment,
      // before the offer was drawn.
      const said = { postLoginHold: true,
                     request: req, gated: true,
                     application: String(step.authn.application || ''),
                     credential: { kind: 'password' },
                     risk: step.risk,
                     riskDecision: step.riskDecision };
      const started = this.startSession(res, step.username, ['pwd'], '1',
                                        step.authn.protocol, said);
      if (this.refusedSession(res, base, step.authn, step.username, started,
                              said)) {
        log.debug('Leaving Authn.mfaSetupAct(). Refused.');
        return;
      }
      this.returnToCaller(res, step.authn, null, null);
      log.debug('Leaving Authn.mfaSetupAct(). Ignored.');
      return;
    }

    if (action === 'webauthn') {
      if (!offered.webauthn) {
        errorCodes.mark(res, 'STS-AUTHN-0175');
        this.stepRefused(res, 'Security keys cannot be set up in this ' +
                              'realm.');
        log.debug('Leaving Authn.mfaSetupAct(). Keys are off.');
        return;
      }
      // THE ORDINARY CEREMONY FROM HERE: a step asking for `webauthn` for a
      // person who holds no `mfa` key is the registration, and a verified
      // one enrols the key and starts the session exactly as the
      // security-key box does. Marked as the ceremony it was minted for, so
      // the passkey page draws its enrolment (`stepProblem()`).
      step.factor = 'webauthn';
      step.atSignIn = true;
      pendingMfa.set(setupId, step);
      this.stepAnswer(res, 'mfa', 'webauthn', setupId, WEBAUTHN_PATH, 'mfa');
      log.debug('Leaving Authn.mfaSetupAct(). The key ceremony.');
      return;
    }

    if (action === 'totp') {
      if (!offered.totp) {
        errorCodes.mark(res, 'STS-AUTHN-0175');
        this.stepRefused(res, 'Authenticator apps cannot be set up in this ' +
                              'realm.');
        log.debug('Leaving Authn.mfaSetupAct(). TOTP is off.');
        return;
      }
      const begun = credentials.beginTotpEnrolment(step.username,
                                                   { base: base });
      if (!begun.ok || !credentials.pendingTotpFor(step.username)) {
        errorCodes.mark(res, errorCodes.codeOf(begun) || 'STS-AUTHN-0176');
        this.stepRefused(res, ((begun.errors || [])[0]) ||
                              'The authenticator app could not be set up.');
        log.debug('Leaving Authn.mfaSetupAct(). Not started.');
        return;
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
      this.stepAnswer(res, 'mfa', 'enrol-totp', setupId, MFA_SETUP_PATH,
                      'mfa');
      log.debug('Leaving Authn.mfaSetupAct(). The secret.');
      return;
    }

    // confirm
    if (step.factor !== 'enrol-totp') {
      errorCodes.mark(res, 'STS-AUTHN-0174');
      this.stepRefused(res, 'Choose a second factor to set up first.');
      log.debug('Leaving Authn.mfaSetupAct(). Nothing to confirm.');
      return;
    }
    const allowed = await websecurity.attemptShared('mfa-code', req,
                                                    step.username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0040');
      this.stepRefused(res, allowed.detail, 429);
      log.debug('Leaving Authn.mfaSetupAct(). Rate limited.');
      return;
    }
    const confirmed = credentials.confirmTotpEnrolment(step.username,
      String(body.code || ''));
    if (!confirmed.ok) {
      errorCodes.mark(res, errorCodes.codeOf(confirmed) || 'STS-AUTHN-0177');
      // THE SAME SECRET IS DRAWN AGAIN: mistyping six digits must not mean
      // scanning again. An enrolment that expired meanwhile goes back to
      // the choice.
      if (!credentials.pendingTotpFor(step.username)) {
        step.factor = 'enrol';
        pendingMfa.set(setupId, step);
        this.stepRefused(res, 'That set-up expired before it was ' +
                              'confirmed. Start it again.');
      } else {
        this.stepRefused(res, (confirmed.errors ||
                               ['That code is not right.'])[0]);
      }
      log.debug('Leaving Authn.mfaSetupAct(). Not confirmed.');
      return;
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
    // app enrolled a moment ago. `otp` once: a step after a proof (#475) may
    // already carry it.
    const said = { postLoginHold: true,
                   request: req, risk: step.risk,
                   application: String(step.authn.application || ''),
                   credential: { kind: 'totp' } };
    const started = this.startSession(res, step.username,
      this.firstAmrOf(step).filter(function (one) {
        return one !== 'otp';
      }).concat(['otp']), 'mfa', step.authn.protocol, said);
    if (this.refusedSession(res, base, step.authn, step.username, started,
                            said)) {
      log.debug('Leaving Authn.mfaSetupAct(). Refused.');
      return;
    }
    this.returnToCaller(res, step.authn, null, null);
    log.debug('Leaving Authn.mfaSetupAct(). Signed in.');
  }

  // ---------------------------------------------------------------------------
  // `POST /authn-api/mfa/{id}/webauthn` (#572): the passkey step's ceremony
  // result, verified — what `POST /authn/webauthn` did, moved whole. A
  // refusal is the step's own page again with the check that failed named;
  // a verified ceremony enrols the key or spends the assertion and finishes
  // the step (`finishWebauthn()`).
  //
  // **WHETHER IT IS A REGISTRATION IS THE STEP'S, NOT THE BODY'S** since
  // #572: the form carried `mode`, which the page had computed from the keys
  // the person held; it is computed here the same way
  // (`webauthnFacts()`), so a caller cannot ask for an enrolment the page
  // would not have drawn. `stepProblem()` refuses the enrolment ceremony to
  // a step not minted for it, as the page's GET always did.
  // ---------------------------------------------------------------------------
  /**
   * Verifies a passkey step's ceremony result and finishes the step.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param posted - `{ credential }`, the ceremony's JSON form
   * @returns nothing; the answer is sent
   */
  mfaWebauthnAct(req: any, res: any, mfaId: string, posted: any): any {
    const { log, baseUrlOf, errorCodes, credentials, stats, mode,
      webauthnVerifier, webauthnPolicy } = this.deps;
    const self = this;
    log.debug("Entering Authn.mfaWebauthnAct().");
    const base = baseUrlOf(req);
    const found = this.stepProblem('webauthn', mfaId);
    if (found.problem) {
      errorCodes.mark(res, found.problem.code);
      this.stepRefused(res, found.problem.why);
      log.debug("Leaving Authn.mfaWebauthnAct(). No step.");
      return undefined;
    }
    const step = found.step;
    const facts = this.webauthnFacts(base, mfaId, step, '');
    const body: any = { mfa_id: mfaId, mode: facts.mode,
                   credential: posted && posted.credential };
    let credential;
    try {
      credential = JSON.parse(String(body.credential || '{}'));
    } catch (e) {
      log.debug("Caught in a callback in module scope: " +
                ((e && e.message) || e));
      log.debug("Leaving Authn.mfaWebauthnAct(). The posted credential was " +
                "not JSON.");
      errorCodes.mark(res, 'STS-AUTHN-0021');
      return this.stepRefused(res, 'The browser returned something this ' +
                                   'server could not read.');
    }
    // What was posted, for the ceremony's row (#943): its transports,
    // attachment and the browser's error name, nothing else.
    body.posted = credential;
    if (!credential.error && !credential.response) {
      // THE REAL BUTTON UNDER THE SCRIPT (#470): pressed with the script
      // blocked, it posts the step with no credential. Answered as the
      // portal answers it, rather than as a registration that "could not
      // be checked".
      log.debug("Leaving Authn.mfaWebauthnAct(). No ceremony ran.");
      errorCodes.mark(res, 'STS-AUTHN-0022');
      return this.stepRefused(res, 'Your browser did not run the ceremony. ' +
        'This step needs JavaScript — a passkey is used by the browser and ' +
        'no form can do it. Allow scripts for this page and try again.');
    }
    if (credential.error) {
      // The browser refused the ceremony. Its error is deliberately ambiguous
      // — no credential, declined, and timed out are one error — so report it
      // as given rather than guessing which happened.
      log.debug("Leaving Authn.mfaWebauthnAct(). The browser refused: " +
                credential.error);
      errorCodes.mark(res, 'STS-AUTHN-0022');
      // THE BROWSER'S ERROR NAME ON THE CEREMONY'S ROW (#943), as the
      // page's script reported it; never its message.
      this.noteStepCeremony(req, body, step, 'STS-AUTHN-0022');
      return this.stepRefused(res, credential.error +
        ' (WebAuthn reports one error for ' +
        'several situations, so this does not say which.)');
    }

    // THE RP ID MUST FIT, IN PRODUCT MODE, BEFORE ANYTHING IS VERIFIED. See
    // rpIdProblem(): the fallback to the request's host is a development
    // convenience and not something a deployment's ceremony may rest on.
    const rpRefusal = this.rpIdProblem(base);
    if (rpRefusal) {
      log.warn('authn: a WebAuthn ceremony for "' + step.username + '" was ' +
               'REFUSED. ' + rpRefusal);
      log.debug("Leaving Authn.mfaWebauthnAct(). The RP ID does not fit.");
      errorCodes.mark(res, 'STS-AUTHN-0023');
      this.noteStepCeremony(req, body, step, 'STS-AUTHN-0023');
      return this.stepRefused(res, rpRefusal);
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
          log.debug("Leaving Authn.mfaWebauthnAct(). Enrolment is switched " +
                    "off.");
          errorCodes.mark(res, 'STS-AUTHN-0044');
          this.noteStepCeremony(req, body, step, 'STS-AUTHN-0044');
          return this.stepRefused(res, 'Passkeys are switched off in this ' +
            'realm (webauthn.enabled), so a new one cannot be registered ' +
            'here. A passkey already registered goes on working.');
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
          // of the pubKeyCredParams this realm offered (#105), in the lane
          // the ceremony was armed in (#643).
          // The classical retry's list where the step was armed for one
          // (#944), so a credential the retry did not ask for is refused
          // by the same check.
          // And no wider than what the options offered under the step's
          // passkey profile (#940), recorded when they were armed.
          expectedAlgorithms: webauthnPolicy.heldToOffer(
            webauthnPolicy.algorithmIds(step.lane || 'classical',
                                        !!step.classicalOnly),
            step.offered)
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
          // A POST-LOGIN STEP (#1096) IS THE EXCEPTION: it is minted only
          // after the person has authenticated in full, so its
          // registration is not one on a passwordless path that proved
          // nothing.
          if (step.passwordless && !step.postLogin &&
              !mode.enrolsKeysOnFirstUse()) {
            log.info('authn: product mode, so a primary security key was ' +
                     'NOT enrolled for "' + step.username + '" at the ' +
                     'sign-in screen.');
            verdict = errorCodes.mark({ ok: false,
                        why: 'This service is in product mode, where a ' +
                             'passkey that signs in on its own is added ' +
                             'at /portal/keys after signing in, never at ' +
                             'the sign-in screen.' },
                        'STS-AUTHN-0206');
          } else if (!mode.autoCreates() &&
                     !this.knownPerson(step.username)) {
            log.info('authn: product mode, so a WebAuthn key was NOT ' +
                     'enrolled for "' + step.username + '" — there is no ' +
                     'directory entry for them and enrolling would create ' +
                     'one.');
            verdict = errorCodes.mark({ ok: false,
                        why: 'This service is in product mode, where a ' +
                             'passkey can only be registered for ' +
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
              // NO LABEL (#470): the key takes its provider's name or its
              // group's (`credentials.defaultKeyName()`), and its owner
              // renames it on `/portal/keys`.
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
              // CTAP 2.1's minPinLength, as the key reported it (#529).
              minPinLength: credentials.Credentials.reportedMinPinLength(
                verdict),
              // The handle the page created it under (#474), and the lane
              // the step was armed in (#643).
              userHandle: step.userHandle || undefined,
              lane: String(step.lane || 'classical'),
              userVerified: !!(verdict.flags && verdict.flags.uv),
              aaguid: verdict.aaguid || null,
              algorithm: verdict.algorithm || null,
              coseAlg: verdict.coseAlg || null,
              // #470: what the passkey pages group and describe it by.
              backupEligible: !!(verdict.flags && verdict.flags.be),
              backupState: !!(verdict.flags && verdict.flags.bs),
              transports: credentials.transportsOf(credential)
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
        // `allowCredentials` IS A HINT (#739). A sign-in that must earn
        // `phrh` named only the keys whose record can; an assertion that
        // names some other key of the role is the same refusal, here,
        // rather than a session the authorization endpoint then rejects.
        if (String((step.authn || {}).phishingClass || '') === 'phrh') {
          const leaf = require('../common/phishing_resistance');
          if (!leaf.storedKeyEarnsHardware(known)) {
            throw errorCodes.mark(new Error(
              'This sign-in asks for a hardware-protected ' +
              'phishing-resistant passkey, and the passkey that answered ' +
              'cannot earn it.'), 'STS-AUTHN-0459');
          }
        }
        // WEBAUTHN LEVEL 3 SECTION 7.2 STEP 6 (#474): a `userHandle` the
        // authenticator returned must be the one this key was created
        // under. The username was typed, so its absence is allowed.
        const handled = credentials.userHandleRefusal(step.username, known,
          String((credential.response || {}).userHandle || ''), false);
        if (!handled.ok) {
          throw errorCodes.mark(new Error(handled.why),
                                errorCodes.codeOf(handled));
        }
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
          previousSignCount: known.signCount,
          // RS1 only where `webauthn.insecureAlgorithms` allows it
          // (2026-10-01).
          allowInsecure: webauthnPolicy.insecureAlgorithmsAllowed()
        });
        // A CLONE, BY THE ENTRY'S COUNTER (#231): everything else verified
        // and the counter did not go up. Refused below like any failed
        // check; `noteKeyCloned()` tells RISC and risk scoring.
        if (credentials.Credentials.clonedKeyVerdict(verdict)) {
          credentials.noteKeyCloned(step.username, known.credentialId,
            'signature counter ' + verdict.signCount + ', last recorded ' +
            known.signCount);
        }
        if (verdict.ok) {
          // WHICH KEY ANSWERED, for the authentication event (#62 P0): the
          // stored record, since the assertion names itself only by id.
          verdict.answeredBy = { id: known.credentialId,
                                 aaguid: known.aaguid || null,
                                 lane: credentials.keyLane(known),
                                 // Whether the key's stored statement is
                                 // trusted, for EAP's `phrh` (#723).
                                 attestationTrusted: !!(known.attestation &&
                                   known.attestation.trusted === true) };
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
                      flags: verdict.flags,
                      challenge: step.challenge,
                      ttlMs: this.mfaStepTtlMs() };
        }
      }
    } catch (e) {
      log.debug("Leaving Authn.mfaWebauthnAct(). Verification threw: " +
                e.message);
      errorCodes.mark(res, errorCodes.codeOf(e) || 'STS-AUTHN-0027');
      this.noteStepCeremony(req, body, step,
                            errorCodes.codeOf(e) || 'STS-AUTHN-0027');
      return this.stepRefused(res, 'The second factor could not be ' +
                                   'checked: ' + e.message);
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
                                        why: attested.why,
                                        // For the ceremony's row (#943).
                                        algorithm: verdict.algorithm },
                                      errorCodes.codeOf(attested) ||
                                      'STS-AUTHN-0241');
            return null;
          }
          toRegister.record.attestation = attested.attestation;
          // Who made or holds it (#470): MDS where a BLOB is loaded.
          return credentials.keyProviderFor(toRegister.record.aaguid,
            attested.attestation).then(function (named) {
            toRegister.record.provider = named.provider;
            toRegister.record.providerSource = named.providerSource;
            return credentials.addKeyClaimed(toRegister.username,
                                             toRegister.record,
                                             toRegister.role);
          });
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
                                      why: (stored.errors || []).join(' '),
                                      // For the ceremony's row (#943).
                                      algorithm: verdict.algorithm },
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
        self.stepRefused(res, 'The passkey could not be recorded. Try again.');
      });
      log.debug("Leaving Authn.mfaWebauthnAct(). Writing the registration.");
      return undefined;
    }
    if (!toSpend) {
      log.debug("Leaving Authn.mfaWebauthnAct(). Nothing to spend.");
      return this.finishWebauthn(req, res, base, body, step, verdict);
    }
    credentials.spendAssertion(toSpend).then(function (spent) {
      // THE ATTESTATION RULES IN FORCE (#530), asked once the assertion is
      // spent and before the session: a refusal reaches the same page as
      // every failed check, naming why.
      if (!spent.ok) {
        return spent;
      }
      const heldKey = credentials.keysOf(step.username).filter(
        function (one) {
          return String(one.credentialId) === String(toSpend.credentialId);
        })[0] || null;
      return self.attestationAtSignIn(step.username, heldKey,
        step.authn && step.authn.application)
        .then(function (refused) {
          return refused ? Object.assign({}, spent, { attestation:
                                                       refused })
                         : spent;
        });
    }).then(function (spent) {
      if (spent.attestation) {
        verdict = errorCodes.mark({ ok: false, checks: verdict.checks,
                                    failed: [spent.attestation.why] },
                                  spent.attestation.code);
      } else if (!spent.ok) {
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
      self.stepRefused(res, 'The second factor could not be checked. Try ' +
                            'again.');
    });
    log.debug("Leaving Authn.mfaWebauthnAct(). Spending the assertion.");
    return undefined;
  }

  // The routes, in the order they were always registered (rule 1). Called by
  // `common/protocol_stack.ts` through the module's `registerRoutes(app)`.
  /**
   * Registers the `/authn/*` routes on the shared app, in their order.
   *
   * @param app - the express app
   */
  registerRoutes(app: AppModule) {
    const { log, baseUrlOf, randomId, parseBody, oauthError, stats, config,
      gate, credentials, websecurity, mode, validation, audit, errorCodes,
      webauthnVerifier, webauthnPolicy } = this.deps;
    const self = this;
    log.debug("Entering Authn.registerRoutes().");

    // -----------------------------------------------------------------------
    // AN ACCOUNT SELECTION TICKET IS TAKEN OFF EVERY REQUEST FIRST (#561),
    // before any route below reads the query — so a relying party never
    // sees it and a SAML redirect binding's signed query is the one it
    // signed — and spent (`spendAccountTicket()`). With
    // `authn.multipleAccounts` off nothing is touched. A failure here costs
    // the selection, never the request.
    // -----------------------------------------------------------------------
    app.use((req, res, next) => {
      try {
        this.spendAccountTicket(req);
      } catch (e) {
        log.error(errorCodes.tag('STS-AUTHN-0344') + 'authn: an account ' +
                  'selection ticket could not be read: ' +
                  ((e && e.message) || e));
      }
      next();
    });

    app.use((req, res, next) => {
      // A session read that failed is not a missing cookie. Nothing below
      // may mint a replacement arrival, and the cookie stays.
      if (this.windowOn()) {
        const found = this.cookieSession(req, SESSION_COOKIE);
        if (found && found.error) {
          this.refuseUnread(res);
          return;
        }
      }
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
      const usable = this.refreshPartners(record);
      if (usable < 2) {
        log.info('authn: the chooser was asked for ' + record.id + ' and "' +
                 (record.application || '(none)') + '" now names ' +
                 usable +
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
      // THE SHELL (#571): the browser asks `/authn-api` for the partners.
      this.signInShell(req, res, String(record.application || ''));
      log.debug("Leaving the federation chooser. Offered " + usable +
                " partner(s) for " + record.id + ".");
    });

    // THE ACCOUNT PICKER (#561), a shell like the chooser's: the browser asks
    // `GET /authn-api/pending/{id}/accounts` for the accounts. Refused
    // where the setting is off or the sign-in is not waiting on a choice.
    app.get(ACCOUNTS_PATH, (req, res) => {
      log.debug("Entering the account picker.");
      const asked = validation.check(req, 'query', PENDING_ID_QUERY);
      if (!asked.ok) {
        errorCodes.mark(res, 'STS-AUTHN-0001');
        return this.refuseInvalid(res, asked);
      }
      const record = AccountSets.enabled()
        ? this.pendingForAccounts(asked.value.authn) : null;
      if (!record) {
        log.debug("Leaving the account picker. Nothing waits on a choice.");
        errorCodes.mark(res, AccountSets.enabled() ? 'STS-AUTHN-0003'
                                                   : 'STS-AUTHN-0343');
        return oauthError(res, 400, 'invalid_request',
          'There is no sign-in waiting under that id, or it has expired. ' +
          'Start the request again from the application that sent you here.');
      }
      this.signInShell(req, res, String(record.application || ''));
      log.debug("Leaving the account picker.");
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
      // THE SHELL (#571): the browser asks `/authn-api` for the view, which
      // carries the configuration's problems (`screenProblem()`).
      this.signInShell(req, res, String(record.application || ''));
      log.debug("Leaving the authentication screen. The shell for " +
                record.id + ".");
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
      log.debug('Leaving the password change screen. The shell.');
      // THE SHELL (#571): the browser asks `/authn-api` for the step.
      return this.signInShell(req, res,
                              String((step.authn &&
                                      step.authn.application) || ''));
    });

    // THE LANGUAGE CHOOSER (#539). A POST, from a real form on every
    // user-facing page, so it works with script blocked. It sets the
    // chooser's cookie, writes a signed-in person's own preferredLanguage —
    // which outranks the cookie, so a choice that did not reach the entry
    // would change nothing for them — and sends the browser back with a 303
    // to a LOCAL path (`PageLocale.safeReturn()`), never to one a request
    // named elsewhere. No CSRF token: the session cookie is SameSite=Lax, so a
    // cross-site POST carries no session and writes no entry, and a cookie
    // choosing a language is not worth defending. A tag no catalog answers
    // is refused in English (rcbj's decision on #539: errors stay English).
    app.post(LANGUAGE_PATH, (req, res) => {
      log.debug('Entering the language chooser endpoint.');
      const posted = validation.checkParsed(parseBody(req), 'body',
                                            LANGUAGE_FORM);
      if (!posted.ok) {
        errorCodes.mark(res, 'STS-I18N-0008');
        log.debug('Leaving the language chooser endpoint. Invalid.');
        return this.refuseInvalid(res, posted);
      }
      const tag = i18n.canonical(posted.value.lang);
      if (!tag || !i18n.answers(tag)) {
        errorCodes.mark(res, 'STS-I18N-0008');
        log.debug('Leaving the language chooser endpoint. Not offered.');
        return res.status(400).type('text/plain').send('"' +
          String(posted.value.lang || '').slice(0, 64) + '" is not a ' +
          'language this service has a catalog for.');
      }
      res.append('Set-Cookie', PageLocale.cookieLine(tag));
      const session = this.sessionOf(req);
      if (session && session.user && session.authenticated !== false &&
          session.user.username) {
        const who = String(session.user.username);
        let written: any = null;
        try {
          written = require('../ldap/person_editor').update(who,
            { attribute: 'preferredLanguage', mode: 'set', value: tag },
            { actor: who, via: 'the language chooser' });
        } catch (e) {
          log.debug('Caught in the language chooser endpoint: ' +
                    ((e && e.message) || e));
          written = null;
        }
        if (!written || !written.ok) {
          // The cookie still carries the choice, and a page drawn for this
          // person reads their entry first: said in the log, not refused.
          log.warn(errorCodes.tag('STS-I18N-0009') + 'authn: the language ' +
                   'chooser could not write preferredLanguage=' + tag +
                   ' for "' + who + '": ' + ((written && (written.errors ||
                   []).join(' ')) || 'the person editor could not be ' +
                   'asked') + '.');
        }
      }
      log.debug('Leaving the language chooser endpoint. ' + tag);
      return res.redirect(303, PageLocale.safeReturn(posted.value.return));
    });


    // -------------------------------------------------------------------------
    // THE SECOND-FACTOR STEPS' PAGES (#572): each answers the sign-in
    // surface's shell, and the browser draws the page from `GET
    // /authn-api/mfa/{id}?page=` and sends its acts there; the form POSTs
    // are gone. Each GET still refuses what it always refused before it
    // drew anything (`stepProblem()`) — an expired step, a code page for
    // somebody with no app, a passkey page for somebody with no key of the
    // step's role — with the 400 it always answered, so a hand-made address
    // is not a way to find out whether a sign-in is in progress.
    // -------------------------------------------------------------------------
    Object.keys(STEP_PAGES).forEach(function (page) {
      const path = STEP_PAGES[page];
      app.get(path, (req, res) => {
        log.debug('Entering the ' + page + ' step\'s shell.');
        const asked = validation.check(req, 'query', MFA_STEP_QUERY);
        if (!asked.ok) {
          errorCodes.mark(res, page === 'setup' ? 'STS-AUTHN-0174'
                                                : 'STS-AUTHN-0018');
          log.debug('Leaving the ' + page + ' step\'s shell. Bad shape.');
          return self.refuseInvalid(res, asked);
        }
        const found = self.stepProblem(page, String(asked.value.mfa || ''));
        if (found.problem) {
          errorCodes.mark(res, found.problem.code);
          log.debug('Leaving the ' + page + ' step\'s shell. Refused.');
          // error-code: none — marked above, stepProblem()'s code
          return oauthError(res, 400, 'invalid_request', found.problem.why);
        }
        // In product mode an RP ID that does not fit is RECORDED here, as
        // the page's GET always did; the view says it on the page.
        if (page === 'webauthn' && self.rpIdProblem(baseUrlOf(req))) {
          errorCodes.mark(res, 'STS-AUTHN-0023');
        }
        log.debug('Leaving the ' + page + ' step\'s shell.');
        return self.signInShell(req, res, String((found.step.authn &&
          found.step.authn.application) || ''));
      });
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

    // THE SIGN-IN SURFACE'S SCRIPT (#571): brotli, gzip or neither, by the
    // request's Accept-Encoding, from the build's precompressed files.
    app.get(SIGNIN_SCRIPT_PATH, (req, res) => {
      log.debug("Entering the sign-in surface's script.");
      ShellDocument.sendFile(req, res, this.signInBundle(),
                             'application/javascript');
      log.debug("Leaving the sign-in surface's script.");
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

// The facade is a plain object the checker sees as a Map, so forEach is
// typed read-only. Replacing it is what a caller that still walks
// authn.sessions does while the window is on: the realm Map is unflushed
// rows, and the walk has to page the index. A resident walk uses
// realmMap(), which is the Map and not this function.
(sessions as any).forEach = function (fn, thisArg) {
  return slot.get().forEachSession(fn, thisArg);
};

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
            'passed, and, in each realm, at most that realm\'s ' +
            'authn.sessionShedPerSweep of one subject\'s own surplus ' +
            'sessions.',
  owner: 'authn/authn.ts',
  everySetting: SESSION_SWEEP_SETTING,
  everySettingUnit: 's',
  run: function (): any {
    return { ended: slot.get().sweepExpiredSessions() };
  }
});

// ---------------------------------------------------------------------------
// THE ACCOUNT SETS' CLEAN-UP, AS A SCHEDULER JOB (#561), beside the session
// expiry: in each realm, every browser's account set is brought up to date —
// a session that ended moves to remembered, a remembered account older than
// `authn.rememberedAccountDays` is dropped — and a set left empty is
// deleted. A CLUSTER job run per realm, so the store it walks is the
// realm's; a pass about hourly, spread over the hour since #784 (a run a
// minute, a second's work each), because nothing waits on it: a set is
// pruned again whenever its browser draws the picker, and a remembered
// account past its days is only an extra row there until the next pass.
// ---------------------------------------------------------------------------
scheduler.register({
  id: ACCOUNT_SET_EXPIRY_JOB,
  title: 'Account set expiry',
  describe: 'Brings every browser\'s account set up to date (#561): an ' +
            'account whose session ended is remembered as signed out, one ' +
            'remembered longer than authn.rememberedAccountDays is dropped, ' +
            'and an empty set is deleted.',
  owner: 'authn/authn.ts',
  scope: 'realm',
  // EVERY MINUTE, A SECOND'S WORK EACH (#784): a pass over every set still
  // takes about an hour, spread over it. See AccountSets.sweepBudgeted().
  everyMs: function (): number {
    return 60 * 1000;
  },
  run: function (): any {
    return slot.get().sweepAccountSetsBudgeted();
  }
});

// A realm's removal ends its sessions first and waits for what that sends
// (#232; `realms.retire()`). Registered here, at 8 in the require order, so it
// runs before the directory's and Shared Signals' hooks: the sessions end
// before the people are purged and the streams are closed.
realms.onRetire({
  name: 'authn',
  announce: function (id: string, ctx: any): void {
    slot.get().retireRealmSessions(id, ctx);
  },
  deliver: function (id: string, ctx: any): Promise<void> {
    return slot.get().settleRealmEnds(id, ctx);
  }
});

// ---------------------------------------------------------------------------
// What the rest of this service uses.
//
// `sessions` is handed out rather than copied because the admin console reports
// on the live store; `startSession` / `endSession` are functions rather than
// four lines repeated per call site for the reason written above them.
// ---------------------------------------------------------------------------

/**
 * The authentication service: the sign-in screen, the second factors and the
 * sign-on session every protocol reads.
 *
 * The functions forward to the instance the composition root installs.
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  Authn: Authn,
  /**
   * Installs the instance the composition root built.
   *
   * @param instance - the instance
   */
  installInstance: (instance: Authn): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   *
   * @returns the slot's origin
   */
  instanceOrigin: (): string => slot.origin(),
  // What two nodes' copies of one session become, for
  // `tests/cluster_lww_stores.js` — the merge is declared on the store and
  // the store is reached through the persistence layer, so the rule itself is
  // asserted here directly.
  mergeSessionRows: slot.forward('mergeSessionRows'),
  noteSessionChanged: slot.forward('noteSessionChanged'),
  LOGIN_PATH: LOGIN_PATH,
  MFA_SETUP_PATH: MFA_SETUP_PATH,
  POST_LOGIN_PATH: POST_LOGIN_PATH,
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
  // A session's binding to a browser key (#725), for the session rows the
  // sign-out and the console draw.
  deviceBindingOf: deviceBound.bindingOf,
  registeredDeviceOf: slot.forward('registeredDeviceOf'),
  cookieSession: slot.forward('cookieSession'),
  MAX_SESSION_EVENTS: MAX_SESSION_EVENTS,
  startArrivalSession: slot.forward('startArrivalSession'),
  ANONYMOUS_USERNAME: ANONYMOUS_USERNAME,
  sessions: sessions,
  cookiesOf: slot.forward('cookiesOf'),
  sessionOf: slot.forward('sessionOf'),
  // SEVERAL ACCOUNTS IN ONE BROWSER (#561): `authn/CLAUDE.md`, *Several
  // signed-in accounts in one browser*, has each one's contract.
  hintAccount: slot.forward('hintAccount'),
  accountSessionsOf: slot.forward('accountSessionsOf'),
  refuseAccountsUnread: slot.forward('refuseAccountsUnread'),
  bindingSessionOf: slot.forward('bindingSessionOf'),
  sessionCookieNames: slot.forward('sessionCookieNames'),
  afterAccountSignOut: slot.forward('afterAccountSignOut'),
  hintAccountKey: slot.forward('hintAccountKey'),
  signedInAccounts: slot.forward('signedInAccounts'),
  accountChoiceNeeded: slot.forward('accountChoiceNeeded'),
  accountTicketFor: slot.forward('accountTicketFor'),
  spendAccountTicket: slot.forward('spendAccountTicket'),
  noteAccountAmbiguous: slot.forward('noteAccountAmbiguous'),
  browserAccounts: slot.forward('browserAccounts'),
  pendingForAccounts: slot.forward('pendingForAccounts'),
  accountsView: slot.forward('accountsView'),
  accountsAct: slot.forward('accountsAct'),
  sweepAccountSets: slot.forward('sweepAccountSets'),
  sweepAccountSetsInSlices: slot.forward('sweepAccountSetsInSlices'),
  sweepAccountSetsBudgeted: slot.forward('sweepAccountSetsBudgeted'),
  auditActorSessionOf: slot.forward('auditActorSessionOf'),
  ACCOUNTS_PATH: ACCOUNTS_PATH,
  multipleAccounts: AccountSets.enabled,
  ACCOUNT_SET_COOKIE: AccountSets.COOKIE,
  ACCOUNT_TICKET_PARAM: AccountSets.TICKET_PARAM,
  accountSetCookieName: AccountSets.cookieName,
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
  // And the one exception, which starts from a session the code flow already
  // made (2026-09-30): the portal adopting a live console session.
  adoptRelyingPartySession: slot.forward('adoptRelyingPartySession'),
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
  holdPresentation: slot.forward('holdPresentation'),
  // The three the protocol-independent logout needs, and the reason each is
  // here rather than reimplemented over there: /logout ends sessions it was not
  // handed a cookie for, so it names them by id — and every one of them still
  // has to go through dropSession(), which is where the RFC 9700 refresh
  // revocation and the one `session.end` audit row live. A second delete
  // somewhere else would be a sign-out that revoked nothing and logged nothing,
  // and it would look exactly like this one from the outside.
  sessionsOf: slot.forward('sessionsOf'),
  // A partner sign-out's question: which sessions carry this relationship.
  // The sealed fedPartnerSession is still the object the caller matches.
  sessionsForRelationship: slot.forward('sessionsForRelationship'),
  // The SAML 2.0 attribute authority's question (#189): which live session
  // gave a service provider a NameID.
  sessionsMatching: slot.forward('sessionsMatching'),
  liveSessionCountsAsync: slot.forward('liveSessionCountsAsync'),
  liveSessionPageAsync: slot.forward('liveSessionPageAsync'),
  sessionWindowOn: slot.forward('sessionWindowOn'),
  sessionsHeldUnder: slot.forward('sessionsHeldUnder'),
  sessionById: slot.forward('sessionById'),
  warmSessionAsync: slot.forward('warmSessionAsync'),
  // Who vouched for a session's latest sign-in — asked by the authorization
  // endpoint for the bootstrap administrator's claim at issuance (#446).
  latestAuthorityOf: slot.forward('latestAuthorityOf'),
  // Whether a removed credential authenticated a session (#722), for
  // `logout/logout.ts`'s `endFactorSessions()`.
  sessionNamesFactor: slot.forward('sessionNamesFactor'),
  endSessionById: slot.forward('endSessionById'),
  afterSignIn: slot.forward('afterSignIn'),
  endEverySessionIn: slot.forward('endEverySessionIn'),
  pendingEndReports: slot.forward('pendingEndReports'),
  clearSessionCookie: slot.forward('clearSessionCookie'),
  beginAuthentication: slot.forward('beginAuthentication'),
  /**
   * Forwards to `Authn.restartPendingAtHome()`: restarts a pending sign-in's
   * flow at the person's home cell (#98 D9).
   */
  restartPendingAtHome: slot.forward('restartPendingAtHome'),
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
  // The sign-in surface's bundle (#571), which the SPNEGO door's shell loads
  // too (#575).
  SIGNIN_SCRIPT_PATH: SIGNIN_SCRIPT_PATH,
  // The wallet door's two paths (#38), for `oid4vc/vc_signin.ts`, which uses
  // `pendingFor` and `completeAuthentication` for the Kerberos door's reasons.
  WALLET_PATH: WALLET_PATH,
  WALLET_WAIT_PATH: WALLET_WAIT_PATH,
  // The wallet's two pages are routes of the sign-in surface (#574): the
  // shell they answer, and the address an answer names, as a redirect
  // would have named it.
  signInShell: slot.forward('signInShell'),
  locationOf: slot.forward('locationOf'),
  // The consent screen is a page of the sign-in surface too (#576): it
  // serves this bundle at its own address, `/oauth2/consent.js`.
  signInBundle: slot.forward('signInBundle'),
  PASSWORD_FACTOR_PATH: PASSWORD_FACTOR_PATH,
  // The wallet as a factor (#38's follow-ups): read a second-factor step,
  // finish one with a presentation, and ask for a second factor after one.
  mfaStepFor: slot.forward('mfaStepFor'),
  finishWithWallet: slot.forward('finishWithWallet'),
  beginSecondFactorAfterWallet: slot.forward('beginSecondFactorAfterWallet'),
  beginSecondFactorAfterFederation:
    slot.forward('beginSecondFactorAfterFederation'),
  assessSignIn: slot.forward('assessSignIn'),
  adoptSessionRisk: slot.forward('adoptSessionRisk'),
  sessionsForRisk: slot.forward('sessionsForRisk'),
  pendingFor: slot.forward('pendingFor'),
  completeAuthentication: slot.forward('completeAuthentication'),
  // The emailed code and link (#64), for `authn/email_factor.ts`: its three
  // paths, and the pending-step functions the header above them argues.
  EMAIL_CODE_PATH: EMAIL_CODE_PATH,
  EMAIL_LINK_PATH: EMAIL_LINK_PATH,
  EMAIL_LINK_OPEN_PATH: EMAIL_LINK_OPEN_PATH,
  BACKUP_CODE_PATH: BACKUP_CODE_PATH,
  mintMfaStep: slot.forward('mintMfaStep'),
  saveMfaStep: slot.forward('saveMfaStep'),
  dropMfaStep: slot.forward('dropMfaStep'),
  takePending: slot.forward('takePending'),
  firstAmrFor: slot.forward('firstAmrFor'),
  refuseAtScreen: slot.forward('refuseAtScreen'),
  // THE SIGN-IN SURFACE (#571), for `authn/authn_api.ts`: its paths, the
  // views it is drawn from and the acts it sends, each this module's own
  // logic, and the answer helpers the API shares with them.
  AUTHN_API_PATH: AUTHN_API_PATH,
  SELECT_IDP_PATH: SELECT_IDP_PATH,
  PASSWORD_CHANGE_PATH: PASSWORD_CHANGE_PATH,
  screenView: slot.forward('screenView'),
  screenProblem: slot.forward('screenProblem'),
  screenAct: slot.forward('screenAct'),
  // Whether a sign-in must be a passkey with no username (#608).
  usernamelessRequired: slot.forward('usernamelessRequired'),
  passkeyOptions: slot.forward('passkeyOptions'),
  selectIdpView: slot.forward('selectIdpView'),
  refreshPartners: slot.forward('refreshPartners'),
  passwordChangeStep: slot.forward('passwordChangeStep'),
  passwordChangeView: slot.forward('passwordChangeView'),
  passwordChangeAct: slot.forward('passwordChangeAct'),
  preferredLanguageOf: slot.forward('preferredLanguageOf'),
  answerJson: slot.forward('answerJson'),
  stepAnswer: slot.forward('stepAnswer'),
  // The second-factor steps' pages and acts (#572), for `/authn-api` and
  // the emailed factor's shells.
  stepPagePath: slot.forward('stepPagePath'),
  mfaView: slot.forward('mfaView'),
  stepRefused: slot.forward('stepRefused'),
  mfaTotpAct: slot.forward('mfaTotpAct'),
  mfaBackupCodeAct: slot.forward('mfaBackupCodeAct'),
  mfaPasswordAct: slot.forward('mfaPasswordAct'),
  mfaWebauthnOptions: slot.forward('mfaWebauthnOptions'),
  mfaWebauthnAct: slot.forward('mfaWebauthnAct'),
  mfaSetupAct: slot.forward('mfaSetupAct'),
  postLoginAct: slot.forward('postLoginAct'),
  mfaStartOver: slot.forward('mfaStartOver'),
  passwordChangeStartOver: slot.forward('passwordChangeStartOver'),
  finishEmailSecondFactor: slot.forward('finishEmailSecondFactor'),
  finishEmailFirstFactor: slot.forward('finishEmailFirstFactor')
};
