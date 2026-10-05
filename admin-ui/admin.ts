// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin.ts
//
// ---------------------------------------------------------------------------
// The admin console. It began as five pages over the state admin_stats.js
// holds, and one more — /admin/groups — over the embedded LDAP directory next
// door; the list below is those first pages, and `SECTIONS` further down is
// the whole of it now.
//
//   GET  /admin           what the console is, and what it can do to this
// service
//   GET  /admin/metrics   every call, every artifact, and both kinds of session
//   GET  /admin/users     everyone this service has authenticated; with ?user=
// it is
//                         one of them, their sessions, and what was issued on
// each
//   GET  /admin/groups    every group in the embedded LDAP directory; with
// ?group= it
//                         is one of them, every attribute it has, and everybody
// in it
//   GET  /admin/tokens    what was issued — every JWT, every SAML assertion and
// every
//                         Kerberos ticket, filtered and paged — and the buttons
// that
//                         invalidate the ones that can be
//   POST /admin/tokens    revoke / restore, one token or a whole class of them
//   GET  /admin/audit     what happened here, in order — every authentication,
//                         session, directory operation, console interaction,
//                         management API call and protocol endpoint call, as
//                         rows rather than as counters, filtered and paged
//   GET  /admin/claims    the custom claims every new token will carry
//   POST /admin/claims    add, remove, clear, or replace a whole set
//   GET  /admin/saml-attributes   the same two halves for the two SAML sets
//   POST /admin/saml-attributes   the same seven actions, on those two sets
//
// Every GET also answers `?format=json`, and every POST answers JSON when it
// was sent JSON. That is not decoration: this repository's own
// `tests/vendored/admin_api.js` and its siblings drive the console over HTTP
// with no browser, and a console reachable only by clicking is a console no
// test can assert against.
//
// **This module renders; it decides nothing.** All the state, all the caps and
// all the rules about what a claim may be called live in admin_stats.js, so a
// test can exercise them without going near an HTML page, and so this file
// stays the one place the markup is. It reads the browser sign-on session
// store, which `../authn/authn.ts` owns, so the metrics page can report real
// sign-on sessions beside the ones derived from what was issued.
//
// **It must come AFTER oauth2.js in `common/protocol_stack.ts`** (rule 5) —
// in the require order and, since #50's R1, in the order of that file's
// `register()` calls as well — and that is a dependency rather than a
// preference: it requires
// `../oauth-oidc/oauth2.ts` for the drift report (see that require below).
// The dependency is one way — oauth2.js knows nothing about this module — so
// it is not a cycle.
//
// ---------------------------------------------------------------------------
// THIS CONSOLE IS PROTECTED NOW, AND THE OLD PARAGRAPH IS KEPT BELOW BECAUSE
// MOST OF IT IS STILL TRUE.
//
// The console gate is UNCONDITIONAL. Every page and every form under /admin
// needs a session of the console's own — got through the OIDC code flow
// against this service's authorization server (`common/oidc_rp.ts`, since
// 2026-09-06) — and one of two roles — Admin Read and Admin Write — held as
// two ordinary groups in the embedded directory of the realm the person
// signed in through (per realm since 2026-09-14, #32; admin-ui/CLAUDE.md 8d).
// The gate is one `app.use('/admin', ...)` further down this file and the
// roles are `./admin_rbac.js`; both have headers of their own.
//
// **IT IS A TURNSTILE AND NOT A LOCK, and that distinction is the same one
// SCIM's authentication carries.** In development mode this service checks no
// password — the username typed at the sign-in screen simply becomes the
// identity — so what the gate proves there is that somebody TYPED a name that
// holds a role (product mode verifies the password; `common/mode.js`). What it
// buys is what a mock is for: a client, or a person, can now be driven through
// 302 to a sign-in screen, 401 with no session, 403 with the wrong role and a
// role model that can be granted and revoked, none of which was reachable here
// before.
//
// **`/admin-api` WAS NOT GATED UNTIL 2026-09-09** and it is now: it takes an
// OAuth 2.0 access token carrying `admin:read` / `admin:write`, and
// `adminApi.authRequired=false` restores the open API
// (`mgmt-api/CLAUDE.md`). With that switch off, the sentence below is true of
// this PORT even though it is not true of this PAGE — which is why it stays
// rather than being deleted:
//
//   anyone who can reach this port can revoke every token this service has
//   issued and add a claim to every token it issues next. That is fine for a
//   mock on a laptop or on a compose network and is not fine on a public
//   address, which is the same thing that was already true of /oauth2/token —
//   it will mint a token for any username asked of it. Do not put this service
//   on a public address.
//
// Every page says which state the gate is in (see gateBanner()),
// because "protected" and "protected, but nobody holds a role so anybody who
// signs in is an administrator" are very different things to be reading a
// console under.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, and `oauth-oidc/oauth2.ts`'s for a file this size. `AdminConsole`
// takes every module it reads through its constructor as
// `AdminConsoleDeps`, whose names are the ones this file used at its top
// level before, so each method takes what it reads with one destructuring
// line and its body reads as it did. Every function of the old file is a
// method of the same name — with ONE exception each for two names the old
// file declared TWICE (`credentialCell()`, `samlOverrideFieldRow()`): the
// later declaration is the one JavaScript's hoisting gave every caller, so
// it keeps the name. Both `samlOverrideFieldRow()`s went with the create
// form's per-role tables on 2026-09-30 (the field grid); the earlier
// `credentialCell()` was
// the delegation table's own and is `delegationCredentialCell()` since #70,
// which fixed that table's two calls to reach it.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which holds every
// route and middleware of the old file in the old order — the console gate
// (`app.use('/admin', …)`) and the realm chooser ahead of every page, and
// `/admin/api-explorer`'s CSP relaxation where it was. Until #50's R1 the
// transitional code called it at load, where the LAST of them used to be
// registered rather than the first, because the old file declared tables
// between its routes that some registrations read at load
// (`PROTOCOL_SETTINGS_PAGES`); nothing between the first route and the last
// registers a route or requires a module. **Since R1 (2026-09-16) requiring
// this module registers nothing**: the module exports `registerRoutes(app)`
// and `common/protocol_stack.ts` calls it at 18, straight after the require,
// which is where requiring this module used to register them — so rule 1's
// order, within this file and against every other module, is unchanged.
//
// The stores, the slot variables every `set…()` fills (rule 3e) and the
// tables are still declared at module scope, where they were, so what a slot
// sets is what the pages read.
//
// **SINCE R2 (#50, 2026-09-16) THE COMPOSITION ROOT BUILDS THE INSTANCE**
// and installs it; this module builds none of its own. It exports
// `registerRoutes(app)` for the root to call, and the old names, as FACADES
// that forward to that instance, for every module that requires this one by
// them. What loading this module used to do with its own instance — the
// sidebar's flattening, the setting-homes check, the module constants drawn
// with `note()` and `warn()`, and the read layer's settings block — is a
// list of `WIRE_STEPS`, each beside the declaration it fills, run by
// `AdminConsole.wire()` when the instance is installed. A process without the
// root builds a default instance at load, as loading this module always did.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
const { log, xmlEscape, baseUrlOf, parseBody, userFor,
        // The parts of an upload, for the RFC 9728 import's file field: the
        // one place this console needs a FILENAME, which parseBody() does not
        // keep.
        multipartParts } = helpers;
// The error-code registry. A leaf: it records which failure condition a
// response reports, on the response object and never in its bytes.
import errorCodes = require('../common/error_codes');
// RFC 9728 protected resource metadata, for /admin/applications/new's import:
// the realm's authorization servers a document is compared with, the redraw of
// a loaded document after a refused create, and the document the third tab
// leaves. A library that registers nothing.
import resourceMetadata = require('../oauth-oidc/protected_resource_metadata');

// ---------------------------------------------------------------------------
// THE ACTION LAYER (2026-09-12), AND WHY THESE NAMES ARE STILL IN SCOPE HERE.
//
// Thirty-one actions, the tables they dispatch on and the pure helpers they
// share moved to `admin-core/admin_actions.ts` — see that file's header for
// what may be in it and what may not. `mgmt-api/admin_api.ts` requires it too,
// and no longer requires this module for them, which is the whole point: the
// surface a machine drives is no longer downstream of the surface a person
// reads.
//
// **THEY ARE ALIASED BACK RATHER THAN REWRITTEN AT EVERY CALL SITE**, and
// that is a deliberate choice about what a reviewer has to check. This file
// calls these names several hundred times — from the routes, from the views
// that draw the buttons an action dispatches on, and from each other. Turning
// each into `adminActions.x` would have made the move a diff nobody could
// read, in which a behaviour change and a rename look identical. Here the
// move is a deletion and one block, and every remaining line of this file is
// untouched.
// ---------------------------------------------------------------------------
import adminActions = require('../admin-core/admin_actions');

// ---------------------------------------------------------------------------
// AND THE READ HALF (2026-09-12), on the same terms.
//
// Thirty-seven functions that answer a question and reach no markup at all —
// `scimJson()`, `realmsJson()`, `cryptoView()`, the six XACML views and the
// rest — moved to `admin-core/admin_views.ts`. They needed no surgery: they
// were already pure, so they travelled exactly as the actions did.
//
// **WHAT DID NOT GO IS THE POINT OF THE LINE.** Every view that builds HTML
// stayed, because `{ json, inner }` computed in one pass is the strongest
// form of rule 7 there is and splitting it is bespoke work on interleaved
// code. And so did this console's own STRUCTURE — `consoleJson()`,
// `configJson()`, `settingsGroupsFor()`, `protocolSettingsJsonFor()` and
// `configSettingsJson()` — which is pure and still belongs here: a caller
// asking which pages this console has is asking the console about itself.
// ---------------------------------------------------------------------------
import adminViews = require('../admin-core/admin_views');
// Which endpoints each Protocols page lists. It reads every route-registering
// module out of `require.cache` and never loads one, so requiring it here
// moves nothing; see its header and `respond()`.
import protocolEndpoints = require('../admin-core/protocol_endpoints');
const pagingOf = adminViews.pagingOf;
const pagingJson = adminViews.pagingJson;
const pagedRows = adminViews.pagedRows;
const tokensView = adminViews.tokensView;
const sessionProtocolsIn = adminViews.sessionProtocolsIn;
const sessionsView = adminViews.sessionsView;
const DEFAULT_PER_PAGE = adminViews.DEFAULT_PER_PAGE;
const DELEGATION_PER_PAGE = adminViews.DELEGATION_PER_PAGE;
const MAX_ROWS = adminViews.MAX_ROWS;
const auditView = adminViews.auditView;
const errorCodesView = adminViews.errorCodesView;
const usedAssertionsView = adminViews.usedAssertionsView;
const delegationView = adminViews.delegationView;
const delegationPolicyView = adminViews.delegationPolicyView;
const clusterSummary = adminViews.clusterSummary;
const permissionGroupsView = adminViews.permissionGroupsView;
const queryOne = adminViews.queryOne;
const chooserMatches = adminViews.chooserMatches;
const claimsRequestPreview = adminViews.claimsRequestPreview;
const claimsRequestJson = adminViews.claimsRequestJson;
const userinfoClaimsJson = adminViews.userinfoClaimsJson;
const signalsJson = adminViews.signalsJson;
const signalsState = adminViews.signalsState;
const ssfJson = adminViews.ssfJson;
const ssfDeadLettersJson = adminViews.ssfDeadLettersJson;
const caepJson = adminViews.caepJson;
const caepSessionsState = adminViews.caepSessionsState;
const caepApplicationsState = adminViews.caepApplicationsState;
const caepSessionsJson = adminViews.caepSessionsJson;
const riscJson = adminViews.riscJson;
const riscAccountsState = adminViews.riscAccountsState;
const riscApplicationsState = adminViews.riscApplicationsState;
const riscAccountsJson = adminViews.riscAccountsJson;
const spiffeListeners = adminViews.spiffeListeners;
const spiffeJson = adminViews.spiffeJson;
const spiffeEntriesJson = adminViews.spiffeEntriesJson;
const spiffeAgentsJson = adminViews.spiffeAgentsJson;
const spiffeBrokersJson = adminViews.spiffeBrokersJson;
const spiffeSelectorText = adminViews.spiffeSelectorText;
const newUserContainer = adminViews.newUserContainer;
const CREDENTIAL_CHOICES = adminViews.CREDENTIAL_CHOICES;
const knownUserKeys = adminViews.knownUserKeys;
const saml2ServiceProviders = adminViews.saml2ServiceProviders;
const saml2Facts = adminViews.saml2Facts;
const valuesFor = adminViews.valuesFor;
const saml11RelyingParties = adminViews.saml11RelyingParties;
const saml11Facts = adminViews.saml11Facts;
const asDriftRows = adminViews.asDriftRows;
const asTruthRequest = adminViews.asTruthRequest;
const pageParamsOf = adminViews.pageParamsOf;
const NOT_A_VIEW = adminViews.NOT_A_VIEW;
const applicationPermissionsState = adminViews.applicationPermissionsState;
const federationRow = adminViews.federationRow;
const peopleRows = adminViews.peopleRows;
const mergeFactors = adminViews.mergeFactors;
/**
 * Builds a query string from the current parameters plus overrides, empty
 * values omitted; admin_views.ts's queryWith(), re-exported for the pages
 * drawn outside this file.
 */
const queryWith = adminViews.queryWith;
/**
 * How many session blocks a drill-down page shows by default, from
 * admin_views.ts; `?per=` overrides it.
 */
const DEFAULT_BLOCKS_PER_PAGE = adminViews.DEFAULT_BLOCKS_PER_PAGE;
const sessionRowsFor = adminViews.sessionRowsFor;
const tokensBySession = adminViews.tokensBySession;
const logoutInventoryFor = adminViews.logoutInventoryFor;
const logoutFamilies = adminViews.logoutFamilies;

const claimSetsJson = adminViews.claimSetsJson;
const claimsJson = adminViews.claimsJson;
const claimsPreviewUser = adminViews.claimsPreviewUser;
const claimsRequestParameter = adminViews.claimsRequestParameter;
const consentView = adminViews.consentView;
const consoleRpSession = adminViews.consoleRpSession;
const cryptoView = adminViews.cryptoView;
const directoryPageJson = adminViews.directoryPageJson;
const gateStateFor = adminViews.gateStateFor;
const keysExport = adminViews.keysExport;
const keysView = adminViews.keysView;
const metricsJson = adminViews.metricsJson;
const permissionsView = adminViews.permissionsView;
const realmJson = adminViews.realmJson;
const realmRootUrl = adminViews.realmRootUrl;
const realmSettingRows = adminViews.realmSettingRows;
const realmsJson = adminViews.realmsJson;
const rolesPreview = adminViews.rolesPreview;
const rolesRegister = adminViews.rolesRegister;
const rolesView = adminViews.rolesView;
const samlAssertionSeconds = adminViews.samlAssertionSeconds;
const samlAssertionsJson = adminViews.samlAssertionsJson;
const samlAttributesJson = adminViews.samlAttributesJson;
const scimJson = adminViews.scimJson;
const scimMappingRow = adminViews.scimMappingRow;
const scimMonitorJson = adminViews.scimMonitorJson;
const signOnSessionRows = adminViews.signOnSessionRows;
const tokenLifetimesJson = adminViews.tokenLifetimesJson;
const tokenSetView = adminViews.tokenSetView;
const vcJson = adminViews.vcJson;
const vcPreviewUser = adminViews.vcPreviewUser;
const vpConfigJson = adminViews.vpConfigJson;
const xacmlDecideView = adminViews.xacmlDecideView;
const xacmlEditorView = adminViews.xacmlEditorView;
const xacmlMonitorView = adminViews.xacmlMonitorView;
const xacmlPepsView = adminViews.xacmlPepsView;
const xacmlPoliciesView = adminViews.xacmlPoliciesView;
const xacmlView = adminViews.xacmlView;

const APPLICATION_ACTIONS = adminActions.APPLICATION_ACTIONS;
const CONSENT_ACTIONS = adminActions.CONSENT_ACTIONS;
const FIELD_PREFIX = adminActions.FIELD_PREFIX;
const FORM_FURNITURE = adminActions.FORM_FURNITURE;
const MFA_ACTIONS = adminActions.MFA_ACTIONS;
const PERMISSION_ACTIONS = adminActions.PERMISSION_ACTIONS;
const ROLE_ACTIONS = adminActions.ROLE_ACTIONS;
const ROLE_MEMBER_KINDS = adminActions.ROLE_MEMBER_KINDS;
const SAML11_RP_KIND = adminActions.SAML11_RP_KIND;
const SAML2_SP_KIND = adminActions.SAML2_SP_KIND;
const SAML_ASSERTION_KEYS = adminActions.SAML_ASSERTION_KEYS;
const SAML_ASSERTION_SETTINGS = adminActions.SAML_ASSERTION_SETTINGS;
/**
 * The actions the console's own Shared Signals inbox takes, from
 * admin_actions.ts.
 */
const SIGNALS_CONSOLE_ACTIONS = adminActions.SIGNALS_CONSOLE_ACTIONS;
const SPIFFE_AGENT_ACTIONS = adminActions.SPIFFE_AGENT_ACTIONS;
const SPIFFE_ENTRY_ACTIONS = adminActions.SPIFFE_ENTRY_ACTIONS;
const SPIFFE_FIELD_ATTRIBUTES = adminActions.SPIFFE_FIELD_ATTRIBUTES;
const TOKEN_LIFETIME_KEYS = adminActions.TOKEN_LIFETIME_KEYS;
const USERS_ACTIONS = adminActions.USERS_ACTIONS;
const USER_FIELD_PREFIX = adminActions.USER_FIELD_PREFIX;
const applicationFieldsFrom = adminActions.applicationFieldsFrom;
const applicationsAction = adminActions.applicationsAction;
const asAction = adminActions.asAction;
const caepAction = adminActions.caepAction;
const claimsAction = adminActions.claimsAction;
const configAction = adminActions.configAction;
const configKnows = adminActions.configKnows;
const configSettingFor = adminActions.configSettingFor;
const consentAction = adminActions.consentAction;
const federationAction = adminActions.federationAction;
const fieldToAttribute = adminActions.fieldToAttribute;
const groupsAction = adminActions.groupsAction;
/**
 * Reads the `jti` out of a pasted token, or takes the text as a jti;
 * admin_actions.ts's jtiFrom(). The token's signature is not verified.
 */
const jtiFrom = adminActions.jtiFrom;
const logoutAction = adminActions.logoutAction;
const mfaAction = adminActions.mfaAction;
const noXacml = adminActions.noXacml;
const permissionsAction = adminActions.permissionsAction;
const rbacAction = adminActions.rbacAction;
const realmsAction = adminActions.realmsAction;
const riscAction = adminActions.riscAction;
const roleMemberKindOf = adminActions.roleMemberKindOf;
const rolesAction = adminActions.rolesAction;
const saml11Action = adminActions.saml11Action;
const saml2Action = adminActions.saml2Action;
const samlAssertionRowFor = adminActions.samlAssertionRowFor;
const samlAssertionsAction = adminActions.samlAssertionsAction;
const sessionsAction = adminActions.sessionsAction;
const signalsAction = adminActions.signalsAction;
const spiffeAgentsAction = adminActions.spiffeAgentsAction;
const spiffeBrokersAction = adminActions.spiffeBrokersAction;
const spiffeCommaList = adminActions.spiffeCommaList;
const spiffeEntriesAction = adminActions.spiffeEntriesAction;
const spiffeUnknownAction = adminActions.spiffeUnknownAction;
const spiffeAction = adminActions.spiffeAction;
const SPIFFE_ACTIONS = adminActions.SPIFFE_ACTIONS;
const ssfAction = adminActions.ssfAction;
const sweepText = adminActions.sweepText;
const tokenAction = adminActions.tokenAction;
const tokenLifetimesAction = adminActions.tokenLifetimesAction;
const truthy = adminActions.truthy;
const userFieldsFrom = adminActions.userFieldsFrom;
const usersAction = adminActions.usersAction;
const vcAction = adminActions.vcAction;
const vpConfigAction = adminActions.vpConfigAction;
const xacmlAction = adminActions.xacmlAction;
import config = require('../common/config');
// The credential lifecycle, for the activation link the users page issues. A
// LEAF (rule 3): it registers no route and requires nothing here.
import credentials = require('../common/credentials');
// RFC 6238 ITSELF, for /admin/totp: the settings it draws and the algorithm
// table `?format=json` reports. A LIBRARY (rule 3) that registers no route, and
// `credentials.js` above already requires it — so this is a second reader of
// one module rather than a new edge in the require order.
import totp = require('../common/totp');
// THE THIRD SECOND FACTOR (2026-09-10), for `/admin/backup-codes` and for the
// block on a person's own row under `/admin/users`. A LIBRARY (rule 3): it
// registers nothing and requires only `config`, `crypto` and `helpers`, so it
// can neither move a route nor join a cycle.
import backupCodes = require('../common/backup_codes');
// THE OTHER SECOND FACTOR, for /admin/webauthn — the ceremony's options and
// this service's policy about what a key may be. A LIBRARY (rule 3) on the same
// terms: it registers no route and requires only `config`, `helpers` and
// `authn/webauthn.js`, so it can neither move a route nor close a cycle, and
// `common/credentials.ts` above already requires it. **It is NOT
// `authn/authn.ts`**, which is 8 and owns the session: a require from here to
// that module would be the console reaching into the sign-in service, and the
// rule `/admin/crypto-metadata` is built on says an algorithm table is read
// from the module that PERFORMS the algorithm.
import webauthnPolicy = require('../authn/webauthn_policy');
// CSRF and rate limiting for this console. A LEAF (rule 3): it registers no
// route and requires only config, crypto and helpers, so it can neither move a
// route nor close a cycle.
import websecurity = require('../common/websecurity');
// The access-control gate. A LEAF (rule 3): registers nothing, requires only
// config and helpers. Its decider is filled by xacml/xacml_access_pep.ts at
// 23c, so before that line every check here is allowed — which is what a
// process without the XACML family does.
import accessGate = require('../common/access_gate');
// The mode. A LEAF (rule 3): registers nothing, requires only `config`.
import mode = require('../common/mode');
// THE VERSION, M.N.O, drawn at the foot of every page in this console. A LEAF
// (rule 3) that requires nothing from this repository, so it can neither move a
// route nor join a cycle — which matters here, because this module is at 18 and
// four other modules spread across the require order read the same file.
//
// **READ ONCE, AT REQUIRE TIME, AND NOT PER PAGE.** The version cannot change
// while the process runs: it is stamped into the artifact at build time or
// computed once at startup, and reading a file on every page render to learn
// something that is fixed for the life of the process is work in the one place
// this console does the most of it.
import version = require('../common/version');
const APP_VERSION = version.load();
const APP_BUILD_INFO = version.buildInfo(APP_VERSION);
// What this service writes down, and whether it is working. A PLAIN REQUIRE in
// the ordinary direction: that module is a library — it registers no route, so
// this line moves nothing in the router — and it requires only `config.js` and
// `realms.js`, neither of which reaches back here. Rule 3e's test therefore
// asks for no slot, both ways round. `/admin/persistence` renders its
// `status()` and `GET /admin/ldap/service` publishes the same object.
import persistence = require('../persistence/persistence');
// THE CLUSTER (2026-09-14, #46), for /admin/cluster's status block. Libraries:
// they register no route, and every one of them is already loaded by
// persistence.js, app.js or service_state.js, so these are cache hits.
import cluster = require('../cluster/cluster');
import clusterSecrets = require('../cluster/cluster_secrets');
import clusterBarrier = require('../cluster/cluster_barrier');
// WHERE THE TWO PRIMORDIAL SECRETS COME FROM, and whether the keystore is
// reading one at all — for the runtime line at the foot of every page
// (`runtimeFooter()`). Both are LEAVES (rule 3): `secrets.js` requires only
// `config` and `error_codes`, `keystore.js` is loaded long before this module
// by the startup it serves, so neither require can move a route or close a
// cycle.
import secrets = require('../common/secrets');
import keystore = require('../common/keystore');
// TRUST REALMS: the registry behind /admin/realms, and the switcher this shell
// draws on every page. It requires config.js and nothing else here, registers
// no route, and is already loaded by helpers.js — so its position is not a
// position at all.
import realms = require('../common/realms');
// A CREATE CLAIMS ITS NAME ACROSS NODES (2026-09-14, #46 follow-up) — the
// console's own user and group forms, as `/admin-api` already did. A LIBRARY
// (rule 3): it registers no route, and reaches the directory module through
// the require cache, so this require moves nothing in the route order.
import createClaims = require('../ldap/directory_create_claims');
import personEditor = require('../ldap/person_editor');
import stats = require('../common/admin_stats');
// The browser sign-on sessions, from the authentication service that creates
// them — shared between the OAuth 2.0 / OIDC flow, WS-Federation and SAML 2.0.
//
// **THIS FILE STILL READS THEM AND NEVER ENDS ONE, AND THE REASON CHANGED ON
// 2026-08-24.** It used to be that ending a session from a third place would be
// a third way to get the cleanup wrong: /oauth2/logout and wsignout1.0 each had
// a fan-out written into it, and a console button would have been a third copy
// that quietly notified nobody.
//
// That is no longer the argument, because the fan-outs are now FUNCTIONS rather
// than copies — `wsfed.cleanupTargetsFor()`, `saml2_sso.logoutTargetsFor()` and
// `frontchannel_logout.js`, each owned by the module whose protocol it belongs
// to — and `authn.js`'s `dropSession()` is the single place a session actually
// stops existing. So /admin/logout DOES end sessions, and it ends them through
// exactly those functions.
//
// What is still true is the line this file holds to: this map is READ here and
// written nowhere here. The console's page calls `logout.ts`, which calls
// `authn.js`. A `sessions.delete()` in this file would be the fourth way, and
// the one that skipped the RFC 9700 refresh revocation and the audit row.
//
// THE CONSOLE HOLDS NO SESSION OF ITS OWN since the cutover (#446): the
// static console signs in in the browser as a public client and holds a
// DPoP-bound token, so the console session, the cookie reader, the sign-in
// redirect and the Sign out handler that used to be imported from this module
// are gone. What is left is `sessions` — read, never written — for the
// dashboard's count of sign-on sessions, and `sessionOf()`, which the realm
// chooser asks so that a browser already signed in is not asked again.
// `common/oidc_rp.ts` still registers the console's callback on its client.
import oidcRp = require('../common/oidc_rp');
import authn = require('../authn/authn');
const { sessions } = authn;
// WHO MAY USE THIS CONSOLE. A library (rule 3): it registers no route, so
// requiring it here moves nothing in the router, and it requires only
// config.js, helpers.js and audit.js — none of which requires it back. The two
// roles it decides from are two ORDINARY GROUPS in the embedded directory,
// which it reaches through a slot ldap_server.js fills; see its header for why
// that is a directory group rather than a store of this console's own.
import rbac = require('./admin_rbac');
// WHAT A REALM ADMINISTRATOR MAY NOT REACH (2026-09-14, #32): the service-wide
// pages, actions and settings, in one table the management API reads too. A
// library with no route.
import adminScope = require('./admin_scope');
// WHICH REALM TO SIGN IN THROUGH (2026-09-14, #32), asked before a bare /admin
// sends anybody to sign in. A library with no route, shared with the portal.
import loginRealmChooser = require('../common/realm_chooser');
// The credential claim set: which LDAP attributes an issued Verifiable
// Credential carries, and the invented values behind them. A library like
// admin_stats.js — it registers no route — so requiring it here neither adds to
// the express router nor makes a cycle, and /admin/vc below is the page that
// sets it. The DIRECTORY half of it (populating entries, reading values back)
// is ldap_server.js's, wired into that module through a slot for the
// route-order reason rule 6 gives.
import vcClaims = require('../oid4vc/vc_claims');
// The other end of that: which of those claims the mock OID4VP Verifier — the
// "bar door" at /oid4vp/verifier — ASKS a wallet for, and in which credential
// format. A library like vc_claims.js and admin_stats.js, registering no route,
// so requiring it here neither moves a route nor makes a cycle; vc_verifier.js
// reads the same module from the other side of the require order.
import vpConfig = require('../oid4vc/vc_verifier_config');
// The THIRD reader of that same catalogue: which LDAP attributes a token or an
// assertion carries, per claim set. A library like the two above, registering
// no route, so requiring it here neither moves a route nor makes a cycle — it
// requires admin_stats.js and vc_claims.js, and neither requires it back. It is
// what turns /admin/claims from a page of typed constants into one that can put
// what the directory says into an access token. See its header for why the
// selection is per-set and why nothing is selected on a fresh start.
import claimAttributes = require('../common/claim_attributes');
// The FOURTH library over that catalogue's territory: which LDAP attribute each
// SCIM member is, in both directions. Read here for the mapping tables on
// /admin/scim, and by scim.js for the conversions themselves. It registers no
// route and requires only helpers.js and vc_claims.js, so requiring it here
// neither moves a route nor makes a cycle — which is exactly why the
// conversions live in a library rather than in scim.js, where a require from
// this file would have dragged every /scim and /ldap route ahead of the
// console's own.
import scimMap = require('../scim/scim_map');
// The groups claim: which directory groups reach a token, whether it is on, and
// what it would say about one person. A LIBRARY like the line above — it
// registers no route, so requiring it here cannot reorder the router
// /admin/sts-metadata is built by walking, and it requires helpers.js,
// config.js and admin_stats.js, none of which requires this file. It is
// required for the same reason claim_attributes.js is: the page and the
// management API both report this feature, and neither should be reading its
// four settings itself.
import groupClaims = require('../common/group_claims');
// The audit log: what happened here, in order, as rows rather than as counters.
// A library like the three above — it registers no route — so requiring it here
// neither moves a route nor makes a cycle. It holds the events and this file
// renders them at /admin/audit, which is the same split admin_stats.js has and
// for the same reason: a test can walk the log over JSON without going near an
// HTML page.
import auditLog = require('../common/audit');
// The application registry, whose store is the ou=applications container in the
// embedded directory. A library that registers no route, so requiring it from
// the console cannot move anything in the route order — unlike ldap_server.js,
// which is why the user and group readers below are hooks rather than requires.
// Nothing is cached on either side: every read here is a directory read, which
// is what lets this page show an ldapmodify that happened a second ago.
import applications = require('../common/applications');
// A LIBRARY (rule 3): it registers no route, and it is required here for the
// metadata refresh action. It requires helpers, config and applications and
// nothing that requires this file, so it closes no cycle.
import spMetadata = require('../saml/sp_metadata');
// The SAML 2.0 Web Browser SSO profile, for the slug rule, the per-application
// entityID and the endpoint URLs — so that /admin/saml2 names the same
// addresses the metadata document publishes rather than rebuilding them here.
// A page that computed its own would be the console and the endpoints
// disagreeing about a URL, which is the failure a service provider meets as a
// 404 that looks like this service being down.
//
// **A PLAIN REQUIRE IN THE ORDINARY DIRECTION, AND NOT A SIXTH SLOT.** Rule
// 3e's test is whether a require would close a cycle or move a route, and this
// one does neither: `common/protocol_stack.ts` requires `saml/saml2_sso.ts` at
// position 10a and this file at 18, so that module's routes are already in the
// router by the time this line runs, and it requires nothing from here. (Since
// #50's R1 requiring it registers nothing in any case — the stack's
// `register()` call at 10a does — so the route half of the test cannot fail.)
import saml2 = require('../saml/saml2_sso');
// The SAML 1.1 browser profiles, for the same reason and on the same terms:
// this page must name the endpoints and the providerID that module names,
// because a console that derived a URL of its own would be a console telling
// somebody to configure a path nothing serves. It is required at position 10b
// in `common/protocol_stack.ts` and this file at 18, so this is a plain
// require in the ordinary direction — not an inverted slot, and rule 3e's test
// is why.
import saml11 = require('../saml/saml11_sso');
// The authorization server profiles — what each discovery document publishes.
// A library that registers no route, so requiring it here moves nothing.
import authorizationServers = require('../oauth-oidc/authorization_servers');
// The federation REGISTER, and only the register. It is a library that
// registers no route, so requiring it here moves nothing and closes no cycle —
// rule 3e's test again, and it passes both ways round: that module requires
// only config.js, helpers.js and audit.js.
//
// **`federation/federation_sp.ts` is deliberately NOT required here**, and it
// is the same line drawn around `spiffe_server.js` twenty lines down: that
// module registers /federation and its four endpoints, and
// `common/protocol_stack.ts` requires it at position 10c — BEFORE this file —
// so a require from here would be harmless today and would silently become
// the reason a route moved the day somebody reorders the two. (That was the
// argument while a require was a registration. Since #50's R1 the stack
// registers those routes at 10c with its own `register()` call, so no require
// could move them; a require from here would still load the module, and run
// its load-time work, from inside the console's — which is reason enough.)
// What this page needs from it is the shape of the URLs to configure at the
// partner, and those
// come from `federation.PATHS` — one copy of the strings, in the library both
// sides may reach, so this page
// and that router cannot come to name different paths. See that constant's
// header, where the failure it prevents is spelt out.
import federation = require('../federation/federation');
// ---------------------------------------------------------------------------
// THE FEDERATION PICTURE, in the two halves everything else in this console
// draws a diagram in: a MODEL that knows the register and no geometry, and a
// RENDERER that knows the geometry and nothing about federation. It is the same
// split as `common/delegation.js` / `./delegation_map.js` next door and it is
// the same reason — the code that decides what a box IS must not be able to
// reach the code that decides where a box GOES.
//
// Both are libraries and neither registers a route, so neither can be the
// reason one is missing and their position here does not matter.
// ---------------------------------------------------------------------------
import federationGraph = require('../federation/federation_graph');
import federationDiagram = require('./federation_diagram');
// The two SPIFFE LIBRARIES, and only those two. `spiffe_ca.js` holds the trust
// domain's authorities and `spiffe_registry.js` the registration entries and
// agents; both register nothing, so requiring them here moves no route and
// cannot close a cycle. `spiffe_id.js` comes with them for the server ID.
//
// **`spiffe_server.js` is deliberately NOT required here.** That module
// registers the bundle endpoint and /spiffe, and `common/protocol_stack.ts`
// requires this file FIRST — so a require from here would pull those routes
// into the express router ahead of the console's own, and
// GET /admin/sts-metadata is built by walking that router. (Since #50's R1
// requiring it registers nothing — the stack's `register()` call at 23 does —
// but that module requires THIS file for the shell, so a require from here
// would still close a cycle, and the slot below stays.) What this page
// needs from it is two facts about sockets, and they arrive through a reader
// slot instead: the same inversion setDirectoryReader(), setGroupReader() and
// setScimReader() already use, and justified by rule 3e's test in exactly the
// same way.
import spiffeCa = require('../spiffe/spiffe_ca');
import spiffeRegistry = require('../spiffe/spiffe_registry');
// WHO MAY CALL THE SPIRE SERVER API. A library like the two above it — it
// registers nothing and starts nothing — so neither thing that forces a slot
// applies, and it is required directly rather than read through
// `setSpiffeReader()`. What DOES need the slot is which of the four sockets
// bound, which is a fact about a socket and only `spiffe_server.js` knows it.
import spiffeAuth = require('../spiffe/spiffe_auth');
import spiffeIdLib = require('../spiffe/spiffe_id');
// ---------------------------------------------------------------------------
// THIS CONSOLE AS A SHARED SIGNALS RECEIVER (2026-09-10), and it is a PLAIN
// REQUIRE rather than a ninth slot for the reason rule 3e states: a slot is
// what you pay for a require that would close a cycle or move a route, and
// this one does neither. `ssf/ssf_receivers.ts` registers nothing (rule 3) and
// requires only libraries — `helpers`, `config`, `realms`, `audit`,
// `ssf_subjects`, `ssf_events`, `ssf_streams`, `ssf_http` — none of which
// requires this file.
//
// It is emphatically NOT `ssf/ssf.ts`, which is at 23b and registers every
// /ssf route and the well-known document: a require of THAT from here would
// drag all of it ahead of the management API's own routes, which is exactly
// what the eighth slot exists to prevent. Since #50's R1 its own routes are
// registered by `common/protocol_stack.ts` at 23b wherever it is loaded, but
// it requires this file (a cycle) and `ldap/ldap_server.js`, which is still
// JavaScript and still registers the directory's routes when required.
//
// What crosses it is this console's own inbox and the stream behind it. See
// GET /admin/signals below.
// ---------------------------------------------------------------------------
import signals = require('../ssf/ssf_receivers');
// For the DRIFT report: the document this service would publish, to compare a
// profile's overrides against. oauth2.js is required before admin.ts in
// `common/protocol_stack.ts` (rule 5), so this is a plain require in the
// ordinary direction.
import oauth2 = require('../oauth-oidc/oauth2');
// WHO ACTED ON WHOSE BEHALF. A library like the four above — it registers no
// route — so requiring it here neither moves a route nor closes a cycle. It
// holds the acts and this file renders them at /admin/delegation, the same
// split audit.js has.
import delegation = require('../common/delegation');
// WHO MAY ACT ON WHOSE BEHALF — THE CONFIGURED HALF OF THE SAME QUESTION, and a
// SEPARATE REGISTER from the one above rather than a filter over it. That
// module holds delegation ACTS, which are evidence; this one holds delegated
// PERMISSIONS, which are intent: a resource application exposes an API and a
// client application is granted permissions on it, in Microsoft Entra ID's
// shape, before anybody has asked for anything. `/admin/delegation` draws both
// and labels which is which on every heading, because the interesting reading
// is the DIFFERENCE — a grant nobody has used, and a delegation nobody granted.
//
// A library like the ones around it: it registers no route, requires only
// helpers.js and applications.js, and holds the MODEL while this file holds the
// HTML. Its header argues the model and says why the ordering rule (define
// before grant) is enforced in applications.js rather than in either of them.
import appPermissions = require('../common/app_permissions');
// WHAT A PERSON AGREED AN APPLICATION MAY ASK FOR ON THEIR BEHALF — the THIRD
// register in this family and the first one whose rows are about a person
// rather than about two applications. `delegation.js` is what happened,
// `app_permissions.js` is what an operator allowed, and this is what somebody
// SAID YES TO. The three are drawn on two pages and never merged, for the
// reason /admin/delegation gives about the first two: an act, an intent and a
// consent look alike in a table and answer three different questions.
//
// A library like the ones around it: it registers no route, requires
// helpers.js, config.js, applications.js and admin_stats.js, and holds the
// MODEL while this file holds the HTML. Its header argues both halves — the
// per-person record and the per-application override — and why the second is
// an override rather than a record.
import consent = require('../common/consent');
// THE ROLE REGISTER, a plain require in the ordinary direction and it can stay
// one: `common/roles.js` is a LEAF that requires `helpers` and `config` and
// nothing else here, so no slot is needed and rule 3e is explicit that a slot
// is what you reach for when a require would close a cycle or move a route.
import roles = require('../common/roles');
// THE ISSUANCE VOCABULARY, for the preview's menu. A leaf too, and it is the
// TABLE this page needs rather than the decision — what decides is reached
// through setRolePreviewer() below, because that lives in `xacml/` at 23c.
import issuanceGate = require('../common/issuance_gate');
// THE PICTURE OF THAT REGISTER, at /admin/delegation/map. A library like
// `./admin_rbac.js` — it registers no route, requires only helpers.js and
// @dagrejs/dagre, and knows nothing about this console: it is HANDED a resolver
// that says what each box is, because what a party IS belongs here (the
// registry and the directory reader are here) and where a box GOES belongs
// there. Its own header weighs the dependency and argues why the layout is not
// hand-rolled.
import delegationMap = require('./delegation_map');
// THE CONSOLE'S RENDERING KIT (#446): the prose helpers — note(), warn(),
// tip() and what they stand on — as a module the browser can load. This
// file's methods of those names are delegates. Pure, requires nothing of
// this service but `common/html`'s kind of leaf, so it cannot join a cycle.
import WebKit = require('./web_kit');
import SettingsForms = require('./web_settings');
// ONE PERSON, END TO END: the same picture drawn of everything this service has
// done in one identity's name — the delegation acts naming them AND the
// ordinary OAuth 2.0, OIDC, SAML, Kerberos and SPIFFE issuance that no
// delegation register has ever held. A library like the two above: it registers
// no route, requires only helpers.js, admin_stats.js and delegation.js, and
// holds the MODEL while this file holds the HTML. Its header argues why the
// union of the two registers is there rather than here.
import userGraph = require('../common/user_graph');
// ONE CREDENTIAL'S ANCESTRY, at /admin/tokens/credential. A library like the
// one above (rule 3): it registers nothing, requires nothing in this service
// but the two registers and `user_graph.js`, and is HANDED nothing — it is
// asked for an identifier and answers with a graph in the shape this file
// already draws.
import credentialGraph = require('../common/credential_graph');
// The CONFIGURED half of that page: which Kerberos principals may delegate to
// which, out of the two attributes that decide it. It is read from the module
// that OWNS the principal database, for the reason every store rule here is
// where it is — what those two attributes mean is a statement about that store,
// and this file renders and decides nothing.
//
// A plain require in the ordinary direction, and both tests that would force a
// slot pass: `krb5_principals.js` registers no route (the KDC's own `/KdcProxy`
// and `/krb5/principals` are in `krb5_kdc.js`), and `common/protocol_stack.ts`
// requires the Kerberos modules BEFORE this one, so nothing here can be the
// reason a route moved. It is the same argument the two SPIFFE libraries above
// are required under.
import krb5Principals = require('../kerberos/krb5_principals');

// The input validator. A LEAF (rule 3): it registers no route of its own and
// requires only `config`, `bunyan` and zod, so it closes no cycle here and
// moves nothing in the route order.
import validation = require('../common/validation');
// THE CLOSED SETS a console form is held to (#86). A LEAF (rule 3) requiring
// only `bunyan`; `mgmt-api/admin_api.ts` fills its register at wire time from
// the OpenAPI table, and the check below reads it. A register both modules
// require in the ordinary direction, not a slot: neither calls the other.
import closedSets = require('../common/closed_sets');
import InstanceSlot = require('../common/instance_slot');
// This thread's identity (#364): a request worker is a thread of this
// process, so the pid alone no longer tells two of them apart.
import WorkerChannel = require('../common/worker_channel');
import ProtocolSettingsPage = require('./web_protocol_settings');
import RolesPage = require('./web_roles');
import GroupsPage = require('./web_groups');
import AuditPage = require('./web_audit');
import FederationPage = require('../federation/web_federation');
import UsersPage = require('./web_users');
import WebShell = require('./web_shell');
import RealmsPage = require('./web_realms');
import ClaimsPage = require('./web_claims');
import DashboardPage = require('./web_dashboard');

// REQUIRED FOR THE ORDER THEY WERE ALWAYS REQUIRED IN, AND READ NOWHERE HERE
// (#50). TypeScript drops an `import … = require()` whose name nothing reads,
// and that would take the require out of this module's load sequence; each
// `void` is the read that keeps it where it is.
void scimMap;
void spMetadata;
void saml2;
void spiffeIdLib;
void consent;
void roles;
// THE PROTOCOL-INDEPENDENT LOGOUT IS NOT REQUIRED HERE, AND THAT IS RULE 3e's
// TEST ANSWERING YES FOR THE SIXTH TIME. It is reached through a SLOT below —
// setLogoutReader(), which `../logout/logout.ts` fills at its own require time,
// exactly as ldap_server.js, spiffe_server.js and scim.js fill the five above
// it.
//
// A plain require would close a cycle AND move routes, which is both halves of
// the test at once — and the second half survives #50's R1, because the
// routes it would move are `ldap_server.js`'s, which is still JavaScript and
// registers when required. That module requires `ldap_server.js` (for the
// bound connections that are the LDAP session), and `ldap_server.js` requires
// THIS file to fill those five slots — so `admin.ts -> logout.ts ->
// ldap_server.js -> admin.ts` hands ldap_server.js a half-initialised console
// whose `setDirectoryReader` is undefined, and the symptom arrives as
// something that is not a function. It would also drag every `/ldap` route
// into the router ahead of the console's own, which is rule 6 read backwards.
//
// See the slot itself, further down, beside the other five.






// ---------------------------------------------------------------------------
// The page shell.
//
// One for every page, with the nav in it, so a page cannot be added without
// a way back — which held for the SECTIONS and did not hold for the pages under
// them until `up` existed, because the nav's answer on a drill-down was the
// section's own tab, drawn as text. See navBar(). The CSS is inline because
// app.js sets `default-src 'none'` with `style-src 'unsafe-inline'`: a
// stylesheet as its own resource would need its own exception and would buy
// nothing.
//
// There is NO SCRIPT anywhere in this file, and that constrains the design
// rather than merely describing it — `script-src 'none'` is what makes the
// whole family of reflected-content problems moot for this service, so these
// pages do not get an exception. Every control on them is therefore a plain
// form POST, and every list is sorted server-side. (The one console page with
// a script is `/admin/api-explorer`, drawn by `./api_explorer.js` since
// 2026-09-09; admin-ui/CLAUDE.md argues it.)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE NAVIGATION, WHICH IS NOW A LIST DOWN THE LEFT RATHER THAN A ROW ACROSS
// THE TOP, AND IS GROUPED.
//
// Seventeen tabs on one line wrapped to three rows on a laptop and to five on
// anything narrower, and a reader looking for `Verifier request` had to read
// all seventeen labels to find out it was not `Credential claims`. What the row
// could not express is that these pages are not seventeen peers: some are about
// PROTOCOLS this service speaks, some are about what is in its DIRECTORY, one
// is history, and the rest are about the service itself.
//
// So SECTIONS is the structure and `NAV` below is derived from it. Two rules
// about that and both are load-bearing:
//
//   * **`NAV` is DERIVED and never written by hand.** `upTo()` and `trailBar()`
//     look a path up in it to label a breadcrumb, so a page in SECTIONS that
//     was not in NAV would leave a drill-down whose trail names a path instead
//     of a section. Deriving it makes that impossible rather than merely
//     unlikely.
//   * **The section a page is in is NOT a crumb.** A section has no page of its
//     own, so a crumb for it could not be a link, and a trail with a dead crumb
//     in the middle of it teaches a reader not to trust the ones beside it —
//     the rule the LAST crumb already follows for the same reason. The section
//     is visible where it is useful, which is the sidebar: the heading above
//     the page you are on is the answer to "what else is near this".
//
// WHERE THE PAGES THE ASK DID NOT NAME WENT. Four sections were asked for by
// name — Protocols (SCIM, SPIFFE, Verifier request, Credential claims, Custom
// claims), Directory (Users, Groups, Applications), Monitoring (Audit log) and
// Server configuration (Service metadata) — and seven pages were not mentioned.
// They are placed by the same question rather than left dangling: SPIFFE's
// registration entries and agents are SPIFFE, and authorization servers are
// OAuth, so all three are protocol pages; the console index, the metrics and
// the issued-token list describe the SERVICE'S OWN state rather than any one
// protocol, so they were an Overview at the top; and the configuration page and
// the admin roles below it are what this service is set up with, so they sit
// with the service metadata.
//
// TWO OF THOSE THREE MOVED TO MONITORING ON 2026-08-24, and what the move
// corrected is the question the section was answering. "Describes the service's
// own state rather than a protocol" is true of Metrics and Tokens, and it is
// equally true of the Audit log — which was in Monitoring by itself — so the
// old split was not between two kinds of page, it was between two kinds of
// ANSWER: a number, a list, and a history of what this service has done. Those
// are three ways of asking one question, and a reader who wants to know what
// happened should find all three under one heading rather than learn that the
// counters are filed away from the events they count.
//
// So Monitoring holds them in widening detail — Metrics (how much), Tokens
// (what came out), Audit log (what happened, in order) — and its `what` was
// rewritten with them, because "history rather than state" was the sentence
// that made the old split sound principled and is now false of two of its three
// pages. A section description that survives the pages moving under it is a
// description that was never about them.
//
// OVERVIEW IS A SECTION OF ONE NOW, and that is deliberate rather than a
// leftover. `/admin` is where a reader LANDS: it is the only page here whose
// job is to point at the others, so it is the one page that cannot sit under a
// heading naming a kind of content. Folding it into Monitoring would put the
// front door inside one of the rooms. The rule this trades against is the one
// stated for GROUPS below — a group of one is a heading buying nothing, which
// is why SCIM is ungrouped — and it does not reach here: a group's heading
// competes with the pages beside it inside a section, while a section's heading
// is the top-level structure, and dropping this one would leave `/admin` as a
// page under no heading at all in a sidebar where every other page has one.
//
// PROTOCOLS HAS A THIRD LEVEL NOW, AND ONLY PROTOCOLS DOES. Eight pages under
// one heading is the same list the row across the top was — a reader looking
// for `Registration entries` had to know that entries are a SPIFFE idea before
// the label could tell them anything — and the eight are not eight peers
// either: three configure what this service ISSUES over OAuth2/OIDC, three are
// the workload-identity side, one is the verifier's request and one is
// provisioning. So an item in a section may be a page (`path` + `label`) or a
// GROUP (`title` + `items`), and `isNavGroup()` is the one place that decides
// which. Three rules about a group, each the section rule one level down:
//
//   * A GROUP IS NOT A CRUMB AND HAS NO PAGE, for exactly the reason a section
//     does not. `trailBar()` is therefore untouched by this and must stay that
//     way — the trail is still `Admin console › Registration entries › <id>`.
//   * `NAV` IS STILL DERIVED, now through `sectionPages()`, which flattens a
//     group's pages into the section that holds it. Everything downstream —
//     `upTo()`, the trail, `consoleJson().pages` — reads NAV and so cannot tell
//     a grouped page from an ungrouped one, which is the point: grouping is a
//     fact about the SIDEBAR, not about the pages.
//   * A GROUP MAY HOLD A GROUP, AND ONE DOES (2026-10-01, rcbj's ask):
//     Cert issuance › SPIFFE, the four SPIFFE pages under a heading of their
//     own inside the certificate group. It was "nesting stops here" until
//     then, on the argument that a fourth level needs its own breadcrumb —
//     and it does not, for the first rule's reason: a group is not a crumb,
//     so the trail is the same at any depth. `groupPages()` is the one walk
//     that flattens every depth; the sidebar, the guide and the realm
//     administrator's filter each recurse. Keep it to that one case unless a
//     heading passes the group test on its own.
//
// ONE PLACEMENT IN HERE IS A JUDGEMENT RATHER THAN AN OBVIOUS FACT, and it is
// worth knowing which. `Credential claims` (`/admin/vc`) is the OID4VCI
// ISSUER's claim configuration, so it could be argued into OAuth2 / OIDC — the
// issuer is an OAuth2 authorization server wearing another hat, and the page
// sits beside `Custom claims` in the code. It is under Verifiable Credentials
// because the reader looking for it is thinking about a CREDENTIAL rather than
// about a token, and because the two halves of the credential lifecycle —
// what the issuer puts in and what the verifier asks for — answer each other
// and are worth reading together.
//
// `SAML` IS A GROUP WITH ONE PAGE IN IT AND THAT IS AN EXCEPTION WORTH
// ARGUING, because the rule right beside it says the opposite: `SCIM` is left
// ungrouped for the smaller reason that a group of one is a heading buying
// nothing, and it still is. What makes SAML different is that the heading names
// a PROTOCOL FAMILY this service speaks in two versions and two profiles, and
// the page under it — `Custom SAML attributes` (`/admin/saml-attributes`), the
// two assertion claim sets, moved off `/admin/claims` on 2026-08-24 — is one
// aspect of that family rather than the whole of it. A reader looking for what
// a WS-Federation assertion will carry looks for the word SAML; ungrouped, that
// page would sit among the protocol pages reading as something OAuth-adjacent,
// which is exactly the confusion the grouping was introduced to end. SCIM's one
// page IS the whole of SCIM here, so its heading would say the label twice.
// The test for a second group of one is that question and not this precedent:
// does the heading name more than the page under it does?
// ONE ROW BELOW IS A PAGE THIS FILE DOES NOT DRAW. `Service metadata`
// (`/admin/sts-metadata`) is built by `../sts_metadata.js`, which derives its
// whole content from the live express router and therefore has to be the LAST
// module `common/protocol_stack.ts` loads; it calls `respond()` for this
// shell. Nothing about the nav knows that, and that is the point — a page
// here is a `path` and a
// `label` whoever builds it. It was `/sts-metadata`, outside the console
// altogether, until 2026-08-24.
//
// EVERY PAGE ROW CARRIES A `blurb`, AND THAT IS WHAT `/admin` IS BUILT FROM.
// The Overview page's *What this console is* list used to be a hand-written
// `<ul>` in the index route, and it drifted exactly the way this repository
// warns everything else about: it described seven pages while the sidebar
// offered twenty-five, so the front door of this console was quietly the least
// complete description of it. The list is DERIVED from this table now
// (`consoleGuide()` below), so a page added here appears there with no second
// edit — and a page added here with no `blurb` appears there SAYING SO, in the
// same spirit as `/admin/sts-metadata` reporting an undescribed route rather
// than omitting it. A blurb is prose about ONE page and belongs beside that
// page's `path` and `label` for the same reason its label does; a second table
// keyed by path would be the drift back again with an extra lookup.
const SECTIONS = [
  { title: 'Overview',
    what: 'Where a reader lands, and what it points at.',
    items: [
      // NO `blurb`, and that is not an omission. `consoleGuide()` drops the
      // page it is being drawn ON before it looks for one, and this is the
      // only page it is ever drawn on — a row here describing this page would
      // be text nothing can render, which is the kind of thing that is edited
      // for years after it stopped being read.
      { path: '/admin', label: 'Console' }
    ] },
  { title: 'Protocols',
    what: 'One page per family, each configuring or reporting what that ' +
          'protocol does here.',
    items: [
      { title: 'OAuth2 / OIDC',
        what: 'Which authorization server a flow runs against, how long what ' +
              'it issues lasts, and what this service puts into it.',
        items: [
          // FIRST IN ITS GROUP, and the position is the argument for the page
          // existing: the other four are about one aspect each — which server,
          // how long, which claims — and this one is the family's own
          // configuration, which is what a reader who has not decided what
          // they are looking at yet wants first.
          { path: '/admin/oauth2', label: 'OAuth 2.0 / OIDC settings',
            blurb: 'The appconfig rows behind the authorization ' +
                   'server: the issuer identifier, RFC 9700 mode and OAuth ' +
                   '2.1 mode, the ' +
                   'registered redirect URIs and how a loopback one is ' +
                   'matched, Front-Channel Logout, the refresh token\'s idle ' +
                   'timeout and whether a sign-out revokes it, the client ' +
                   'assertion\'s clock skew — and the deliberate defect ' +
                   '<code>oauth2.breakIdTokenNonce</code>, which makes this ' +
                   'service return an ID Token whose <code>nonce</code> is ' +
                   'wrong so that a client can find out whether it checks ' +
                   '(development mode only). ' +
                   'The five a CLIENT may answer for itself — the three ' +
                   'lifetimes, the refresh idle timeout and whether a ' +
                   'sign-out revokes refresh tokens — moved to ' +
                   '<a href="/admin/token-lifetimes">Token lifetimes</a> ' +
                   'on 2026-08-27, which is where their defaults live now.' },
          { path: '/admin/authorization-servers',
            label: 'Authorization servers',
            blurb: 'Several authorization servers in ONE process, told apart ' +
                   'by the path component the two discovery shapes already ' +
                   'carry — RFC 8414 inserts it after the well-known segment ' +
                   'and OpenID Connect Discovery appends the segment to it. ' +
                   'Each has its own issuer, its own keys and its own idea ' +
                   'of what it will accept, so a client can be pointed at a ' +
                   'second one without a second process. A path nobody has ' +
                   'configured publishes the document this service always ' +
                   'published, which is what keeps a client that has never ' +
                   'heard of this page unaffected by it.' },
          { path: '/admin/token-lifetimes', label: 'Token lifetimes',
            blurb: 'How long an access token, an ID Token and a refresh ' +
                   'token issued here are good for, and how far out a clock ' +
                   'may be before this service stops believing one of its ' +
                   'own. Four configuration settings with a page of their ' +
                   'own, written through the same function <a ' +
                   'href="/admin/oauth2">the OAuth 2.0 / OIDC settings</a> ' +
                   'write through — a change made on either page is one ' +
                   'change.' },
          { path: '/admin/claims', label: 'Custom claims',
            blurb: 'What to add to every OAuth 2.0 access token and every ' +
                   'OIDC ID Token this service issues FROM NOW ON. Two sets, ' +
                   'because those two go to different readers and the ' +
                   'interesting configuration is usually the one where they ' +
                   'DIFFER. Additive only: a custom claim is never allowed ' +
                   'to displace one the protocol defines, because an ' +
                   '<code>exp</code> settable from a web form would produce ' +
                   'tokens that fail to verify with nothing pointing back at ' +
                   'the page. Nothing already issued changes — a token is a ' +
                   'signed document and this page cannot reach inside one.' },
          { path: '/admin/userinfo-claims', label: 'UserInfo claims',
            blurb: 'The same two halves for the <strong>UserInfo ' +
                   'response</strong>, and the one claims page here with no ' +
                   '"nothing already issued changes" warning on it — which ' +
                   'is the point of it being a page of its own. That ' +
                   'response is built on EVERY call, so a claim added here ' +
                   'reaches a client that signed in an hour ago and has done ' +
                   'nothing since. It is also the one claim set a CLIENT can ' +
                   'add to: OpenID Connect Core section 5.5\'s ' +
                   '<code>claims</code> request parameter names individual ' +
                   'claims, and they are answered off that person\'s entry ' +
                   'under <code>ou=users</code>.' }
        ] },
      { title: 'SAML',
        what: 'BOTH identity providers — SAML 2.0\'s Web Browser SSO profile ' +
              'and SAML 1.1\'s two browser profiles, each with its relying ' +
              'parties and the metadata each one is configured from — and ' +
              'what this service puts into an assertion, 2.0 and 1.1 alike, ' +
              'which is also what WS-Trust and WS-Federation carry. The two ' +
              'profiles are separate pages because they are separate ' +
              'implementations: SAML 1.1 has no request message and no ' +
              'Single Logout, so half of what the 2.0 page reports has no ' +
              'spelling over there.',
        items: [
          { path: '/admin/saml2', label: 'SAML 2.0 identity provider',
            blurb: 'Every service provider this identity provider has been ' +
                   'asked about, what each one was sent and over which ' +
                   'binding, and what this service calls ITSELF to each of ' +
                   'them. What goes INTO the next assertion moved to ' +
                   '<a href="/admin/saml-assertions">SAML assertions</a> ' +
                   'on 2026-08-27, because those five are per application ' +
                   'now and this page configures the identity provider. ' +
                   'Metadata is published PER service provider — the ' +
                   'identity provider names itself differently to each one, ' +
                   'the way Okta and Ping do — and it is minted for anything ' +
                   'asked for, so nothing has to be registered here first: ' +
                   'asking for a service provider\'s metadata is what ' +
                   'creates it.' },
          { path: '/admin/saml11', label: 'SAML 1.1 identity provider',
            blurb: 'The same, for the older profiles, and it is a SEPARATE ' +
                   'implementation rather than a version flag. SAML 1.1 has ' +
                   'no request message, so a relying party cannot identify ' +
                   'itself in the protocol at all — it is named by ' +
                   'Shibboleth\'s <code>providerId</code>, by the path ' +
                   'segment of a scoped endpoint, or GUESSED from the origin ' +
                   'of the <code>TARGET</code> — and there is no Single ' +
                   'Logout to configure and no request signature to record. ' +
                   'What it has that 2.0 does not is a SOAP responder that ' +
                   'is also an attribute authority.' },
          { path: '/admin/saml-assertions', label: 'SAML assertions',
            blurb: 'THE DEFAULTS EVERY SAML APPLICATION INHERITS: how long ' +
                   'an assertion is valid, whether it and its response are ' +
                   'signed, the NameID format and the artifact lifetime — ' +
                   'five per profile — plus the clock skew written into ' +
                   'both ends of the validity window. Ten of the eleven can ' +
                   'be overridden PER APPLICATION on ' +
                   '<a href="/admin/applications">an application entry</a>, ' +
                   'and this page names the attribute that does it beside ' +
                   'each row; the skew cannot, because it is a fact about ' +
                   'the clocks in this estate rather than about one relying ' +
                   'party. All eleven reach WS-Trust and WS-Federation too — ' +
                   'their assertions come out of the same two builders.' },
          { path: '/admin/saml-attributes', label: 'Custom SAML attributes',
            blurb: 'The same two halves for the assertions: every SAML 2.0 ' +
                   'and SAML 1.1 attribute added to what the two identity ' +
                   'providers, WS-Trust and WS-Federation issue from now on. ' +
                   'One store behind this page and ' +
                   '<a href="/admin/claims">Custom claims</a>; two ' +
                   'vocabularies, because 2.0 has <code>Name</code> and an ' +
                   'optional <code>NameFormat</code> where 1.1 has ' +
                   '<code>AttributeName</code> and a REQUIRED ' +
                   '<code>AttributeNamespace</code>, and one list could not ' +
                   'have served both.' }
        ] },
      { title: 'Verifiable Credentials',
        what: 'Both halves: what the OID4VCI issuer puts in a credential, ' +
              'and what the OID4VP verifier asks a wallet to present.',
        items: [
          // THE ORDER PAIRS EACH PROTOCOL WITH THE PAGE THAT SAYS WHAT GOES
          // THROUGH IT — issuance, then what an issued credential carries;
          // presentation, then what a wallet is asked for. Grouping the two
          // settings pages together instead would put the OID4VP settings
          // three rows from the request they configure.
          { path: '/admin/oid4vci', label: 'OpenID4VCI',
            blurb: 'The issuer\'s own settings: which wallet the offer pages ' +
                   'send somebody to, which authorization server the ' +
                   'credential endpoint trusts a token from, how many ' +
                   'credentials one request may ask for, how long a deferred ' +
                   'issuance pretends to take, whether a credential request ' +
                   'must be encrypted, and whether the SD-JWT VC and ldp_vc ' +
                   'issuers name themselves by DID or by URL — the one ' +
                   'choice here that changes what a verifier has to resolve.' },
          { path: '/admin/vc', label: 'Credential claims',
            blurb: 'Which claims a Verifiable Credential issued from now on ' +
                   'carries, chosen from a catalogue of LDAP attribute TYPES ' +
                   'rather than of claim names: the value of a claim is the ' +
                   'value on that person\'s directory entry. Saving a ' +
                   'selection also populates the directory, so an LDAP ' +
                   'client and a wallet describe one person. It applies to ' +
                   'all five OID4VCI configurations at once.' },
          { path: '/admin/vc-status', label: 'Credential status',
            blurb: 'This realm\'s status lists — the Token Status List every ' +
                   'JOSE credential names and the two Bitstring Status ' +
                   'Lists the W3C ones name — where they are served, and ' +
                   'every issued credential\'s index and status, with ' +
                   'Suspend, Reinstate and Revoke. A revoked or suspended ' +
                   'credential is refused by every verifier that reads the ' +
                   'list, this one included, and signs nobody in.' },
          { path: '/admin/oid4vp', label: 'OpenID4VP',
            blurb: 'The verifier\'s own settings: the client identifier it ' +
                   'presents as, where it sends a holder to present, how ' +
                   'fresh a Key Binding JWT has to be, and the claims its ' +
                   'request asks for by default. The DCQL query itself is on ' +
                   '<a href="/admin/vc-verifier-config">Verifier request</a> ' +
                   'next door — these four are the settings around it.' },
          { path: '/admin/vc-verifier-config', label: 'Verifier request',
            blurb: 'The other end of that lifecycle: what the mock Verifier ' +
                   'at <code>/oid4vp/verifier</code> asks a wallet for, and ' +
                   'in which credential format. It reaches the wire as the ' +
                   '<code>dcql_query</code> of the next OID4VP ' +
                   'Authorization Request, and it is what the presentation ' +
                   'is then checked against — a claim asked for and not ' +
                   'presented fails by name.' }
        ] },
      // A GROUP OF FIVE, and the heading names more than any one page does —
      // which is the test the SAML group set and the one SCIM fails, so SCIM
      // is ungrouped one row below and this is not. XACML here is a decision
      // point, a repository, an editor, the enforcement points elsewhere that
      // pull it, and a way to try the thing — five ways of saying what
      // authorization is CONFIGURED to do.
      //
      // IT WAS A GROUP OF SIX UNTIL 2026-09-06 and the page that left is the
      // one worth recording: `/admin/xacml/monitor` is about TRAFFIC rather
      // than configuration, so it belongs in Monitoring with every other page
      // that answers "what has this service done", and it is there now. It is
      // still drawn by `xacml/xacml_admin.ts` and still lives under
      // `/admin/xacml/` — a console page is a `path` and a `label` in this
      // table whoever builds the body, which is the same arrangement the eight
      // `/admin/ldap/*` pages have with the Directory section. The rule read
      // off it: WHERE A PAGE IS FILED IS DECIDED BY THE QUESTION IT ANSWERS,
      // not by the module that draws it or the path space it sits in.
      { title: 'XACML',
        what: 'Authorization: what this service DECIDES, the policies it ' +
              'decides with, and how to write one.',
        items: [
          { path: '/admin/xacml', label: 'XACML settings',
            blurb: 'What the Policy Decision Point is, whether it is on, and ' +
                   'the one setting that belongs to the Policy ENFORCEMENT ' +
                   'point rather than to the PDP — a deny-biased PEP refuses ' +
                   'an Indeterminate and a permit-biased one allows it, and ' +
                   'they agree on everything else.' },
          { path: '/admin/xacml/policies', label: 'Policies',
            blurb: 'The repository, which IS ou=policies in the embedded ' +
                   'directory rather than a copy of it. Enable a policy, ' +
                   'disable it without deleting it, choose which one is the ' +
                   'ROOT the PDP starts from, and create one from an RBAC or ' +
                   'ABAC template.' },
          { path: '/admin/xacml/editor', label: 'Policy editor',
            blurb: 'The guided editor. Every element offers exactly what ' +
                   'XACML allows at that point — computed on the server by ' +
                   'the same code that validates the result, so it cannot ' +
                   'offer something that will then be refused. There is no ' +
                   'draft state: the policy you are editing is the policy ' +
                   'the PDP is using.' },
          { path: '/admin/xacml/peps', label: 'Remote PEPs',
            blurb: 'The Policy Enforcement Points in OTHER processes that ' +
                   'pull this repository and enforce it there. They hold ' +
                   'their own copy of the engine, so the question this page ' +
                   'answers is not whether they are up but whether ' +
                   'everybody is deciding with the SAME policy &mdash; ' +
                   'which is the question a distributed authorization ' +
                   'deployment actually has and the one nothing else here ' +
                   'can answer. Nothing on it reaches into another process.' },
          { path: '/admin/xacml/decide', label: 'Try a decision',
            blurb: 'Ask the PDP about somebody and see the answer, which ' +
                   'policies applied, what the PIP found on their directory ' +
                   'entry, and — separately — what the embedded PEP would do ' +
                   'with it. The last two are different answers, and when a ' +
                   'policy "is not working" it is nearly always because only ' +
                   'one of them was being looked at.' }
        ] },
      { path: '/admin/scim', label: 'SCIM',
        blurb: 'The provisioning endpoint at <code>/scim/v2</code>: what it ' +
               'requires of a caller, which of RFC 7644 section 2\'s six ' +
               'schemes it will take, and what it has written. It is the ' +
               'only protocol family here whose purpose is to WRITE, and ' +
               'what it writes is the embedded directory — there is no ' +
               'second store and no cache, so a <code>POST ' +
               '/scim/v2/Users</code> and an <code>ldapadd</code> create the ' +
               'same entry and somebody provisioned over SCIM appears on ' +
               '<a href="/admin/users">Users</a>.' },
      // SHARED SIGNALS AND ITS TWO VOCABULARIES ARE ONE GROUP (rcbj,
      // 2026-10-01): Protocols -> SSF holds the Shared Signals page and the
      // CAEP and RISC pages. They were three rows side by side, argued apart
      // because SSF is the PIPE and CAEP and RISC are VOCABULARIES over it —
      // which is still true, and is now said by the heading: a reader looking
      // for either vocabulary finds it under the pipe it is spoken over. The
      // paths did not move; NAV is derived, so nothing else changed.
      { title: 'SSF',
        what: 'The Shared Signals Framework and the two event vocabularies ' +
              'spoken over it: CAEP, about sessions, and RISC, about ' +
              'accounts. The streams, their receivers and every setting ' +
              'that decides what is sent are here; what was sent is under ' +
              'Monitoring.',
        items: [
          { path: '/admin/ssf', label: 'Shared Signals',
            blurb: 'The <strong>Shared Signals Framework</strong> (OpenID ' +
                   'SSF 1.0): the streams this transmitter has agreed, who ' +
                   'each one is about, what is queued for it and what a ' +
                   'receiver refused. It is the one protocol family here ' +
                   'that TALKS BACK &mdash; every other answers a request, ' +
                   'and this one delivers a Security Event Token nobody ' +
                   'asked for, at the moment something happens. <strong>SSF ' +
                   'is the pipe and not the vocabulary</strong>: it defines ' +
                   'two events of its own, both about the pipe, and the ' +
                   'vocabularies are <a href="/admin/caep">CAEP</a> (what ' +
                   'happened to a SESSION) and <a ' +
                   'href="/admin/risc">RISC</a> (what happened to an ' +
                   'ACCOUNT). TWO things here generate an event on their own ' +
                   'now, and they watch different registers: CAEP, where a ' +
                   'session starting, being presented or ending sends a ' +
                   'Security Event Token with nobody having asked, and RISC, ' +
                   'where a change to the DIRECTORY does.' },

          { path: '/admin/caep', label: 'CAEP',
            blurb: 'The <strong>Continuous Access Evaluation ' +
                   'Profile</strong> (OpenID CAEP 1.0, final 2 September ' +
                   '2025): the enterprise SESSION vocabulary spoken over <a ' +
                   'href="/admin/ssf">Shared Signals</a>. Eight event types ' +
                   '&mdash; session revoked, established and presented, ' +
                   'token claims change, credential change, assurance level ' +
                   'change, device compliance change, risk level change ' +
                   '&mdash; each with the members the specification gives it ' +
                   'and the four it gives them all. <strong>It is the one ' +
                   'page here that configures this service to act without ' +
                   'being asked</strong>: with <code>caep.autoEmit</code> ' +
                   'on, a sign-in, a single sign-on and a sign-out each send ' +
                   'an event to whoever agreed to be told. All eight fire on ' +
                   'their own (device compliance since #164), and this page ' +
                   'also carries the form that emits one by hand, on demand.' },

          { path: '/admin/risc', label: 'RISC',
            blurb: 'The <strong>Risk Incident Sharing and ' +
                   'Coordination</strong> profile (OpenID RISC Profile ' +
                   'Specification 1.0, published 29 August 2025 and final on ' +
                   '2 September 2025): the ACCOUNT vocabulary spoken over <a ' +
                   'href="/admin/ssf">Shared Signals</a>, and the second of ' +
                   'the two. Fourteen event types &mdash; account disabled, ' +
                   'enabled and purged, credential change required, ' +
                   'credential compromise, identifier changed and recycled, ' +
                   'the four opt-out events, recovery activated and recovery ' +
                   'information changed, and one that RISC itself deprecates ' +
                   'in favour of a CAEP event. <strong>Eleven of them carry ' +
                   'no payload members at all</strong>, so the subject is ' +
                   'the entire message, which is what makes ' +
                   '<code>risc.subjectFormat</code> the most consequential ' +
                   'setting on the page. With <code>risc.autoEmit</code> on, ' +
                   'a person deleted from the directory, an account marked ' +
                   'inactive and a changed mail address each send an event ' +
                   '&mdash; a DIFFERENT observer from CAEP\'s, watching the ' +
                   'directory rather than the sessions.' },
        ]
      },

      // PROTOCOLS → DELEGATION (2026-10-01, rcbj): every control that was on
      // Monitoring → Delegation. Ungrouped for Federation's reason below —
      // delegation spans three families (Kerberos, WS-Trust, RFC 8693) and
      // the permissions it configures are OAuth scopes — and under Protocols
      // because it is CONFIGURATION; the acts it is read against stay in
      // Monitoring, which no longer changes anything.
      { path: '/admin/delegation-settings', label: 'Delegation',
        blurb: 'The delegated permissions register, configured: which ' +
               'RESOURCE applications expose an API under a base URI, the ' +
               'permissions each defines on it, and which CLIENT ' +
               'applications hold them — Expose an API, Define a ' +
               'permission, Remove and Revoke for every application — and ' +
               '<code>delegation.maxRecords</code>, how many acts ' +
               '<a href="/admin/delegation">Monitoring &rsaquo; ' +
               'Delegation</a> keeps. A grant is made on an application\'s ' +
               'own Permissions tab, from either end.' },

      // UNGROUPED, beside SCIM, and the placement needed the same argument the
      // delegation page needed. Federation spans FIVE protocol families, so
      // under any one of the groups above it would mean choosing which four
      // fifths of the answer to hide — which is exactly what put
      // /admin/delegation in Monitoring. It does not go there, though: that
      // page is an OBSERVATION and this one is CONFIGURATION, and it is the
      // only page in this console that configures something a protocol
      // endpoint will REFUSE on. A section of its own was considered and
      // fails this console's own test for one — the heading would name
      // nothing the page under it does not.
      { path: '/admin/federation', label: 'Federation',
        blurb: 'Relationships with a FOREIGN identity service, in either ' +
               'direction, in five protocols — consuming somebody else\'s ' +
               'assertions as a service provider, or asserting to a foreign ' +
               'service provider with a per-partner attribute release ' +
               'policy. It is the one page in this console that configures a ' +
               'REFUSAL: everywhere else this service accepts what it is ' +
               'given, and it cannot do that at an assertion consumer ' +
               'service, because what arrives there is an unauthenticated ' +
               'request claiming to be a person and the session it would ' +
               'produce is the same one every other family and this console ' +
               'read. So a relationship is created DISABLED and an assertion ' +
               'is refused unless it verifies against the certificate ' +
               'configured on it.' },
      // OPENID FEDERATION 1.1 (#132, 2026-09-23), beside Federation because a
      // reader looking for one looks for the other — and a separate page,
      // because it is a different thing: TRUST THROUGH A CHAIN of signed
      // statements, where `/admin/federation` is a bilateral relationship
      // with one pinned key. Drawn by oidfed/oidfed_admin.ts.
      { path: '/admin/oidfed', label: 'OpenID Federation',
        blurb: 'This realm as an OpenID Federation 1.1 entity: its Entity ' +
               'Configuration and role (Trust Anchor, Intermediate or Leaf), ' +
               'its Federation Entity Keys and their history, the ' +
               'subordinates it vouches for and the Trust Anchors it ' +
               'trusts, the Trust Marks it issues and carries, resolving ' +
               'another entity\'s Trust Chain, and the ' +
               '<code>oidfed.*</code> settings.' },
      // CLAIMS PROVIDERS (#147, 2026-09-24), beside the two above for the same
      // reason: another party this realm is configured to trust, here for
      // claims about a person — OpenID Connect aggregated and distributed
      // claims. Drawn by oauth-oidc/claims_providers_admin.ts.
      // OPENID PROVIDER COMMANDS (#151, 2026-09-26), beside Claims
      // Providers for the same reason: another party this realm acts
      // towards, here telling relying parties what to do with an account.
      // Drawn by oauth-oidc/provider_commands_admin.ts.
      { path: '/admin/commands', label: 'Provider Commands',
        blurb: 'OpenID Provider Commands: each client\'s command_endpoint ' +
               'and what it supports, sending an account command about a ' +
               'person or a tenant command about everybody, what each ' +
               'relying party said about each account, tenant runs, and ' +
               'the deliveries.' },
      { path: '/admin/claim-providers', label: 'Claims Providers',
        blurb: 'The OpenID Providers this realm fetches claims from for a ' +
               'person who linked one on the portal, passed to a relying ' +
               'party as aggregated or distributed claims (OpenID Connect ' +
               'Core 5.6.2): the register, the redirect URI to register at ' +
               'each, every person\'s link, and revoking one.' },

      // FIVE PAGES ADDED ON 2026-08-27, AND EVERY ONE OF THEM EXISTS BECAUSE
      // ITS FAMILY HAD SETTINGS AND NO PAGE. Kerberos has nineteen appconfig
      // rows, SCIM has eighteen and SPIFFE twenty-eight — and until this date
      // only the last two were reachable from a page about the protocol they
      // configure. The other five families' settings were on /admin/config
      // among a hundred and fifty-four rows, which is the same as being
      // nowhere for anybody who looked under the protocol first.
      //
      // They are UNGROUPED, beside SCIM and Federation, for the reason a group
      // of one is refused everywhere else here: the heading would say the
      // label twice. They come after those two rather than before, in the
      // order the families arrived in this service, because there is no
      // ranking between them that a reader would predict — alphabetical would
      // put TLS before WS-Trust and teach nobody anything.
      // ---------------------------------------------------------------
      // THE TWO SECOND FACTORS, UNDER PROTOCOLS (2026-09-10).
      //
      // A group of two would be a heading that said the label twice, so they
      // are two flat items — the arrangement /admin/federation and
      // /admin/scim already have. They sit together and before Kerberos
      // because they are the two mechanisms a PERSON authenticates with here
      // beside a password, and somebody looking for one is usually about to
      // look at the other.
      //
      // **WHO HOLDS ONE IS NOT HERE.** That is <a
      // href="/admin/users">Users</a>, which is filed under Directory — where a
      // page is FILED is decided by the question it answers, and these two
      // answer *what does the mechanism do*.
      // ---------------------------------------------------------------
      // GNAP (RFC 9635 + RFC 9767), 2026-09-12. A FLAT item rather than a
      // group: its one Protocols page carries the settings, the endpoints, the
      // authorization server capabilities, the grants and the resource sets,
      // and the traffic page is filed under Monitoring by the question it
      // answers. Both are drawn by gnap/gnap_admin.ts.
      { path: '/admin/gnap', label: 'GNAP',
        blurb: 'The Grant Negotiation and Authorization Protocol (RFC 9635) ' +
               'and its resource server connections (RFC 9767): one ' +
               'authorization server per trust realm and per named ' +
               'authorization server. The endpoints, what each authorization ' +
               'server offers, the five token formats and their verification ' +
               'material, the grants it is holding, the resource sets ' +
               'registered with it, and the <code>gnap.*</code> settings. ' +
               '<strong>A key proof is verified in every mode</strong> ' +
               '&mdash; what is mode-gated is whether a proved key nobody ' +
               'registered is admitted.' },
      { path: '/admin/totp', label: 'TOTP MFA',
        blurb: 'An authenticator app as a second factor &mdash; RFC 6238 ' +
               'over RFC 4226 &mdash; and the eight parameters the ' +
               'specification leaves open: the digest, the digits, the ' +
               'length of a step, how much clock skew is forgiven, the ' +
               'secret length, the label a phone shows, and how long an ' +
               'unconfirmed enrolment lives. <strong>Codes are checked FOR ' +
               'REAL in every mode</strong>, which almost nothing else on ' +
               'this service is &mdash; a permissive one-time password ' +
               'verifier is not permissive, it is broken. Changing the ' +
               'digest, the digits or the period affects NEW enrolments ' +
               'only; the skew window applies to everybody. Who actually ' +
               'holds one, and the Clear that is the only way back for a ' +
               'lost phone, are on that person\'s row under <a ' +
               'href="/admin/users">Users</a>.' },
      { path: '/admin/backup-codes', label: 'Recovery codes',
        blurb: 'The way back in when the second factor is not to hand ' +
               '&mdash; a set of single-use codes a person generates for ' +
               'themselves, standing in for an authenticator app or a ' +
               'security key in the <code>mfa</code> role. <strong>The ' +
               'only mechanism on this console that no specification ' +
               'defines</strong>: there is no RFC for a recovery code, so ' +
               'every decision behind it is this service\'s own and ' +
               '<code>common/backup_codes.ts</code> argues each one. Since ' +
               '2026-09-11 it is <strong>hashed with scrypt, the same way a ' +
               'password is</strong> &mdash; it was encrypted until then, so ' +
               'that a person could read their remaining codes back, and ' +
               'hashing is what made that impossible. A person GENERATES ' +
               'their own set from the user portal, is shown it once, and it ' +
               'is stored only when they confirm they have saved it; ' +
               'generating again REPLACES. There is no control on THIS ' +
               'console that issues a set &mdash; a set belongs to the ' +
               'person and is generated from their own account page. Who ' +
               'holds one, how many they have left, and the Clear that ' +
               'removes a set an operator has reason to distrust, are on ' +
               'that person\'s row under <a href="/admin/users">Users</a>.' },
      { path: '/admin/webauthn', label: 'WebAuthn',
        blurb: 'Security keys &mdash; W3C WebAuthn Level 3 over FIDO CTAP2 ' +
               '&mdash; as a second factor OR as the only credential on an ' +
               'account, the settings behind the ceremony, and what is done ' +
               'with an authenticator\'s attestation statement. ' +
               '<strong>There were none of these until 2026-09-10</strong>: ' +
               'the RP name, the algorithms offered, the user verification ' +
               'requirement, the attestation conveyance and the timeout were ' +
               'literals in a string, and this service said there was ' +
               'nothing an operator could usefully turn &mdash; which was ' +
               'true of the cryptography and false of the ceremony. One of ' +
               'them is ENFORCED and the rest are requests: user ' +
               'verification is checked against a flag inside the bytes the ' +
               'authenticator signed, and nothing signed says what the ' +
               'browser was asked about attestation, the resident key or the ' +
               'attachment. Who holds a key is on that person\'s row under ' +
               '<a href="/admin/users">Users</a>.' },
      // DEVICE REGISTRATION (#164, #218, 2026-09-26): HOW a device comes to
      // be in the register and how it is recognised — the enrolment
      // methods, attestation, the MDM feed — and every `devices.*` setting.
      // Under Protocols because those are the protocol doors a device
      // arrives through (Native SSO today; EST, SCEP, WebAuthn and JWK
      // proofs as #164's phase 2 builds them); the register itself is
      // Directory → Devices, and what it did is Monitoring → Devices.
      // Drawn by `admin-ui/devices_admin.ts`.
      { path: '/admin/device-registration', label: 'Device registration',
        blurb: 'How a phone, a computer or a host comes to be in this ' +
               'realm\'s device register and how it is recognised again: ' +
               'each enrolment method and whether it is built, the kinds of ' +
               'key a device is known by, what attestation means here, and ' +
               'every <code>devices.*</code> setting &mdash; how many ' +
               'devices a person or an application may own and how many ' +
               'keys one device may hold.' },
      // A GROUP OF TWO SINCE 2026-09-13, asked for by rcbj. The two pages were
      // flat siblings — `Kerberos` and `Kerberos principals` — on the argument
      // that a `Kerberos` heading over a `Kerberos` page would say the label
      // twice. That test is about the LABELS, and renaming the settings page
      // `Kerberos settings` (the `XACML settings` and `OAuth 2.0 / OIDC
      // settings` shape) answers it; the heading now names more than either
      // page does, which is the test a group has to pass. The stored keys are
      // under Protocols and not Directory because the question they answer is
      // what the KDC holds a key for, which is configuration of that protocol
      // — even though both halves of the store are directory entries.
      { title: 'Kerberos',
        what: 'The KDC: its settings, and the long-term keys it holds for ' +
              'people and services.',
        items: [
          { path: '/admin/kerberos', label: 'Kerberos settings',
            blurb: 'The KDC\'s own settings: the realm, the two raw ports, ' +
                   'the clock skew and the deliberate clock OFFSET, the one ' +
                   'password every user account shares, the names that stay ' +
                   'unknown so a client can be shown a real KDC error, the ' +
                   'long-term keys behind krbtgt and the inter-realm trust, ' +
                   'and whether a ticket presented at ' +
                   '<code>/authn/spnego</code> may start a browser session ' +
                   'at all. Most of them are restart-only: the principal ' +
                   'database is built from them when the process starts.' },
          { path: '/admin/kerberos/principals', label: 'Principals',
            blurb: 'Who this KDC holds a stored long-term key for: the ' +
                   'directory people whose keys were derived from their own ' +
                   'password (product mode) with the kvno and enctypes and ' +
                   'whether the keys still match the password, and the ' +
                   'SERVICE principals an operator created here with a ' +
                   'random key. A create or a rotate hands over an MIT ' +
                   'keytab ONCE; no page ever shows a key. Delete and clear ' +
                   'controls need Admin Write.' } ] },
      { path: '/admin/ldap', label: 'LDAP / LDAPS',
        blurb: 'The embedded directory\'s two raw sockets and the store ' +
               'behind them: the ports, the base DN every realm\'s subtree ' +
               'hangs under, whether a name seen for the first time gets an ' +
               'entry, and the two ceilings that keep a mock from being ' +
               'filled up. What is IN the directory is on ' +
               '<a href="/admin/users">Users</a> and ' +
               '<a href="/admin/groups">Groups</a>; this page is the ' +
               'directory itself.' },
      { path: '/admin/wstrust', label: 'WS-Trust',
        blurb: 'The security token service at <code>/sts</code>, ' +
               'WS-Trust 1.0 to 1.4, and the one setting it has of its own — ' +
               'who its tokens say issued them. What an assertion CONTAINS ' +
               'is the SAML pages next door, because the assertion is built ' +
               'by the same two functions the SAML profiles use.' },
      { path: '/admin/wsfed', label: 'WS-Federation',
        blurb: 'The passive requestor profile at <code>/wsfed</code>, its ' +
               'entity ID, and the mock relying party that checks a sign-in ' +
               'response line by line. The assertion it carries is a SAML ' +
               '1.1 one, so its issuer and its attributes are configured on ' +
               'the SAML pages — this page says which setting is which and ' +
               'links to them rather than offering a third form onto the ' +
               'same value.' },
      // PKI, UNGROUPED, BESIDE TLS AND SCIM. A group of its own would be a
      // heading naming nothing the one page under it does not — this
      // console's own test for one, applied the way Federation and SCIM are
      // filed. It goes NEXT TO TLS deliberately: they are the two pages here
      // about X.509, and a reader who has just read that a verified client
      // certificate starts a session is one keystroke from the page that
      // issues certificates.
      { path: '/admin/pki', label: 'PKI',
        blurb: 'A <strong>certificate authority this service maintains for ' +
               'this trust realm</strong> — Root CA, Intermediate CA, ' +
               'Issuing CA — and the signing key pairs it issues from the ' +
               'bottom of it to applications. It exists for <strong>RFC 7521 ' +
               'and RFC 7523</strong>: an application authenticates at the ' +
               'token endpoint, or presents an authorization grant, with a ' +
               'signed assertion instead of a shared secret, and a signing ' +
               'key nobody vouched for is a key an operator has to move by ' +
               'hand. All three tiers are built in one act or none is — a ' +
               'half-built hierarchy is exactly the state in which somebody ' +
               'issues a certificate that verifies here and nowhere else. ' +
               'ONE ROOT CA FOR THE SERVICE, an Intermediate CA per realm ' +
               'and per the process, and an Issuing CA under each for ' +
               'every use case — so one anchor covers every key this ' +
               'service holds. It was a Root PER REALM until 2026-09-11, ' +
               'on the argument that a CA shared across realms would be ' +
               'one authority vouching for several identity services. ' +
               'Every authority on it signs a CRL and answers OCSP, and a ' +
               'certificate replaced or rotated goes on its issuer\'s list ' +
               'as superseded without anybody asking — but this service ' +
               'CONSULTS no list of its own or anybody else\'s, so a ' +
               'certificate revoked here still authenticates here. Taking a ' +
               'key pair off an application is a third thing again: it stops ' +
               'this service ACCEPTING what that key signs and puts nothing ' +
               'on any list. The encoder is the parent ' +
               'project\'s own PKI code, vendored byte-identical, so a ' +
               'certificate issued here and one issued on its PKI / X.509 ' +
               'page are built by one encoder.' },
      // CERT ISSUANCE (2026-09-13 as *Certificate enrollment*; RENAMED AND
      // WIDENED 2026-09-22 at rcbj's ask): every protocol by which something
      // asks the certificate authority above for a certificate. It was the
      // three enrollment protocols, with SPIFFE a group of its own beneath
      // them; SPIFFE is IN it now, because an X509-SVID is a certificate this
      // realm's SPIFFE Issuing CA issues (`common/pki.js`) and a reader who
      // has just read PKI is looking for every way this service hands one
      // out, not for three of the four. Each page is still drawn by its own
      // family module (acme/, est/, scep/, spiffe/); the three enrollment
      // pages have a Monitoring twin, grouped there under the same heading.
      { title: 'Cert issuance',
        what: 'ACME, EST, SCEP and SPIFFE all issue from this realm\'s ' +
              'certificate authority. The three enrollment protocols issue ' +
              'to the person or application that authenticated — or, for a ' +
              'holder of Admin Write, to any entry in the realm — and keep ' +
              'every certificate on the entry it names; SPIFFE issues an ' +
              'X509-SVID to a WORKLOAD, against a registration entry rather ' +
              'than a directory identity.',
        items: [
          // ===== ACME section row (acme/acme_admin.ts) =====
          { path: '/admin/acme', label: 'ACME',
            blurb: 'Automatic Certificate Management Environment (RFC 8555): ' +
                   'the directory, accounts bound by External Account ' +
                   'Binding, orders, pre-validated authorizations and ' +
                   'revocation, issuing from this realm\'s ACME Issuing CA.' },
          // ===== EST section row (est/est_admin.ts) =====
          { path: '/admin/est', label: 'EST',
            blurb: 'Enrollment over Secure Transport (RFC 7030): cacerts, ' +
                   'simpleenroll, simplereenroll, serverkeygen and csrattrs, ' +
                   'authenticated by a password, a client secret or a ' +
                   'certificate this realm issued.' },
          // ===== SCEP section row (scep/scep_admin.ts) =====
          { path: '/admin/scep', label: 'SCEP',
            blurb: 'Simple Certificate Enrolment Protocol (RFC 8894): ' +
                   'GetCACaps, GetCACert and PKIOperation over CMS, the RA ' +
                   'certificate, and single-use challenge passwords issued ' +
                   'for one entry and one profile.' },
          // ===== SPIFFE's four pages (spiffe/spiffe_server.ts) =====
          // A GROUP INSIDE THE GROUP (2026-10-01, rcbj's ask): moving SPIFFE
          // into Cert issuance on 2026-09-22 dropped its own heading, and
          // four pages — `Registration entries`, `Agents`, `Brokers` among
          // them — then sat beside ACME, EST and SCEP reading as more
          // enrollment protocols. The heading names a family the pages under
          // it are aspects of, the test any group passes.
          { title: 'SPIFFE',
            what: 'Workload identity: the trust domain, the entries that ' +
                  'decide what a workload gets, the agents that ask for it ' +
                  'and the brokers that ask on a workload\'s behalf.',
            items: [
            { path: '/admin/spiffe', label: 'SPIFFE',
              blurb: 'The trust domain, the signing authority behind every ' +
                     'X509-SVID and JWT-SVID, the four sockets the Workload ' +
                     'API and the SPIRE Server API answer on, and how a ' +
                     'caller at the Workload API is identified — the ' +
                     '<code>transport:</code>, <code>endpoint:</code> and ' +
                     '<code>peer:</code> selectors, and whether an ASSERTED ' +
                     'one is believed. A caller on the Unix socket is ' +
                     'ATTESTED (unix, docker, k8s) and a caller over TCP is ' +
                     'not; an agent is attested by its node attestor.' },
            { path: '/admin/spiffe/entries', label: 'Registration entries',
              blurb: 'Which workload gets which SPIFFE ID, and what an SVID ' +
                     'issued against that entry carries. The store is the ' +
                     'embedded directory under ' +
                     '<code>ou=entries,ou=spiffe</code>, so a form here, an ' +
                     '<code>ldapmodify</code> and the SPIRE Server API\'s ' +
                     '<code>BatchUpdateEntry</code> are three doors onto one ' +
                     'entry, and nothing caches it — a change takes effect ' +
                     'on the next SVID.' },
            { path: '/admin/spiffe/agents', label: 'Agents',
              blurb: 'Every agent that has attested, with what it was given ' +
                     'and when. These entries are a RECORD rather than ' +
                     'configuration — this service wrote all of it when the ' +
                     'agent attested — which is why nothing on an agent is ' +
                     'editable and the ban is the only control.' },
            { path: '/admin/spiffe/brokers', label: 'Brokers',
              blurb: 'Who may call the SPIFFE Broker API — the node proxies ' +
                     'and meshes that ask for a workload\'s SVIDs by ' +
                     'referencing it — and which kinds of reference each may ' +
                     'use. The list is <code>spiffe.brokers</code>, read on ' +
                     'every call.' },
            ] },
        ] },
      { path: '/admin/tls', label: 'TLS / mutual TLS',
        blurb: 'The certificate the main port and LDAPS 636 present, ' +
               'regenerated on every start, and what this service makes of a ' +
               'CLIENT certificate presented to it. The names and addresses ' +
               'that certificate carries are settings here; whether the MAIN ' +
               'port is HTTPS at all is <code>global.https</code> on <a ' +
               'href="/admin/config">Configuration</a>, because it is a fact ' +
               'about the process rather than about this certificate. The ' +
               'two listeners of this service\'s own — 8443, and 9443 which ' +
               'required a client certificate — were deleted on ' +
               '2026-09-16.' },
      // Beside the certificate it configures, and UNGROUPED: a `TLS` heading
      // over `TLS / mutual TLS` would say the label twice.
      { path: '/admin/tls/trust', label: 'Client-certificate truststore',
        blurb: 'Every anchor the main port verifies a client ' +
               'certificate against (LDAPS 636 asks for none) — which, since ' +
               'a verified certificate is an identity here, is the list of ' +
               'whose certificates this service believes. Each row says ' +
               'whether it came from <code>tls.trustAnchorsFile</code> or ' +
                 'was ' +
               'added while the process was running; add PEM certificates or ' +
               'remove one row at a time, in either mode. An anchor added ' +
               'here is kept in the directory ' +
                 '(<code>ou=trustAnchors</code>), ' +
               'so it survives a restart and reaches every process, and ' +
                 'there ' +
               'is deliberately no button that empties it.' }
    ] },
  { title: 'Directory',
    what: 'The embedded LDAP directory, and the identities this service has ' +
          'seen. The two are different questions and these pages keep them ' +
          'apart.',
    items: [
      { path: '/admin/users', label: 'Users',
        blurb: 'Every userid this service has been given as part of an ' +
               'interaction that SUCCEEDED, across all sixteen protocol ' +
               'families, with what each one holds. Click a name for the ' +
               'sessions they are signed in on, the tokens issued on each of ' +
               'those sessions, and the assertions, tickets and credentials ' +
               'issued to them. It also lists the subjects that were never ' +
               'here at all — an exchanged token names one, so does a ' +
               'WS-Trust <code>OnBehalfOf</code> and a Kerberos S4U request ' +
               '— and says so on the row. <strong>A person can be created ' +
               'here ahead of their first sign-in</strong>: the Create box ' +
               'on this page opens <em>New user</em>, where every attribute ' +
               'a person in this directory may carry is a field, only the ' +
               'username is required, a box left empty records NO VALUE, and ' +
               'somebody is given a way IN — a password you type, one ' +
               'generated and shown once, or a single-use activation link ' +
               'shown once at which they choose a password or a security key ' +
               'for themselves. The invented person this console used to ' +
               'create without asking is a button there rather than the ' +
               'default. Nobody is ever removed.' },
      // -------------------------------------------------------------------
      // `/admin/users/new` HAS NO ROW HERE, AND THAT IS A PLACEMENT RATHER
      // THAN AN OMISSION (2026-09-06).
      //
      // It had one for a day, between Users and Groups, and what that row
      // said in the sidebar was that creating a person is a PLACE in this
      // console rather than something you do to the list you are looking at.
      // It is the second: the page is reached from the Create box on
      // `/admin/users` — the box carries the typed name to it — and from the
      // *Create another* link on its own success page. Nothing else links to
      // it and nothing needs to.
      //
      // **THE RULE IT FOLLOWS IS THE ONE `sectionPages()` ALREADY IMPLIED**:
      // a row here is a DESTINATION, and a page that only ever makes sense
      // as the next step from another page is a DRILL-DOWN. Seven pages were
      // already in that position before this one — the two pictures, the
      // delegation chain, the SPIFFE and XACML drill-downs — and none of them
      // has a row either. Neighbouring sections make the same distinction
      // without needing it said: Groups and Roles both create from a form on
      // the list page and neither has a *New group* tab.
      //
      // Three things follow and each is done rather than assumed:
      //
      //   * **It is drawn with `active` = `/admin/users` and an `up`**, so
      //     the Users tab is marked (as a LINK, which is what `up` means to
      //     `navItem()`) and the trail reads
      //     `Admin console › Users › New user`. All seven `respond()` calls
      //     in that handler pass it, including the two refusals and the
      //     success page — a page that lost its trail on the one response
      //     that says "here is a password, once" would be the worst one to
      //     lose it on.
      //   * **`/admin` stops listing it.** `consoleGuide()` is derived from
      //     this table, so a page with no row here is absent from the
      //     Overview list as well as from the sidebar. That is why the Users
      //     blurb above now carries what this row used to say: the front door
      //     still describes the create flow, on the page it belongs to.
      //   * **`GET /admin-api/users/new` STAYS.** Rule 7 requires an
      //     operation for every console PAGE and says nothing against one for
      //     a drill-down; the catalogue it publishes is what a script builds
      //     a create from, and `tests/vendored/bulk_load.js` reads it.
      //     Deleting a working operation to tidy a table would be a
      //     regression dressed as consistency.
      // -------------------------------------------------------------------
      { path: '/admin/groups', label: 'Groups',
        blurb: 'Every group in the embedded LDAP directory, with how many of ' +
               'its members name an entry that is actually there. Click one ' +
               'for every attribute it holds and everybody in it, each ' +
               'member linked back to their row on Users. It reports the ' +
               'DIRECTORY rather than what this service has issued, and the ' +
               'one thing to know about it is that <strong>a group here ' +
               'grants nothing</strong>: no endpoint reads one and nothing ' +
               'decides anything on one. A token can CARRY one — see ' +
               '<code>groups.claim</code> — which is a different sentence. ' +
               'The two named on <a href="/admin/rbac">Admin roles</a> are ' +
               'the exception and grant exactly one thing: this console.' },
      { path: '/admin/roles', label: 'Roles',
        blurb: 'Who holds a role, and what requires one. A role is a name a ' +
               'person, a GROUP or an APPLICATION can be mapped into, and ' +
               'holding one is what this service decides an ISSUANCE on: an ' +
               'application entry names the roles it requires, and nothing ' +
               'is issued for it &mdash; no token, assertion, ticket or ' +
               'session &mdash; to somebody who holds none of them. The ' +
               'decision is made by the XACML PDP against a policy you can ' +
               'read and edit, never by an <code>if</code> in an issuance ' +
               'site. <strong>It is not <a href="/admin/rbac">Admin ' +
               'roles</a></strong>, which is two directory groups that grant ' +
               'this console and nothing else. An application that names no ' +
               'required role requires <code>EVERYBODY</code>, which ' +
               'everybody holds, so an unedited service refuses nobody.' },
      { path: '/admin/applications', label: 'Applications',
        blurb: 'Every relying party this service has been asked about — a ' +
               '<code>client_id</code> at the token endpoint, a ' +
               '<code>wtrealm</code> on a sign-in response, an entityID on ' +
               'an AuthnRequest — with what each one was given and when. An ' +
               'entry usually appears because an identifier was ACCEPTED, ' +
               'and one can also be created here ahead of the first ' +
               'connection, which is what RFC 9700 mode needs if it is to ' +
               'judge a client against its own redirect URIs rather than ' +
               'against a setting. A hand-made entry records that it was ' +
               'made by hand, so it cannot be mistaken for one that turned ' +
               'up once and never came back. <strong>There are TWO ways to ' +
               'add one and both are at the foot of this page</strong>: the ' +
               'short row, which takes an identifier and a name and nothing ' +
               'else, and the <em>New application</em> button beside it, ' +
               'where the PROTOCOL FAMILIES the entry is declared for are ' +
               'ticked from a closed list and its per-protocol identifiers ' +
               'and redirect URIs are typed. In product mode the ' +
               'declaration is enforced — an application is issued nothing ' +
               'through a family it is not declared for — and in ' +
               'development it is a record of intent; the redirect URIs and ' +
               'the secret beside it are what RFC 9700 mode judges the next ' +
               'request against.' },
      // DEVICES (#164, #218, 2026-09-26): the register itself, in Directory
      // because its store is — every device is an entry under `ou=devices`,
      // owned by a person or an application entry. A destination, with a
      // drill-down per device (`?device=`) and a create form on the list,
      // the way Groups creates from its own list. Drawn by
      // `admin-ui/devices_admin.ts`; the entries as the directory holds them
      // are `/admin/ldap/devices` below.
      { path: '/admin/devices', label: 'Devices',
        blurb: 'Every phone, computer and host this realm knows, each owned ' +
               'by ONE person or ONE application: the applications that ' +
               'used it, the keys it is recognised by (a certificate, a JWK ' +
               'or DPoP key, a linked WebAuthn credential, and the Native ' +
               'SSO secret), whether it is attested or self-asserted, its ' +
               'compliance, and when it was last used. Click one to edit ' +
               'it, add or remove a key, give it to another owner or remove ' +
               'it; register one by hand at the foot of the list.' },
      // ATTRIBUTE SOURCES (#94): in Directory because what they write is
      // on people's directory entries, and the register is `ou=
      // attributesources` in this realm's directory.
      { path: '/admin/attribute-sources', label: 'Attribute sources',
        blurb: 'The SQL databases this realm reads people\'s attributes ' +
               'from, onto their entries: each source\'s database, the row ' +
               'it reads and the columns it writes, when it reads (at ' +
               'sign-in, once, on a schedule, on demand) and what a ' +
               'failure does, with its status, a test and a read-now.' },
      // -------------------------------------------------------------------
      // POLICIES (2026-09-12), asked for by rcbj as *Directory → Policies*,
      // with the password policy as the first kind of policy it configures.
      //
      // **IT IS IN DIRECTORY BECAUSE ITS STORE IS**: the profile is an entry
      // under `ou=passwordPolicies` in this realm's directory, like every
      // other page in this section draws a container. It is a DESTINATION
      // rather than a drill-down — nothing else in the console leads to it
      // as a next step — which is the test the two `/new` pages failed.
      //
      // **THE LABEL IS SHARED WITH `/admin/xacml/policies` AND
      // `/admin/ldap/policies`**, and the blurb says the difference on the
      // Overview page rather than leaving it to a reader: those draw
      // `ou=policies`, which holds documents a PDP evaluates, and this draws
      // profiles `credentials.setPassword()` checks. Different sections,
      // different containers; the label is the one rcbj asked for.
      // -------------------------------------------------------------------
      { path: '/admin/policies', label: 'Policies',
        blurb: 'The rules this realm holds a CREDENTIAL to, starting with ' +
               'the <strong>password policy</strong>: a minimum length, how ' +
               'many previous passwords may not be reused, how many symbols, ' +
               'and whether an uppercase letter and a number are required — ' +
               'the <em>default profile</em>, stored as ' +
               '<code>cn=default,ou=passwordPolicies</code> in this realm\'s ' +
               'directory. <strong>Enforced in product mode</strong>, at ' +
               'every door that sets a password: the console, ' +
               '<code>/admin-api</code>, the user portal, an activation link ' +
               'and an LDAP modify. A generated password is drawn to satisfy ' +
               'it in both modes. Beside it, the <strong>authentication ' +
               'policy</strong> (#64): which ways of signing in this realm ' +
               'accepts as a first and as a second factor, and when a second ' +
               'is required — <code>cn=default,ou=authnPolicies</code>, ' +
               'inherited from the default realm by a realm with none. It ' +
               'is not the XACML policy repository, ' +
               'which is <a href="/admin/xacml/policies">Protocols → XACML → ' +
               'Policies</a>.' },
      // -------------------------------------------------------------------
      // `/admin/applications/new` HAS NO ROW HERE EITHER, and it is the
      // second page to leave this table on 2026-09-06. The rule and the three
      // consequences are written out beside the Users row above and are not
      // repeated; `admin-ui/CLAUDE.md` carries the argument.
      //
      // **IT IS A WEAKER CASE THAN `/admin/users/new`'s ONLY IN THAT IT IS
      // EVEN CLEARER.** That page is the ONLY way to create a person, so a
      // reader could at least argue the row was a destination. This one is
      // not even that: `/admin/applications` has carried a short *Add an
      // application* row since it grew its six actions, and both it and this
      // page POST to `/admin/applications` with `action=create` and reach one
      // `createApplication()`. So the sidebar was offering a tab for the
      // LONGER of two forms on one page — which is a fact about that page's
      // layout, not a place in this console.
      //
      // Its `respond()` count is ONE rather than seven, and that difference
      // is the same fact read again: this page posts to the list rather than
      // to itself, so a refusal and a success are the list page's 303 and
      // never a redraw here.
      // -------------------------------------------------------------------
      // -------------------------------------------------------------------
      // THE SECOND GROUP IN THIS CONSOLE, AND THE FIRST OUTSIDE PROTOCOLS.
      //
      // These five pages were `/ldap`, `/admin/ldap/directory`,
      // `/admin/ldap/applications`, `/admin/ldap/federations` and
      // `/admin/ldap/spiffe` until 2026-09-01 — five HTML pages outside the
      // console, in their own shell, with their own CSS, no sidebar, no
      // breadcrumb, no realm switcher and no gate. Every one of them shows what
      // is in this service's directory, which is what the four pages above them
      // show; the only thing that made them a separate surface was where they
      // happened to have been written. They are drawn by `ldap/ldap_server.js`
      // still — a page here is a `path` and a `label` whoever builds it,
      // exactly as `/admin/sts-metadata` is — and they answer in this shell
      // now.
      //
      // THEY ARE A GROUP AND NOT EIGHT MORE ITEMS, and the test is the one
      // stated for SAML above: does the heading name more than the page under
      // it does? It does. The four pages above are each ONE KIND OF THING
      // this service has seen, drawn the way the console draws things; these
      // five are the STORE UNDERNEATH all four, entry by entry and attribute
      // by attribute, which is a different question and one a reader either
      // wants or does not. Ungrouped they would have doubled the length of
      // this section with rows that read as alternatives to Users and
      // Applications rather than as the layer beneath them.
      //
      // THREE MORE JOINED THEM ON 2026-09-05 — `ou=roles`, `ou=policies` and
      // `ou=peps`. Each of those containers' owning modules published a
      // SCHEMA whose comment said it was drawn on a page under
      // `/admin/ldap/*`, and for three of them no such page had ever been
      // written: the export was dead in `common/roles.js` since that
      // afternoon, in `xacml/xacml_store.ts` since XACML phase two and in
      // `xacml/xacml_pep_registry.ts` since phase five. They are drawn by
      // `ldap/ldap_server.js` like the other five, for the reason stated
      // there.
      //
      // WHAT MOVING THEM COST is that they are GATED now: they are `/admin`
      // pages, so the console gate applies and a reader needs a session
      // and a role. That is a real change and it is the right one — a dump of
      // every attribute of every entry includes `oauthClientSecret` and
      // `fedClientSecret` in the clear, and it was the one surface in this
      // service printing those to anybody who could reach the port while the
      // console next door asked for a role to show far less. `/admin-api`
      // mirrors all eight, behind its access token since 2026-09-09, and that
      // is what a test drives.
      { title: 'As the directory holds it',
        what: 'The store underneath the five pages above: every entry, every ' +
              'attribute, and the vocabulary each container uses.',
        items: [
          { path: '/admin/ldap/directory', label: 'Every entry',
            blurb: 'The whole store, DN by DN, with where each entry came ' +
                   'from — seeded, added over LDAP, or created because ' +
                   'somebody authenticated — and every attribute it holds ' +
                   'with every value. It is not LDAP: it is this service ' +
                   'showing its own store, which is how a reader tells an ' +
                   'empty directory from a search filter that matched ' +
                   'nothing. A value too long for its column is shortened ' +
                   'and the whole of it is one hover away.' },
          { path: '/admin/ldap/applications', label: 'Application entries',
            blurb: 'The same applications <a href="/admin/applications">' +
                   'Applications</a> lists, as the DIRECTORY holds them: one ' +
                   'entry per identifier under <code>ou=applications</code>, ' +
                   'every attribute on it, and the published SCHEMA — the ' +
                   'object classes and every attribute name with what sets ' +
                   'it. That schema is why this page exists rather than ' +
                   'being a column on the other one: this directory is ' +
                   'schemaless, so an entry carrying thirty invented ' +
                   'attribute names needs somewhere to say what they mean or ' +
                   'a client reading one back is guessing.' },
          { path: '/admin/ldap/federations', label: 'Federation entries',
            blurb: 'The application registry\'s twin, for ' +
                   '<code>ou=federations</code> — and the one container in ' +
                   'this directory where an <code>ldapmodify</code> is a ' +
                   'SECURITY change. Everywhere else an edit changes what ' +
                   'this service hands out; ' +
                   '<code>fedSigningCertificate</code> decides whose ' +
                   'assertions it will BELIEVE and <code>fedEnabled</code> ' +
                   'turns a partner on. It publishes the schema with a ' +
                   'column the applications page has no need of: which ' +
                   'DIRECTION each attribute is for.' },
          { path: '/admin/ldap/roles', label: 'Role entries',
            blurb: 'The membership half of the role register, as the ' +
                   'directory holds it: one entry per role under ' +
                   '<code>ou=roles</code>, and a person, a GROUP and an ' +
                   'APPLICATION are all first-class members of one. The ' +
                   'other half is not in that container — which roles an ' +
                   'application DEMANDS is <code>appRequiredRole</code> on ' +
                   'the application\'s own entry — so nothing here refuses ' +
                   'anybody by itself. It also lists the six BUILT-IN roles, ' +
                   'which are computed and in no container at all: an empty ' +
                   '<code>ou=roles</code> is the ordinary state of a service ' +
                   'deciding every issuance against <code>EVERYBODY</code> ' +
                   'and refusing nobody.' },
          { path: '/admin/ldap/policies', label: 'Policy entries',
            blurb: 'The XACML policy repository as the directory holds it: ' +
                   'one entry per policy or policy set under ' +
                   '<code>ou=policies</code>, holding the document itself, ' +
                   'with exactly one of them the root. <strong>A write here ' +
                   'skips the typechecker</strong>, which is not true of any ' +
                   'other door into this repository \u2014 every write ' +
                   'through <a href="/admin/xacml">XACML</a> is statically ' +
                   'validated so that a policy which does not typecheck is ' +
                   'refused rather than answering Indeterminate on every ' +
                   'request, and an <code>ldapmodify</code> reaches the ' +
                   'entry directly.' },
          { path: '/admin/ldap/peps', label: 'PEP entries',
            blurb: 'The remote Policy Enforcement Points that have ' +
                   'registered with this PDP, under <code>ou=peps</code>. ' +
                   'Almost every attribute is a RECORD this service wrote ' +
                   'rather than configuration \u2014 an identity here was ' +
                   'taken from the CLIENT CERTIFICATE the PEP presented and ' +
                   'never from the body it sent. An empty container is not a ' +
                   'feature that is off: a PEP pulls the repository and ' +
                   'converges whether or not it ever registers, and ' +
                   'registering is what buys it the change nudge.' },
          { path: '/admin/ldap/spiffe', label: 'SPIFFE entries',
            blurb: 'The two SPIFFE containers as the directory holds them. ' +
                   '<code>ou=entries</code> is CONFIGURATION — which SPIFFE ' +
                   'ID a workload gets, under which parent, matching which ' +
                   'selectors — and <code>ou=agents</code> is a RECORD of ' +
                   'what has attested, which is why nothing about an agent ' +
                   'is editable anywhere. The entries ARE the registry: ' +
                   'nothing caches them, so an <code>ldapmodify</code> of ' +
                   '<code>spiffeX509SvidTtl</code> changes the lifetime of ' +
                   'the next SVID the Workload API hands out.' },
          { path: '/admin/ldap/devices', label: 'Device entries',
            blurb: 'The device register as the directory holds it: one ' +
                   'entry per device under <code>ou=devices</code>, every ' +
                   'attribute on it, and the SCHEMA &mdash; a key, the last ' +
                   'compliance change and the enrolment are one JSON value ' +
                   'each, and a client reading an entry over 389 has ' +
                   'nowhere else to learn what they mean. The Native SSO ' +
                   'secret\'s hash is withheld here as from every LDAP read.' },
          { path: '/admin/ldap/service', label: 'The directory service',
            blurb: 'The two raw sockets and the store behind them, as they ' +
                   'actually are right now rather than as they are ' +
                   'configured: whether TCP 389 and LDAPS 636 really bound ' +
                   '(this page is HTTP and answers either way, so it is the ' +
                   'only way to tell a running listener from one whose port ' +
                   'was taken), how many entries are held, whether any of it ' +
                   'survives a restart, the bind policy, and the four ' +
                   'structural rules this directory does still enforce. What ' +
                   'the sockets are SET to is ' +
                   '<a href="/admin/ldap">LDAP / LDAPS</a> under Protocols.' }
        ] }
    ] },
  { title: 'Monitoring',
    what: 'What this service has done: how much of it, what came out, and ' +
          'what happened in order.',
    items: [
      { path: '/admin/metrics', label: 'Metrics',
        blurb: 'Every endpoint call by route and status class, every token ' +
               'and artifact this service has issued with how many are still ' +
               'valid, and sessions counted BOTH ways: the browser sign-on ' +
               'sessions this service really holds, and the sessions implied ' +
               'by what it has issued. Every figure is computed when the ' +
               'page is drawn rather than kept up to date as things happen, ' +
               'because "valid" and "expired" are functions of the clock.' },
      // BEFORE Tokens and not after it, and the order is the argument: a
      // session is the thing that is live NOW and a token is what came out of
      // one, so a reader working out what is going on reads them in that
      // direction. It sits under Metrics because that page COUNTS sessions
      // two ways and names none of them — this is the list behind the first
      // of those two figures.
      { path: '/admin/sessions', label: 'Sessions',
        blurb: 'Every session this service is holding RIGHT NOW, across the ' +
               'three protocols that have one: the browser sign-on session ' +
               'every browser family here shares, the Kerberos ' +
               'ticket-granting ticket (a TGT IS the Kerberos session), and ' +
               'the LDAP connection (RFC 4511 makes the Bind a state of the ' +
               'CONNECTION, so in LDAP the connection is the session). Who ' +
               'is signed in, through which protocol, what it carries, when ' +
               'it expires &mdash; and <strong>how that expiry is worked ' +
               'out, which is different in all three</strong>. Each row ' +
               'links to the credentials issued on it and carries a Revoke ' +
               'button that goes through the same termination ' +
               '<a href="/logout">the protocol-independent sign-out</a> ' +
               'uses. What this service has HANDED OUT is ' +
               '<a href="/admin/tokens">Tokens</a>: those outlive every ' +
               'session here.' },
      { path: '/admin/tokens', label: 'Tokens',
        blurb: 'Everything issued and still remembered, in ONE table: every ' +
               'JWT, every SAML assertion (WS-Trust\'s, WS-Federation\'s and ' +
               'both browser profiles\' alike) and every Kerberos ticket, ' +
               'newest first — one table rather than three because a ' +
               'sign-in that produced an ID Token and an assertion is one ' +
               'event. And the buttons that invalidate the ones that can be: ' +
               'one access token, one ID Token, one refresh token, ' +
               'everything for one subject, or everything of one kind. ' +
               'Revocation here is the SAME revocation RFC 7009\'s ' +
               '<code>/oauth2/revoke</code> performs, so introspection, ' +
               'UserInfo and the refresh grant all honour it.' },
      // IMMEDIATELY AFTER TOKENS, AND THE PAIR IS THE ARGUMENT: that page is
      // what this service HANDED OUT and this one is what it was HANDED and
      // spent. Filed under Monitoring rather than beside the RFC 7523 and RFC
      // 7522 settings under Protocols, because it answers "has this assertion
      // been used, by whom, and until when is that remembered" — a question
      // about what happened, which is this section's heading.
      { path: '/admin/used-assertions', label: 'Used assertions',
        blurb: 'Every RFC 7523 JWT and RFC 7522 SAML assertion this realm ' +
               'has ACCEPTED — as client authentication or as an ' +
               'authorization grant — and that has not yet expired. <strong>' +
               'Each is accepted once, ever</strong>: one history for both ' +
               'uses and both profiles, persisted in whatever store is open ' +
               'so a restart forgets nothing, and on postgres claimed ' +
               'atomically so no two processes accept one assertion. An ' +
               'assertion is spent only when the token request it came with ' +
               'issued tokens; a request that failed for another reason ' +
               'releases it. A row is kept until the assertion would have ' +
               'expired and not a moment longer. The <code>jti</code> of ' +
               'every RFC 9101 request object something was issued on is ' +
               'kept here too, as a request object. No control: forgetting ' +
               'a row would make a still-valid assertion usable again.' },
      // Beside the tokens it points at rather than under Protocols, and that
      // was the decision: delegation is the one feature here that is
      // deliberately NOT a protocol family — six of its eight mechanisms come
      // from three different families and the whole value is reading them
      // against each other in one table. Under Protocols it would have had to
      // be filed under one of the three.
      { path: '/admin/delegation', label: 'Delegation',
        blurb: 'Who acted on whose behalf, through what, to reach what: ' +
               'eight mechanisms from three protocol families — Kerberos\'s ' +
               'S4U2Self, two flavours of S4U2Proxy and a forwarded TGT, ' +
               'WS-Trust\'s <code>OnBehalfOf</code> and <code>ActAs</code>, ' +
               'and RFC 8693\'s impersonation and delegation — against ONE ' +
               'model, because the question a reader arrives with is ' +
               'protocol-independent. Beside them, read-only, who MAY ' +
               'delegate to whom and the delegated permissions register; ' +
               'both are changed elsewhere (<a ' +
               'href="/admin/delegation-settings">Protocols &rsaquo; ' +
               'Delegation</a>). ' +
               '<a href="/admin/delegation/map">The picture</a> draws the ' +
               'same acts as a graph, laid out on the SERVER because this ' +
               'console runs no script.' },
      // THE SHARED SIGNALS PAGES ARE A GROUP (2026-09-14), and the fourth is
      // what made them one. CAEP sessions, RISC accounts and Signals received
      // were three loose rows in this section, each argued into Monitoring on
      // its own; a dead-letter page made four answers to one family's "what
      // happened", and four rows a reader has to recognise as one family is
      // what a group is for. The group is filed where the pages were, beside
      // Delegation. Where each page is filed is still decided by the question
      // it answers: Protocols → Shared Signals is what the streams are
      // CONFIGURED to do and holds every control on them; everything here is
      // what happened. The paths did not move, so nothing but this table
      // changed for the three that were already here.
      { title: 'Shared Signals',
        what: 'What this service has said about sessions and accounts, what ' +
              'its own console has been told, and what it could not deliver ' +
              '— in the realm being read.',
        items: [
          // Beside Delegation and for the reason Delegation is beside the
          // tokens it points at: this is an OBSERVATION and not a
          // configuration. The CAEP settings are at /admin/caep under
          // Protocols, and putting the table there with them would have buried
          // the one thing on it no other page in this console can show — a
          // session this service NO LONGER HOLDS, and what was said about it on
          // its way out.
          { path: '/admin/caep-sessions', label: 'CAEP sessions',
            blurb: 'One row per session this service has held, ' +
                   '<strong>including the ones it no longer holds</strong>, ' +
                   'with the CAEP state it is in &mdash; established, ' +
                   'presented, revoked &mdash; its assurance level, its ' +
                   'device compliance, its risk level, and a count of every ' +
                   'CAEP event type sent about it. The register outliving ' +
                   'the session is the point: the session store forgets one ' +
                   'the moment it is signed out, so a row saying ' +
                   '<code>revoked</code> is the only remaining evidence ' +
                   'that it existed and was revoked. Beside it, which ' +
                   'streams would take a CAEP event at all &mdash; because ' +
                   'a count of zero almost always means nobody asked for ' +
                   'that type, and SSF gives a receiver no other notice of ' +
                   'that.' },

          // And the ACCOUNT register beside the session one. Two pages rather
          // than two tables on one, because a session and an account are not
          // the same kind of thing: a session begins, is used and ends and
          // there are many per person, and an account IS the person and
          // outlives every session on it. One page would have had a first
          // column that was sometimes one and sometimes the other.
          { path: '/admin/risc-accounts', label: 'RISC accounts',
            blurb: 'One row per account this service has been told anything ' +
                   'about, <strong>including accounts that no longer ' +
                   'exist</strong>, with the three states RISC tracks: the ' +
                   'lifecycle (active, disabled, purged), the opt-out ' +
                   'state, and whether a credential has been reported ' +
                   'compromised. They move independently &mdash; an account ' +
                   'can be opted out and perfectly healthy &mdash; which is ' +
                   'why they are three columns rather than one word. The ' +
                   'register outliving the account is starker than the CAEP ' +
                   'one outliving a session: a purged account is gone from ' +
                   'the directory entirely, so the row is the only ' +
                   'remaining evidence that anybody was told. Beside the ' +
                   'counts, the events this transmitter built and ' +
                   'deliberately did NOT send, because the account had ' +
                   'opted out.' },

          // THE RECEIVER'S PAGE, after the transmitter's two registers. The
          // Shared Signals settings, the streams and every other receiver's
          // stream are at Protocols → Shared Signals, which is where somebody
          // goes to change what arrives here rather than to read it.
          //
          // **IT IS THE ONE PAGE IN THIS CONSOLE ABOUT SOMETHING THIS CONSOLE
          // WAS SENT.** Every other page here reads a store this process
          // holds; this one reads a queue that was delivered to it over HTTP,
          // signed, addressed to it by name, which it verified. That is the
          // whole difference between a console showing its own notes and an
          // application that is a receiver.
          { path: '/admin/signals', label: 'Signals received',
            blurb: 'Every Security Event Token this console has been ' +
                   'DELIVERED, in the realm being read. This console is a ' +
                   'registered Shared Signals receiver with a stream of its ' +
                   'own (<code>sts-admin-console</code>), seeded at ' +
                   'startup, asking for every CAEP and every RISC event ' +
                   'type — so what is on this page arrived over RFC 8935 ' +
                   'push at <code>/admin/signals/receive</code>, carrying ' +
                   'the stream\'s own bearer token, and was verified ' +
                   'against this service\'s signing key before it was ' +
                   'recorded. Each row opens out into the SET as it ' +
                   'arrived. <strong>An empty page has five causes and only ' +
                   'one of them is &ldquo;nothing has ' +
                   'happened&rdquo;</strong>, so the ones that apply are ' +
                   'named at the top rather than left to be guessed: the ' +
                   'transmitter off, the receivers off, the stream deleted, ' +
                   '<code>ssf.pushDelivery</code> off, or a vocabulary ' +
                   'turned off under it. What a PERSON sees about ' +
                   'themselves is the same delivery to a different ' +
                   'receiver, at <a href="/portal/signals">the user ' +
                   'portal</a>.' },

          // WHAT THIS REALM'S FEDERATION PARTNERS SENT (#373), beside what
          // this console was sent: the same framework with the realm as the
          // RECEIVER. Configured on each relationship (Protocols →
          // Federation); this page only reads. Drawn by
          // ssf/ssf_transmitters_admin.ts.
          { path: '/admin/ssf/transmitters', label: 'Signals from partners',
            blurb: 'The federation partners whose Shared Signals this ' +
                   'realm receives: each relationship\'s stream at its ' +
                   'partner (poll or push) and whether it is healthy, every ' +
                   'Security Event Token that arrived and whether it ' +
                   'verified, the person it named through the ' +
                   'relationship, what the signal-response policy let it ' +
                   'do here, and the sign-ins partners have blocked. ' +
                   'Read only: a partner\'s stream is configured and acted ' +
                   'on from its relationship\'s page.' },

          // LAST IN THE GROUP, because it is what the others cannot show:
          // every one of them is full and correct while a SET is failing to
          // reach its receiver. Its own page rather than a table on
          // /admin/ssf, which already draws each stream's letters in that
          // stream's card: the questions somebody arrives with during an
          // incident — how many, since when, why, which streams, still
          // happening? — are counts over every stream at once. Read-only; the
          // Revive and Drop controls stay on the stream's card, linked from
          // each row. `ssf/ssf_dead_letter_report.ts` computes it.
          { path: '/admin/ssf/dead-letters', label: 'Dead letters',
            blurb: 'Every Security Event Token this realm\'s transmitter ' +
                   'could not deliver and is still holding, counted: how ' +
                   'many, <strong>when</strong> (a timeline over ' +
                   '<code>ssf.deadLetterRetentionS</code>), <strong>why' +
                   '</strong> &mdash; a push that failed, the push backlog ' +
                   'full, a stream declared dead, a SET sent to a dead ' +
                   'stream &mdash; by error code, by the receiver\'s HTTP ' +
                   'status and by event type, and which streams are dead, ' +
                   'half-open or failing. Then the letters themselves, ' +
                   'searched and paged, without their tokens. Two things on ' +
                   'it are <strong>per process</strong> and say so: the push ' +
                   'cap, which every realm shares, and the recent sweeps. ' +
                   'Nothing here resends or drops anything; those controls ' +
                   'are on each stream at ' +
                   '<a href="/admin/ssf">Protocols &rarr; Shared Signals</a>.' }
        ] },

      // OUTBOUND DELIVERIES (#151, 2026-09-26): what this service POSTed to
      // an address a client registered — Back-Channel Logout Tokens, CIBA
      // pings and pushes, OpenID Provider Commands — on the one durable
      // queue, with each kind's dead letters and Retry. Drawn by
      // oauth-oidc/provider_commands_admin.ts.
      { path: '/admin/deliveries', label: 'Outbound deliveries',
        blurb: 'Every Logout Token, CIBA notification and OpenID Provider ' +
               'Command this realm sent to a relying party, by kind: ' +
                 'pending, ' +
               'sent and <strong>dead</strong> — each dead letter with its ' +
               'code and the reason, and a Retry that sends it again as a ' +
               'new generation.' },

      // Beside Delegation and not inside it, and the argument is the one both
      // of that page's pictures rest on: every row there is about two
      // APPLICATIONS, and every row here has a PERSON in it. Merging them would
      // put "webapp1 may reach the API" and "alice let webapp1 read her
      // profile" under one heading, which are the two halves of the question a
      // reader arrives with and are answered by two different registers.
      { path: '/admin/consent', label: 'Consent',
        blurb: 'What a person agreed an application may ask for on their ' +
               'behalf. The authorization endpoint asks the first time a ' +
               'given username signs in to a given <code>client_id</code> ' +
               'for a given scope, and issues nothing until they answer — ' +
               '<code>oauth2.consentRequired</code>, which is ON by default ' +
               'and is the one policy here that is. Answers are ordinary ' +
               'attributes on ordinary entries: <code>oauthConsent</code> on ' +
               'the person, one value per (person, application, scope). ' +
               'Beside them the OVERRIDE — <code>oauthGlobalConsent</code> ' +
               'on an application\'s entry, which skips the prompt for ' +
               'everybody and writes nothing about anybody, so taking one ' +
               'away asks everybody again.' },
      // AFTER CONSENT, AND THE PAIR IS THE ARGUMENT (#142): consent is what a
      // person agreed to, a grant what a client holds on the strength of it.
      // Drawn by `oauth-oidc/grant_management_admin.ts`.
      { path: '/admin/grants', label: 'Grants',
        blurb: 'The OAuth grants clients hold through Grant Management for ' +
               'OAuth 2.0 — each named by a grant_id, created, merged and ' +
               'replaced by ordinary authorization requests, and readable ' +
               'and revocable by its client at /oauth2/grants/{grant_id}. ' +
               'Revoke one here and every refresh token under it is ' +
               'refused on every node.' },
      // AFTER CONSENT AND BEFORE SIGN-OUT, and the pair either side is the
      // argument. Consent is what a person AGREED an application may ask for;
      // this is what the policy DECIDED when something asked. Both are records
      // of a permission question already answered, which is what this
      // section's heading says and what kept it out of the XACML group under
      // Protocols: every other page in that group is CONFIGURATION — the
      // settings, the repository, the editor, the registered enforcement
      // points, the what-if — and this one is the only one about TRAFFIC.
      // A reader asking "why was that request refused" is asking a monitoring
      // question, and the durable half of the answer is the Audit log two rows
      // down. It is drawn by `xacml/xacml_admin.ts` and still lives under
      // `/admin/xacml/`; a console page is a `path` and a `label` in this
      // table whoever builds the body.
      { path: '/admin/xacml/monitor', label: 'XACML decisions',
        blurb: 'What authorization is actually DOING rather than how it is ' +
               'configured: how many decisions are being made, by which ' +
               'enforcement point, and how many of them are refusals. Every ' +
               'PEP is on it &mdash; the three EMBEDDED in this process and ' +
               'every REMOTE one that has registered &mdash; with its own ' +
               'figures. Two things it keeps apart on purpose: <strong>a ' +
               'decision is not an enforcement</strong>, because a ' +
               'deny-biased PEP refuses a NotApplicable that a permit-biased ' +
               'one allows and an undischargeable obligation turns a Permit ' +
               'into a refusal; and <strong>a remote PEP\'s numbers are ' +
               'reported by it</strong> rather than seen here, so the totals ' +
               'are given as here, remote and the sum. The counters are in ' +
               'memory and start with the process; the durable record of a ' +
               'refusal is the <a href="/admin/audit">audit log</a>, and the ' +
               'policies these decisions are made with are under ' +
               '<a href="/admin/xacml">Protocols</a>.' },
      // GNAP's traffic, filed here beside XACML's for the same reason: what the
      // applications using it have DONE is a monitoring question, and the
      // configuration is on Protocols -> GNAP.
      { path: '/admin/gnap/monitor', label: 'GNAP grants',
        blurb: 'Every application that uses GNAP &mdash; client instances ' +
               'and resource servers, declared or seen &mdash; with what ' +
               'each has done since the process started: grants requested, ' +
               'approved and denied, tokens issued by format, rotations, ' +
               'revocations, failed key proofs, introspections and ' +
               'registrations, and the GNAP error codes it was answered ' +
               'with. No reset: the durable record is the Audit log.' },
      // CERT ISSUANCE TRAFFIC (2026-09-13; GROUPED 2026-09-22 at rcbj's ask,
      // under the heading its Protocols counterpart carries). Three flat rows
      // sat here beside the other traffic pages, which read as three
      // unrelated protocols rather than as one question — *what has been
      // issued, and to whom* — asked over three wire formats. **SPIFFE is
      // NOT in this group**, unlike the Protocols one: it has no monitoring
      // page, and a heading listing three of four families is the drift a
      // reader cannot see. Adding one puts it here.
      { title: 'Cert issuance',
        what: 'What each enrollment protocol has done in this realm — the ' +
              'requests, the certificates issued, and the refusals with the ' +
              'code each was answered with. The durable record is the Audit ' +
              'log; these counters are this process\'s own.',
        items: [
          // ===== ACME monitoring row =====
          { path: '/admin/acme/monitor', label: 'ACME enrollments',
            blurb: 'What the ACME server has done in this realm: requests ' +
                   'by operation, certificates issued and revoked, refusals ' +
                   'by error code, the profiles asked for, the accounts and ' +
                   'EAB keys that asked, and the most recent requests.' },
          // ===== EST monitoring row =====
          { path: '/admin/est/monitor', label: 'EST enrollments',
            blurb: 'What the EST server has done in this realm: requests by ' +
                   'operation, certificates issued (and server-generated ' +
                   'keys), refusals by error code, the profiles asked for, ' +
                   'who authenticated and how, and the most recent ' +
                   'requests.' },
          // ===== SCEP monitoring row =====
          { path: '/admin/scep/monitor', label: 'SCEP enrollments',
            blurb: 'What the SCEP server has done in this realm: GetCACaps, ' +
                   'GetCACert and PKIOperation counts, certificates issued, ' +
                   'challenges created and redeemed, refusals by error code ' +
                   'and failInfo, and the most recent requests.' }
        ] },
      // THE AUTHORIZATION SERVER'S OWN TRAFFIC (2026-09-13), filed here and
      // not under Protocols beside `/admin/oauth2` for the XACML monitor's
      // reason: that page is what the server is CONFIGURED to do and this is
      // what it has DONE. Drawn by `oauth-oidc/oauth2_monitor_admin.ts`; a
      // console page is a `path` and a `label` in this table whoever builds
      // the body. It is in SECTIONS, one per mechanism, so the next OAuth
      // mechanism counted is a section of it rather than a row here.
      { path: '/admin/oauth2/monitor', label: 'OAuth 2.0 / OIDC activity',
        blurb: 'What the authorization server has done in this realm, one ' +
               'section per mechanism. RFC 9126 pushed authorization ' +
               'requests first: pushes and refusals, request_uris read, ' +
               'spent, expired and refused at the authorization endpoint, ' +
               'per client with the OAuth errors returned — and every ' +
               'pushed request the store still holds, with a Withdraw ' +
               'button on each. No reset.' },
      // AFTER THE XACML MONITOR AND BEFORE SIGN-OUT, and the pair either
      // side is the argument again: the page above it counts authorization
      // DECISIONS and this one counts PROVISIONING CALLS, and both are the
      // same kind of thing — traffic, in memory, since the process started,
      // with the audit log two rows down as the durable half. It is drawn by
      // `admin.ts` itself and lives under `/admin/scim/`; a console page is a
      // `path` and a `label` in this table whoever builds the body and
      // whatever path space it sits in, which is the rule
      // `/admin/xacml/monitor` established and `/admin/sts-metadata` has had
      // since 2026-08-24.
      //
      // IT IS NOT UNDER PROTOCOLS WITH `/admin/scim`, for that page's own
      // reason: where a page is filed is decided by the QUESTION IT ANSWERS.
      // `/admin/scim` answers "what is this surface" — the schemes, the
      // endpoints, the attribute mapping, the eighteen settings. This one
      // answers "how much traffic is there, from whom, and how much of it is
      // failing", which is what somebody asks when a provisioning client is
      // misbehaving rather than when it is being set up.
      { path: '/admin/scim/monitor', label: 'SCIM metrics',
        blurb: 'What the provisioning surface has actually been asked to do: ' +
               'how many calls, how many worked, how many failed, and ' +
               '<strong>who is calling</strong> &mdash; one row per ' +
               'authenticated principal, with what it used and what it ' +
               'touched. Broken down by API call type with the latency and ' +
               'the bytes each returned, by resource type, by authentication ' +
               'scheme (including the ones at zero, because a scheme that is ' +
               'OFF is the most useful row for somebody asking why a client ' +
               'cannot get in), and by what went back &mdash; status class, ' +
               'status and <code>scimType</code>. Two things it is careful ' +
               'about: <strong>a client is an authenticated principal, not a ' +
               'connection</strong>, because SCIM is stateless HTTP and has ' +
               'nothing to be connected; and <strong>a caller the gate ' +
               'refused is not a client</strong> and appears in no row, even ' +
               'when the credential carried a name. The counters are in ' +
               'memory, per trust realm, and start with the process; the ' +
               'durable record is the <a href="/admin/audit">audit log</a>, ' +
               'and what the surface IS lives on ' +
               '<a href="/admin/scim">Protocols &rarr; SCIM</a>.' },
      // Beside the tokens page rather than under Protocols, and for the same
      // reason delegation is: signing somebody out is deliberately NOT a
      // protocol family. It reaches nine stores across six families and the
      // whole value is doing all of them at once, so filing it under one would
      // be filing it under the wrong one. It is an ACTION page in a section
      // whose heading says "what this service has done" — which /admin/tokens
      // already is, since revoking is a control and that page has four of them.
      { path: '/admin/logout', label: 'Sign-out',
        blurb: 'Name an identity to see everything this service is still ' +
               'holding for them — every browser sign-on session, every ' +
               'token it can still revoke, every outstanding authorization ' +
               'code and credential offer, every directory connection bound ' +
               'as them, and the Kerberos sign-out instant — and to end any ' +
               'of it. It is <a href="/logout">/logout</a> done to somebody ' +
               'else: the same nine stores through the same functions, ' +
               'except that the front-channel notifications cannot be ' +
               'delivered from here. The back-channel Logout Tokens are, and ' +
               'the page lists where each got to.' },
      // AFTER the traffic pages and BEFORE the audit log, and the order is
      // the same widening-detail argument the rest of this section follows:
      // Metrics says how much, the pages between say what came out, this says
      // what was SEALED on the way to the store, and the audit log says what
      // happened in order. It is the last page here whose subject is state
      // rather than history.
      //
      // **IT IS NOT A SECOND `/admin/crypto-metadata`**, which is the filing
      // question somebody will ask: that page is what this service DOES when
      // it signs or encrypts, is identical on a service that started a second
      // ago, and is filed under Protocols with the rest of what this service
      // IS. The numbers on this one go up while a reader watches.
      // AFTER Encryption and before the audit log, on this section's
      // widening-detail order: Encryption is what this service does to what
      // it writes down, and this is what the thing it writes down is DOING.
      //
      // **IT IS NOT A SECOND HALF OF `/admin/persistence`**, which is the
      // filing question somebody will ask: that page is under Settings and
      // answers what this service is CONFIGURED to write down and where,
      // reads the same on a service that started a second ago, and owns the
      // eighteen `persistence.*` settings. The numbers on this one move while
      // a reader watches.
      { path: '/admin/database', label: 'Database',
        blurb: 'Everything PostgreSQL will tell this service about itself ' +
               '&mdash; commits and rollbacks, the buffer cache hit ratio, ' +
               'every backend and every lock, the background writer, the ' +
               'checkpointer and the write-ahead log &mdash; beside the ' +
               'state of the schema this service owns in it: per-table and ' +
               'per-index statistics, sizes, columns, constraints, and which ' +
               'indexes nothing has ever scanned. <strong>The shape of the ' +
               'page is decided by the server it is pointed at</strong>: ' +
               'every statement behind it asks for all of a view\'s columns, ' +
               'because PostgreSQL moves them between major versions and a ' +
               'page naming its own would be wrong on every server but one. ' +
               'A probe the service\'s least-privilege role may not read ' +
               'costs a ROW here and not the page. Empty, with a sentence ' +
               'saying which of three reasons it is, unless ' +
               '<code>persistence.mode</code> is <code>postgres</code>.' },
      { path: '/admin/encryption', label: 'Encryption',
        blurb: 'What this service encrypts AT REST &mdash; its own signing ' +
               'keys, the certificate authority, the assertion key pairs it ' +
               'issues to applications, authenticator secrets, recovery ' +
               'codes and, in product mode on postgres, everything it mints ' +
               '&mdash; with the key that protects it, the algorithm, and ' +
               'how many encryptions and decryptions have happened in this ' +
               'process. It lists what is DELIBERATELY not sealed beside ' +
               'what is, because the question a reader brings is almost ' +
               'always &ldquo;is <em>this</em> encrypted&rdquo; and a table ' +
               'of only the yeses answers it by silence. No sealed value and ' +
               'no opened one appears on it, and it has no control: rotating ' +
               'the key-encryption key is a deployment act, and a ' +
               'decrypt-this button would be the one door onto material no ' +
               'door is supposed to have.' },
      // AFTER Encryption and before the audit log, and the order is this
      // section's widening-detail argument once more: Encryption is what this
      // service seals and with which key, and this is where that key CAME
      // FROM and what the thing holding it is doing. It is the last page here
      // whose subject is a system somebody else is running.
      //
      // **IT IS NOT A SECOND HALF OF `/admin/config`'s Key material group**,
      // which is the filing question somebody will ask: those rows say what
      // this service is CONFIGURED to read and where, and read identically on
      // a service that started a second ago. Everything on this page can be
      // broken while every one of them is right.
      { path: '/admin/secrets', label: 'Secret store',
        blurb: 'Where this service\'s two primordial secrets come from ' +
               '&mdash; the key-encryption key everything it seals is sealed ' +
               'under, and the database password &mdash; whether this ' +
               'process actually read them, and what the store at the other ' +
               'end is doing. For a mounted file that is its path, mode, ' +
               'owner and mtime, and which members are in it if it holds ' +
               'JSON. For HashiCorp Vault or OpenBao it is the whole state ' +
               'the store will publish: initialised, sealed or unsealed, the ' +
               'seal type, the version and build, the cluster and its ' +
               'leader, the certificate this service authenticates with and ' +
               'when it expires, the policies the token it got carries, ' +
               '<strong>what that identity may actually do asked of the ' +
               'store rather than quoted from a policy file</strong>, and ' +
               'every version of the secret the store has kept. For AWS, GCP ' +
               'and Azure it is the metadata each of them publishes &mdash; ' +
               'rotation, the KMS key, version states and staging labels ' +
               '&mdash; through a DESCRIBE rather than a get. <strong>No ' +
               'secret value appears on it, no probe fetches one, and it has ' +
               'no control</strong>: no reveal, no rotate, no test-read. A ' +
               'probe refused with 403 is usually the read-only policy ' +
               'working and is drawn as a row saying so.' },
      // THE CACHES (#74, 2026-09-17), after the secret store and before the
      // audit log: one more page whose subject is the process itself, and
      // the last of them that is state rather than history. Drawn by
      // `admin-ui/caches_admin.ts` out of `common/cache_registry.js`.
      { path: '/admin/caches', label: 'Caches',
        blurb: 'Every cache this service holds in memory &mdash; CRLs and ' +
               'OCSP answers, signed metadata, fetched request objects, ' +
               'parsed policies, the directory\'s indexes, decrypted and ' +
               'derived keys &mdash; with its size against its bound, how ' +
               'many entries are still valid and how many have expired but ' +
               'not yet been evicted, and the hit ratio since the process ' +
               'started. Open one to see its entries, each with how long it ' +
               'is still valid. <strong>Keys only, never values</strong>, ' +
               'and no control: a cache is emptied by the settings that ' +
               'bound it, not by a button. The figures are the answering ' +
               'process\'s own.' },
      // THE WORKER POOLS (#327, 2026-09-28), after the caches and before the
      // scheduler: one more page whose subject is the process itself — what
      // it has forked to do its work, and how that is going. Drawn by
      // `admin-ui/worker_pools_admin.ts` out of the two pool modules.
      { path: '/admin/worker-pools', label: 'Worker pools',
        blurb: 'The three pools of child processes this node runs &mdash; ' +
               'the request workers, the console and portal\'s own ' +
               'workers, and the post-quantum workers every process forks ' +
               'on its first post-quantum job &mdash; each with its workers ' +
               'now, busy and free, its maximum and initial size, how many ' +
               'crashed or never started against how many were stopped, ' +
               'and its average response time. A pool that is off says ' +
               'so. <strong>The figures are this node\'s</strong>, drawn ' +
               'by its front process; no control.' },
      // NODE HEALTH (#329, 2026-09-28), beside the worker pools: the
      // container they all run in — its CPU and memory from the cgroup — and
      // the memory of every one of those processes. Drawn by
      // `admin-ui/node_health_admin.ts`.
      { path: '/admin/node-health', label: 'Node health',
        blurb: 'The container this node runs in &mdash; its CPU ' +
               'utilisation against its quota and its memory against its ' +
               'limit, from its cgroup &mdash; and the Node.js memory of ' +
               'every process in it: the front process, each request and ' +
               'console worker, each post-quantum child, with the total. ' +
               'The ECS task metadata endpoint beside them where there is ' +
               'one. A source that is not there says so. <strong>The ' +
               'figures are this node\'s</strong>, drawn by its front ' +
               'process; no control.' },
      // THE SCHEDULER (2026-09-22, #49), after the caches and before the
      // audit log: the last page whose subject is the process itself, and the
      // one that says whether the background work is being DONE. Drawn by
      // `admin-ui/scheduler_admin.ts` out of `cluster/scheduler.ts`.
      { path: '/admin/scheduler', label: 'Scheduler',
        blurb: 'Every periodic job this service runs &mdash; the ' +
               'session-expiry sweep, the CRL directory refresh, and every ' +
               'job registered after them &mdash; with its schedule, its ' +
               'last run and how it ended, and the time to its next run as ' +
               'a duration and an absolute time in UTC by the database\'s ' +
               'clock. <strong>A cluster job runs once for the whole ' +
               'service</strong>, on the scheduler\'s leader, which the ' +
               'page names; a per-process job has a row per process. ' +
               'Admin Write may run a job now, and on a cluster may ask ' +
               'the leader to hand the scheduler to another node.' },
      // DEVICES (#164, #218, 2026-09-26): what the register holds, counted
      // — by owner kind, compliance, attestation and key kind, and the
      // Native SSO devices bound to a live session against ended ones — and
      // what happened to it over time: creations, removals and evictions at
      // a person's bound. Drawn by `admin-ui/devices_admin.ts`.
      { path: '/admin/devices/monitor', label: 'Devices',
        blurb: 'The device register counted: how many devices persons and ' +
               'applications own, how many are compliant, attested, known ' +
               'by each kind of key, and bound to a live Native SSO sign-in ' +
               'against ended ones &mdash; and, day by day, how many were ' +
               'registered, removed, or evicted to make room at a ' +
               'person\'s bound.' },
      // MAIL (#63, 2026-09-22), after the scheduler: what this service SENT
      // — the outbox, its dead letters, and in development the captured
      // messages. Drawn by `admin-ui/mail_admin.ts` out of `common/mail.ts`;
      // how it is configured to send is Server configuration → Mail.
      { path: '/admin/mail/outbox', label: 'Mail outbox',
        blurb: 'Every message this realm queued &mdash; a reset link, a ' +
               'verification link, a security notice, a test &mdash; to ' +
               'whom, and what became of it: sent, captured (development), ' +
               'pending or a DEAD LETTER an administrator can retry. A sent ' +
               'message keeps no body; in development a captured one is ' +
               'shown whole, links included.' },
      // RISK (#62, 2026-09-22), after the scheduler and before the audit log:
      // the external datasets a risk score reads and the refused passwords it
      // counts. Drawn by `admin-ui/risk_admin.ts` out of `risk/`.
      { path: '/admin/risk', label: 'Risk',
        blurb: 'The external datasets a risk score reads &mdash; ' +
               'geolocation, the network an address belongs to, Tor exits, ' +
               'IP reputation and an operator\'s own allow and deny lists ' +
               '&mdash; each with its active version, whether it is fresh, ' +
               'and every version loaded or refused. Look up what they say ' +
               'about an address, import a list, activate, roll back. ' +
               'Below, every refused password in the realm, attributed to a ' +
               'person and a network and never to a typed name.' },
      // The scoring itself measured (#62): drawn by the same file.
      { path: '/admin/risk-scoring', label: 'Risk scoring',
        blurb: 'The risk scoring system measured over a window: ' +
               'assessments over time by level, how scores and levels ' +
               'fell, every signal beside its factor and how often it ' +
               'fired, decisions, doors and countries, what people said ' +
               'about their own sign-ins, and &mdash; for this process ' +
               '&mdash; how long an assessment takes and the reactions ' +
               'taken.' },
      // GEOLOCATION (#255, 2026-09-26), beside the risk pages whose
      // assessments it counts: `admin-ui/geolocation_admin.ts`.
      { path: '/admin/geolocation', label: 'Geolocation',
        blurb: 'Where the realm\'s people signed in from, on a map: the ' +
               'world with every country shaded by how many people it ' +
               'counts, then a continent, then a country and its cities. ' +
               'Live sessions by default, or everybody over the last day, ' +
               'week or month. Drawn from what risk scoring recorded, so it ' +
               'needs a geolocation dataset on Monitoring &rarr; Risk; a ' +
               'place with too few people to be anonymous is shaded and ' +
               'not numbered.' },
      { path: '/admin/audit', label: 'Audit log',
        blurb: 'What this service was ASKED to do, in the order it was ' +
               'asked, newest first. Every other page here is state; this ' +
               'one is history — Metrics can say the directory holds eleven ' +
               'entries, and only this page can say that a twelfth was ' +
               'created at 14:02 and deleted at 14:03 by somebody bound as ' +
               '<code>uid=carol</code> over LDAPS. It is a ring with a ' +
               'settable cap, so the oldest rows are dropped rather than ' +
               'kept forever.' },
      // THE ERROR CODES (2026-09-12), filed under Monitoring and beside the
      // audit log, by the question it answers rather than by what it lists.
      // A reader arrives here holding a code off an audit row or a log line
      // and wanting to know what failed — and the one column only a running
      // service can draw, how often this realm's held rows carry each code, is
      // an account of what this service has DONE. A catalogue with no such
      // column would belong in the documentation, which is where the rest of
      // this table is published (`docs/error-codes.md`).
      { path: '/admin/error-codes', label: 'Error codes',
        blurb: 'Every way this service can fail or refuse, by subsystem, ' +
               'with what the client is told instead and how many rows in ' +
               'the audit log carry each code right now. A code is an ' +
               'operator\'s name for a condition: it is on the audit row and ' +
               'in the log line, and <strong>it is never sent to a ' +
               'client</strong>, so a protocol\'s own errors are exactly ' +
               'what they always were.' }
    ] },
  { title: 'Server configuration',
    what: 'What this service is set up with, and who may change it.',
    items: [
      // FIRST in this section, above Configuration, and the order is an
      // argument rather than a preference: every page in this console shows one
      // realm, and Configuration in particular WRITES to the realm it is being
      // read in. Somebody who does not yet know that realms exist should meet
      // the page that says so before the page that acts on it.
      { path: '/admin/realms', label: 'Trust realms',
        blurb: 'Several logical copies of this service in one process, told ' +
               'apart by a segment at the front of the path. A realm has its ' +
               'own configuration, its own signing key, its own sessions, ' +
               'codes, tokens, artifacts, statistics and audit log — so a ' +
               'token minted in one does not verify against another\'s ' +
               'JWKS, which is the point of a realm rather than a side ' +
               'effect. What a realm separates is what this service ISSUES: ' +
               'the embedded directory is SHARED, and so are Kerberos, the ' +
               'certificate the main port and LDAPS 636 present, and ' +
               'SPIFFE\'s four sockets, because a socket has no path to put ' +
               'a realm segment in.' },
      { path: '/admin/config', label: 'Configuration',
        blurb: 'Every setting this service has, grouped by the protocol it ' +
               'belongs to, with where each value came from: a runtime ' +
               'override set here, an environment variable, the appconfig ' +
               'file this process was started with, or the defaults that one ' +
               'is unioned on top of. Higher beats lower, and a setting with ' +
               'a value NOWHERE stops the service from starting rather than ' +
               'defaulting quietly. Like every writing page here, it writes ' +
               'the realm it is read IN.' },
      // BESIDE Configuration, because it answers the question that page's
      // `global.mode` row raises: what does the mode change? It is drawn by
      // `admin-ui/mode_admin.ts` (#181) and changes nothing — the setting is
      // written on Configuration.
      { path: '/admin/mode', label: 'Mode',
        blurb: 'What <code>global.mode</code> changes, and what is in force ' +
               'in this realm: every requirement with its development and ' +
               'product answers, every development-only setting with the ' +
               'value stored and the value in force — a product realm ' +
               'ignores a development-only value it still holds — and ' +
               'what product mode still does not check. Read from ' +
               '<code>common/mode.js</code>, the one place the two modes ' +
               'are told apart.' },
      { path: '/admin/persistence', label: 'Persistence',
        blurb: 'Whether anything here survives a restart, and where it is ' +
               'written. THREE things can be — the embedded directory (which ' +
               'is also the applications registry, the federation register ' +
               'and the SPIFFE registry), the trust realm registry, and the ' +
               'runtime setting changes made on pages like Configuration. ' +
               'NOTHING THIS SERVICE MINTS ever is: sessions, tokens, codes, ' +
               'artifacts, tickets, the statistics and the audit log go with ' +
               'the process, because the signing key is regenerated on every ' +
               'start and a token that outlived it would verify against ' +
               'nothing. Three modes: memory, which writes nothing and is ' +
               'the default; ldif, a file per realm and no database; and ' +
               'postgres. It is PERSISTENCE and not COORDINATION — one ' +
               'process per store.' },
      { path: '/admin/cluster', label: 'Cluster',
        blurb: 'Whether several containers against one postgres store ' +
               'behave as one service: which node is a member, which holds ' +
               'which lease, and what active-active mode still refuses to ' +
               'start without. Every clustered write is fenced by the ' +
               'node\'s membership, and a node that loses it exits.' },
      // CELLS (#98, 2026-09-28), beside Cluster: one service deployed as
      // several cells in several jurisdictions. Drawn by
      // `admin-ui/cells_admin.ts`.
      // LISTENERS (#423, 2026-10-02), beside Cells: every socket, its TLS
      // policy and client authentication, a realm's own listener, and their
      // settings. Drawn by `admin-ui/listeners_admin.ts`.
      { path: '/admin/listeners', label: 'Listeners',
        blurb: 'Every socket this service answers on and what each is held ' +
               'to: TLS 1.2 on or off, the TLS 1.3 cipher suites in order, ' +
               'post-quantum only, the key-exchange groups, and whether it ' +
               'asks for a client certificate, requires one, or neither. In ' +
               'a realm with a listener of its own, that listener and its ' +
               'settings; otherwise the default listeners it is served on.' },
      { path: '/admin/cells', label: 'Cells',
        blurb: 'One service deployed as several cells, each a copy of the ' +
               'whole stack in one legal jurisdiction: which cell this is, ' +
               'which others there are and whether they answer, the global ' +
               'tier\'s replica lag, how many people each cell holds, the ' +
               'sessions held away from home, and another cell\'s residents ' +
               'where its release policy permits.' },
      // MAIL (#63, 2026-09-22), beside Cluster: how this service SENDS
      // mail — the transport, where a link points, the realm's wording of
      // each message, a test message, and the Mail settings group. Drawn by
      // `admin-ui/mail_admin.ts`; what it sent is Monitoring → Mail outbox.
      { path: '/admin/mail', label: 'Mail',
        blurb: 'The one outbound mail channel: which transport this realm ' +
               'sends through (SMTP with STARTTLS or implicit TLS and ' +
               'optional DKIM, Amazon SES, Azure Communication Services, ' +
               'the Gmail API &mdash; or, in development, the capture ' +
               'transport), whether it could be built, where a mailed link ' +
               'points, a test message, and the wording of each message ' +
               'per language. A realm may override the service\'s ' +
               'transport. No secret is ever shown here.' },
      { path: '/admin/rbac', label: 'Admin roles',
        blurb: 'Who holds the two roles that grant this console — Admin ' +
               'Read and Admin Write — granted and revoked here. They are ' +
               'ORDINARY GROUPS in the shared directory rather than a store ' +
               'of the console\'s own, so this page, ' +
               '<code>/admin-api</code>, an <code>ldapmodify</code> on 389 ' +
               'or 636 and a SCIM PATCH are four doors onto one membership ' +
               '— which is the point, since a role no test can grant is a ' +
               'role no test can exercise. While NEITHER group has a member, ' +
               'anybody who signs in holds both.' },
      // THE EMBEDDED PROTOCOL DEBUGGER (2026-09-13), beside Admin roles and
      // for the reason it is in this section at all: the question it answers
      // is whether this service is set up to serve the debugger and to whom,
      // and "to whom" is the two roles on the page above. `debugger/
      // debugger_admin.js` draws it.
      { path: '/admin/debugger', label: 'Protocol debugger',
        blurb: 'The identity protocol debugger this service can serve on a ' +
               'listener of its own: whether it is embedded, the port and ' +
               'origin it answers on, the api process it forwards /api to ' +
               'and what that process may dial, and its settings. It is ' +
               'signed in to through this service\'s own authorization ' +
               'server as <code>sts-debugger-ui</code>, and its api needs an ' +
               'access token carrying ' +
               '<code>urn:sts:debugger-api:debugger</code> — issued to ' +
               'console administrators and nobody else. There is no setting ' +
               'that opens it.' },
      { path: '/admin/sts-metadata', label: 'Service metadata',
        blurb: 'Every endpoint this process registered, read off the LIVE ' +
               'express router, with the specification each one claims and ' +
               'how much of that specification is really implemented. ' +
               'Because it is read off the router it cannot go stale, and it ' +
               'reports both kinds of drift: a route registered and ' +
               'undescribed, and a description whose path is not registered ' +
               '— which is what a rename produces. A protocol that registers ' +
               'no route at all is its one blind spot, so the KDC\'s raw ' +
               '88 and the directory\'s 389 and 636 are described by hand.' },
      // THE SECOND PAGE IN THIS CONSOLE THIS FILE DOES NOT DRAW, and it sits
      // beside the first for the reason they are both here: each is a REPORT
      // about the whole service rather than a control over one part of it, and
      // a reader who wants "what does this thing do" wants them together.
      // `admin-ui/crypto_metadata.ts` builds it, calls `respond()` for this
      // shell, and fills setCryptoReporter() below so that `/admin-api/crypto`
      // can mirror it. Nothing about the nav knows any of that — a page here
      // is a `path` and a `label` whoever builds it.
      // THE THIRD PAGE IN THIS CONSOLE THIS FILE DOES NOT DRAW, and the
      // newest. `admin-ui/api_explorer.ts` builds it at 19a, after the
      // management API whose route table its document is built from. It is
      // filed HERE, beside Service metadata, because the question it answers
      // is the same one at a different scale: that page is every endpoint this
      // process registered, and this is every operation of the one API that
      // can change them, with a form that calls it.
      { path: '/admin/api-explorer', label: 'API explorer',
        blurb: 'Every operation of the management API at ' +
               '<code>/admin-api</code>, read from the same OpenAPI document ' +
               'that API publishes — which is generated from the table that ' +
               'registers the routes, so an operation cannot be undocumented ' +
               'nor documented and absent — with a form that calls it and ' +
               'the equivalent <code>curl</code> line beside each one. ' +
               '<strong>It was <code>/admin-api/docs</code> until ' +
               '2026-09-09</strong>, when that API began requiring an OAuth ' +
               '2.0 access token: a browser navigating to a URL carries ' +
               'none, so the one page here written to be opened in a browser ' +
               'had become the one page a browser could not open. Calls from ' +
               'this page use a token minted for YOU, carrying exactly the ' +
               'scopes your console roles grant — <code>admin:read</code> ' +
               'for Admin Read, <code>admin:write</code> for Admin Write — ' +
               'so an operation you may not perform is refused here by the ' +
               'same policy that would refuse it anywhere else. It is the ' +
               'only page in this console with a script on it.' },
      { path: '/admin/keys', label: 'Key pairs',
        blurb: 'Every key pair this process generated at start, what each ' +
               'one is used for, and <strong>a way to take it away</strong>. ' +
               'It is the deliberate opposite of Cryptography beside it: ' +
               'that page publishes key types, identifiers and fingerprints ' +
               'and no key material at all, and this one hands over the ' +
               'private half in PEM, DER, JWK or a password-protected ' +
               'PKCS#12 — the debugger\'s own keystore code, vendored. ' +
               'Defensible because of what these keys are: made at start, ' +
               'held in memory, dead with the process, protecting nothing. ' +
               'It needs ADMIN WRITE, which is stronger than any other read ' +
               'here, because on this page reading is taking.' },
      { path: '/admin/crypto-metadata', label: 'Cryptography',
        blurb: 'What this service does when it SIGNS, VERIFIES, ENCRYPTS or ' +
               'DECRYPTS something — for every identity service it ' +
               'advertises, with the algorithms each really uses and the ' +
               'envelope each is wrapped in (JOSE, XMLDSIG and XML ' +
               'Encryption, WS-Security, COSE, X.509, Kerberos). Every ' +
               'algorithm table is READ FROM THE MODULE THAT PERFORMS THE ' +
               'ALGORITHM, the way Service metadata reads its endpoint list ' +
               'off the live router, so none of it can claim something this ' +
               'service does not do — and it reports drift against that ' +
               'page\'s own family list in both directions. It carries a ' +
               'POST-QUANTUM section whose headline is not the flattering ' +
               'one: the signatures are partly post-quantum and the key ' +
               'establishment is entirely classical. It publishes no private ' +
               'key and no secret.' }
    ] }
];

// What `AdminConsole` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface AdminConsoleDeps {
  log: typeof log;
  xmlEscape: typeof xmlEscape;
  baseUrlOf: typeof baseUrlOf;
  parseBody: typeof parseBody;
  userFor: typeof userFor;
  multipartParts: typeof multipartParts;
  errorCodes: typeof errorCodes;
  resourceMetadata: typeof resourceMetadata;
  adminActions: typeof adminActions;
  adminViews: typeof adminViews;
  protocolEndpoints: typeof protocolEndpoints;
  pagingOf: typeof pagingOf;
  pagingJson: typeof pagingJson;
  pagedRows: typeof pagedRows;
  tokensView: typeof tokensView;
  sessionsView: typeof sessionsView;
  DEFAULT_PER_PAGE: typeof DEFAULT_PER_PAGE;
  DELEGATION_PER_PAGE: typeof DELEGATION_PER_PAGE;
  MAX_ROWS: typeof MAX_ROWS;
  auditView: typeof auditView;
  errorCodesView: typeof errorCodesView;
  usedAssertionsView: typeof usedAssertionsView;
  delegationView: typeof delegationView;
  clusterSummary: typeof clusterSummary;
  permissionGroupsView: typeof permissionGroupsView;
  queryOne: typeof queryOne;
  chooserMatches: typeof chooserMatches;
  claimsRequestPreview: typeof claimsRequestPreview;
  userinfoClaimsJson: typeof userinfoClaimsJson;
  signalsJson: typeof signalsJson;
  ssfJson: typeof ssfJson;
  ssfDeadLettersJson: typeof ssfDeadLettersJson;
  caepJson: typeof caepJson;
  caepSessionsState: typeof caepSessionsState;
  caepApplicationsState: typeof caepApplicationsState;
  riscJson: typeof riscJson;
  riscAccountsState: typeof riscAccountsState;
  riscApplicationsState: typeof riscApplicationsState;
  spiffeJson: typeof spiffeJson;
  spiffeEntriesJson: typeof spiffeEntriesJson;
  spiffeAgentsJson: typeof spiffeAgentsJson;
  spiffeBrokersJson: typeof spiffeBrokersJson;
  spiffeSelectorText: typeof spiffeSelectorText;
  newUserContainer: typeof newUserContainer;
  CREDENTIAL_CHOICES: typeof CREDENTIAL_CHOICES;
  knownUserKeys: typeof knownUserKeys;
  saml2Facts: typeof saml2Facts;
  valuesFor: typeof valuesFor;
  saml11Facts: typeof saml11Facts;
  asDriftRows: typeof asDriftRows;
  pageParamsOf: typeof pageParamsOf;
  applicationPermissionsState: typeof applicationPermissionsState;
  queryWith: typeof queryWith;
  DEFAULT_BLOCKS_PER_PAGE: typeof DEFAULT_BLOCKS_PER_PAGE;
  logoutFamilies: typeof logoutFamilies;
  claimsJson: typeof claimsJson;
  claimsPreviewUser: typeof claimsPreviewUser;
  claimsRequestParameter: typeof claimsRequestParameter;
  consentView: typeof consentView;
  consoleRpSession: typeof consoleRpSession;
  gateStateFor: typeof gateStateFor;
  metricsJson: typeof metricsJson;
  permissionsView: typeof permissionsView;
  realmJson: typeof realmJson;
  realmsJson: typeof realmsJson;
  rolesPreview: typeof rolesPreview;
  rolesRegister: typeof rolesRegister;
  samlAssertionSeconds: typeof samlAssertionSeconds;
  samlAssertionsJson: typeof samlAssertionsJson;
  samlAttributesJson: typeof samlAttributesJson;
  scimJson: typeof scimJson;
  scimMonitorJson: typeof scimMonitorJson;
  signOnSessionRows: typeof signOnSessionRows;
  tokenLifetimesJson: typeof tokenLifetimesJson;
  tokenSetView: typeof tokenSetView;
  vcJson: typeof vcJson;
  vcPreviewUser: typeof vcPreviewUser;
  vpConfigJson: typeof vpConfigJson;
  ROLE_ACTIONS: typeof ROLE_ACTIONS;
  ROLE_MEMBER_KINDS: typeof ROLE_MEMBER_KINDS;
  SAML11_RP_KIND: typeof SAML11_RP_KIND;
  SAML2_SP_KIND: typeof SAML2_SP_KIND;
  SAML_ASSERTION_SETTINGS: typeof SAML_ASSERTION_SETTINGS;
  applicationsAction: typeof applicationsAction;
  asAction: typeof asAction;
  caepAction: typeof caepAction;
  claimsAction: typeof claimsAction;
  configAction: typeof configAction;
  configSettingFor: typeof configSettingFor;
  consentAction: typeof consentAction;
  federationAction: typeof federationAction;
  groupsAction: typeof groupsAction;
  logoutAction: typeof logoutAction;
  permissionsAction: typeof permissionsAction;
  rbacAction: typeof rbacAction;
  realmsAction: typeof realmsAction;
  riscAction: typeof riscAction;
  rolesAction: typeof rolesAction;
  saml11Action: typeof saml11Action;
  saml2Action: typeof saml2Action;
  samlAssertionRowFor: typeof samlAssertionRowFor;
  samlAssertionsAction: typeof samlAssertionsAction;
  sessionsAction: typeof sessionsAction;
  signalsAction: typeof signalsAction;
  spiffeAgentsAction: typeof spiffeAgentsAction;
  spiffeBrokersAction: typeof spiffeBrokersAction;
  spiffeEntriesAction: typeof spiffeEntriesAction;
  spiffeAction: typeof spiffeAction;
  ssfAction: typeof ssfAction;
  tokenAction: typeof tokenAction;
  tokenLifetimesAction: typeof tokenLifetimesAction;
  truthy: typeof truthy;
  userFieldsFrom: typeof userFieldsFrom;
  usersAction: typeof usersAction;
  vcAction: typeof vcAction;
  vpConfigAction: typeof vpConfigAction;
  config: typeof config;
  credentials: typeof credentials;
  totp: typeof totp;
  backupCodes: typeof backupCodes;
  webauthnPolicy: typeof webauthnPolicy;
  websecurity: typeof websecurity;
  accessGate: typeof accessGate;
  mode: typeof mode;
  persistence: typeof persistence;
  cluster: typeof cluster;
  clusterSecrets: typeof clusterSecrets;
  clusterBarrier: typeof clusterBarrier;
  secrets: typeof secrets;
  keystore: typeof keystore;
  realms: typeof realms;
  createClaims: typeof createClaims;
  stats: typeof stats;
  oidcRp: typeof oidcRp;
  sessions: typeof sessions;
  rbac: typeof rbac;
  adminScope: typeof adminScope;
  loginRealmChooser: typeof loginRealmChooser;
  vcClaims: typeof vcClaims;
  vpConfig: typeof vpConfig;
  claimAttributes: typeof claimAttributes;
  groupClaims: typeof groupClaims;
  auditLog: typeof auditLog;
  applications: typeof applications;
  saml11: typeof saml11;
  authorizationServers: typeof authorizationServers;
  federation: typeof federation;
  federationGraph: typeof federationGraph;
  federationDiagram: typeof federationDiagram;
  spiffeCa: typeof spiffeCa;
  spiffeRegistry: typeof spiffeRegistry;
  spiffeAuth: typeof spiffeAuth;
  signals: typeof signals;
  oauth2: typeof oauth2;
  delegation: typeof delegation;
  appPermissions: typeof appPermissions;
  issuanceGate: typeof issuanceGate;
  delegationMap: typeof delegationMap;
  userGraph: typeof userGraph;
  credentialGraph: typeof credentialGraph;
  krb5Principals: typeof krb5Principals;
  validation: typeof validation;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadHelpers(): typeof import('../common/helpers');
}

type RouteApp = typeof app;

/**
 * The admin console at `/admin`: since #446 the static console's document
 * and script, the shell answer `GET /admin-api/console` draws its frame
 * from, the realm chooser in front of a bare `/admin`, and the read models
 * and slots the management API still reaches through it.
 *
 * It decides nothing; the actions live in admin-core.
 */

const APPLICATION_TAB_IDS = ['tab-overview', 'tab-config', 'tab-credentials',
  'tab-origins', 'tab-signals', 'tab-statements', 'tab-addresses',
  'tab-permissions', 'tab-roles', 'tab-metadata', 'tab-entry', 'tab-remove'];

// A PERSON'S PAGE AS TABS (rcbj, 2026-10-01), the application page's model:
// seven tabs, the Attributes tab one sub-tab per field group (ufg-<group>,
// each with its own Save) and the Credentials tab one per kind of credential.
const USER_TAB_IDS = ['utab-overview', 'utab-activity', 'utab-attributes',
  'utab-credentials', 'utab-federation', 'utab-gnap', 'utab-entry',
  'utab-signout'];
const USER_SUB_TAB_IDS = ['ucred-factors', 'ucred-password', 'ucred-keys',
  'ucred-kerberos'].concat(personEditor.FIELD_GROUPS.map(function (group) {
  return 'ufg-' + group.id;
}));

class AdminConsole {
  // What the Cluster page's `prepare` step last read from the other cells
  // (#361): `{ at, rows, error? }`, or null in single-cell mode.
  peerClustersNow: any = null;

  /**
   * Builds the console over the given modules.
   *
   * @param deps - the modules and helpers the console reads
   */
  constructor(private readonly deps: AdminConsoleDeps) {
    deps.log.debug("Entering AdminConsole.constructor().");
    deps.log.debug("Leaving AdminConsole.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Returns the dependencies the composition root builds the console from.
   *
   * @returns the real modules
   */
  static defaultDeps(): AdminConsoleDeps {
    log.debug("Entering AdminConsole.defaultDeps().");
    log.debug("Leaving AdminConsole.defaultDeps().");
    return {
      log: log,
      xmlEscape: xmlEscape,
      baseUrlOf: baseUrlOf,
      parseBody: parseBody,
      userFor: userFor,
      multipartParts: multipartParts,
      errorCodes: errorCodes,
      resourceMetadata: resourceMetadata,
      adminActions: adminActions,
      adminViews: adminViews,
      protocolEndpoints: protocolEndpoints,
      pagingOf: pagingOf,
      pagingJson: pagingJson,
      pagedRows: pagedRows,
      tokensView: tokensView,
      sessionsView: sessionsView,
      DEFAULT_PER_PAGE: DEFAULT_PER_PAGE,
      DELEGATION_PER_PAGE: DELEGATION_PER_PAGE,
      MAX_ROWS: MAX_ROWS,
      auditView: auditView,
      errorCodesView: errorCodesView,
      usedAssertionsView: usedAssertionsView,
      delegationView: delegationView,
      clusterSummary: clusterSummary,
      permissionGroupsView: permissionGroupsView,
      queryOne: queryOne,
      chooserMatches: chooserMatches,
      claimsRequestPreview: claimsRequestPreview,
      userinfoClaimsJson: userinfoClaimsJson,
      signalsJson: signalsJson,
      ssfJson: ssfJson,
      ssfDeadLettersJson: ssfDeadLettersJson,
      caepJson: caepJson,
      caepSessionsState: caepSessionsState,
      caepApplicationsState: caepApplicationsState,
      riscJson: riscJson,
      riscAccountsState: riscAccountsState,
      riscApplicationsState: riscApplicationsState,
      spiffeJson: spiffeJson,
      spiffeEntriesJson: spiffeEntriesJson,
      spiffeAgentsJson: spiffeAgentsJson,
      spiffeBrokersJson: spiffeBrokersJson,
      spiffeSelectorText: spiffeSelectorText,
      newUserContainer: newUserContainer,
      CREDENTIAL_CHOICES: CREDENTIAL_CHOICES,
      knownUserKeys: knownUserKeys,
      saml2Facts: saml2Facts,
      valuesFor: valuesFor,
      saml11Facts: saml11Facts,
      asDriftRows: asDriftRows,
      pageParamsOf: pageParamsOf,
      applicationPermissionsState: applicationPermissionsState,
      queryWith: queryWith,
      DEFAULT_BLOCKS_PER_PAGE: DEFAULT_BLOCKS_PER_PAGE,
      logoutFamilies: logoutFamilies,
      claimsJson: claimsJson,
      claimsPreviewUser: claimsPreviewUser,
      claimsRequestParameter: claimsRequestParameter,
      consentView: consentView,
      consoleRpSession: consoleRpSession,
      gateStateFor: gateStateFor,
      metricsJson: metricsJson,
      permissionsView: permissionsView,
      realmJson: realmJson,
      realmsJson: realmsJson,
      rolesPreview: rolesPreview,
      rolesRegister: rolesRegister,
      samlAssertionSeconds: samlAssertionSeconds,
      samlAssertionsJson: samlAssertionsJson,
      samlAttributesJson: samlAttributesJson,
      scimJson: scimJson,
      scimMonitorJson: scimMonitorJson,
      signOnSessionRows: signOnSessionRows,
      tokenLifetimesJson: tokenLifetimesJson,
      tokenSetView: tokenSetView,
      vcJson: vcJson,
      vcPreviewUser: vcPreviewUser,
      vpConfigJson: vpConfigJson,
      ROLE_ACTIONS: ROLE_ACTIONS,
      ROLE_MEMBER_KINDS: ROLE_MEMBER_KINDS,
      SAML11_RP_KIND: SAML11_RP_KIND,
      SAML2_SP_KIND: SAML2_SP_KIND,
      SAML_ASSERTION_SETTINGS: SAML_ASSERTION_SETTINGS,
      applicationsAction: applicationsAction,
      asAction: asAction,
      caepAction: caepAction,
      claimsAction: claimsAction,
      configAction: configAction,
      configSettingFor: configSettingFor,
      consentAction: consentAction,
      federationAction: federationAction,
      groupsAction: groupsAction,
      logoutAction: logoutAction,
      permissionsAction: permissionsAction,
      rbacAction: rbacAction,
      realmsAction: realmsAction,
      riscAction: riscAction,
      rolesAction: rolesAction,
      saml11Action: saml11Action,
      saml2Action: saml2Action,
      samlAssertionRowFor: samlAssertionRowFor,
      samlAssertionsAction: samlAssertionsAction,
      sessionsAction: sessionsAction,
      signalsAction: signalsAction,
      spiffeAgentsAction: spiffeAgentsAction,
      spiffeBrokersAction: spiffeBrokersAction,
      spiffeEntriesAction: spiffeEntriesAction,
      spiffeAction: spiffeAction,
      ssfAction: ssfAction,
      tokenAction: tokenAction,
      tokenLifetimesAction: tokenLifetimesAction,
      truthy: truthy,
      userFieldsFrom: userFieldsFrom,
      usersAction: usersAction,
      vcAction: vcAction,
      vpConfigAction: vpConfigAction,
      config: config,
      credentials: credentials,
      totp: totp,
      backupCodes: backupCodes,
      webauthnPolicy: webauthnPolicy,
      websecurity: websecurity,
      accessGate: accessGate,
      mode: mode,
      persistence: persistence,
      cluster: cluster,
      clusterSecrets: clusterSecrets,
      clusterBarrier: clusterBarrier,
      secrets: secrets,
      keystore: keystore,
      realms: realms,
      createClaims: createClaims,
      stats: stats,
      oidcRp: oidcRp,
      sessions: sessions,
      rbac: rbac,
      adminScope: adminScope,
      loginRealmChooser: loginRealmChooser,
      vcClaims: vcClaims,
      vpConfig: vpConfig,
      claimAttributes: claimAttributes,
      groupClaims: groupClaims,
      auditLog: auditLog,
      applications: applications,
      saml11: saml11,
      authorizationServers: authorizationServers,
      federation: federation,
      federationGraph: federationGraph,
      federationDiagram: federationDiagram,
      spiffeCa: spiffeCa,
      spiffeRegistry: spiffeRegistry,
      spiffeAuth: spiffeAuth,
      signals: signals,
      oauth2: oauth2,
      delegation: delegation,
      appPermissions: appPermissions,
      issuanceGate: issuanceGate,
      delegationMap: delegationMap,
      userGraph: userGraph,
      credentialGraph: credentialGraph,
      krb5Principals: krb5Principals,
      validation: validation,
      loadHelpers: function () {
        return require('../common/helpers');
      }
    };
  }

  // The work loading this module did with its instance (#50, R2): the
  // `WIRE_STEPS` below the class, in the order they are written. Run once by
  // the slot, for whichever instance is installed.
  /**
   * Runs the module's wire steps, in order, for the installed instance.
   *
   * @param instance - the console instance that was installed
   */
  static wire(instance: AdminConsole): void {
    log.debug("Entering AdminConsole.wire(). " + WIRE_STEPS.length +
              " step(s).");
    WIRE_STEPS.forEach(function (step) {
      step(instance);
    });
    log.debug("Leaving AdminConsole.wire().");
  }

  // Drawn by `web_dashboard.ts` (#446).
  /**
   * Tells whether a row of a section's items is a group of pages.
   *
   * @param item - a row of a section's `items`
   * @returns true when the row has an `items` array
   */
  isNavGroup(item) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.isNavGroup().");
    log.debug("Leaving AdminConsole.isNavGroup().");
    return DashboardPage.isNavGroup(item);
  }

  // Every PAGE in one section, in sidebar order, with a group's pages spliced
  // in where the group sits — and a group inside a group spliced in the same
  // way (Cert issuance › SPIFFE, 2026-10-01). See the note above SECTIONS.
  /**
   * Lists every page in one section, in sidebar order, groups flattened.
   *
   * @param section - a row of SECTIONS
   * @returns the section's pages
   */
  sectionPages(section) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.sectionPages(). section=" + section.title);
    const pages = this.groupPages(section.items);
    log.debug("Leaving AdminConsole.sectionPages(). " + pages.length +
              " page(s).");
    return pages;
  }

  // The pages in a list of rows, in order, every group at every depth
  // flattened into it. The one walk `sectionPages()`, the sidebar's open
  // state and the guide share, so none of them can stop a level short.
  /**
   * Lists the pages in a list of section rows, groups flattened at any depth.
   *
   * @param items - a section's or a group's `items`
   * @returns the pages, in sidebar order
   */
  groupPages(items) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.groupPages().");
    const pages = [];
    items.forEach(function (item) {
      if (self.isNavGroup(item)) {
        self.groupPages(item.items).forEach(function (page) {
          pages.push(page);
        });
        return;
      }
      pages.push(item);
    });
    log.debug("Leaving AdminConsole.groupPages(). " + pages.length +
              " page(s).");
    return pages;
  }

  // Every group `config.js` declares, in its order. Read off the table rather
  // than off `config.groups()` because this runs at start-up (at require time
  // until #50's R2; when the instance is installed now) and that call
  // describes every setting — the group NAME is all that is being checked, and
  // asking for a hundred and fifty-four descriptions to get twenty-two strings
  // would also drag a realm lookup into module load.
  /**
   * Lists every setting group config.js declares, in its order.
   *
   * @returns the group names
   */
  declaredSettingGroups() {
    const { log, config } = this.deps;
    log.debug("Entering AdminConsole.declaredSettingGroups().");
    const seen = [];
    config.SETTINGS.forEach(function (setting) {
      if (seen.indexOf(setting.group) < 0) {
        seen.push(setting.group);
      }
    });
    log.debug("Leaving AdminConsole.declaredSettingGroups().");
    return seen;
  }

  // The three ways this table can be wrong, checked once at start-up (when the
  // instance is installed, since #50's R2). Each would otherwise be found by a
  // person who could not find a setting, which is the slowest way to find any
  // of them.
  /**
   * Checks SETTING_HOMES against config.js's groups and the console's pages.
   *
   * Each problem is logged as an error under STS-ADMIN-0015.
   *
   * @returns the problems found, as sentences; empty when there are none
   */
  checkSettingHomes() {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AdminConsole.checkSettingHomes().");
    const problems = [];
    const declared = this.declaredSettingGroups();
    const homed = SETTING_HOMES.map(function (row) { return row.group; });

    declared.forEach(function (group) {
      const rows =
          homed.filter(function (name) { return name === group; }).length;
      if (rows === 0) {
        problems.push('The setting group "' + group + '" has no page to live ' +
          'on. Add a row to SETTING_HOMES in admin-ui/admin.ts naming the ' +
          'console page that should draw it, or it is editable nowhere.');
      }
      if (rows > 1) {
        problems.push('The setting group "' + group + '" has ' + rows + ' ' +
          'rows in SETTING_HOMES. One row may name several pages; two rows ' +
          'cannot say which of them a reader is meant to believe.');
      }
    });

    SETTING_HOMES.forEach(function (row) {
      if (declared.indexOf(row.group) < 0) {
        problems.push('SETTING_HOMES names the setting group "' + row.group +
          '", which config.js does not declare. It was probably renamed ' +
          'there.');
      }
      row.pages.forEach(function (path) {
        const known = NAV.some(function (item) { return item.path === path; });
        if (!known) {
          problems.push('SETTING_HOMES sends the "' + row.group +
            '" settings to ' +
            path + ', which is not a page in this console\'s SECTIONS. ' +
            'Nothing would draw them.');
        }
      });
    });

    problems.forEach(function (problem) {
      log.error(errorCodes.tag('STS-ADMIN-0015') + 'admin console: ' + problem);
    });
    log.debug("Leaving AdminConsole.checkSettingHomes(). " + problems.length +
              " problem(s).");
    return problems;
  }

  /**
   * Escapes a value for HTML, drawing null and undefined as empty.
   *
   * @param v - the value to escape
   * @returns the escaped text
   */
  esc(v) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering AdminConsole.esc().");
    log.debug("Leaving AdminConsole.esc().");
    return xmlEscape(v == null ? '' : String(v));
  }

  // The kit's (#446), where its reasoning went with it.
  /**
   * Picks a list page's filter and page parameters out of a query.
   *
   * Only the keys LIST_PARAMS names for the section are kept; the first of a
   * repeated parameter wins.
   *
   * @param section - the list page's path
   * @param query - the request's query object
   * @returns the list view, as parameter names to strings
   */
  listViewOf(section, query) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.listViewOf().");
    log.debug("Leaving AdminConsole.listViewOf().");
    return WebKit.listViewOf(section, query);
  }

  // `up` is set on a drill-down — a page reached from a link on one of the
  // sections below rather than one of the sections itself — and what it changes
  // is the ACTIVE TAB.
  //
  // That tab was drawn as plain text on every page whose `active` matched, and
  // `active` is the section's path on the list page and on every page
  // underneath it alike. So on a drill-down the one control that pointed at the
  // list was the one control this shell had turned off, and the only way back
  // from /admin/applications?application=x was the browser's own Back button or
  // a link at the foot of a long page. On a drill-down the tab is a LINK: still
  // bold, because the reader is inside that section, and underlined so that
  // "the section you are in" cannot be read as "not clickable".
  //
  // It is one `<nav>` holding one `<ul>` per section with a heading above it.
  // The heading is plain text and NOT a link, for the reason the section is not
  // a crumb: there is no page behind it. The section containing the page being
  // drawn is marked, so a reader who arrived on a deep link can see where they
  // are without reading every label.
  //
  // A GROUP inside a section is drawn as an `<li>` holding a heading and a
  // `<ul>` of its own, rather than as a second `<ul>` beside the first: a group
  // belongs INSIDE the section's list — it is three of that list's items said
  // together — and a sibling list would tell a screen reader the section ended
  // where the group began. Its heading is plain text for the same reason the
  // section's is, and the marker on the group holding the current page is a
  // rule down the left like the section's, one level in.
  /**
   * Draws the console's navigation: the realm chooser and every section.
   *
   * A realm administrator sees only the pages of their realm and no chooser.
   *
   * @param active - the path of the page being drawn
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @param req - the request, or nothing
   * @returns the `<nav>` as HTML
   */
  navBar(active, up, req) {
    const { log, gateStateFor } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.navBar(). active=" + active);
    // A REALM ADMINISTRATOR'S SIDEBAR (2026-09-14, #32) leaves out the pages
    // that belong to the whole service, which the gate would refuse them, and
    // the realm switcher, since their console is one realm. The service
    // administrator's is unchanged.
    const state = req ? gateStateFor(req) : null;
    const realmOnly = !!(state && state.authority === 'realm');
    const html = '<nav aria-label="Admin console sections">' +
      // FIRST, inside this card rather than above it. It does not select a page
      // — it selects which service the pages are about — but it is the first
      // question a reader has about the column, so it is the first thing in it.
      (realmOnly ? '' : this.realmChooser(req)) +
      this.visibleSections(state).map(function (section) {
        const inThisSection = self.sectionPages(section)
          .filter(function (item) {
          return item.path === active;
        }).length > 0;
        const links = section.items.map(function (item) {
          return self.navItem(item, active, up);
        }).join('');
        return '<div class="navsec' + (inThisSection ? ' open' : '') + '">' +
          '<p class="navhead" title="' + self.esc(section.what) + '">' +
          self.esc(section.title) + '</p><ul>' + links + '</ul></div>';
      }).join('') + '</nav>';
    log.debug("Leaving AdminConsole.navBar(). " + SECTIONS.length +
              " section(s).");
    return html;
  }

  // SECTIONS as one state may see it: service pages dropped for a realm
  // administrator, a group with nothing left dropped with them, and a section
  // with nothing left dropped too. The table itself is never edited.
  /**
   * Returns SECTIONS as one gate state may see them.
   *
   * For a realm administrator, service pages and any group or section left
   * empty are dropped; the table itself is not changed.
   *
   * @param state - the gate state, or null
   * @returns the sections to draw
   */
  visibleSections(state): any[] {
    const { log, adminScope } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.visibleSections().");
    if (!state || state.authority !== 'realm') {
      log.debug("Leaving AdminConsole.visibleSections(). Everything.");
      return SECTIONS;
    }
    const shown = function (item) {
      log.debug("Entering shown().");
      log.debug("Leaving shown().");
      return adminScope.pageVisible(state, item.path);
    };
    // A group is kept with what is left of it, at any depth, and dropped when
    // nothing is.
    const visible = function (items) {
      log.debug("Entering visible().");
      const kept = items.map(function (item) {
        if (!self.isNavGroup(item)) {
          return shown(item) ? item : null;
        }
        const inner = visible(item.items);
        return inner.length ? Object.assign({}, item, { items: inner }) : null;
      }).filter(Boolean);
      log.debug("Leaving visible().");
      return kept;
    };
    const out = SECTIONS.map(function (section) {
      return Object.assign({}, section, { items: visible(section.items) });
    }).filter(function (section) {
      return section.items.length > 0;
    });
    log.debug("Leaving AdminConsole.visibleSections(). " + out.length +
              " section(s).");
    return out;
  }

  // One row of a section's list: a page, or a group holding pages.
  /**
   * Draws one row of a section's list: a page, or a group holding pages.
   *
   * @param item - the row
   * @param active - the path of the page being drawn
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @returns the `<li>` as HTML
   */
  navItem(item, active, up) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.navItem(). " +
              (this.isNavGroup(item) ? 'group ' + item.title
                                                         : 'page ' +
                                                             item.path));
    if (!this.isNavGroup(item)) {
      log.debug("Leaving AdminConsole.navItem(). A page.");
      return this.navLink(item, active, up);
    }
    const open = this.groupPages(item.items).filter(function (page) {
      return page.path === active;
    }).length > 0;
    // A row of a group may itself be a group (Cert issuance › SPIFFE), so
    // each row is drawn by this method again rather than by navLink().
    const html = '<li class="navgrp' + (open ? ' open' : '') + '">' +
      '<p class="navsub" title="' + this.esc(item.what) + '">' +
      this.esc(item.title) +
      '</p><ul>' + item.items.map(function (row) {
        return self.navItem(row, active, up);
      }).join('') + '</ul></li>';
    log.debug("Leaving AdminConsole.navItem(). A group of " +
              item.items.length + " page(s).");
    return html;
  }

  /**
   * Draws one page's nav entry.
   *
   * The active page is plain text, or a link back up on a drill-down.
   *
   * @param item - the page's NAV row
   * @param active - the path of the page being drawn
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @returns the `<li>` as HTML
   */
  navLink(item, active, up) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.navLink(). path=" + item.path);
    if (item.path === active) {
      if (up) {
        log.debug("Leaving AdminConsole.navLink(). Active, and a drill-down.");
        return '<li><a class="here" href="' + this.esc(up.href) + '"' +
               ' title="Back to ' + this.esc(up.label) + '"' +
               // A drill-down's active item IS a link, so it is already in the
               // tab order and must stay there — only the autofocus is added.
               ' autofocus>' + this.esc(item.label) + '</a></li>';
      }
      log.debug("Leaving AdminConsole.navLink(). Active.");
      return '<li><span class="here"' + ACTIVE_NAV_FOCUS +
             ' aria-current="page">' + this.esc(item.label) + '</span></li>';
    }
    log.debug("Leaving AdminConsole.navLink().");
    return '<li><a href="' + this.esc(item.path) + '">' + this.esc(item.label) +
           '</a></li>';
  }

  /**
   * Builds the address of the reader's own user portal.
   *
   * @param req - the request
   * @param gate - the gate state, whose realm the person signed in through
   *   chooses the portal
   * @returns the portal's absolute URL
   */
  portalHref(req, gate) {
    const { log, realms } = this.deps;
    log.debug("Entering AdminConsole.portalHref().");
    const home = realms.get((gate && gate.identityRealm) ||
                            realms.DEFAULT_ID) ||
                 realms.get(realms.DEFAULT_ID);
    log.debug("Leaving AdminConsole.portalHref(). realm=" + (home && home.id));
    return this.realmRoot(req) + realms.prefixOf(home) + PORTAL_PATH;
  }

  // The base URL with the CURRENT realm's prefix taken back off, so that what
  // is built from it starts at the root. baseUrlOf() adds the ambient prefix by
  // design — this and the switch route below are the two callers in this
  // service that do not want it, and they say so here rather than working
  // around it somewhere else.
  /**
   * Returns the base URL with the current realm's prefix taken off.
   *
   * @param req - the request
   * @returns the base URL at the root
   */
  realmRoot(req) {
    const { log, baseUrlOf, realms } = this.deps;
    log.debug("Entering AdminConsole.realmRoot().");
    // AT A CELL'S OWN CONSOLE ADDRESS, THAT ADDRESS (#361, 2026-09-30).
    // baseUrlOf() is the pinned public name, so the realm switcher, the
    // portal link and every other absolute URL built here sent a console
    // opened at `https://cac1.<public name>` back to the shared name —
    // another host, no session, a second sign-in, and (rcbj found) a
    // passkey then refused for the wrong origin. The address is one the
    // service is configured with (`cells.consoleUrl`), never the Host's say.
    const cells = require('../common/cells');
    const hit = cells.consoleOfHost(String((req && req.headers &&
                                            req.headers.host) || ''));
    if (hit) {
      log.debug("Leaving AdminConsole.realmRoot(). The cell's own console " +
                "address.");
      return hit.consoleUrl;
    }
    const withRealm = baseUrlOf(req);
    log.debug("Leaving AdminConsole.realmRoot().");
    return withRealm.slice(0, withRealm.length - realms.currentPrefix().length);
  }

  // Where the reader is, INSIDE the realm. req.url has already had the prefix
  // stripped by the time any route sees it, which is the whole trick, and is
  // also what makes this the path to re-enter in the other realm — so switching
  // lands on the same page with the same filter rather than back at /admin.
  /**
   * Returns the request's path and query without the realm prefix.
   *
   * @param req - the request
   * @returns the path inside the realm; `/admin` when there is none
   */
  realmRelativePath(req) {
    const { log, realms } = this.deps;
    log.debug("Entering AdminConsole.realmRelativePath().");
    const here = String(req.originalUrl || '/admin');
    log.debug("Leaving AdminConsole.realmRelativePath().");
    return here.slice(realms.currentPrefix().length) || '/admin';
  }

  /**
   * Draws the trust realm switcher, a GET form to the realm switch route.
   *
   * @param req - the request
   * @returns the form as HTML; empty when no realm is defined
   */
  realmChooser(req) {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.realmChooser().");
    if (!realms.active()) {
      log.debug("Leaving AdminConsole.realmChooser(). No realms are defined.");
      return '';
    }
    const currentId = realms.currentId();
    const options = realms.list().map(function (realm) {
      return '<option value="' + self.esc(realm.id) + '"' +
        (realm.id === currentId ? ' selected' : '') + '>' +
        self.esc(realm.name) + '</option>';
    }).join('');
    log.debug("Leaving AdminConsole.realmChooser(). " + realms.count() +
              " realm(s).");
    return '<form class="realmpick" method="get" action="' +
      this.esc(this.realmRoot(req) + REALM_SWITCH_PATH) + '">' +
      '<label for="realmpick">Trust realm</label>' +
      '<input type="hidden" name="to" value="' +
        this.esc(this.realmRelativePath(req)) + '">' +
      '<div class="realmpickrow">' +
        '<select id="realmpick" name="realm">' + options + '</select>' +
        '<button class="secondary">Go</button>' +
      '</div></form>';
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS PROCESS IS RUNNING AS, under the version at the foot of every
  // page (2026-09-13).
  //
  // Four facts somebody asks in front of this console as often as "which
  // build": whether requests are DISPATCHED to request workers or answered by
  // one process, whether the realm is in PRODUCT or DEVELOPMENT mode, which
  // PERSISTENCE store is open, and where the two primordial SECRETS — the
  // key-encryption key and the database password — are read from. Each answer
  // was a page away (`/admin/persistence`, `/admin/secrets`, `global.mode` on
  // `/admin/config`), and the pages that change what an endpoint does are
  // exactly where a reader needs to know which of those worlds they are
  // changing it in.
  //
  // **EVERY FACT IS READ FROM THE MODULE THAT OWNS IT, PER RENDER.** The mode
  // is runtime-settable and per realm, the store's `status()` is what
  // `/admin/persistence` draws, and `secrets.describe()` is what
  // `/admin/secrets` draws — so the footer cannot say something those pages do
  // not. It says WHERE a secret comes from and never WHAT it is, which is
  // `describe()`'s own rule.
  //
  // **IT MAY NOT BREAK A PAGE.** Each fact is computed inside its own guard and
  // a fact that throws is drawn as `unknown`: a footer that took the console
  // down would cost every page for one line of information.
  // ---------------------------------------------------------------------------
  /**
   * Reads what this process is running as, for the page footer.
   *
   * The process arrangement, the mode, the open store and where the two
   * secrets come from; a fact that throws is `unknown`.
   *
   * @returns the facts, by name
   */
  runtimeFacts(): Record<string, any> {
    const { log, config, mode, persistence, secrets, keystore } = this.deps;
    log.debug("Entering AdminConsole.runtimeFacts().");
    const facts: Record<string, any> = {};
    try {
      // The #364 rule: the default of one worker is none without a store
      // that coordinates.
      const count = require('../common/process_memory').requestWorkers();
      const rawDispatch = config.value('workers.dispatch');
      const dispatch = (Array.isArray(rawDispatch) ? rawDispatch
                                                   : String(rawDispatch || '')
                                                       .split(','))
        .map(function (one) { return String(one).trim(); })
        .filter(Boolean);
      // AND THE HOSTED-SURFACE POOL (2026-09-13), which is where this page is
      // drawn from whenever there is one — so "this page from worker N" names
      // which pool N is in, or it would read as a protocol worker.
      const surfaceCount =
        parseInt(config.value('workers.surfaceCount'), 10) || 0;
      const pool = process.env.STS_REQUEST_WORKER_POOL === 'surfaces'
        ? 'hosted-surface ' : '';
      facts.process = (count > 0 || surfaceCount > 0) && dispatch.length
        ? 'dispatch (' + count + ' request worker' + (count === 1 ? '' : 's') +
          (surfaceCount
            ? ' + ' + surfaceCount + ' for the console and portal' : '') +
          (process.env.STS_REQUEST_WORKER
            ? '; this page from ' + pool + 'worker ' + WorkerChannel.id()
            : '') + ')'
        : 'single process';
    } catch (e) {
      log.debug("Caught in AdminConsole.runtimeFacts(): " +
                ((e && e.message) || e));
      // Drawn as unknown rather than guessed; see the header.
      facts.process = 'unknown';
    }
    try {
      facts.mode = mode.current();
    } catch (e) {
      log.debug("Caught in AdminConsole.runtimeFacts(): " +
                ((e && e.message) || e));
      // Drawn as unknown rather than guessed; see the header.
      facts.mode = 'unknown';
    }
    let store = null;
    // THE STORE THAT IS OPEN, which is not always the one configured:
    // `status().mode` is `memory` until `persistence.start()` has opened the
    // configured store, and a store that cannot open stops the service — so a
    // mismatch is only ever a process that has not opened it, and it is SAID
    // rather than hidden behind the configured name.
    let effective = 'memory';
    try {
      store = persistence.status();
      effective = String(store.mode || store.configuredMode || 'memory');
      const db = store.database;
      facts.database = effective === 'postgres'
        ? (db ? 'postgres (' + db.host + ':' + db.port + '/' + db.database + ')'
              : 'postgres')
        : effective === 'ldif'
          ? 'ldif (' + (store.dataDir || 'no data directory') + ')'
          : effective === 'memory' ? 'memory (nothing written down)'
                                   : effective;
      if (store.mode && store.configuredMode &&
          store.configuredMode !== store.mode) {
        facts.database += ' — persistence.mode is ' + store.configuredMode +
                          ' and no such store is open in this process';
      }
    } catch (e) {
      log.debug("Caught in AdminConsole.runtimeFacts(): " +
                ((e && e.message) || e));
      // Drawn as unknown rather than guessed; see the header.
      facts.database = 'unknown';
    }
    try {
      const kek = secrets.describe();
      const kekFrom = kek.configured
        ? kek.label + (kek.where && kek.where.from ? ' (' + kek.where.from + ')'
                                                   : '')
        : 'not configured';
      facts.keyEncryptionKey = keystore.persists()
        ? kekFrom
        : 'not read (signing keys are generated at start)';
    } catch (e) {
      log.debug("Caught in AdminConsole.runtimeFacts(): " +
                ((e && e.message) || e));
      // Drawn as unknown rather than guessed; see the header.
      facts.keyEncryptionKey = 'unknown';
    }
    try {
      const password = secrets.describeDatabasePassword();
      facts.databasePassword = effective !== 'postgres'
        ? 'not used (no database)'
        : password.configured
          ? password.label + (password.where && password.where.from
            ? ' (' + password.where.from + ')' : '')
          : 'the connection string';
    } catch (e) {
      log.debug("Caught in AdminConsole.runtimeFacts(): " +
                ((e && e.message) || e));
      // Drawn as unknown rather than guessed; see the header.
      facts.databasePassword = 'unknown';
    }
    log.debug("Leaving AdminConsole.runtimeFacts().");
    return facts;
  }

  /**
   * Draws a whole console page around a body.
   *
   * The shell adds the styles, sidebar, heading, Refresh and account menu,
   * trail, gate banner, derived tooltips and the footer.
   *
   * @param title - the page's title
   * @param active - the path of the page, which marks the nav
   * @param inner - the page body as HTML
   * @param up - upTo()'s answer on a drill-down, or nothing
   * @param gate - the gate state
   * @param req - the request
   * @returns the whole document as HTML
   */
  page(title, active, inner, up, gate, req) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.page(). title=" + title + ", up=" +
              (up ? up.href : "none"));
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><meta name="viewport" content="width=device-width, ' +
      'initial-scale=1"><title>' + this.esc(title) + ' — IYA STS ' +
      'admin</title><style>' + this.stylesheet() +
      '</style></head><body>' +
      // Drawn by `web_shell.ts` (#446), from the shell answer the static
      // console fetches, passed through JSON as every page's view is.
      WebShell.frame(JSON.parse(JSON.stringify(
                       this.shellJson(req, gate || null))),
                     { title: title, active: active, up: up || null,
                       inner: inner,
                       path: req ? this.realmRelativePath(req) : '/admin' }) +
      '</body></html>\n';
    log.debug("Leaving AdminConsole.page(). " + html.length + " bytes.");
    return html;
  }
  // ---------------------------------------------------------------------------
  // THE CONSOLE'S ONE STYLESHEET (#446): every page's `<style>` until the
  // cutover, and `/admin/console.css` for the static console — one source, so
  // the two consoles cannot be styled apart while both exist.
  // ---------------------------------------------------------------------------
  /**
   * Returns the console's stylesheet.
   *
   * @returns the CSS
   */
  stylesheet(): string {
    const { log, applications } = this.deps;
    log.debug("Entering AdminConsole.stylesheet().");
    const css = 'body{font-family:system-ui,-apple-system,"Segoe ' +
      'UI",Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem ' +
      '1rem;color:#222;line-height:1.45}' +
      // THE TWO COLUMNS. Flex rather than grid because the behaviour wanted at
      // a narrow width is "the sidebar stops being a column and becomes a block
      // above the page", which is what `flex-wrap` does for nothing — and this
      // console runs no script, so a layout that needed one would not be an
      // option anyway. The sidebar's `flex` is `0 0 auto` with a fixed basis so
      // that a long label wraps inside it instead of widening it and squeezing
      // the tables, which is the failure mode of letting it size to content.
      // THE CAP WIDENED FROM 92rem TO 104rem ON 2026-09-01, and the reason is
      // one column on one page rather than a general preference for wide
      // layouts. `/admin/ldap/directory` draws EVERY ATTRIBUTE OF EVERY ENTRY,
      // and an attribute value here is routinely an opaque forty-character
      // identifier — a DN, a certificate thumbprint, a client secret — so that
      // column is the widest thing in this console by a distance. At 92rem it
      // spilled past the card on a laptop. The extra twelve are what let the
      // shortening below (clipped()) keep a value readable instead of cutting
      // it to a stub, and every other page is unaffected: `.main` is `flex:1 1
      // 32rem`, so a page whose content is narrower stays the width its content
      // wants.
      '.shell{display:flex;flex-wrap:wrap;align-items:flex-start;gap:18px;' +
      'max-width:104rem;margin:0 auto}' +
      // THE SIDEBAR SCROLLS ITSELF RATHER THAN WITH THE PAGE. `position:sticky`
      // alone was not enough and the reason is easy to miss: a sticky box that
      // is TALLER than the viewport is pinned by its TOP, so the bottom of the
      // nav sits below the fold and the only way to reach it is to scroll the
      // whole document to its end — which got harder as the console grew, since
      // the page a reader is on decides how far that is. Capping the column at
      // the viewport and letting the nav overflow inside itself makes the two
      // scrollbars independent: the tab list is reachable from anywhere on any
      // page, at any length, and the page under it does not move.
      //
      // The column is a flex COLUMN so that the two lines above the nav keep
      // their natural height and the nav takes what is left; `min-height:0` on
      // the nav is what actually permits it to shrink below its content, which
      // is the flexbox rule that makes an overflow child scroll instead of
      // pushing its parent. The cap is `100vh` less the 1rem the sticky top
      // holds plus 1rem of air below it, which is the geometry once the
      // column is STUCK. Before the first scroll it is still in flow, an inch
      // or so down the document, so the card can reach the bottom edge of the
      // window — CSS cannot subtract an offset it does not know, and the only
      // way to close that inch would be a script this console does not have.
      // It costs nothing: the list is scrollable in that state as well.
      '.side{flex:0 0 13.5rem;position:sticky;top:1rem;max-height:calc(100vh ' +
      '- 2rem);display:flex;flex-direction:column}' +
      // `min-width:0` on a flex child is what stops a wide table inside the
      // card from pushing the whole layout past the viewport: without it the
      // card's minimum width is its content's, and one long DN widens the page
      // rather than scrolling inside its own cell.
      '.main{flex:1 1 ' +
      '32rem;min-width:0}.brand{font-size:.82em;font-weight:700;' +
      'color:#12107c;margin:0 0 ' +
      '2px;letter-spacing:.02em}.brandsub{font-size:.72em;color:#666;' +
      'margin:0 ' +
      '0 14px}.card{background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:10px;padding:24px 28px;box-shadow:0 6px 24px ' +
      'rgba(0,0,0,.08)}h1{font-size:1.35em;margin:0 0 4px;color:#12107c}' +
      // THE HEAD ROW — the title, and the refresh control pushed to the far end
      // of it. `align-items:baseline` so a control that much smaller sits on
      // the heading's baseline rather than being centred against a taller box,
      // and `flex-wrap` so that at a narrow width it drops underneath the title
      // instead of squeezing it to one word a line. The bottom margin is what
      // `p.sub` used to contribute before the issuer line came off this shell;
      // without it every page's breadcrumb trail sits up against its heading.
      '.pagehead{display:flex;flex-wrap:wrap;gap:10px;align-items:baseline;' +
      'justify-content:space-between;margin:0 0 14px}' +
      '.pagehead h1{margin:0}' +
      // The controls at the right-hand end of that row. `align-items:baseline`
      // again, because a <button> and an <a class=btn> are different boxes and
      // centring them against each other leaves the text half a pixel apart.
      '.pagehead .pagetools{display:flex;gap:8px;align-items:baseline}' +
      '.pagehead form.signout{display:inline;margin:0}' +
      // THE ACCOUNT MENU (2026-09-10). `position:relative` on the <details> and
      // `position:absolute` on the panel, so that opening it OVERLAYS the page
      // rather than pushing the card's first heading down — a menu that reflows
      // the page under it moves whatever the reader was about to click.
      //
      // The summary is drawn as a quiet button so it reads as a control beside
      // Refresh rather than as a word floating in the corner, and the caret is
      // a `::after` because the default triangle sits on the wrong side and
      // cannot be moved. `list-style:none` plus the -webkit- rule is what
      // removes it: the two together, because neither does it in both engines.
      // The same pair is on `details.fold` further down for the same reason.
      '.usermenu{position:relative}' +
      '.usermenu>summary{cursor:pointer;list-style:none;display:inline-flex;' +
      'gap:.4em;align-items:center;border:1px solid ' +
      '#d5d5dd;border-radius:6px;padding:4px ' +
      '10px;background:#fff;color:#333;font-size:.85em}.usermenu>' +
      'summary::-webkit-details-marker{display:none}' +
      '.usermenu>summary::after{content:"\\25be";color:#888;font-size:.9em}' +
      '.usermenu>summary:hover{background:#f4f6fb}' +
      '.usermenu[open]>summary{background:#eef2fb;border-color:#c3d0ea;' +
      'color:#12107c}' +
      // `z-index` because the panel overlaps the card's own content, and
      // `text-align:left` because `.pagetools` sits at the right-hand end of a
      // space-between row and the panel would otherwise inherit that.
      '.usermenupanel{position:absolute;right:0;top:calc(100% + ' +
      '6px);z-index:30;min-width:15rem;background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:8px;box-shadow:0 8px 28px ' +
      'rgba(0,0,0,.14);padding:8px;text-align:left}.usermenupanel ' +
      '.usermenuwho{margin:0 0 6px;padding:0 ' +
      '8px;color:#666;font-size:.75em}.usermenupanel ' +
      'a{display:block;padding:6px 8px;border-radius:5px;color:#12107c;' +
      'text-decoration:none;font-size:.85em}.usermenupanel ' +
      'a:hover{background:#eef2fb;text-decoration:none}' +
      // The sign-out form is `display:inline` in the rule above, which is right
      // in the head row and wrong in a stacked panel — so it is a block here,
      // separated from the link by the same hairline the nav uses, and its
      // button fills the width so the whole row is the target.
      '.usermenupanel form.signout{display:block;margin:6px 0 ' +
      '0;border-top:1px solid #eee;padding-top:6px}.usermenupanel ' +
      'form.signout button{width:100%}h2{font-size:1.05em;margin:1.8em 0 ' +
      '.5em;color:#12107c;border-bottom:1px solid ' +
      '#eee;padding-bottom:.2em}h3{font-size:.92em;margin:1.2em 0 ' +
      '.4em}p.sub{color:#666;font-size:.85em;margin:0 0 14px}' +
      // THE SIDEBAR. A list per section with a heading over it, in the same
      // card material as the page so the two read as one surface rather than as
      // a frame around a document. `flex:0 1 auto` with `min-height:0` and
      // `overflow-y:auto` is the whole of the independent scrolling described
      // on `.side` above: the card is its natural height while it fits and
      // scrolls inside itself when it does not, so a short nav does not become
      // a stretched empty box.
      'nav{background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:10px;padding:14px 14px ' +
      '8px;font-size:.85em;box-shadow:0 6px 24px rgba(0,0,0,.06);flex:0 1 ' +
      'auto;min-height:0;overflow-y:auto}' +
      // THE REALM CHOOSER, first inside the nav card and separated from the
      // sections by a hairline rather than by a card of its own. Its label is
      // `.navhead`'s metrics on purpose: it sits above a list of choices in the
      // same column, so anything else would read as a different KIND of thing
      // and put the reader back to wondering which pane it belonged to.
      '.realmpick{margin:0 0 12px;padding:0 0 10px;' +
      'border-bottom:1px solid #e6e6ee}' +
      '.realmpick label{display:block;margin:0 0 4px;font-size:.7em;' +
      'text-transform:uppercase;letter-spacing:.06em;color:#8a8a99;' +
      'font-weight:700}' +
      // The select takes the room and the button takes what it needs, so a long
      // realm name is readable in the column rather than truncated to fit a
      // button beside it.
      '.realmpickrow{display:flex;gap:6px;align-items:stretch}.realmpick ' +
      'select{flex:1 1 auto;min-width:0;font-size:1em;padding:3px ' +
      '4px;border:1px solid ' +
      '#c9c9d4;border-radius:5px;background:#fff;color:#222}.realmpick ' +
      'button{flex:0 0 auto;padding:3px 9px;font-size:.92em}.navsec{margin:0 ' +
      '0 12px}.navsec:last-child{margin-bottom:4px}' +
      // The section heading. Not a link and it must not look like one — there
      // is no page behind a section, which is the same reason it is not a
      // crumb.
      '.navhead{margin:0 0 4px;font-size:.7em;text-transform:uppercase;' +
      'letter-spacing:.06em;color:#8a8a99;font-weight:700}' +
      // The section the current page is in. A rule down its left rather than a
      // background, so that the mark reads as "you are in here" and not as a
      // second selected item beside the selected one.
      '.navsec.open{border-left:3px solid ' +
      '#12107c;margin-left:-14px;padding-left:11px}.navsec.open ' +
      '.navhead{color:#12107c}' +
      // A GROUP INSIDE A SECTION. It is an <li>, so `nav li` has already given
      // it the item metrics; what these rules do is take the item LOOK back off
      // it (it is a heading with a list under it, not a thing to click) and
      // indent the list it holds behind a hairline, which is what says "these
      // three are one thing" without a second colour or a box.
      '.navgrp{margin:6px 0 4px}' +
      // The group heading. Smaller than the section's and sentence-cased rather
      // than upper, so that two headings above one link cannot be read as two
      // sections — the section is the shout, the group is the aside.
      '.navsub{margin:0 0 3px;padding:0 6px;font-size:.78em;color:#6a6a80;' +
      'font-weight:700;letter-spacing:.01em}.navgrp.open' +
      // `>` and not a descendant: inside an open group, a group the page is
      // NOT in keeps the grey heading.
      '>.navsub{color:#12107c}.navgrp>ul{margin:0;padding-left:8px;' +
      'border-left:1px solid ' +
      '#e2e2ea}.navgrp.open>ul{border-left-color:#c3c0e0}nav ' +
      'ul{list-style:none;margin:0;padding:0}nav ' +
      'li{margin:0;font-size:1em}nav a,nav .here{display:block;padding:3px ' +
      '6px;border-radius:5px;text-decoration:none;line-height:1.3}nav ' +
      'a{color:#12107c}nav a:hover{background:#f0f0f7}' +
      // THE PAGE YOU ARE ON, AND IT USED TO BE A WHISPER (2026-09-05).
      //
      // It was `background:#eceaf6` — a lavender four shades off the card's own
      // white — which on a list of thirty-odd links read as "very slightly
      // different" rather than as "here". It now takes the same solid brand
      // fill the pager's current page has had all along (`.pagenav .here`), so
      // the two "you are here" markers in this console finally look alike.
      //
      // `scroll-margin` is the other half of the autofocus above: without it
      // the browser reveals the item flush against the top edge of the
      // scrolling card, where it reads as the first item in the list rather
      // than as one somewhere in the middle. Three lines of room above it keeps
      // its neighbours visible, which is what tells a reader where they are.
      'nav .here{font-weight:700;color:#fff;background:#12107c;' +
      'scroll-margin:4.5rem 0}' +
      // The focus ring is suppressed ONLY for the active item, and only because
      // the autofocus above puts focus there on every single page load — a ring
      // drawn around it would be a permanent artefact rather than a signal that
      // the keyboard is there. Every other link in this nav keeps its ring.
      'nav .here:focus{outline:none}' +
      // The active item on a DRILL-DOWN. It keeps the weight and the fill
      // `.here` gives it, because the reader is still inside that section, and
      // takes back the link colour and an underline, because it is a link again
      // and a bold black label reads as text nobody can click — which is
      // exactly what it was.
      'nav a.here{color:#fff;text-decoration:underline;background:#12107c}' +
      '.crumb{font-size:.82em;margin:0 0 14px;color:#666}' +
      '.crumb a{text-decoration:none;font-weight:600}' +
      '.crumb a:hover{text-decoration:underline}' +
      '.crumb .sep{margin:0 .45em;color:#aaa}' +
      // The last crumb is the page being drawn. It is not a link and must not
      // look like one, or the one crumb that does nothing is the one a reader
      // clicks.
      '.crumb ' +
      '.leaf{color:#222;font-weight:600}.warn{background:#fff8e1;border:1px ' +
      'solid #ffe082;padding:9px ' +
      '12px;border-radius:5px;font-size:.82em;margin:0 0 ' +
      '16px}.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px ' +
      '11px;border-radius:5px;font-size:.85em;margin:0 0 ' +
      '14px}.err{background:#fdecea;border:1px solid ' +
      '#f5c6c2;color:#b00020;padding:8px ' +
      '11px;border-radius:5px;font-size:.85em;margin:0 0 14px}' +
      // THE MESSAGE A PRESSED BUTTON CAME BACK WITH STAYS ON SCREEN
      // (2026-10-01). A form's answer lands at the section the button was in
      // (withReturnAnchors()), so a notice drawn at the top of the card would
      // be off screen; it sticks to the top of the window instead. The
      // sections a page is anchored at leave room under it.
      '.flash{position:sticky;top:0;z-index:30;padding-top:6px;' +
      'background:#fff}.flash>*:last-child{margin-bottom:10px}' +
      'h2[id],h3[id],h4[id],.fg-cell[id]{scroll-margin-top:5rem}' +
      // A VALUE THAT EXISTS ONCE. It is drawn big, monospaced and wrapping —
      // `word-break:break-all` rather than a scroll box — because the two
      // things that land in it are a base64url password and an activation URL,
      // and both are copied by selecting them. A block a reader has to scroll
      // sideways to select the end of is how half a credential gets pasted into
      // a message. `user-select:all` makes one click take the whole value; it
      // is a convenience, and selecting by hand still works where a browser
      // ignores it.
      '.secret{background:#f4f6ff;border:2px solid ' +
      '#12107c;border-radius:6px;padding:12px 14px;margin:0 0 12px;' +
      'font-family:ui-monospace,Menlo,Consolas,monospace;font-size:1em;' +
      'word-break:break-all;user-select:all}.tiles{display:flex;' +
      'flex-wrap:wrap;' +
      'gap:10px;margin:.6em 0 1em}.tile{border:1px solid ' +
      '#e2e2ea;border-radius:8px;padding:10px ' +
      '14px;min-width:9rem;background:#fbfbfd}.tile ' +
      '.n{font-size:1.5em;font-weight:700;color:#12107c;' +
      'line-height:1.1}.tile ' +
      '.l{font-size:.74em;color:#666;text-transform:uppercase;' +
      'letter-spacing:.03em}' +
      // THE FIRST CHART IN THIS CONSOLE (/admin/ssf/dead-letters, 2026-09-14).
      // An inline SVG laid out on the server, so it needs no script; this only
      // lets it shrink with the card, and lays its legend out as one wrapping
      // row of swatch-and-label pairs whose text stays in ink.
      '.chart svg{display:block;width:100%;height:auto;max-width:780px}' +
      '.legend{display:flex;flex-wrap:wrap;gap:4px 18px;font-size:.8em;' +
      'color:#333;margin:.3em 0 .9em}.legend span{display:inline-flex;' +
      'align-items:center;gap:6px}code.ec{white-space:nowrap}' +
      'table{border-collapse:collapse;width:100%;' +
      'margin:.4rem 0 .9rem;font-size:.8em}th,td{border:1px solid ' +
      '#e2e2ea;padding:.3rem .5rem;text-align:left;vertical-align:top}' +
      'th{background:#f0f0f5;font-weight:600}tr:nth-child(even) ' +
      'td{background:#fafafc}td.num,th.num{text-align:right;' +
      'font-variant-numeric:tabular-nums}' +
      // A cell holding a list of opaque identifiers. `overflow-wrap:anywhere`
      // is the one that also shrinks the cell's MINIMUM width, which is the
      // property that matters: break-all alone wraps the text and still lets
      // one unbreakable did:jwk widen the whole table past the card it sits in.
      'td.who{overflow-wrap:anywhere;line-height:1.9}' +
      'td.who code{white-space:normal}' +
      // THE "EVERY ATTRIBUTE" CELL on the four directory pages. One `<div>` per
      // attribute rather than `<br>`-separated text, so a value that DOES wrap
      // (a short multi-valued attribute, say) stays visually under its own
      // name instead of running into the next attribute's line. The cell does
      // not need `overflow-wrap` the way `td.who` does, because everything long
      // in it has been through clipped() — which is the point of that helper.
      'td.attrs>div{margin:.15em 0}' +
      '.vals{display:inline-block;vertical-align:top}' +
      // The DN column on the directory dump. Given a share rather than left to
      // the browser's auto layout, which sizes a column to its widest cell and
      // therefore handed the longest DN in the store a third of the table while
      // the attributes — the column with everything in it — got squeezed.
      'th.dn,td.dn{width:26%}th.from,td.from{width:8%}' +
      // A cell of short counted facts, one per line. Without the nowrap the
      // browser breaks "0 session(s)" across two lines in a narrow column and
      // the number ends up on a line of its own, reading as a value with no
      // label.
      'td.counts{white-space:nowrap}' +

      // A TABLE WITH A COLUMN PER EVENT TYPE, IN A BOX THAT SCROLLS SIDEWAYS.
      // The RISC accounts table is five fixed columns, then one per RISC event
      // type — fourteen of them — then three more; twenty-two columns do not
      // fit the card on a laptop and no amount of shortening inside a cell
      // makes them, because a count is already one character and a heading
      // cannot be narrower than its shortest word. So the TABLE keeps its
      // natural width and the BOX round it scrolls. That is the one arrangement
      // here that takes nothing away: dropping columns loses the number
      // somebody came for, and letting it spill past the card leaves those
      // columns unreachable rather than merely off to one side.
      //
      // `width:auto` with `min-width:100%` is the pair that does the work, and
      // the first half is easy to leave out: `table` above is `width:100%`, and
      // a table told to be exactly its container's width inside a scroll box
      // never overflows it — it squeezes, and the box never scrolls, so the
      // wrapper looks like it did nothing. Auto lets it take what its content
      // needs; the minimum keeps a table that DOES fit looking like every other
      // table on the page instead of shrinking to its text.
      '.wide{overflow-x:auto;max-width:100%}' +
      '.wide>table{width:auto;min-width:100%}' +

      // -------------------------------------------------------------------
      // A VALUE TOO LONG FOR ITS CELL, AND THE POPUP THAT GIVES IT BACK.
      //
      // See clipped() below for what this is for and why the truncation is
      // done in the markup rather than by CSS. What these rules add is the
      // half that has to be a HOVER: the full value, in a box the reader can
      // put the pointer INTO and select out of.
      //
      // IT IS NOT A `title` ATTRIBUTE, and that is the whole design. A native
      // tooltip cannot be selected, so a shortened client secret or DN would
      // be readable and not copyable — and copying it is the entire reason
      // somebody hovers a value on these pages. A `title` is still set beside
      // it, because a native tooltip is what a keyboard user and a screen
      // reader get; the rule this console holds to is that nothing is ever
      // said ONLY in a tooltip, and here the full value is in the document
      // either way.
      //
      // THERE IS NO SCRIPT (app.js sets `script-src 'none'`), so the popup is
      // `:hover` and `:focus-within` and nothing else. `tabindex="0"` on the
      // wrapper is what makes the second one reachable from a keyboard.
      //
      // The box hangs off the BOTTOM EDGE with no gap, so the pointer can
      // travel from the truncated text into the box without crossing dead
      // space and dismissing it — a gap here is the classic way a hover popup
      // becomes unusable. `z-index` puts it over the rows below; `max-width`
      // is in `ch` because what it holds is monospace and the useful measure
      // is characters rather than inches.
      '.trunc{position:relative;border-bottom:1px dotted #9a9ab0;cursor:help}' +
      '.trunc>.full{display:none;position:absolute;z-index:30;left:0;' +
      'top:100%;' +
      'min-width:16rem;max-width:88ch;padding:7px 9px;background:#fffdf3;' +
      'border:1px solid #d9d2a8;border-radius:6px;' +
      'box-shadow:0 6px 18px rgba(0,0,0,.18);font-size:1.05em;' +
      'overflow-wrap:anywhere;white-space:normal;cursor:text}' +
      // ONE CLICK SELECTS THE WHOLE VALUE. `user-select:all` is on the `code`
      // and not on the box, so the hint under it stays out of the selection —
      // a copy that carried "58 characters — select to copy" into somebody's
      // configuration file would be a helper that breaks the thing it helps.
      '.trunc>.full code{user-select:all;-webkit-user-select:all;' +
      'background:transparent;padding:0}.trunc:hover>.full,.trunc:focus>' +
      '.full,' +
      '.trunc:focus-within>.full{display:block}' +
      // The one-line reminder under the value. `user-select:none` so that a
      // reader who selects the box to copy it does not carry this sentence
      // into their clipboard with the value — which would be a tooltip that
      // breaks the thing it exists to help with.
      '.trunc>.full .hint{display:block;margin-top:5px;font-size:.72em;' +
      'color:#7a7460;font-family:system-ui,-apple-system,sans-serif;' +
      'user-select:none;-webkit-user-select:none}.state-valid{color:#0b6b4f;' +
      'font-weight:600}.state-expired{color:#8a6d00}' +
      '.state-revoked{color:#b00020;font-weight:600}.state-none{color:#666}' +
      'form.inline{display:inline;margin:0}button{padding:5px ' +
      '10px;border-radius:5px;border:1px solid #12107c;background:#12107c;' +
      'color:#fff;font-size:.8em;cursor:pointer}' +
      'button.secondary{background:#fff;color:#12107c}' +
      'button.danger{background:#b00020;border-color:#b00020}' +
      // `number` joined this list with /admin/token-lifetimes, whose four
      // inputs are the console's first. Without it they are the one control in
      // the card drawn in the browser's default chrome, beside a form that
      // matches everything else — which reads as a half-finished page rather
      // than as a missing selector.
      'input[type=text],input[type=number],textarea,' +
      'select{box-sizing:border-box;padding:6px 8px;border:1px solid #bbb;' +
      'border-radius:5px;font-size:.85em;font-family:inherit}' +
      'textarea{width:100%;min-height:7rem;font-family:ui-monospace,' +
      'SFMono-Regular,Menlo,monospace}.formrow{display:flex;flex-wrap:wrap;' +
      'gap:8px;align-items:center;margin:.5em 0}.formrow ' +
      'label{font-size:.78em;font-weight:600;color:#555}' +

      // ---------------------------------------------------------------------
      // THE SEARCH PANE UNDER A CHOOSER (chooserPane()). `max-height` with
      // `overflow-y:auto` is the whole point of it rather than trim: the
      // control must be the same size showing one match or twenty, because it
      // sits above the table the reader came for and the `<select>` it replaced
      // was one line whatever the register held. Twenty rows at this size is
      // about 26em, so the pane scrolls from roughly the eleventh — which is
      // what makes the count and the `next 20` link under it the page's own
      // statement about what is off-screen rather than a thing the reader has
      // to notice.
      //
      // `.on` is the entry the page is ALREADY showing, marked because the
      // chooser is drawn under a selected application as well as over a bare
      // list, and a search result identical to the page behind it reads as a
      // link that does nothing.
      // ---------------------------------------------------------------------
      // A FORM THAT IS A FRAGMENT TARGET — the two chooser searches and the
      // delegation table's filter. See chooserPane() for why they submit to
      // themselves by fragment; this is the one rule they need in return.
      // `scroll-margin-top` stops the browser from putting the form flush
      // against the top of the window, and the size of it is measured rather
      // than picked: each of these forms has ONE line above it that says what
      // it is for — a folded sentence over the choosers, the `What happened`
      // heading over the filter — and 3rem is what brings that line back onto
      // the screen with the form. Landing one line lower would hide it, which
      // is the wrong thing to hide from somebody who has just arrived at the
      // control. It is the only effect this class has and the only reason any
      // of those forms has a class at all.
      // ---------------------------------------------------------------------
      // THE PKI PANE (`/admin/pki`). Ten rules, and they are here rather than
      // in `admin-ui/pki_admin.ts` because this is the console's ONE
      // stylesheet: a page with a `<style>` of its own would be the second
      // place a reader has to look for why something is laid out as it is, and
      // `script-src 'none'` is already the reason there is no third.
      //
      // **`.pki-cols` IS THE WHOLE LAYOUT DECISION.** That pane is three blocks
      // — the certificate fields, the key pair and the subject DN — which are
      // one act and read as one act only side by side; stacked, the button at
      // the top of the second is nine screens above the extensions it applies
      // to. `auto-fit` with a 22rem floor drops to two columns and then to one
      // on a narrow window without a media query, which is the same rule the
      // page it is modelled on uses.
      //
      // **`.pki-extlist` IS A COLUMN FLOW AND NOT A GRID**, and that is not
      // taste: a grid lays its items out in ROW order, so twenty-two cards of
      // different heights leave a ragged gap under every short one. A column
      // flow packs them and keeps document order down each column.
      //
      // **THE TEXTAREA RULE IS AN OVERRIDE AND HAS TO BE.** This console's
      // default is `min-height:7rem`, which is right for a policy document and
      // wrong for twenty-odd one-item-per-line boxes: at 7rem each the pane is
      // about four screens of empty box. They are sized by their `rows`
      // attribute here instead, which is what the markup already says.
      // ---------------------------------------------------------------------
      '.pki-cols{display:grid;grid-template-columns:repeat(auto-fit,' +
      'minmax(22rem,1fr));gap:14px;margin:.6em 0 ' +
      '1em;align-items:start}.pki-col{border:1px solid ' +
      '#e2e2ea;border-radius:8px;padding:10px 12px;background:#fbfbfd;' +
      'min-width:0}.pki-group{font-size:.82em;font-weight:700;color:#12107c;' +
      'text-transform:uppercase;letter-spacing:.03em;margin:.9em 0 .4em}' +
      '.pki-col>.pki-group:first-child{margin-top:0}.pki-row{display:flex;' +
      'flex-wrap:wrap;gap:8px;align-items:flex-end;margin:.45em 0}.pki-row>' +
      'label{font-size:.78em;font-weight:600;color:#555;display:flex;' +
      'flex-direction:column;gap:3px}.pki-field{margin:.45em 0}.pki-field>' +
      'label{font-size:.78em;font-weight:600;color:#555;display:block}' +
      '.pki-flag{font-weight:400;font-size:.78em;color:#333;' +
      'display:inline-flex;align-items:center;gap:4px;flex-direction:row}' +
      '.pki-flags{display:flex;flex-wrap:wrap;gap:2px 10px;margin:.3em ' +
      '0}.pki-extlist{columns:24rem 3;column-gap:14px;margin:.6em 0 1em}' +
      '.pki-ext{break-inside:avoid;-webkit-column-break-inside:avoid;' +
      'display:inline-block;width:100%;border:1px solid ' +
      '#e2e2ea;border-radius:8px;padding:8px 10px;margin:0 0 10px;' +
      'background:#fbfbfd}.pki-exthead{display:flex;flex-wrap:wrap;gap:8px;' +
      'align-items:baseline;border-bottom:1px solid ' +
      '#eeeef4;padding-bottom:4px;margin-bottom:5px}.pki-ext ' +
      'textarea,.pki-col ' +
      'textarea{min-height:0}form.finder{scroll-margin-top:3rem}' +
      '.chooser{max-height:13.5em;overflow-y:auto;border:1px solid ' +
      '#e2e2ea;border-radius:6px;background:#fbfbfd;margin:.1em 0 ' +
      '.3em}.chooser ul.hits{list-style:none;margin:0;padding:0}.chooser ' +
      'li{border-bottom:1px solid #eeeef4;padding:.3rem ' +
      '.55rem;font-size:.82em;overflow-wrap:anywhere}.chooser ' +
      'li:last-child{border-bottom:none}.chooser ' +
      'li.on{background:#eef0ff}.chooser ' +
      '.hitwhat{display:block;color:#666;font-size:.9em}.chooser ' +
      'p.none{margin:.55rem;font-size:.82em;color:#666}' +
      'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
      'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;' +
      'border-radius:3px;word-break:break-all}a{color:#12107c}' +
      '.note{font-size:.78em;color:#666;margin:.3em 0 1em}' +

      // ---------------------------------------------------------------------
      // THE FOLDS. See note() for what is folded and why; this is only what one
      // LOOKS like, and two of the rules here are doing more than decoration.
      //
      // `list-style:none` and the ::-webkit-details-marker rule remove the
      // browser's own triangle so that ::before can draw one that points the
      // same way in every engine — Safari's marker and Firefox's differ, and a
      // page of two kinds of triangle reads as two kinds of control. The
      // triangle is drawn in the link colour because that is what this console
      // has already taught a reader to click.
      //
      // The summary is `display:list-item` NOWHERE and flex here on purpose: a
      // summary of two lines with the marker floating beside the first is the
      // one layout that made the fold look broken at narrow widths.
      // ---------------------------------------------------------------------
      'details.fold{margin:.3em 0 1em}details.fold>summary{cursor:pointer;' +
      'list-style:none;display:flex;gap:.45em;align-items:baseline;' +
      'font-weight:600;color:#3a3a4a}details.fold>' +
      'summary::-webkit-details-marker{display:none}details.fold>' +
      'summary::before{content:"\\25b8";color:#12107c;flex:none;' +
      'font-size:.9em}' +
      'details.fold[open]>summary::before{content:"\\25be"}details.fold>' +
      'summary:hover{color:#12107c}' +
      // A SECTION drawn as a fold, for a block whose BODY is a reference
      // table rather than a paragraph. The summary is styled as the <h2> it
      // replaces — same size, same colour, same rule under it — so a reader
      // meets the heading exactly where it was and the table under it costs
      // one click instead of five screens of scrolling. It is not the plain
      // fold's look because a section heading that reads like a paragraph's
      // heading makes a page of eight cards look like a footnote.
      'details.fold.section{margin:1.8em 0 1em}details.fold.section>' +
      'summary{font-size:1.05em;color:#12107c;font-weight:600;' +
      'border-bottom:1px solid #eee;padding-bottom:.2em}details.fold.section>' +
      'summary::before{color:#12107c}details.fold.section>' +
      '.foldbody{margin:.5em 0 0}' +
      // A fold inside a table cell takes the cell's own weight and slant. The
      // summary is emphasised elsewhere because it is a heading over a
      // paragraph; in a column it is the cell's text, and a bold row beside a
      // plain one reads as the bold one meaning more.
      'td details.fold>summary{font-weight:inherit;font-style:inherit;' +
      'color:inherit}td details.fold{margin:0}td details.fold ' +
      '.foldbody{margin:.3em 0 0 ' +
      '1.05em}details.fold>summary:focus-visible{outline:2px solid ' +
      '#12107c;outline-offset:2px;border-radius:3px}' +
      // The body sits under the summary, indented to the width of the marker so
      // that the prose lines up with the words above it rather than with the
      // triangle.
      'details.fold .foldbody{margin:.45em 0 0 1.05em}' +
      'details.fold .foldbody>p:first-child{margin-top:0}' +
      'details.fold .foldbody>p:last-child{margin-bottom:0}' +
      // A folded warning keeps the box, so a page with a caveat on it still
      // looks like one when the caveat is closed.
      'details.warn.fold{margin:.6em 0}' +
      'details.warn.fold>summary{color:#6b4e00}' +
      'details.warn.fold>summary::before{color:#8a6d00}' +
      // A folded list item. The marker of the <li> would sit beside the fold's
      // own triangle, which is two bullets for one item.
      'li.foldli{list-style:none;margin-left:-1.2em}' +
      'li.foldli details.fold{margin:.35em 0}' +

      // ---------------------------------------------------------------------
      // THE TOOLTIP AFFORDANCE, DRAWN BY AN ATTRIBUTE SELECTOR AND NOT BY A
      // MARKER IN THE MARKUP. A label that carries a `title` gets the dotted
      // underline and the help cursor because it carries one — so a caller that
      // adds a tooltip cannot forget to add the sign that there is one, which
      // is the whole failure mode of a tooltip nobody can see. `code[title]` is
      // left alone deliberately: shortened() has put the full value in a title
      // on hundreds of table cells since long before this, and underlining
      // every one of them would draw a page of dotted lines.
      // ---------------------------------------------------------------------
      // A fold that lands inside a form row takes a line of its own. Without
      // this it is a flex item beside the control it captions, which shrinks
      // the summary to a column two words wide.
      '.formrow details.fold{flex-basis:100%;margin:.2em 0 ' +
      '0}label[title]{cursor:help;text-decoration:underline dotted #b4b4c4;' +
      'text-underline-offset:3px}th[title],.tipword[title]{cursor:help;' +
      'text-decoration:underline dotted #b4b4c4;text-underline-offset:3px}' +
      // THE OVERVIEW PAGE'S DERIVED LIST OF EVERY PAGE HERE (consoleGuide()).
      // Its shape is the sidebar's — sections, one group level under Protocols,
      // pages under that — so it is given the sidebar's rhythm rather than the
      // body text's: the section heading close to its own list, the section's
      // `what` tight under the heading rather than at `.note`'s full paragraph
      // spacing, and a group's title and description on their own lines above
      // its three pages. Without the last of those a group reads as a fourth
      // page whose blurb happens to be long.
      '.guide h3{margin:1.6em 0 .1em;color:#12107c}' +
      '.guide p.note{margin:.1em 0 .5em}' +
      '.guide li{margin:.5em 0}' +
      // The page's link and its folded description read as one row: the fold
      // sits tight under the link rather than at a paragraph's distance.
      '.guide details.fold{margin:.1em 0 .1em .1em}.guide ' +
      'details.fold>summary{font-weight:400;color:#666}.guide ' +
      '.grp{display:block;font-weight:700;color:#12107c}.guide ' +
      '.grpwhat{display:block;font-size:.92em;color:#666;margin:.1em 0 .2em}' +
      // A page in the nav that nobody described. Marked rather than dropped —
      // see consoleGuide() — so it has to LOOK like a report and not like prose
      // somebody wrote on purpose.
      '.guide .undescribed{color:#a33}.meta{margin-top:22px;padding-top:12px;' +
      'border-top:1px solid #eee;font-size:.76em;color:#666}.meta ' +
      'div{margin:3px 0}ul{margin:.3em 0;padding-left:1.2em}li{margin:.25em ' +
      '0;font-size:.85em}' +
      // The head copy of this control is a fragment TARGET — see pageNavPair()
      // for why every paging link carries `#list-<param>`. The scroll margin is
      // the same 3rem the search forms take and for the same reason: the line
      // immediately above a pager is the heading or the filter that says which
      // list it moves, and landing flush would put that line just off-screen.
      '.pagenav{display:flex;flex-wrap:wrap;gap:6px;align-items:center;' +
      'margin:.5em 0;font-size:.8em;scroll-margin-top:3rem}.pagenav ' +
      'a,.pagenav .here,.pagenav .off{display:inline-block;padding:3px ' +
      '8px;border-radius:5px;border:1px solid #d5d5dd;background:#fff;' +
      'text-decoration:none;min-width:1.6em;text-align:center}.pagenav ' +
      '.here{background:#12107c;border-color:#12107c;color:#fff;' +
      'font-weight:700}.pagenav .off{color:#aaa;background:#f7f7fa}.pagenav ' +
      '.where{border:0;background:none;color:#666;padding-left:.4em}' +
      // ---------------------------------------------------------------------
      // THE SERVICE METADATA PAGE'S OWN CLASSES, AND WHY THEY ARE IN THIS FILE
      // RATHER THAN IN THE ONE THAT USES THEM.
      //
      // `/admin/sts-metadata` is built by `../sts_metadata.js` — it derives its
      // whole content from the live express router, which is why it is the last
      // module `common/protocol_stack.ts` loads — but it is drawn by page()
      // like every other console page, and page() emits the ONLY <style> this
      // console has. A <style> of its own would have to sit inside <body>,
      // which browsers accept and no validator does, and there would then be
      // two stylesheets to keep in step. So its classes live here, the way
      // .tile's and .state-valid's do: a shared stylesheet with a few
      // page-specific rules in it.
      // ---------------------------------------------------------------------
      // A paragraph of explanation above a table. Wider and quieter than body
      // text; `.sub` is the page subtitle and cannot double as this, because
      // that one is metrics-sized and appears once.
      '.lead{color:#555;font-size:.85em;margin:0 0 12px;max-width:62rem}' +
      '.m{font-weight:600;color:#0b6b4f;white-space:nowrap}' +
      '.none{color:#999}' +
      // Why a path is not a link, beside the path. Italic and grey because it
      // is an aside about the row rather than part of it.
      '.why{color:#999;font-size:.85em;font-style:italic}' +
      '.eff{color:#b26a00;cursor:help}' +
      '.bad{color:#b00020;font-weight:600}' +
      'td.p{width:22%}td.n{width:16%}td.s{width:14%}' +
      'td.p a{text-decoration:none}td.p a:hover ' +
      'code{text-decoration:underline}' +
      // A LINK THAT LOOKS LIKE A BUTTON, which is not decoration here: the
      // download control has to be an <a download> — these pages run no
      // script, so nothing else can hand a browser a file — and a
      // control that saves a document should not read as a sentence.
      // The copy buttons (2026-10-01): small, beside the value they copy.
      'button.copybtn{padding:1px 7px;margin-left:6px;font-size:.8em;' +
      'vertical-align:baseline}' +
      'a.btn{display:inline-block;padding:5px 10px;border-radius:5px;' +
      'border:1px solid #12107c;background:#12107c;color:#fff;font-size:.8em;' +
      'text-decoration:none}' +
      'a.btn:hover{background:#0d0b5e;color:#fff}' +
      // The quiet form, matching button.secondary below, for a link that is on
      // every page and is nobody's next action. Both rules out-specify the two
      // above them, so the order they are written in here does not matter.
      'a.btn.secondary{background:#fff;color:#12107c}' +
      'a.btn.secondary:hover{background:#eef0fb;color:#12107c}' +
      // The protocol cards at the top of that page. Flex rather than grid for
      // the reason the shell is: what is wanted at a narrow width is "the row
      // becomes fewer columns", which flex-wrap does for nothing. `flex:1 1
      // 15rem` lets the last row stretch rather than leaving a ragged gap.
      '.protos{display:flex;flex-wrap:wrap;gap:9px;margin:.6em 0 1.4em}' +
      '.proto{flex:1 1 15rem;border:1px solid #e2e2ea;border-radius:8px;' +
      'padding:9px 12px;background:#fbfbfd}' +
      '.proto a,.proto .n{font-weight:700;font-size:.85em;line-height:1.3}' +
      '.proto .n{color:#222}' +
      '.proto .d{font-size:.75em;color:#666;margin-top:3px;line-height:1.4}' +
      // The count and the specification links. Smallest thing on the card,
      // because it is the one part a reader scans rather than reads.
      '.proto .c{font-size:.72em;color:#8a8a99;margin-top:5px}' +
      // ---------------------------------------------------------------------
      // /admin/delegation/map's OWN CLASSES, here for the reason the service
      // metadata page's are: page() emits the console's ONLY <style>, and a
      // second one inside <body> is markup no validator accepts.
      // ---------------------------------------------------------------------
      // THE FRAME ROUND THE DIAGRAM, AND `overflow:auto` IS THE WHOLE OF IT. An
      // SVG is generated at its natural size and a busy one is wider than the
      // card; without this the picture either widens the page past the viewport
      // (the failure `min-width:0` on `.main` exists to prevent, arriving by
      // another door) or is squeezed to fit and becomes unreadable. It scrolls
      // inside its own box instead, and the filter above it is how a reader
      // makes it small enough not to need to.
      '.diagram{overflow:auto;max-width:100%;border:1px solid #e2e2ea;' +
      'border-radius:8px;background:#fff;padding:12px;margin:.6em 0 .4em}' +
      // `max-width:none` states that the picture is not to be scaled to the
      // box, because a diagram scaled down is one whose labels have stopped
      // being legible while still looking as though they should be.
      '.diagram svg{display:block;max-width:none}' +
      // The key. A table like every other, with the shape column sized to the
      // swatches rather than to its heading.
      'table.key td.art{width:5.5rem;text-align:center;vertical-align:middle;' +
      'background:#fff}' +
      'table.key td.art svg{vertical-align:middle}' +
      // The narrow case. One breakpoint and no more: below it the sidebar stops
      // being sticky and sits above the page as an ordinary block, which is
      // what flex-wrap has already done to it by then — the rule only undoes
      // the stickiness, which on a full-width block would pin the whole nav to
      // the top of the viewport and take the screen with it. The cap and the
      // nav's own scrollbar come off with the stickiness, and for the same
      // reason: down here the sidebar is a full-width block ABOVE the page, so
      // a scrollbox inside it would be a second scrolling region in the
      // ordinary flow of the document with nothing pinned beside it to make
      // sense of.
      '@media (max-width:56rem){.side{position:static;flex:1 1 100%;' +
      'max-height:none;display:block}nav{overflow-y:visible}' +
      '.navsec{display:inline-block;vertical-align:top;min-width:11rem;' +
      'margin-right:1.2em}.navsec.open{margin-left:0;padding-left:0;' +
      'border-left:0;border-top:3px solid #12107c;padding-top:6px}}' +
      // ---------------------------------------------------------------------
      // /admin/applications/new's CONDITIONAL FIELDS, and the reason this is
      // CSS and not a script.
      //
      // That page offers a field for every protocol family this service has,
      // and most of them are irrelevant to any one application: somebody
      // registering an OAuth client was reading past a SAML entityID, a
      // Kerberos SPN and ten SAML assertion settings to reach the box they came
      // for. So a field is shown only when the family it belongs to is TICKED.
      //
      // `script-src 'none'` holds. This is `:has()` — the checkbox is already
      // in the same form as the fields, and already has an id — so the browser
      // does the whole thing with a selector and this console still ships no
      // script. It is the same answer the collapsible prose blocks got with
      // `<details>`: the test for a script is that the page CANNOT work without
      // one, and a form that shows every field works, it is just longer.
      //
      // THE FALLBACK IS TO SHOW EVERYTHING, which is why the rules are inside
      // `@supports selector(:has(*))`. A browser without `:has()` gets the page
      // exactly as it was before this existed — every field, all the time — and
      // the page says so rather than leaving somebody to wonder why nothing
      // hides. Showing too much is the safe direction: no control a person
      // needs is ever missing, and nothing they type is ever dropped, because
      // the SERVER reads whatever was posted and does not care what was
      // visible.
      //
      // `display:revert` and not `block`: these rules are applied to <tr> as
      // well as to <div>, and `block` on a table row makes it a block box that
      // no longer lines up with the header above it.
      '@supports selector(:has(*)){' +
      'form.newapp .pf{display:none}' +
      // One rule per family, generated from the same PROTOCOLS table the
      // checkboxes are drawn from — so a family added there gets its rule for
      // nothing, and cannot get a checkbox without one.
      // One CHECKBOX per choice, and a combined choice (Verifiable
      // Credentials) shows every family it stands for.
      applications.FAMILY_CHOICES.map(function (choice) {
        return choice.families.map(function (family) {
          return 'form.newapp:has(#proto-' + choice.id + ':checked) .pf-' +
                 family + '{display:revert}';
        }).join('');
      }).join('') +
      // The prompt that replaces the fields until something is ticked, and its
      // own disappearance. Without it the page below the checkbox table is
      // empty and reads as broken rather than as waiting.
      'form.newapp:has(input[name="protocol"]:checked) ' +
      '.pf-hint{display:none}}.pf-hint{color:#555;font-size:.85em;' +
      'background:#fbfbfd;border:1px ' +
      'dashed #d5d5dd;border-radius:8px;padding:10px 12px;margin:.6em ' +
      '0}' +
      // The off-screen default button of /admin/applications/new — see the
      // form there. Off-screen rather than `display:none`, which some
      // browsers skip when choosing the button Enter presses.
      '.default-submit{position:absolute;left:-10000px;width:1px;height:1px;' +
      'overflow:hidden}' +
      // ---------------------------------------------------------------------
      // THE APPLICATION FIELD GRID (2026-09-30): cells that wrap to as many
      // columns as the card has room for, each a field's name, the families
      // it belongs to and its control; a list's boxes each with a delete
      // button, and a "+" under them.
      '.fg{display:grid;grid-template-columns:repeat(auto-fill,' +
      'minmax(19rem,1fr));gap:.6rem .8rem;margin:.4em 0 1em}' +
      '.fg-cell{border:1px solid #e3e3ea;border-radius:8px;padding:8px 10px;' +
      'background:#fbfbfd;min-width:0}' +
      '.fg-name{display:block;font-weight:600;overflow-wrap:anywhere}' +
      '.fg-for{display:block;color:#666;font-size:.78em;margin:.1em 0 .4em}' +
      '.fg-cell input[type=text],.fg-cell input[type=number],' +
      '.fg-cell select,.fg-cell textarea{width:100%;box-sizing:border-box;' +
      'min-height:0}' +
      '.fg-item{display:flex;gap:.3em;align-items:center;margin:.2em 0}' +
      '.fg-item input{flex:1 1 auto}' +
      'button.fg-drop,button.fg-grow{padding:2px 8px;line-height:1.2;' +
      'min-width:0}' +
      'button.fg-grow{font-weight:700;margin-top:.2em}' +
      '.fg-bool,.fg-checks{display:flex;flex-wrap:wrap;gap:.2em .9em}' +
      '.fg-radio{font-weight:400;white-space:nowrap}' +
      '.fg-protos{display:flex;flex-wrap:wrap;gap:.3em 1em;margin:.4em 0 1em}' +
      '.fg-proto{font-weight:400;white-space:nowrap}' +
      '.fg-view{align-items:center;gap:.8em}' +
      // ---------------------------------------------------------------------
      // /admin/applications/new's RFC 9728 IMPORT (2026-09-13): a checkbox that
      // shows the three ways to give a document, and a pane of three TABS over
      // what was read. Neither needs a script, and neither needs `:has()`: both
      // are the general sibling combinator, which every browser has, so there
      // is no fallback to argue. The checkbox and the three radio buttons come
      // FIRST in their containers precisely so that `~` can reach what follows.
      //
      // THE RADIO BUTTONS POST NOTHING. Each carries `form=` naming a form id
      // no page has, so its form owner is null: the three still make one group,
      // because a radio group is the name within one owner, and none of them is
      // a field of the create form around it. A hidden panel's inputs ARE
      // posted — `display:none` does not take a control out of a form — which
      // is what lets the third tab be edited and then submitted from the first.
      '.prm-source{display:none;margin:.6em 0}' +
      '.prm-use:checked~.prm-source{display:block}' +
      '.prm-tabs{margin:1em 0;border:1px solid #d5d5dd;border-radius:8px;' +
      'background:#fff}' +
      '.prm-tabs>input[type=radio]{position:absolute;opacity:0;width:1px;' +
      'height:1px;margin:0}' +
      '.prm-tablist{display:flex;flex-wrap:wrap;gap:4px;padding:6px 6px 0;' +
      'border-bottom:1px solid #d5d5dd;background:#f6f6fa;' +
      'border-radius:8px 8px 0 0}' +
      '.prm-tablist label{padding:6px 14px;border:1px solid transparent;' +
      'border-bottom:0;border-radius:6px 6px 0 ' +
      '0;cursor:pointer;color:#12107c}.prm-panel{display:none;padding:12px;' +
      'overflow-x:auto}' +
      '.prm-panel pre{white-space:pre-wrap;word-break:break-all;margin:0}' +
      // ---------------------------------------------------------------------
      // TABS (2026-10-01): an application's page, one tab per section, and its
      // configuration one sub-tab per protocol. tabbedPanels() argues the
      // mechanism: the fragment decides, through `:target` and `:has()`. A
      // browser without `:has()` shows every panel, which is the page as it
      // was.
      '.tabbar{display:flex;flex-wrap:wrap;gap:4px;margin:10px 0 14px;' +
      'border-bottom:1px solid #d5d5dd}.tabbar a{padding:6px 12px;' +
      'border:1px solid #d5d5dd;border-bottom:0;border-radius:6px 6px 0 0;' +
      'background:#f6f6fa;color:#12107c;text-decoration:none;' +
      'font-size:.9em}.subbar a{font-size:.85em;padding:4px 10px}' +
      '.tabpanel,.subpanel{scroll-margin-top:1rem}' +
      '@supports selector(:has(*)){' +
      '.tabs>.tabpanel,.subtabs>.subpanel{display:none}' +
      '.tabs>.tabpanel:target,.tabs>.tabpanel:has(:target),' +
      '.subtabs>.subpanel:target,.subtabs>.subpanel:has(:target)' +
      '{display:block}' +
      '.tabs:not(:has(>.tabpanel:target,>.tabpanel :target))>' +
      '.tabpanel.first,.subtabs:not(:has(>.subpanel:target,>.subpanel ' +
      ':target))>.subpanel.first{display:block}' +
      '.tabs:not(:has(>.tabpanel:target,>.tabpanel :target))>.tabbar ' +
      'a.first,.subtabs:not(:has(>.subpanel:target,>.subpanel :target))>' +
      '.subbar a.first{background:#fff;font-weight:700;' +
      'border-color:#12107c}' +
      // The tab being read, one rule per tab: a selector cannot compare a
      // link's href with the id that is targeted, so the ids are named.
      APPLICATION_TAB_IDS.concat(applications.FIELD_GROUPS.map(function (g) {
        return 'cfg-' + g.id;
      }), ['cfg-families'], USER_TAB_IDS, USER_SUB_TAB_IDS).map(function (id) {
        const sub = id.indexOf('cfg-') === 0 ||
          USER_SUB_TAB_IDS.indexOf(id) >= 0;
        const outer = sub ? '.subtabs' : '.tabs';
        const bar = sub ? '.subbar' : '.tabbar';
        return outer + ':has(#' + id + ':target,#' + id + ' :target)>' + bar +
          ' a[href="#' + id + '"]';
      }).join(',') + '{background:#fff;font-weight:700;' +
      'border-color:#12107c}}' +
      ['json', 'table', 'fields'].map(function (tab) {
        return '#prm-tab-' + tab + ':checked~.prm-panel-' + tab +
               '{display:block}' +
               '#prm-tab-' + tab + ':checked~.prm-tablist label[for="prm-tab-' +
               tab +
               '"]{background:#fff;border-color:#d5d5dd;font-weight:600;' +
               'margin-bottom:-1px}' +
               '#prm-tab-' + tab + ':focus-visible~.prm-tablist ' +
               'label[for="prm-tab-' + tab + '"]{outline:2px solid #12107c}';
      }).join('');
    log.debug("Leaving AdminConsole.stylesheet(). " + css.length + " bytes.");
    return css;
  }
  // THE SHELL: the one document every console path answers. It carries no
  // fact and no credential — the static files are public — and its assets
  // are root-relative, so `app.js`'s realm rewrite puts them under the realm
  // the shell was asked in, as it does every href.
  /**
   * Builds the static console's shell document.
   *
   * @param registered - `oidcRp.ensureConsoleCallback()`'s answer: when it
   *   refused the callback address, the shell says why instead of loading
   * @returns the document
   */
  shellDocument(registered: any): string {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.shellDocument().");
    const refused = registered && registered.ok === false;
    const html = '<!DOCTYPE html>\n<html lang="en"><head><meta ' +
      'charset="utf-8"><meta name="viewport" content="width=device-width, ' +
      'initial-scale=1"><title>IYA STS admin</title>' +
      '<link rel="stylesheet" href="/admin/console.css">' +
      (refused ? '' : '<script src="/admin/console.js" defer></script>') +
      '</head><body><div class="shell"><div class="main"><div ' +
      'class="card"><h1>IYA STS admin</h1>' +
      (refused
        ? this.warn(this.esc(registered.why || 'This console cannot sign ' +
                             'in at this address.'),
                    'This console cannot sign in here')
        : '<noscript>' + this.warn('This console is a script that runs ' +
            'in your browser and draws every page from <code>/admin-api' +
            '</code>; with scripts blocked there is nothing it can show.',
            'Scripts are blocked') + '</noscript><p class="lede">' +
          'Signing in&hellip;</p>') +
      '</div></div></div></body></html>\n';
    log.debug("Leaving AdminConsole.shellDocument().");
    return html;
  }

  // The runtime's bundle, built by `build-typescript.sh` beside this module;
  // read once. A tree that was never built (a checkout) has none, and the
  // shell then loads a script that says so.
  /**
   * Returns the static console's script.
   *
   * @returns the bundle's text
   */
  consoleScript(): string {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AdminConsole.consoleScript().");
    if (consoleScriptText === null) {
      try {
        consoleScriptText = require('fs').readFileSync(
          require('path').join(__dirname, 'console.js'), 'utf8');
      } catch (e) {
        log.error(errorCodes.tag('STS-ADMIN-0844') + 'admin: the static ' +
                  'console\'s script could not be read: ' +
                  ((e && e.message) || e));
        consoleScriptText = 'document.body.textContent = "This build of ' +
          'the service has no console script (admin-ui/console.js).";';
      }
    }
    log.debug("Leaving AdminConsole.consoleScript().");
    return consoleScriptText;
  }



  // ---------------------------------------------------------------------------
  // THE SHELL ANSWER (#446): everything `web_shell.ts` draws the frame from
  // that is not the page itself — the gate as it stands for this reader and
  // the labels of the roles it names, the realm and the realms to choose
  // between, where the realm's root and the portal are, the sections this
  // reader may see, a retirement in progress, what this process runs as,
  // what is persisted, and the build. `GET /admin-api/console` answers it.
  // ---------------------------------------------------------------------------
  /**
   * Builds the console's shell answer for one reader.
   *
   * @param req - the express request, or null outside one
   * @param gate - optional; the gate state the banners are drawn from, when
   *   the caller holds one (null draws them as for no gate); the request's
   *   own when left out
   * @param nav - optional; the gate state the sidebar is drawn for — the
   *   request's own when left out, and the token's for `/admin-api/console`
   * @returns the shell answer
   */
  shellJson(req, gate?, nav?) {
    const { log, realms, config, rbac, gateStateFor, persistence } = this.deps;
    log.debug("Entering AdminConsole.shellJson().");
    const navState = nav !== undefined ? nav
      : (req ? gateStateFor(req) : null);
    const given = gate === undefined ? navState : gate;
    const state = given || {};
    const roleLabels = {};
    (state.roles || []).forEach(function (id) {
      const role = rbac.roleFor(id);
      roleLabels[id] = role ? role.label : id;
    });
    let retiring = null;
    try {
      retiring = realms.retiringState() || null;
    } catch (e) {
      // No realm registry answering (a page drawn outside a request); a
      // banner about a realm nobody can name is no banner.
      log.debug("Caught in AdminConsole.shellJson(): " +
                ((e && e.message) || e));
      retiring = null;
    }
    const stored = persistence.status();
    const shell = {
      gate: given || null,
      // Who the SIDEBAR is drawn for: the request's gate, which is the
      // banner's too except where a caller hands page() one of its own.
      navAuthority: navState ? String(navState.authority || '') : '',
      roleLabels: roleLabels,
      realm: { id: realms.currentId(), name: realms.current().name },
      wsTrustIssuer: config.value('wstrust.issuer'),
      realms: realms.active()
        ? realms.list().map(function (one) {
          // `prefix` for the static console's switcher, which moves between
          // realms in the browser rather than through `/admin/realm-switch`.
          return { id: one.id, name: one.name, prefix: realms.prefixOf(one) };
        })
        : null,
      realmRoot: req ? this.realmRoot(req) : '',
      portalHref: req ? this.portalHref(req, given) : '',
      sections: this.visibleSections(navState),
      // Every page's nav label by path, for the trail's section crumb —
      // the whole table, since a crumb names the page whoever reads it.
      navLabels: NAV.reduce(function (out, row) {
        // The first row for a path, as the trail's lookup always took.
        if (!Object.prototype.hasOwnProperty.call(out, row.path)) {
          out[row.path] = row.label;
        }
        return out;
      }, {}),
      retiring: retiring,
      // WHAT THE FOOTER DRAWS, AND NO MORE (#446): the shell is an ANSWER
      // now, read whole by whoever holds a token, so what the footer would
      // hide is left out of it rather than drawn away — a realm
      // administrator gets the mode alone, nobody signed in gets nothing
      // (`WebShell.runtimeFooter()`'s two cases).
      runtime: this.shellRuntimeFacts(given),
      persistence: { enabled: !!stored.enabled,
                     mode: stored.enabled ? String(stored.mode || '') : '' },
      version: { version: APP_VERSION.version,
                 stamped: APP_VERSION.stamped === true,
                 buildInfo: APP_BUILD_INFO }
    };
    log.debug("Leaving AdminConsole.shellJson().");
    return shell;
  }

  /**
   * The runtime facts the shell answer carries for one gate: every fact for
   * a service administrator, the mode alone for a realm administrator, none
   * for nobody signed in.
   *
   * @param gate - the gate the shell is drawn for
   * @returns the facts
   */
  shellRuntimeFacts(gate) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.shellRuntimeFacts().");
    if (gate && gate.enforced && !gate.session) {
      log.debug("Leaving AdminConsole.shellRuntimeFacts(). Nobody.");
      return {};
    }
    const facts = this.runtimeFacts();
    if (gate && gate.authority === 'realm') {
      log.debug("Leaving AdminConsole.shellRuntimeFacts(). A realm's.");
      return { mode: facts.mode };
    }
    log.debug("Leaving AdminConsole.shellRuntimeFacts().");
    return facts;
  }

  // The two directions the table and `SECTIONS` can disagree in: a Protocols
  // page with neither a row nor an exemption, and a row or an exemption naming
  // a page that is not under Protocols (what a rename or a move leaves behind).
  // `tests/protocol_endpoints.js` fails on either; nothing else can see a page
  // appear.
  /**
   * Compares the Protocols pages with the endpoints table and exemptions.
   *
   * @returns `unlisted` (pages with no row) and `stray` (rows for no page)
   */
  protocolEndpointDrift() {
    const { log, protocolEndpoints } = this.deps;
    log.debug("Entering AdminConsole.protocolEndpointDrift().");
    const underProtocols = NAV.filter(function (row) {
      return row.section === 'Protocols';
    }).map(function (row) { return row.path; });
    const listed = protocolEndpoints.pages()
                                    .concat(Object.keys(
                                        protocolEndpoints.exempt()));
    const drift = {
      unlisted: underProtocols.filter(function (path) {
        return listed.indexOf(path) < 0;
      }),
      stray: listed.filter(function (path) {
        return underProtocols.indexOf(path) < 0;
      })
    };
    log.debug("Leaving AdminConsole.protocolEndpointDrift(). " +
              drift.unlisted.length +
              " unlisted, " + drift.stray.length + " stray.");
    return drift;
  }

  // ---------------------------------------------------------------------------
  // THE GATE. WHO GETS INTO THIS CONSOLE AT ALL.
  //
  // It is ONE `app.use('/admin', ...)` registered here, above every route in
  // this file, and that placement is the whole of how it works: express applies
  // middleware only to routes added AFTER it (rule 1), so a route added below
  // this line is guarded and a route added above it would not be. There are
  // none above it, and a new console page must go below — which it will, since
  // every route in this file is below.
  //
  // FOUR THINGS ABOUT IT ARE DELIBERATE.
  //
  // **It authenticates NOTHING itself.** `authn.js` owns the session and the
  // sign-in screen; this asks `consoleRpSession()` who is here and, when nobody
  // is, sends the browser into the OIDC code flow (`sendToConsoleSignIn()`,
  // through `common/oidc_rp.ts`) with the page they wanted as its return
  // address. (Until 2026-09-06 it read the sign-on session directly and sent
  // the browser to `beginAuthentication()`'s URL.) A login screen of this
  // console's own would be a second authentication service, and the one
  // consequence of sharing the first is the good one: sign in at `/authn/login`
  // with a security key and this console knows it, because the flow meets the
  // same sign-on session WS-Federation and the authorization endpoint read.
  //
  // **A BROWSER IS REDIRECTED AND A PROGRAM IS REFUSED, and telling them apart
  // is not a nicety.** Every page here answers `?format=json` and every form
  // accepts a JSON body, precisely so a test can drive this console without a
  // browser — and a 302 to an HTML login screen is not an answer such a caller
  // can read. It would arrive as a 200 full of markup where JSON was expected,
  // which is the shape of failure that costs an afternoon. So: `?format=json`,
  // a JSON content-type or an `Accept` that asks for JSON gets 401 or 403 with
  // a body saying which, and everything else gets the screen.
  //
  // **IT GUARDS `/admin` AND NOT `/admin-api`.** Express matches a `use` path
  // on segment boundaries, so `/admin-api` does not match `/admin` — that is
  // not an accident being relied on, it is the arrangement: the management API
  // has a credential of its own — an OAuth 2.0 access token since 2026-09-09,
  // which `adminApi.authRequired=false` turns off — and is therefore the way
  // back in for somebody who has locked themselves out of the console, which is
  // a state `admin.openWhenEmpty: false` makes reachable. `mgmt-api/CLAUDE.md`
  // argues both halves. It is also why this gate does not break this
  // repository's own `tests/vendored/admin_api.js`.
  //
  // **A REFUSAL IS A PAGE AND NOT A BARE STATUS.** 403 with an empty body is
  // the single least useful thing this could answer: the reader is signed in,
  // the console plainly exists, and nothing tells them that a directory group
  // is what they are missing. The refusal names the role, names the group, and
  // says which four doors can grant it.
  // ---------------------------------------------------------------------------


  // Does this caller want JSON rather than a page? See the header for why the
  // question matters more than it looks.
  //
  // `?format=json` is first because it is the one this console documents on
  // every page. The content-type is what a form-less POST carries. `Accept` is
  // last and is checked for JSON BEFORE html deliberately: a browser sends
  // `text/html,...,*/*` and would match a naive "does it mention json" test on
  // the wildcard alone, so the html half is what decides when both are present.
  /**
   * Tells whether the caller wants JSON rather than a page.
   *
   * @param req - the request
   * @returns true for `?format=json`, a JSON body, or an Accept asking for
   *   JSON and not HTML
   */
  wantsJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.wantsJson().");
    if (String((req.query || {}).format || '') === 'json') {
      log.debug("Leaving AdminConsole.wantsJson().");
      return true;
    }
    if (/json/i.test(String(req.headers['content-type'] || ''))) {
      log.debug("Leaving AdminConsole.wantsJson().");
      return true;
    }
    const accept = String(req.headers.accept || '');
    log.debug("Leaving AdminConsole.wantsJson().");
    return /json/i.test(accept) && !/text\/html/i.test(accept);
  }

  // The default realm's CONSOLE as an ABSOLUTE URL. See the note at its one
  // caller for why absolute: a root-relative href in an HTML body is rewritten
  // by app.js to carry the realm being read, and this link must not be.
  //
  // **IT WAS `LOGIN_PATH` UNTIL 2026-09-06 AND THAT LINK COULD NOT WORK.**
  // `/authn/login` draws a form for a PENDING AUTHENTICATION RECORD and answers
  // `There is no sign-in waiting under that id` to a request naming none — so
  // the one link this console offers somebody whose session expired mid-form
  // went to an OAuth error page. The gate below is what mints a record, through
  // `sendToConsoleSignIn()`, so the way to the sign-in screen is the CONSOLE:
  // an unauthenticated GET of `/admin` in the default realm is answered with a
  // 302 to a screen that has a record behind it and comes back here afterwards.
  //
  // **The record is minted when the link is PRESSED**, which is the property
  // that decides this rather than calling `beginAuthentication()` here: a
  // pending record has a lifetime, and this page is drawn precisely for
  // somebody who has been sitting on a form for longer than one.
  // `portal/portal.ts` fixed the same mistake the same way on the same day and
  // its comment carries the rest.
  /**
   * Returns the default realm's console as an absolute URL.
   *
   * @param req - the request
   * @returns the URL of `/admin` in the default realm
   */
  defaultRealmSignInUrl(req) {
    const { log, realms, baseUrlOf } = this.deps;
    log.debug("Entering AdminConsole.defaultRealmSignInUrl().");
    log.debug("Leaving AdminConsole.defaultRealmSignInUrl().");
    // At a cell's own console address, that address (#361): realmRoot()'s
    // reason. The default realm's console is at its root.
    const cells = require('../common/cells');
    const hit = cells.consoleOfHost(String((req && req.headers &&
                                            req.headers.host) || ''));
    if (hit) {
      return hit.consoleUrl + '/admin';
    }
    return realms.run(realms.DEFAULT_REALM, function () {
      return baseUrlOf(req) + '/admin';
    });
  }

  // The kit's (#446), where its reasoning went with it.
  /**
   * Wraps the messages a pressed button came back with in the strip that
   * stays at the top of the window, so they are seen wherever the page lands.
   *
   * @param html - the messages as HTML
   * @returns the strip, or '' for no messages
   */
  flash(html) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.flash().");
    log.debug("Leaving AdminConsole.flash().");
    return WebKit.flash(html);
  }

  /**
   * Draws one statistics tile.
   *
   * @param n - the number
   * @param label - what it counts
   * @returns the tile as HTML
   */
  tile(n, label) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.tile().");
    log.debug("Leaving AdminConsole.tile().");
    return WebKit.tile(n, label);
  }

  // ---------------------------------------------------------------------------
  // PROSE LONGER THAN A LINE IS COLLAPSED, AND THIS IS THE ONE PLACE THAT
  // DECIDES IT.
  //
  // Every page in this console explains itself at length, and that prose is the
  // point of a mock — the reasoning is the half a person cannot read off a
  // protocol trace. What it cost was the other half: on most pages here the
  // controls somebody actually came for sat several screens down a wall of
  // paragraphs, and the page read as documentation with a form hidden in it. So
  // a note of more than about a line is drawn as a `<details>` whose
  // `<summary>` is its own opening sentence: the point stays on the page, and
  // the argument for it is one click away rather than gone.
  //
  // FOUR THINGS ABOUT IT ARE DECISIONS RATHER THAN MECHANICS.
  //
  // * IT IS NATIVE `<details>`, AND NOTHING ELSE COULD BE. This console is
  //   served under `script-src 'none'` — see ../CLAUDE.md, where that rule and
  //   the pages that relax it are argued — so the debugger's collapse-all
  //   switch, which is a checkbox and a listener, has no equivalent here.
  //   `<details>` needs no script at all, so the whole of this change leaves
  //   that policy untouched and adds no exception to it. What it costs
  //   is the *expand everything* control, which is why the shape below keeps
  //   every summary a full sentence: a reader skimming for one paragraph has to
  //   be able to find it without opening all of them.
  // * THE SUMMARY IS DERIVED, NOT WRITTEN BESIDE THE PROSE. A hand-written
  //   label over a paragraph is a second copy of that paragraph's point, and
  //   the two drift the way every other pair of hand-kept lists in this
  //   repository has — the Overview page's list of console pages is the
  //   standing example, and it described seven pages of twenty-five before
  //   anybody noticed. So the label is the note's own first sentence, which in
  //   this codebase's house style is already the point said shortly. A caller
  //   may still pass one, for the few places where the opening sentence is a
  //   fact and the paragraph is about something else.
  // * THE TEST IS ON THE RENDERED TEXT, NOT ON THE CALLER'S JUDGEMENT. A caller
  //   deciding "this one is short enough" is a decision made once, at writing
  //   time, against a paragraph that then grows. `plainTextOf()` measures what
  //   a reader will actually see — tags stripped, entities resolved — so a note
  //   that grows past a line starts collapsing itself with no edit anywhere.
  // * A SHORT NOTE IS LEFT ALONE. Collapsing a line of text behind a control
  //   that is itself a line of text saves nothing and costs a click, and a page
  //   of nothing but disclosure triangles is the same wall of text with the
  //   words taken out.
  //
  // EVERY FUNCTION IN THIS BLOCK IS DELIBERATELY WITHOUT ENTERING/LEAVING LOGS,
  // which is the exception whenText() and its neighbours already take and for a
  // stronger version of the same reason: note() alone is called about three
  // hundred times on `/admin/config`, so the pair of lines the style rule asks
  // for would be six hundred of them for one page draw, and the request that
  // drew it would be somewhere in the middle. The two places something is worth
  // saying — a list item left open, a page in the nav nobody described — log at
  // the point the decision is made instead.
  // ---------------------------------------------------------------------------


  /**
   * Returns a fragment's visible text: tags removed, whitespace collapsed.
   *
   * Entities are left as they were, so the result is still valid HTML text.
   *
   * @param html - an HTML fragment
   * @returns the text
   */
  plainTextOf(html) {
    return WebKit.plainTextOf(html);
  }

  /**
   * Builds a `title` attribute, with its leading space, from prose.
   *
   * @param text - the prose, as markup or plain text
   * @param max - optional; the length, TIP_CHARS by default; `Infinity`
   *   keeps the whole text
   * @returns the attribute; empty when there is no text
   */
  tip(text, max?) {
    return WebKit.tip(text, max);
  }

  /**
   * Draws a paragraph of explanation, folded when longer than a line.
   *
   * @param html - the paragraph as HTML
   * @param label - optional; a summary, which also forces the fold
   * @returns the note as HTML
   */
  note(html, label?) {
    return WebKit.note(html, label);
  }

  /**
   * Draws a warning box, folded when longer than a line.
   *
   * @param html - the warning as HTML
   * @param label - optional; a summary, which also forces the fold
   * @returns the warning as HTML
   */
  warn(html, label?) {
    return WebKit.warn(html, label);
  }

  /**
   * Wraps a wide table in a focusable box that scrolls sideways.
   *
   * @param label - the region's accessible name
   * @param html - the whole table as HTML
   * @returns the wrapped table as HTML
   */
  wideTable(label, html) {
    return WebKit.wideTable(label, html);
  }

  // The kit's (#446), where its reasoning went with it.
  /**
   * Draws one item of a prose list, folded when longer than a line.
   *
   * An item opening with a link is never folded; one opening with `<code>`
   * keeps it in the summary.
   *
   * @param html - the item as HTML
   * @param label - optional; a summary, which also forces the fold
   * @returns the `<li>` as HTML
   */
  bullet(html, label?) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.bullet().");
    log.debug("Leaving AdminConsole.bullet().");
    return WebKit.bullet(html, label);
  }

  /**
   * Formats an instant as a UTC date and time without milliseconds.
   *
   * @param ms - milliseconds since the epoch
   * @returns the text; a dash when there is none
   */
  whenText(ms) {
    return WebKit.whenText(ms);
  }

  // Drawn by `web_metrics.ts` (#446).
  /**
   * Formats a duration as days, hours, minutes and seconds.
   *
   * @param ms - the duration in milliseconds
   * @returns the text, such as `1d 2h 3m 4s`
   */
  durationText(ms) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.durationText().");
    log.debug("Leaving AdminConsole.durationText().");
    return WebKit.durationText(ms);
  }

  /**
   * Draws a long opaque value shortened, with the whole value in the title.
   *
   * @param value - the value to draw; a dash when empty
   * @param keep - how many characters to keep (18 when not given)
   * @returns a <code> element as HTML
   */
  shortened(value, keep) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.shortened().");
    log.debug("Leaving AdminConsole.shortened().");
    return WebKit.shortened(value, keep);
  }

  /**
   * Draws a value clipped to a limit, with the whole of it on focus.
   *
   * A value over the limit gets a hover/focus panel holding the full text.
   *
   * @param value - the value to draw; a dash when null or empty
   * @param keep - the character limit (CLIP_CHARS when not given)
   * @returns the clipped value as HTML
   */
  clipped(value, keep) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.clipped().");
    log.debug("Leaving AdminConsole.clipped().");
    return WebKit.clipped(value, keep);
  }

  /**
   * Draws an attribute's values, each clipped, one per line.
   *
   * @param values - one value or an array of them
   * @param keep - optional; the character limit passed to clipped()
   * @returns the values as one inline-block column of HTML
   */
  clippedValues(values, keep?) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.clippedValues().");
    log.debug("Leaving AdminConsole.clippedValues().");
    return WebKit.clippedValues(values, keep);
  }

  // ---------------------------------------------------------------------------
  // One table, three families.
  //
  // The tokens page lists JWTs, SAML assertions and Kerberos tickets together
  // and newest first, because that is the order they happened in: a
  // WS-Federation sign-in that produced an ID Token and a SAML 1.1 assertion is
  // one event, and a page that showed the two halves of it in two places would
  // be a page somebody has to correlate by timestamp by hand.
  //
  // What that costs is that most columns mean something slightly different
  // depending on which family the row belongs to, and the way a table like that
  // goes wrong is a column that quietly means two things. So the mapping is
  // written down twice over: once here as ONE FUNCTION PER COLUMN answering for
  // all three families — which is what makes a header like "Client, audience or
  // service" checkable against the three answers underneath it — and once on
  // the page itself as a legend, for the reader, who cannot see this comment.
  //
  // Which families exist and what is in them is decided in admin_stats.js.
  // Nothing here chooses what the list contains; these functions only say how a
  // row is drawn.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // A SET — WHAT CAME BACK IN ONE REPLY — WHICH IS WHAT THE TOKENS TABLE LISTS
  // SINCE 2026-09-05.
  //
  // **The row used to be one credential and is now one issuance.** OAuth 2.0
  // and OIDC are the only families this service speaks that hand back several
  // credentials at once: a code redemption returns an access token, an ID Token
  // and a refresh token, and `response_type=id_token token` returns two in one
  // fragment. Three rows for one reply left the reader to reassemble by
  // comparing timestamps the one thing the protocol had handed over whole — and
  // worse, to GUESS, because two people redeeming two codes at the same client
  // in the same millisecond produce six rows a timestamp cannot separate.
  //
  // Every other family issues one credential per act, so a SAML assertion, a
  // Kerberos ticket and an SVID are each a set of one and are drawn exactly as
  // they were. `stats.issuedSets()` decides which is which — from a set id the
  // ISSUER stated, never from a heuristic over these rows — and this file
  // renders what it is handed, which is the same division tokensView() has
  // always been on.
  //
  // THE SET'S OWN CELLS COME FROM ITS FIRST MEMBER and that is right for every
  // column but two, both of which say so on the page: the scope of a set is the
  // ACCESS TOKEN's, which the refresh token beside it deliberately does not
  // share (see tokenSet() — the refresh token keeps the whole authorized
  // scope), and the audience of a set is not one value at all, which is why the
  // party column reads `client_id`. Both disagreements are visible one click
  // away on the set page, where each member is its own row again.
  // ---------------------------------------------------------------------------


  /**
   * Builds the paging control for one list, as a head and a foot copy.
   *
   * Only the head copy carries the id its links' fragment names; both are
   * empty when the list fits on one page.
   *
   * @param path - the page the links point at
   * @param params - the page parameters every link carries
   * @param pg - the list's paging object from pagingOf()
   * @returns an object whose head and foot are each the control as HTML
   */
  pageNavPair(path, params, pg) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.pageNavPair().");
    log.debug("Leaving AdminConsole.pageNavPair().");
    return WebKit.pageNavPair(path, params, pg);
  }

  // ---------------------------------------------------------------------------
  // GET /admin — the index.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // THE JSON VIEWS, AND WHY EVERY ONE OF THEM IS NOW A FUNCTION.
  //
  // Each page here answers `?format=json`, and until admin_api.js existed each
  // of those objects was built inline in the route handler that also built the
  // markup. That was fine while there was one caller. There are two now — this
  // console and the management API at /admin-api — and two hand-built copies of
  // the same object is precisely the drift the console's own text keeps warning
  // about elsewhere: two views that each look correct alone and never see each
  // other.
  //
  // So the JSON is a function per page, and where the markup needs the same
  // intermediate work (the filtered, paged token list; a user drill-down that
  // is one of three answers) the WHOLE VIEW is the function and the route is
  // what chooses between HTML and JSON. admin_api.js calls these and nothing
  // else — it holds no second opinion about what a metrics reply contains.
  //
  // One cost used to be stated here: the API called usersView() and
  // groupsView(), which build the HTML as well, and threw the markup away. It
  // no longer does — `/admin-api/users` and `/admin-api/groups` call
  // `usersJson()` and `groupsJson()` in `admin-core/admin_views.ts`, which
  // choose between the same answers without drawing a page.
  // ---------------------------------------------------------------------------
  /**
   * Builds the JSON answer of the console's index page.
   *
   * @returns the issuer, uptime, counts of calls, tokens, artifacts,
   *   sessions and users, and the path of every page
   */
  consoleJson() {
    const { log, stats, config, sessions } = this.deps;
    log.debug("Entering AdminConsole.consoleJson().");
    const snap = stats.snapshot();
    const json = {
      issuer: config.value('wstrust.issuer'),
      startedAt: new Date(snap.startedAt).toISOString(),
      uptimeMs: snap.uptimeMs,
      calls: snap.calls.total, tokensHeld: snap.tokens.held,
      tokensRevoked: snap.tokens.revoked,
      artifactsHeld: snap.artifacts.held, signOnSessions: sessions.size,
      usersKnown: snap.users.known,
      usersAuthenticatedHere: snap.users.authenticatedHere,
      pages: NAV.map(function (n) { return n.path; })
    };
    log.debug("Leaving AdminConsole.consoleJson().");
    return json;
  }
  // THE DASHBOARD'S ANSWER (#446): `consoleJson()`'s totals, and what the
  // page draws beside them — the sections this reader may see (the guide is
  // the sidebar written out, so it is the gate's to filter), whether
  // anything here persists, and the base URL the page's examples are
  // written against. `GET /admin-api/status` answers it.
  /**
   * Builds the console index's answer: the totals, the visible sections,
   * persistence and the base URL.
   *
   * @param req - the express request, for the gate and the base URL
   * @returns the answer
   */
  dashboardJson(req) {
    const { log, gateStateFor, baseUrlOf } = this.deps;
    log.debug("Entering AdminConsole.dashboardJson().");
    const stored = persistence.status();
    const json = Object.assign({}, this.consoleJson(), {
      base: baseUrlOf(req),
      persistence: { enabled: !!stored.enabled,
                     mode: stored.enabled ? String(stored.mode || '') : '' },
      sections: this.visibleSections(gateStateFor(req))
    });
    log.debug("Leaving AdminConsole.dashboardJson().");
    return json;
  }


  // ---------------------------------------------------------------------------
  // GET /admin/metrics
  // ---------------------------------------------------------------------------


  // ---------------------------------------------------------------------------
  // GET /admin/tokens, POST /admin/tokens
  // ---------------------------------------------------------------------------



  // Where a form POST sends the browser back to. Revoking the token on page 4
  // and landing on page 1 of an unfiltered list is the paging bug everybody has
  // met, so the row forms carry the view they were rendered in as a `back`
  // field.
  //
  // It is REBUILT rather than echoed, and that is the whole point of doing it
  // here: a redirect target taken from a request body is an open redirect, and
  // one carrying a newline is a header injection. Only the parameters this page
  // understands survive, each of them re-encoded, so the worst a hand-written
  // `back` can produce is a different page of this same table.
  //
  // The list below has to be kept in step with the filter form. A parameter the
  // form offers and this function drops is a filter that silently resets itself
  // the moment somebody revokes a token — which looks like the console losing
  // your place rather than like a missing line here.
  //
  // The users page posts to this same endpoint, so `from` says which of the two
  // pages a button was on. It is read as an ENUM and never as a path: the two
  // paths below are written here, and a `from` naming anything else falls
  // through to the tokens page. That is what keeps the open-redirect property
  // while letting a second page share the handler — a `back` field carrying
  // `//evil.example` would otherwise become a redirect off this service the
  // moment a path came from the body. The drill-down's page parameters, out of
  // a `back` field, for the redirect that follows a revoke.
  //
  // The named parameters above are a WHITELIST, which is the right shape for a
  // redirect target built out of a form field somebody posted — but a whitelist
  // cannot cover this set, because one of the users page's lists has a page
  // parameter per session block and the names therefore depend on which
  // sessions exist. So the rule is a shape rather than a list: a key ending in
  // `Page`, made of the characters a name and a base64url session id are made
  // of, whose value is a positive integer. The value is REBUILT from parseInt
  // rather than passed through, so what lands in the URL is a number this
  // function produced.
  //
  // What it buys is the thing a reader notices immediately: revoking a token
  // from page three of a session's table used to answer with page one of
  // everything, so the row you had just acted on was no longer on screen and
  // neither was its neighbour.
  /**
   * Picks the per-table page parameters out of a posted `back` field.
   *
   * Only keys ending in `Page` whose value is a positive integer survive,
   * and each value is rebuilt from parseInt.
   *
   * @param params - the URLSearchParams parsed from `back`
   * @returns an object of page parameter names to number strings
   */
  drillDownPages(params) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.drillDownPages().");
    const out = {};
    params.forEach(function (value, key) {
      if (!/^[A-Za-z0-9_-]+Page$/.test(key)) {
        return;
      }
      const n = parseInt(String(value), 10);
      if (isFinite(n) && n > 0) {
        out[key] = String(n);
      }
    });
    log.debug("Leaving AdminConsole.drillDownPages(). " +
              Object.keys(out).length + " page " +
        "parameter(s).");
    return out;
  }

  /**
   * Rebuilds where a tokens form POST redirects the browser afterwards.
   *
   * `from` is read as a name (`users`, `set`, else the tokens page) and
   * only whitelisted parameters of `back` are carried, so the target is
   * never a path taken from the body.
   *
   * @param body - the posted form body, with `from` and `back`
   * @returns a path on /admin/users, /admin/tokens/set or /admin/tokens
   */
  backTo(body) {
    const { log, queryWith } = this.deps;
    log.debug("Entering AdminConsole.backTo().");
    let params = null;
    try {
      params = new URLSearchParams(String(body.back || '').replace(/^\?/, ''));
    } catch (e) {
      // Unparseable; the bare page is the right answer and is what the forms
      // that carry no `back` at all get anyway.
      log.debug("Leaving AdminConsole.backTo(). Unparseable back field: " +
                e.message);
      return '/admin/tokens';
    }
    if (String(body.from || '') === 'users') {
      const usersTarget = '/admin/users' + queryWith(Object.assign({
        user: params.get('user') || '',
        q: params.get('q') || '',
        protocol: params.get('protocol') || '',
        per: params.get('per') || '',
        page: params.get('page') || ''
      }, this.drillDownPages(params)), {});
      log.debug("Leaving AdminConsole.backTo(). " + usersTarget);
      return usersTarget;
    }
    // The set page's own buttons, which is the third of the three surfaces that
    // post here. `from` is read as an ENUM and never as a path — the three
    // targets are written out in this function — which is what lets a page
    // share the handler without a `back` field carrying `//evil.example`
    // becoming a redirect off this service.
    if (String(body.from || '') === 'set') {
      const setTarget = '/admin/tokens/set' + queryWith({
        id: params.get('id') || '',
        family: params.get('family') || '',
        kind: params.get('kind') || '',
        state: params.get('state') || '',
        session: params.get('session') || '',
        per: params.get('per') || '',
        page: params.get('page') || ''
      }, {});
      log.debug("Leaving AdminConsole.backTo(). " + setTarget);
      return setTarget;
    }
    const target = '/admin/tokens' + queryWith({
      family: params.get('family') || '',
      kind: params.get('kind') || '',
      state: params.get('state') || '',
      // CARRIED SINCE 2026-09-05, and its absence was a bug rather than a
      // decision: this whitelist has to be kept in step with the filter form
      // above — the comment on this function says so — and `session` was added
      // to that form on 2026-09-04 without being added here. So arriving from
      // /admin/sessions, narrowing to one session and revoking anything sent
      // the reader back to the unfiltered list, which reads as the console
      // losing their place rather than as a missing line here.
      session: params.get('session') || '',
      per: params.get('per') || '',
      page: params.get('page') || ''
    }, {});
    log.debug("Leaving AdminConsole.backTo(). " + target);
    return target;
  }

  // ---------------------------------------------------------------------------
  // MONITORING -> SESSIONS. EVERY SESSION THIS SERVICE IS HOLDING RIGHT NOW.
  //
  // **IT IS THE OTHER HALF OF /admin/tokens AND THE TWO ARE NOT THE SAME
  // LIST.** That page is what this service has HANDED OUT — every one of those
  // outlives the session it came from, several by design and one (a Kerberos
  // service ticket) beyond recall entirely. This page is what it is still
  // HOLDING: the state that makes somebody currently authenticated, which is
  // the question somebody actually arrives with when they ask who is signed in.
  //
  // **THE MODEL IS `logout/logout.ts`'s AND NOT THIS FILE'S**, through the
  // sixth slot. That module is the one answer to "what is a live session"
  // across families — see its CLAUDE.md — and this page walking
  // `authn.sessions`, `boundConnections()` and the ticket register itself would
  // be a SECOND answer, which is the thing rule 3m exists to prevent. It
  // matters more here than on /admin/logout because of the button: a Revoke
  // drawn from one reading and performed by another is a control that acts on
  // something other than the row it is beside.
  //
  // **THE EXPIRY COLUMN IS THE ONE WORTH READING TWICE.** Each session kind
  // works its expiry out differently and the difference is not a detail — a
  // browser session's is absolute and is not extended by use, a TGT's was
  // sealed into the ticket by the KDC and cannot be moved, and an LDAP
  // connection has no expiry at all; since 2026-09-06 an API caller's session
  // is extended by use, and since 2026-09-12 the console's and portal's own
  // sessions are renewed with their refresh token. So the column carries the
  // countdown AND the rule, and the rule comes off `liveSessions()`'s row
  // rather than being written again here.
  //
  // **THE REVOKE BUTTON GOES THROUGH `terminate()`**, the same function
  // /logout's global sign-out uses, with a selection of one — so it writes the
  // same audit row, honours the same two settings and gives the same refusals.
  // What it does NOT do is pretend the three are alike: ending a browser
  // session ends that session, ending an LDAP connection closes a socket, and
  // ending a Kerberos row stamps a sign-out instant on a PRINCIPAL that refuses
  // every ticket it authenticated before now. The last of those does more than
  // the row it is on, and the row says so rather than the button quietly doing
  // it.
  // ---------------------------------------------------------------------------


  // ---------------------------------------------------------------------------
  // GET /admin/audit — what happened here, in order.
  //
  // The other pages on this console are STATE: how many calls, which tokens are
  // still valid, who is in cn=developers. This one is HISTORY, and the
  // difference is the reason it exists. The metrics page can tell you the
  // directory holds eleven entries; only this one can tell you that a twelfth
  // was created at 14:02 and deleted at 14:03, by somebody bound as uid=carol,
  // over LDAPS.
  //
  // Six categories, and every event in the service arrives through one of five
  // funnels rather than from a recording site per feature:
  //
  //   authentication   admin_stats.recordAuthentication(), the single point all
  //                    sixteen protocol families already pass through when a
  //                    credential is ACCEPTED — SCIM being the fifteenth, for
  //                    the three of its schemes that present a credential per
  //                    request, and SPIFFE the sixteenth, for an X509-SVID
  //                    presented over mutual TLS, an agent attesting and a
  //                    JWT-SVID validated
  //   session          authn.js's startSession / endSession, which is where
  // both
  //                    OAuth 2.0 / OIDC and WS-Federation sign in and out
  //   directory        the seven LDAP handlers in ldap_server.js, plus the
  //                    entries this service creates for people who
  //                    authenticated somewhere else
  //   admin / api      app.js's call log, classified by path
  //   protocol         the same call log, everything else
  //
  // **ONE ACT USUALLY PRODUCES SEVERAL ROWS.** A sign-in at /authn/login writes
  // three: the HTTP call, the credential being accepted, and the session that
  // came out of it. They are three facts at three layers rather than one fact
  // three times — and which of them you want depends on the question, which is
  // exactly why the log does not choose. The page says so under the table.
  //
  // **IT OBSERVES ITSELF.** Drawing this page is console access, so it records
  // an `admin.view` row, so the list is one longer than when you asked for it.
  // Suppressing that would put a blind spot exactly where the person reading
  // the audit log stands. It is stated instead, and `?category=` reads past it.
  // ---------------------------------------------------------------------------


  // Drawn by `web_audit.ts` (#446).
  /**
   * Draws one row of the audit log table.
   *
   * @param row - an audit row
   * @param known - the usernames this console has seen, as object keys
   * @returns a <tr> as HTML
   */
  auditRow(row, known) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.auditRow().");
    log.debug("Leaving AdminConsole.auditRow().");
    return AuditPage.auditRow(row, known);
  }

  // ---------------------------------------------------------------------------
  // GET /admin/logout — WHAT ONE IDENTITY IS STILL SIGNED INTO, ANYWHERE, AND
  // THE CONTROLS THAT END IT.
  //
  // The operator's half of `/logout`. The two are one behaviour — both call
  // `logout.ts`'s `inventoryFor()` and `terminate()` and neither decides
  // anything the other does not — and they differ in exactly three ways, each
  // of which is why this page exists rather than a link to the other:
  //
  //   * IT NAMES SOMEBODY ELSE. `/logout` defaults to whoever is holding the
  //     cookie; this page always asks about a `user`, because an operator is
  //     looking AT a person rather than being one.
  //   * IT IS BEHIND THE CONSOLE'S TWO ROLES. Reading it needs Admin Read and
  //     the form needs Admin Write, through the one gate at the top of this
  //     file. `/logout` is behind neither, because signing yourself out must
  //     not require a role.
  //   * IT HAS AN UNDO, and `/logout` deliberately has not. A revoked token can
  //     be restored and a Kerberos sign-out instant can be cleared — NON-SPEC
  //     in both cases, and labelled so, for the reason /admin/tokens gives
  //     about its own restore button: no authorization server could offer it,
  //     and having to restart this service to get back to a working ticket
  //     turns a two-second test into a two-minute one.
  //
  // THE PAGE PAGES AND THE OTHER ONE DOES NOT, which is the standing convention
  // here rather than an inconsistency: a console list page gets paging and a
  // management API resource beside it in the same change. `/logout` groups by
  // family because a person reads it once; this filters and pages because an
  // operator looking at a load generator's identity may have five hundred rows.
  // ---------------------------------------------------------------------------



  // ---------------------------------------------------------------------------
  // GET /admin/delegation — WHO ACTED ON WHOSE BEHALF, THROUGH WHAT, TO REACH
  // WHAT.
  //
  // TWO TABLES, and the split between them is the point of the page rather than
  // a layout choice:
  //
  //   * WHAT HAPPENED — one row per delegation ACT, from common/delegation.js.
  //     Every mechanism in three protocol families, in one vocabulary, refusals
  //     included.
  //   * WHO MAY DELEGATE TO WHOM — the CONFIGURED policy, from
  //     krb5_principals.js. It answers *why would this be refused* before
  //     anybody has tried, and it is Kerberos-only because Kerberos is the only
  //     family here that polices delegation at all. That absence is stated on
  //     the page rather than left to be inferred from an empty column.
  //
  // **IT IS DELIBERATELY NOT A PROTOCOL PAGE**, which is why it is in
  // Monitoring beside the tokens it points at and not under Protocols beside
  // SAML and SCIM. A reader arriving here has a chain in their head — *alice
  // hit the portal, the portal called the API* — and wants to know which hop
  // invented which identity. Filing that under one of the three families would
  // mean choosing which two thirds of the answer to hide.
  //
  // **NO FORM, AND THAT IS A DECISION.** Everything on this page is an
  // observation: an act happened or it did not, and a policy row is somewhere
  // else's configuration. There is nothing here to change, so rule 7 is
  // satisfied by `GET /admin-api/delegation` alone — the same shape
  // /admin/audit has, and for a related reason. A control that let somebody
  // TYPE a chain would put invented rows in a table whose whole worth is that
  // its rows are what actually happened.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // THE CONFIGURED HALF OF /admin/delegation: DELEGATED PERMISSIONS.
  //
  // `common/app_permissions.ts` holds the model and this holds the HTML, the
  // same split every other register on this console has. Five actions, and they
  // are the reason this page HAS a form at all — which reverses a decision
  // stated at length in the route header above, so the reversal is argued here
  // rather than left as an inconsistency somebody re-derives.
  //
  // **THAT HEADER SAID "NO FORM, AND THAT IS A DECISION", AND IT WAS RIGHT
  // ABOUT WHAT IT WAS TALKING ABOUT.** Everything on this page WAS an
  // observation: an act happened or it did not, and a control that let somebody
  // TYPE a chain would put invented rows in a table whose whole worth is that
  // its rows are what actually happened. That sentence is untouched and still
  // governs the acts table, the chains and the picture — none of them has a
  // control and none ever will.
  //
  // What is new is a SECOND REGISTER on the same page, and it is configuration
  // rather than observation: a delegated permission is something somebody
  // DECIDES, like a redirect URI or a federation relationship, and
  // configuration with no way to type it is configuration only an `ldapmodify`
  // can reach. The rule the old header states is therefore intact and sharpened
  // — **nothing that records what HAPPENED has a control, and the thing that
  // records what is ALLOWED is nothing but controls.** The two are drawn under
  // headings that say which is which, because a reader who confused them would
  // draw exactly the wrong conclusion from the difference between them, which
  // is the most useful thing on the page.
  //
  // The five actions are thin: each calls `app_permissions.js`, which calls
  // `applications.updateApplication()`, which is where the RULES are — so the
  // form, `POST /admin-api/permissions/...` and the generic attribute editor on
  // /admin/applications all go through one implementation of "a permission must
  // be defined before it can be granted". See that module's header.
  //
  // **ONE OF THE FIVE FORMS IS NOT DRAWN ON THIS PAGE ANY MORE (2026-09-01).**
  // `grant-permission` is on the CLIENT application's own page — see
  // applicationPermissionsSection() — because a grant is a value on the
  // client's entry, and there the client is the entry the reader is standing on
  // rather than one option in a select of every application here. What this
  // page keeps is the RESOURCE half, which is what it is about: expose an API,
  // define a permission, remove one.
  //
  // `revoke-permission` IS DRAWN IN BOTH PLACES and that is not a leftover. It
  // is a ROW BUTTON, so its two halves are the row it sits on and neither can
  // be got wrong — which is precisely what was wrong with the grant form's two
  // selects. The register here lists every grant in the service and a reader
  // tidying it should not have to open five application pages; the
  // application's own list is the read-back of the grant they just made, and a
  // table with no way to undo the write above it is half a control.
  //
  // None of it touches anything else in this block: every form posts to the
  // same handler, PERMISSION_ACTIONS is still all five, and the paragraph above
  // about the acts half having no control and the configured half being nothing
  // but controls is unchanged. What moved is where one control is DRAWN.
  // ---------------------------------------------------------------------------




  // ---------------------------------------------------------------------------
  // GET /admin/delegation/map — THE SAME ACTS, AS A PICTURE.
  //
  // A DRILL-DOWN OF /admin/delegation AND NOT A SECTION OF ITS OWN. It has no
  // NAV row, it passes `up`, and its active tab is the delegation page's —
  // which is what makes the trail read `Admin console › Delegation › The
  // picture` and what makes the way back carry the filter the reader came in
  // with. The test rule 7a states is the one that decided it: a parameter that
  // merely FILTERS a list is not a drill-down, and this is not a filter — it is
  // a second VIEW of the list, which is exactly what a drill-down is. Putting
  // it in the sidebar was considered and would have been a nineteenth tab that
  // shows nothing the tab above it does not already hold.
  //
  // **IT IS THE SAME VIEW FUNCTION.** `delegationView(req.query)` builds it, so
  // every filter on the table filters the picture, and the two can never come
  // to disagree about which acts they are describing. There is one deliberate
  // difference and it is the whole reason to state it: **the picture is drawn
  // from `view.filtered` and the table is drawn from `view.shown`** — paging a
  // picture would draw the boxes that happen to be on page 2 and the lines that
  // happen to join them, which is a diagram of the pagination rather than of
  // the service. The page says so where the count is printed.
  //
  // **THERE IS NO FORM AND THEREFORE NO NEW OPERATION ON /admin-api** — rule 7,
  // satisfied the same way `/admin/delegation` itself satisfies it. What this
  // page shows is reachable without a browser at `?format=json`, and the same
  // graph is on `GET /admin-api/delegation` in the `graph` member, because a
  // picture a test cannot assert against is a picture that can go wrong
  // quietly.
  //
  // **AND `?format=svg` ANSWERS THE DOCUMENT ALONE.** It is the one shape this
  // console has that is worth saving — a diagram is a thing people put in a
  // ticket — and it is not a fourth response format bolted on: `respond()`
  // still answers HTML and JSON, and this route answers SVG before calling it.
  // The standalone document carries NO LINKS, deliberately: `app.js` rewrites
  // root-relative hrefs into the current realm on the way out of a `text/html`
  // response only, so a link inside an `image/svg+xml` body would be a link
  // that silently leaves the realm — and in a saved file it would be a link to
  // somebody's own machine.
  //
  // **`?format=svg` GETS THE 302 AND NOT THE 401, and that is the gate's rule
  // rather than an oversight here.** The guard answers a program with a status
  // and a body and a BROWSER with the sign-in screen, and it decides which by
  // looking for JSON — `?format=json`, a JSON content-type, a JSON-only
  // `Accept`. Nothing else is a program as far as it is concerned, and this
  // format in particular is reached by clicking a link on this page, so a
  // browser that has been signed out should meet the screen and come back to
  // the document. A caller that wants the picture without a session wants
  // `?format=json` and the graph, which is the shape a test can assert against
  // anyway.
  // ---------------------------------------------------------------------------

  // MOVED TO `admin-core/admin_views.ts` (#446): what a box IS is a
  // view, and the management API answers it too. A delegate.
  /**
   * Works out how the delegation picture draws one node.
   *
   * The shape comes from whether the directory and the registry know the
   * party, and the label is its cn or application name where there is one.
   *
   * @param node - a node of the delegation graph
   * @param known - the usernames this console has seen, as object keys
   * @returns an object of shape, label, sublabel, identifier, title, href
   *   and dashed; the service's own node has no identifier
   */
  delegationNodeLook(node, known) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.delegationNodeLook().");
    log.debug("Leaving AdminConsole.delegationNodeLook().");
    return adminViews.delegationNodeLook(node, known);
  }

  // One attribute off an entry the directory reader handed back, canonically
  // spelled or not. `objectFor()` returns them canonically spelled and a caller
  // asking for `cn` should not have to know that.
  /**
   * Returns an entry's first value of an attribute, matched case-insensitively.
   *
   * @param entry - a directory entry with an `attributes` object
   * @param name - the attribute name
   * @returns the first value as a string, or an empty string
   */
  firstAttributeValue(entry, name) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.firstAttributeValue().");
    if (!entry || !entry.attributes) {
      log.debug("Leaving AdminConsole.firstAttributeValue().");
      return '';
    }
    const wanted = String(name).toLowerCase();
    const key = Object.keys(entry.attributes).filter(function (one) {
      return String(one).toLowerCase() === wanted;
    })[0];
    const values = key ? entry.attributes[key] : null;
    log.debug("Leaving AdminConsole.firstAttributeValue().");
    return (values && values.length) ? String(values[0]) : '';
  }


  // ---------------------------------------------------------------------------
  // THE THREE THINGS EVERY PICTURE PAGE NEEDS, EXTRACTED BECAUSE THERE ARE NOW
  // THREE OF THEM.
  //
  // `/admin/delegation/map` drew the whole graph; `/admin/delegation/chain`
  // draws ONE relationship and `/admin/delegation/application` draws one
  // application's. They differ in which acts they pass to `delegation.graph()`
  // and in nothing else, so the three functions below are shared rather than
  // copied.
  //
  // That is the same argument `delegationView()` makes one layer up and it is
  // worth restating here because the failure it prevents is quiet: three copies
  // of the label rule would be three pages that disagree about what a box is
  // CALLED, and a reader comparing the whole picture with one chain's would
  // have no way to tell that from two boxes that really are different parties.
  // ---------------------------------------------------------------------------

  // Drawn by `web_groups.ts` (#446).
  /**
   * Draws every attribute of one directory entry, operational ones marked,
   * with each value.
   *
   * @param entry - the entry as the directory's readers return it
   * @returns the table as HTML
   */
  attributeTable(entry) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.attributeTable().");
    log.debug("Leaving AdminConsole.attributeTable().");
    return GroupsPage.attributeTable(entry);
  }

  /**
   * Installs the reader that returns one person's LDAP entry, here and in
   * the read layer (admin-core/admin_views.ts). Filled by
   * ldap/ldap_server.js.
   *
   * @param fn - the directory reader
   */
  setDirectoryReader(fn) {
    const { log, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setDirectoryReader().");
    directoryReader = fn;
    // AND THE READ LAYER, which needs it for the new-person answer.
    adminViews.setDirectoryReader(fn);
    log.debug("A directory reader was installed; a user's page will now show " +
              "that user's LDAP entry.");
    log.debug("Leaving AdminConsole.setDirectoryReader().");
  }

  /**
   * Installs the reader of the directory's groups, here and in the read
   * layer. Filled by ldap/ldap_server.js.
   *
   * @param fn - the group reader
   */
  setGroupReader(fn) {
    const { log, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setGroupReader().");
    groupReader = fn;
    // AND THE READ LAYER, for the groups answer.
    adminViews.setGroupReader(fn);
    log.debug("A group reader was installed; /admin/groups will now show the " +
              "directory's groups.");
    log.debug("Leaving AdminConsole.setGroupReader().");
  }

  /**
   * Installs the SPIFFE reader the console's SPIFFE reports are drawn from,
   * here and in the read layer.
   *
   * @param fn - the SPIFFE reader
   */
  setSpiffeReader(fn) {
    const { log, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setSpiffeReader().");
    spiffeReader = fn;
    // AND THE READ LAYER, which draws the three SPIFFE reports out of the same
    // reader — see admin-core/admin_views.ts.
    adminViews.setSpiffeReader(fn);
    log.debug("A SPIFFE reader was installed; /admin/spiffe will now report " +
              "which gRPC listeners bound.");
    log.debug("Leaving AdminConsole.setSpiffeReader().");
  }

  /**
   * Installs the crypto reporter behind /admin/keys and the /admin-api
   * crypto resources, here and in the read layer.
   *
   * A reporter missing `report`, `keys` or `exportKey` is refused whole and
   * logged as STS-ADMIN-0014.
   *
   * @param reporter - the object carrying report(), keys() and exportKey()
   */
  setCryptoReporter(reporter) {
    const { log, errorCodes, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setCryptoReporter().");
    // ONE OBJECT, VALIDATED WHOLE AND REFUSED WHOLE, which is the rule
    // setLogoutReader() follows and for the same reason: a filler that
    // installed the report and not the export would leave one of the three
    // operations answering 503 while the other two worked, and the parity rule
    // would be failing silently rather than loudly.
    const needed = ['report', 'keys', 'exportKey'];
    const missing = needed.filter(function (name) {
      return !reporter || typeof reporter[name] !== 'function';
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-ADMIN-0014') + 'admin: ' +
                                                   'setCryptoReporter() was ' +
                                                   'given something without ' +
                missing.join(', ') + ', and was ignored whole. ' +
                '/admin/keys and the two /admin-api crypto resources will ' +
                'say the reporter is not installed rather than half working.');
      log.debug("Leaving AdminConsole.setCryptoReporter(). Refused.");
      return;
    }
    cryptoReporter = reporter;
    // AND THE READ LAYER, which needs the same thing — see the header of
    // admin-core/admin_views.ts. Still one statement and one writer.
    adminViews.setCryptoReporter(reporter);
    log.debug("Leaving AdminConsole.setCryptoReporter(). Installed.");
  }

  // A request with some query names replaced, for a page that asks a
  // management API view under that operation's names (#446): the console's
  // `/admin/caep-sessions/session?id=` is the operation's `?session=`. The
  // request itself is the prototype, so whatever else a view reads off it —
  // the host, the realm, the gate — is the request's own.
  /**
   * Builds a request whose query has some names replaced.
   *
   * @param req - the request
   * @param names - the query names to set, and their values
   * @returns the request, with that query
   */
  withQuery(req, names) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.withQuery().");
    const out = Object.create(req);
    out.query = Object.assign({}, req.query || {}, names);
    log.debug("Leaving AdminConsole.withQuery().");
    return out;
  }

  /**
   * Installs the logout reader behind /admin/logout and /admin/sessions,
   * here and in the action and read layers.
   *
   * A reader missing inventoryFor(), terminate(), liveSessions() or
   * FAMILIES is refused whole with a warning (STS-ADMIN-0014).
   *
   * @param reader - the logout module's reader
   */
  setLogoutReader(reader) {
    const { log, errorCodes, adminActions, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setLogoutReader().");
    const complete = reader && typeof reader.inventoryFor === 'function' &&
                     typeof reader.terminate === 'function' &&
                     // liveSessions() joined the three on 2026-09-04, for
                     // /admin/sessions and GET /admin-api/sessions. It is
                     // validated with them rather than tested at each call site
                     // for the reason the whole slot is validated whole: a
                     // reader carrying the inventory and not this would leave
                     // that page saying no reader is installed on a service
                     // that plainly has one.
                     typeof reader.liveSessions === 'function' &&
                     Array.isArray(reader.FAMILIES);
    if (!complete) {
      // A warning and not a throw, for the reason admin_rbac.js's install has:
      // a console that will not start is worse than a console with one page
      // that says why it cannot answer.
      log.warn(errorCodes.tag('STS-ADMIN-0014') + 'admin: a logout reader ' +
               'was offered that does not carry inventoryFor(), terminate(), ' +
               'liveSessions() and FAMILIES. It is refused whole — a partial ' +
               'one would leave /admin/logout and /admin/sessions listing ' +
               'what is live and unable to end any of it, which is the worst ' +
               'of the two halves.');
      log.debug("Leaving AdminConsole.setLogoutReader().");
      return;
    }
    logoutReader = reader;
    // AND THE ACTION LAYER, which needs the same object and is handed it
    // from here rather than asking for it — see the header of
    // admin-core/admin_actions.ts. One statement, two destinations: this is
    // the ONLY place either is written, which is what keeps it one answer.
    adminActions.setLogoutReader(reader);
    // AND THE READ LAYER: sessionsView() reads what is live where
    // sessionsAction() ends it, so both halves need this one.
    adminViews.setLogoutReader(reader);
    log.debug("A logout reader was installed; /admin/logout will now list " +
              "and end live sessions across every protocol family.");
    log.debug("Leaving AdminConsole.setLogoutReader().");
  }

  /**
   * Installs the XACML page views, here and in the read and action layers.
   *
   * A set missing any of XACML_PAGE_PARTS is refused whole with a warning
   * (STS-ADMIN-0014).
   *
   * @param parts - the XACML family's page functions
   */
  setXacmlPages(parts) {
    const { log, errorCodes, adminViews, adminActions } = this.deps;
    log.debug("Entering AdminConsole.setXacmlPages().");
    const complete = parts && XACML_PAGE_PARTS.every(function (name) {
      return typeof parts[name] === 'function';
    });
    if (!complete) {
      log.warn(errorCodes.tag('STS-ADMIN-0014') + 'admin: a set of XACML ' +
               'page views was offered that does not carry all seven ' +
               'of ' + XACML_PAGE_PARTS.join(', ') + '. It is ' +
               'refused whole — a partial set would leave /admin-api able to ' +
               'read the policy repository and unable to change it, which ' +
               'reads as a management API that is working and is not.');
      log.debug("Leaving AdminConsole.setXacmlPages().");
      return;
    }
    xacmlPages = parts;
    // AND THE READ LAYER, which needs the same thing — see the header of
    // admin-core/admin_views.ts. Still one statement and one writer.
    adminViews.setXacmlPages(parts);
    // AND THE ACTION LAYER. This is the one collaborator BOTH halves need — the
    // actions dispatch on these pages and the views draw from them — so one
    // statement here has THREE destinations: the variable above, and one in
    // each half. Still exactly one writer, which is the only property that
    // matters; see the header of admin-core/admin_actions.ts.
    adminActions.setXacmlPages(parts);
    log.debug('The XACML page views were installed; /admin-api mirrors them.');
    log.debug("Leaving AdminConsole.setXacmlPages().");
  }

  /**
   * Installs the directory's page views, here and in the read layer.
   *
   * A set missing any of DIRECTORY_PAGE_NAMES is refused whole with a
   * warning (STS-ADMIN-0014).
   *
   * @param views - the directory's page functions
   */
  setDirectoryPages(views) {
    const { log, errorCodes, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setDirectoryPages().");
    const complete = views && DIRECTORY_PAGE_NAMES.every(function (name) {
      return typeof views[name] === 'function';
    });
    if (!complete) {
      // A warning and not a throw, for the reason every other install here
      // gives.
      log.warn(errorCodes.tag('STS-ADMIN-0014') + 'admin: a set of directory ' +
               'page views was offered that does not carry all nine ' +
               'of ' + DIRECTORY_PAGE_NAMES.join(', ') + '. It ' +
               'is refused whole — a partial set would leave some of ' +
               '/admin-api\'s directory operations answering as though no ' +
               'directory were loaded on a service that plainly has one.');
      log.debug("Leaving AdminConsole.setDirectoryPages().");
      return;
    }
    directoryPages = views;
    // AND THE READ LAYER, which needs the same thing — see the header of
    // admin-core/admin_views.ts. Still one statement and one writer.
    adminViews.setDirectoryPages(views);
    log.debug('The nine directory page views were installed; /admin-api ' +
              'mirrors them.');
    log.debug("Leaving AdminConsole.setDirectoryPages().");
  }

  /**
   * Installs the SCIM reader the console's SCIM reports are drawn from,
   * here and in the read layer.
   *
   * @param fn - the SCIM reader
   */
  setScimReader(fn) {
    const { log, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setScimReader().");
    scimReader = fn;
    // AND THE READ LAYER, which needs the same thing — see the header of
    // admin-core/admin_views.ts. Still one statement and one writer.
    adminViews.setScimReader(fn);
    log.debug("A SCIM reader was installed; /admin/scim will now describe " +
              "the SCIM 2.0 endpoints.");
    log.debug("Leaving AdminConsole.setScimReader().");
  }

  /**
   * Installs the writer that creates a person in the directory, here and
   * in the read and action layers.
   *
   * @param fn - the directory writer
   */
  setDirectoryWriter(fn) {
    const { log, adminViews, adminActions } = this.deps;
    log.debug("Entering AdminConsole.setDirectoryWriter().");
    directoryWriter = fn;
    // AND THE READ LAYER, which needs it for the new-person answer.
    adminViews.setDirectoryWriter(fn);
    // AND THE ACTION LAYER, which needs the same object and is handed it
    // from here rather than asking for it — see the header of
    // admin-core/admin_actions.ts. One statement, two destinations: this is
    // the ONLY place either is written, which is what keeps it one answer.
    adminActions.setDirectoryWriter(fn);
    log.debug("A directory writer was installed; /admin/users can now create " +
              "a person in the directory.");
    log.debug("Leaving AdminConsole.setDirectoryWriter().");
  }

  /**
   * Installs the directory's group writers, here and in the read and
   * action layers.
   *
   * An object missing any of GROUP_WRITER_MEMBERS is not installed, and
   * the missing names are logged as STS-ADMIN-0014.
   *
   * @param fns - the group writer functions
   */
  setGroupWriter(fns) {
    const { log, errorCodes, adminViews, adminActions } = this.deps;
    log.debug("Entering AdminConsole.setGroupWriter().");
    const given = fns || {};
    const missing = GROUP_WRITER_MEMBERS.filter(function (name) {
      return typeof given[name] !== 'function';
    });
    if (missing.length) {
      // REFUSED RATHER THAN HALF-INSTALLED, and the warning names what was
      // missing: "the groups page cannot create a group" with no further detail
      // is the kind of message that costs an hour.
      log.error(errorCodes.tag('STS-ADMIN-0014') + "admin: the group writer " +
                                                   "slot was offered an " +
                                                   "object missing " +
                missing.join(', ') + ". It is NOT installed — /admin/groups " +
                "and POST /admin-api/groups will report that no directory is " +
                "loaded, which is true of the writes and not of the reads " +
                "beside them.");
      log.debug("Leaving AdminConsole.setGroupWriter(). Refused.");
      return;
    }
    groupWriter = given;
    // AND THE READ LAYER, for the groups answer.
    adminViews.setGroupWriter(given);
    // AND THE ACTION LAYER, which needs the same object and is handed it
    // from here rather than asking for it — see the header of
    // admin-core/admin_actions.ts. One statement, two destinations: this is
    // the ONLY place either is written, which is what keeps it one answer.
    adminActions.setGroupWriter(given);
    log.debug("Leaving AdminConsole.setGroupWriter(). /admin/groups can now " +
              "create a group and add a member to one.");
  }

  // ---------------------------------------------------------------------------
  // GET /admin/users/new, POST /admin/users/new — CREATE A PERSON, ON A PAGE OF
  // ITS OWN (2026-09-06).
  //
  // **WHAT THIS REPLACED IS THE POINT OF IT.** The Users list carried a single
  // box and a Create button, and pressing it created somebody whose every
  // attribute was INVENTED — a name, an email address, a date of birth, a
  // street, a nationality, none of which anybody had asked for. That was a
  // deliberate and defensible design while the only thing a directory entry had
  // to do was give an issued credential something to assert: `vc_claims.js`
  // invents a consistent person per username, so the entry and the credential
  // agreed, and nobody had to type twenty-five fields to get a usable test
  // subject.
  //
  // It stopped being enough for two reasons. An operator who wants a person
  // with a PARTICULAR email address or employee number had no way to say so at
  // creation — the entry appeared with fictions on it and had to be corrected
  // afterwards, one `ldapmodify` at a time, from outside this console. And a
  // person created here had no way IN: `credentials.js` has been able to set a
  // password and issue a one-time activation link since it was written, and
  // neither was reachable from any screen. The second was a gap rather than a
  // decision — `POST /admin-api/users/issue-activation` existed and nothing
  // pressed it.
  //
  // So this page does three things the box could not:
  //
  //   * **EVERY FIELD A PERSON HERE HAS, TYPED.** Twenty-five of them, drawn
  //     from `vc_claims.js`'s catalogue — the same list `createUser()` checks a
  //     caller's attribute names against, so this form cannot offer a field the
  //     writer would drop. Only the username is required. **A box left empty
  //     records NO VALUE**; it does not fall back to an invented one.
  //   * **THE INVENTED PERSON IS A BUTTON RATHER THAN THE DEFAULT.** *Fill with
  //     example data* writes exactly what this service WOULD have made up for
  //     that username into the empty boxes, and leaves anything already typed
  //     alone. It is development-mode only, argued below.
  //   * **A CREDENTIAL, CHOSEN AT CREATION.** A typed password, a generated one
  //     shown once, an activation link shown once, or none at all.
  //
  // **IT IS NOT A SECOND DOOR ONTO THE DIRECTORY.** The form posts here and
  // this handler calls `usersAction()` — the same function `POST /admin/users`
  // and `POST /admin-api/users/create` call, reaching `ldap_server.js`'s
  // `createUser()`, which is also where an `ldapadd` and a SCIM create are
  // answered. Two forms over one function are two doors; what would break the
  // one-store rule is a second place the value lives, and there is none. That
  // is the same arrangement `/admin/applications/new` argues at length beside
  // its list page's inline row.
  //
  // **WHY IT POSTS TO ITSELF RATHER THAN TO `/admin/users`, WHICH IS WHERE THE
  // APPLICATIONS PAGE POSTS.** Two reasons, and both are about what a create
  // here ANSWERS WITH.
  //
  //   * A generated password and an activation link EXIST ONCE. Every other
  //     form on this console answers with a 303 back to a list and the message
  //     in a query parameter, sliced to 500 characters — which is right for
  //     "four tokens revoked" and catastrophic for a credential: the value
  //     would be in the browser's history, in any proxy log between here and
  //     the browser, and possibly truncated in half. So a create answers with a
  //     PAGE, and the secret is in the body of a response marked `no-store`.
  //   * A refusal has to come back with the twenty-five boxes still filled in.
  //     A redirect loses them, and losing a form somebody has just typed
  //     because the username had a comma in it is the kind of thing that
  //     teaches people not to use a screen.
  //
  // **NOTHING ON THIS PAGE IS A SECOND OPINION ABOUT WHAT A USERNAME MAY BE.**
  // The DN-syntax rule, the refusal of a name already taken, the DID and SPIFFE
  // shapes that are identities rather than usernames — all of it is in
  // `createUser()`, and this form draws whatever it says. The `required` on the
  // username box is a convenience for a browser and not the check.
  // ---------------------------------------------------------------------------

  // The invented person as form values: what `createUser()` WOULD have written
  // for this username, keyed by the catalogue's own spelling.
  //
  // **IT IS THE SAME PERSONA AND NOT A SECOND RANDOM ONE**, which is the whole
  // value of the button: `vc_claims.js` seeds from the username, so pressing
  // Fill shows an operator exactly what accepting the invented person would
  // have got them — and they can then edit it rather than accept or refuse it
  // whole. A generator of its own here would have produced a plausible-looking
  // person that matched nothing, and the difference would have shown up only in
  // an `ldapsearch` weeks later.
  //
  // The rows with no `from` produce nothing, and there is exactly one:
  // `description`, which this service writes itself to say why the entry
  // exists.
  /**
   * Gives the invented persona createUser() would write for a username, as
   * form values keyed by LDAP attribute name.
   *
   * @param username - the username the persona is seeded from
   * @returns an object of attribute name to value
   */
  inventedFieldValues(username) {
    const { log, vcClaims } = this.deps;
    log.debug("Entering AdminConsole.inventedFieldValues(). username=" +
              username);
    const persona = vcClaims.personaFor(String(username || '').trim());
    const out = {};
    vcClaims.personFields().forEach(function (row) {
      if (!row.from) {
        return;
      }
      const value = persona[row.from];
      if (value === undefined || value === null || value === '') {
        return;
      }
      out[row.ldap] = String(value);
    });
    log.debug("Leaving AdminConsole.inventedFieldValues(). " +
              Object.keys(out).length + " " +
        "value(s).");
    return out;
  }

  // Drawn by `web_users.ts` (#446).
  /**
   * The fields `/admin/users/new` draws, as field grid rows: every attribute
   * a person's Attributes tab edits, and the credential catalogue's others
   * (the address), each with its group, example and tooltip.
   *
   * @param json - the form's answer, whose `fieldRows` are every field
   * @param view - `simple` or `advanced`
   * @returns the rows, in group order
   */
  newUserFieldRows(json, view) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.newUserFieldRows().");
    log.debug("Leaving AdminConsole.newUserFieldRows().");
    return UsersPage.newUserFieldRows(json, view);
  }


  // ---------------------------------------------------------------------------
  // GET /admin/groups — every group in the embedded directory, and one of them
  // in full.
  //
  // The first page in this console whose whole content came from another module
  // (several more do now — /admin/rbac, /admin/roles, the /admin/ldap/* pages).
  // This reads the directory through the slot ldap_server.js fills, and it
  // renders exactly what that returns without deciding anything — including
  // what counts as a group, which is that module's rule and is stated on the
  // page rather than reimplemented here.
  //
  // A GROUP IS NOT AN AUTHORISATION HERE, and the page says so where a reader
  // will see it. This paragraph used to say nothing in this service reads these
  // groups at all; three qualifications have landed since, and GROUPS_CAVEAT
  // below carries the first two: the groups claim (`groups.claim`) CARRIES a
  // membership into tokens and assertions without anything acting on it, the
  // two console role groups grant this console (8b in admin-ui/CLAUDE.md), and
  // a role under `ou=roles` may NAME a group (see /admin/roles). Otherwise they
  // are a directory's objects for a directory client to read, and a console
  // that listed them beside the tokens page without saying that would let
  // somebody conclude that adding a user to `cn=directory-admins` changed what
  // their token could do.
  // ---------------------------------------------------------------------------

  // What one attribute of an application entry IS, as the drill-down's third
  // column. Split out of that page because the entry carries FOUR kinds of
  // attribute and the table only ever described one of them — so everything
  // else came out as "not in the published schema", which is true of
  // `objectClass` and `createTimestamp` in the narrowest sense and useless as
  // an explanation.
  //
  // The order is the order of certainty: the registry's own table first, since
  // it is the same table the entry was written from; then the operational ones,
  // which the DIRECTORY sets and no schema of this module's would ever mention;
  // then the object classes, published one heading further down
  // `/admin/ldap/applications`; and only then the honest "somebody wrote this
  // by hand", which is a real state — this directory is schemaless and an
  // ldapmodify can put anything on an entry.
  //
  // No description is invented for an attribute nothing here knows. Saying
  // something confident about a name written by hand is how a page starts
  // lying.
  /**
   * Says what one attribute of an application entry is: from the published
   * schema, an operational attribute, an object class, or written by hand.
   *
   * @param name - the attribute name
   * @param operational - whether the directory marks it operational
   * @returns an object with `text` and, for a schema attribute, `sensitive`
   */
  applicationAttributeNote(name, operational) {
    const { log, adminViews } = this.deps;
    log.debug("Entering AdminConsole.applicationAttributeNote().");
    // `admin_views.ts`'s since #446: the application's answer carries each
    // attribute's note, made by the same function.
    log.debug("Leaving AdminConsole.applicationAttributeNote().");
    return adminViews.applicationAttributeNote(name, operational);
  }


  // ---------------------------------------------------------------------------
  // GET /admin/applications/new — CREATE ONE, ON A PAGE OF ITS OWN.
  //
  // The Applications list has carried an *Add an application* form since it
  // grew its six actions, and this page does not replace it or duplicate it:
  // BOTH POST TO `/admin/applications` WITH `action=create`, both reach
  // `applications.createApplication()`, and there is exactly one store behind
  // them. That is the same arrangement four doors onto one group membership
  // have (rule 8a) and the same one `/admin/token-lifetimes` argues for four
  // settings that `/admin/config` can already write: **two forms over one
  // function are two doors; what breaks the one-store rule is a second PLACE
  // THE VALUE LIVES**, and there is none here.
  //
  // So the question this page has to answer is the one that file's header asks
  // — what is different about the READER'S TASK — and there are three answers:
  //
  //   * **THE PROTOCOL FAMILIES.** Sixteen checkboxes with a sentence each do
  //     not fit in a `.formrow` at the foot of a table of every application
  //     this service has ever seen; they are a table of their own, and the row
  //     on the list page would have had to become a link to somewhere anyway.
  //   * **THE IDENTIFIERS AND THE REDIRECT URIS.** Two dozen more fields (as of
  //     2026-09-16), which is the 2026-08-25 change and the reason this page is
  //     now the only place a whole application can be configured in one post.
  //     Before it, a create took an identifier and a name and nothing else:
  //     every attribute that actually CONFIGURES the application — the
  //     client_id RFC 9700 mode reads, the redirect URIs it matches against,
  //     the entityID, the wtrealm — had to be added afterwards, one `add` at a
  //     time, from a different page.
  //   * **Creating one is a DIFFERENT ERRAND from reading the list.** Somebody
  //     configuring a relying party before it connects has not come to look at
  //     what has already connected, and on the list page that form is below the
  //     paging — so on a service with forty applications it is off the bottom
  //     of the screen, and the one control a person came for is the one they
  //     have to hunt for.
  //
  // **THE KIND SELECT IS GONE, AND ITS ABSENCE IS THE POINT RATHER THAN A
  // TIDY-UP.** This page used to ask for a KIND as well as for the families,
  // and they were two vocabularies for one question that did not line up: eight
  // kinds against fourteen families, five of those families having no kind at
  // all, and a reader made to choose in both. Worse, the two are on opposite
  // sides of the line `applications.js`'s EDITABLE header draws — a family is
  // DECLARED and a kind is DERIVED, written by `seen()` when a protocol
  // actually recognises the identifier — so the select let a form assert a
  // sighting that had not happened, and `view()`'s `recordedProtocols` had to
  // carry a paragraph saying it was not evidence of traffic. The families won
  // because they are what an operator is actually declaring.
  // `createApplication()` still TAKES a kind, because `saml2Action()` and
  // `saml11Action()` pass one when they register a service provider from its
  // own page, and that is a protocol module's statement rather than a person's
  // guess in a select.
  //
  // The inline form STAYS, for the same reason the sign-out page did not remove
  // `/oauth2/logout`: it is where somebody already looking at the list will
  // reach for, and it is one line of markup pointing at the same function.
  //
  // **WHAT LANDS IS AN ORDINARY DIRECTORY ENTRY IN THE REALM THE CONSOLE IS
  // SHOWING.** Nothing on this page knows that — the realm is ambient (rule 3m)
  // and `ou=applications` is resolved by `ldap_server.js` under whichever realm
  // this request arrived in — which is why the container DN is printed rather
  // than described: it is the answer this process gives, not one this page
  // works out, and on `/realm/acme/admin/applications/new` it says `acme`'s.
  // ---------------------------------------------------------------------------


  // The settings that decide what a service provider receives are DRAWN ON THIS
  // PAGE, and until 2026-08-27 they were readings here with a link to
  // /admin/config. What changed is not the rule they were following — one
  // store, one function — but where the door is:
  // `configFormsFor('/admin/saml2')` posts `set-many` to that same endpoint
  // against that same override map, exactly as /admin/token-lifetimes has since
  // it was written. See SETTING_HOMES, which is where the keys are now named; a
  // list of them here would be the second list that disagrees with the first.
  //
  // This page draws TWO groups, and the second is worth knowing about: `SAML`
  // holds `saml.issuer`, the Issuer of every assertion this service builds —
  // 2.0, 1.1 and WS-Federation's, which come out of the same two functions — so
  // it is drawn on the SAML 1.1 page as well and configFormsFor() says so on
  // both.

  // The settings that decide what a relying party receives are DRAWN ON THIS
  // PAGE, for the reason the SAML 2.0 page's equivalent comment gives and
  // through the same function. The `SAML` group appears on both pages because
  // `saml.issuer` governs both profiles; configFormsFor() says so where it
  // draws it, so a reader who sets it here is told it is the same value the 2.0
  // page shows.

  // ===========================================================================
  // `/admin/mfa` WAS HERE AND IT IS GONE (2026-09-10).
  //
  // It arrived that same day and lasted hours, which is the shortest life any
  // page in this console has had — so this marker is worth more than the usual
  // silence: a reader following a link, a bookmark or a sentence in an older
  // file needs to be told where the two halves went rather than meeting a 404.
  //
  // The page did TWO things and could only be filed by one of them. It edited
  // the eight `totp.*` settings, and it drew a roster of who held a second
  // factor with a Clear button on every row. Its own header argued at length
  // that it belonged under Identities because it answered a question about
  // PEOPLE — right about the roster, wrong about the settings, and a reader
  // looking for the skew window and a reader looking for *who has no second
  // factor* landed on one screen and read past each other.
  //
  //   * **THE SETTINGS ARE `/admin/totp` UNDER PROTOCOLS**, beside a new
  //     `/admin/webauthn` — the other second factor, which had no settings at
  //     all until that day. Both are rows in PROTOCOL_SETTINGS_PAGES.
  //   * **THE ROSTER IS COLUMNS ON `/admin/users`** — Known from, Can sign in
  //     with, Second factor — with a `factor` filter and the counts as tiles.
  //     That page's POPULATION had to widen to carry it: see peopleRows().
  //   * **THE PER-PERSON DETAIL AND BOTH CLEAR BUTTONS ARE ON THAT PERSON'S
  //     OWN ROW** — see mfaSection(), which can say what an enrolment IS
  //     rather than only that there is one, because it is drawn for one person
  //     rather than for forty.
  //   * **`mfaAction()` IS `usersAction()`'s `clear-totp` AND `clear-key`.**
  //     Same two acts, same audit rows, same refusals.
  //
  // `GET /admin-api/mfa` and `POST /admin-api/mfa/:action` still exist and
  // answer out of the views above, because an API operation that worked is not
  // worth breaking to tidy a table.
  // ===========================================================================

  // ---------------------------------------------------------------------------
  // GET /admin/consent, POST /admin/consent — WHAT PEOPLE HAVE AGREED TO.
  //
  // THE THIRD REGISTER IN THIS CONSOLE THAT LOOKS LIKE THE OTHER TWO AND
  // ANSWERS A DIFFERENT QUESTION, and saying which is which is most of what
  // this page is for. `/admin/delegation` holds ACTS (what happened) beside
  // INTENT (what an operator allowed between two applications). This page holds
  // neither: it holds what a PERSON said yes to, and the override an operator
  // wrote so that nobody would be asked.
  //
  // It is a page of its own rather than a fourth heading on /admin/delegation
  // for two reasons and the first is enough. Every row there is about two
  // APPLICATIONS; every row here has a person in it, and the whole argument for
  // keeping the acts picture and the permissions picture on separate canvases
  // is that a drawing with a person in it and a drawing without one must not
  // share a frame. The second is arithmetic: that page already carries seven
  // tables.
  //
  // TWO SECTIONS, AND THEY ARE NOT THE SAME KIND OF THING:
  //
  //   * GLOBAL CONSENT is CONFIGURATION. One row per (application, scope), held
  //     as `oauthGlobalConsent` on the application's own entry. Nobody is asked
  //     about a scope named there, and nothing is written about anybody — so
  //     REMOVING one asks everybody again, including the people who would have
  //     said yes.
  //   * RECORDED CONSENT is a RECORD. One row per (person, application, scope),
  //     held as `oauthConsent` on the person's own entry. Removing one asks
  //     that person again and nobody else.
  //
  // Both headings say so, because a reader who confused them would draw exactly
  // the wrong conclusion from an empty second table — which is what a service
  // with everything under global consent correctly looks like.
  //
  // FOUR ACTIONS, and two of them go through `applications.updateApplication()`
  // like every other attribute write in this console, so the ordering rules,
  // the audit row and the `ldapmodify` equivalence all come for free.
  // ---------------------------------------------------------------------------




  /**
   * Installs the hooks /admin/roles uses to preview an issuance decision,
   * here and in the read layer.
   *
   * Refused whole, with STS-ADMIN-0014 logged, unless both preview() and
   * policy() are functions.
   *
   * @param hooks - an object with preview() and policy()
   * @returns true if installed, false if refused
   */
  setRolePreviewer(hooks) {
    const { log, errorCodes, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setRolePreviewer().");
    if (!hooks || typeof hooks.preview !== 'function' ||
        typeof hooks.policy !== 'function') {
      log.error(errorCodes.tag('STS-ADMIN-0014') + 'admin: ' +
                'setRolePreviewer() was offered an object without both ' +
                'preview() and policy(), so it was refused and /admin/roles ' +
                'will say the decision cannot be previewed. Installing half ' +
                'of it would leave the page able to ask a question and ' +
                'unable to say which policy answered.');
      log.debug("Leaving AdminConsole.setRolePreviewer(). Refused.");
      return false;
    }
    rolePreviewer = hooks;
    // AND THE READ LAYER, which needs the same thing — see the header of
    // admin-core/admin_views.ts. Still one statement and one writer.
    adminViews.setRolePreviewer(hooks);
    log.info('admin: /admin/roles can preview an issuance decision — the ' +
             'same call the nine issuance sites make, through the same ' +
             'policy.');
    log.debug("Leaving AdminConsole.setRolePreviewer(). Installed.");
    return true;
  }

  // Drawn by `web_roles.ts` (#446).
  /**
   * Draws one row of the configured roles table: a column per member kind,
   * the permissions, and a Delete form.
   *
   * A console role's people and groups link to Admin roles instead of
   * carrying Remove buttons, and a console role cannot be deleted.
   *
   * @param one - the configured role
   * @param listView - the list view the forms carry
   * @param memberKinds - the kinds of member a role has, as the view
   *   carries them (`memberKinds`)
   * @returns the table row as HTML
   */
  roleRow(one, listView, memberKinds) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.roleRow().");
    log.debug("Leaving AdminConsole.roleRow().");
    return RolesPage.roleRow(one, listView, memberKinds);
  }

  // A DISABLED FIELD POSTS NOTHING, so a console save made while this realm
  // cannot send mail reads every email row as "no" — including one left ON
  // from before mail stopped working. That is the only save that could
  // succeed (`authn_policy.save()` refuses an email row on without mail), and
  // the warning above the form says the rows are off until mail works.

  // ---------------------------------------------------------------------------
  // ONE SECTION PER KIND OF POLICY (#64). The password policy and the
  // authentication policy each have things to say that no field table
  // carries; any other kind is drawn by `genericPolicySection()` from its
  // module alone, which is what makes a future policy cost no page.
  // ---------------------------------------------------------------------------

  // Drawn by `web_claims.ts` (#446).
  /**
   * Draws one claim set: its typed claims or attributes with Remove, Add and
   * Clear forms, followed by its directory attribute half.
   *
   * Shared by the claims and SAML attribute pages; the noun and the SAML
   * NameFormat or namespace column follow the set.
   *
   * @param setId - the claim set's id
   * @param previewUser - the username being previewed
   * @param values - the preview user's attribute values
   * @param pageUrl - the URL the forms post to
   * @returns the section as HTML
   */
  claimSetSection(setId, json, pageUrl) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.claimSetSection().");
    log.debug("Leaving AdminConsole.claimSetSection().");
    return ClaimsPage.claimSetSection(setId, json, pageUrl);
  }

  // ---------------------------------------------------------------------------
  // GET /admin/userinfo-claims, POST /admin/userinfo-claims
  //
  // THE THIRD PAGE ONTO THE ONE CLAIM-SET STORE, added 2026-08-26, and the
  // first one whose subject is not something this service ISSUES.
  //
  // Everything structural about it is /admin/claims: the same two halves (a
  // typed claim and a ticked directory attribute), the same claimsAction() with
  // an `allowed` list, the same setClaimSet() and the same audit row. What it
  // does NOT share with that page is the sentence that page is built around —
  // "nothing already issued changes" — and that difference is the whole
  // argument for it being a page rather than a third section over there.
  //
  // **A UserInfo response is BUILT ON EVERY CALL.** An access token, an ID
  // Token and both assertions are signed documents: a claim added to one of
  // those sets reaches a client at its next sign-in and never reaches the
  // tokens it already holds. A claim added HERE reaches the very next `GET
  // /oauth2/userinfo` from a client that signed in an hour ago and has done
  // nothing since. That is a different thing to be able to demonstrate, and a
  // reader who came to this console to demonstrate it should not have to infer
  // it from a page whose every warning says the opposite.
  //
  // **AND IT IS THE ONE CLAIM SET A CLIENT CAN ADD TO.** OpenID Connect Core
  // section 5.5 lets a client name individual claims in the `userinfo` member
  // of the `claims` request parameter, and this service answers them off the
  // same LDAP catalogue this page ticks from. So this page has a section no
  // other claims page has: what a client may ask for, what the four layers of
  // precedence are, and a PREVIEW of what a given request would return for a
  // given person — built by the functions oauth2.js's UserInfo endpoint itself
  // calls, for the reason every preview here is built that way.
  //
  // THE RESERVED LIST APPLIES HERE and does not apply to the SAML page, which
  // is the one rule a reader coming from /admin/saml-attributes will get wrong:
  // `sub` is required in this response by section 5.3.2 and a client MUST check
  // it against the ID Token's, and the SIGNED form of this response (a client
  // that registered `userinfo_signed_response_alg`) is a JWT carrying `iss`,
  // `aud` and `exp`. admin_stats.js's reservedNames() is where that is decided.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // GET /admin/vc, POST /admin/vc
  //
  // WHICH CLAIMS AN ISSUED CREDENTIAL CARRIES. The page is a list of LDAP
  // attribute types rather than of claim names, and vc_claims.js says at length
  // why; the short version is that this service has a directory, so a claim can
  // have a value that something other than the credential can see.
  //
  // It is the second page here that CHANGES what the protocol endpoints do, and
  // the first that writes to the directory: saving a selection sweeps every
  // person under ou=users and fills in what they are missing. That sweep is the
  // whole point of the page rather than a side effect — without it, ticking
  // `title` would change every future credential and change nothing an LDAP
  // client could see, and the two halves of this service would quietly stop
  // describing the same people.
  // ---------------------------------------------------------------------------

  // The values of a field that may appear MORE THAN ONCE in the body — which is
  // what a list of checkboxes is, and what nothing else on this console needed
  // until now.
  //
  // helpers.parseBody() cannot answer it: it builds a plain object, so a
  // repeated field keeps only its LAST value and a form with ten boxes ticked
  // would arrive as a selection of one. That is not a bug there — every other
  // form on this console has scalar fields, and changing the shape of that
  // function would change what eight other handlers see — so the repetition is
  // read here, from the raw body, beside the parsed one.
  /**
   * Reads every value of a field that may repeat in the body, such as a
   * list of checkboxes, from a JSON body or the raw form body.
   *
   * @param req - the request
   * @param body - the parsed body
   * @param name - the field's name
   * @returns the field's values as strings
   */
  listField(req, body, name) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.listField(). name=" + name);
    const type = String(req.headers['content-type'] || '');
    if (/json/i.test(type)) {
      const value = body[name];
      const out = Array.isArray(value) ? value.map(String)
                : (value == null || value === '' ? [] : [String(value)]);
      log.debug("Leaving AdminConsole.listField(). " + out.length + " " +
                                                       "value(s) from a JSON " +
                                                       "body.");
      return out;
    }
    const raw = typeof req.body === 'string' ? req.body : '';
    const out = new URLSearchParams(raw).getAll(name);
    log.debug("Leaving AdminConsole.listField(). " + out.length +
              " value(s) from a form body.");
    return out;
  }


  // Drawn by `web_realms.ts` (#446).
  /**
   * Draws the table of what trust realms separate and what they share, one
   * row per family, from realms.realmSupport().
   *
   * @param support - `realms.realmSupport()`, from the page's answer
   * @returns the table as HTML
   */
  realmSupportTable(support) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.realmSupportTable().");
    log.debug("Leaving AdminConsole.realmSupportTable().");
    return RealmsPage.realmSupportTable(support);
  }

  // ---------------------------------------------------------------------------
  // /admin/config — THE SETTINGS THAT BELONG TO NO PROTOCOL, AND THE INDEX OF
  // WHERE EVERY OTHER ONE IS EDITED.
  //
  // It was every setting this service has, in one page, until 2026-08-27. What
  // that page got right is that the sections were the PROTOCOLS, in the order
  // config.js's table declares them, because that is where a reader looks:
  // somebody who wants the Kerberos realm thinks of Kerberos. What it got wrong
  // follows from the same sentence — they think of Kerberos, so they open the
  // console's Kerberos page, and until that day the answer there was a table of
  // readings and a link to here. A hundred and fifty-four rows on one page is
  // also a page nobody reads: the group somebody wants is one of twenty-two,
  // and the twenty-one they scroll past are noise every time.
  //
  // So the settings live on the page for the family they configure, and what is
  // left here is the two things that have nowhere else to be:
  //
  //   * **The groups that belong to no protocol** — `Global` (it was five rows,
  //     a bind address, a port, the scheme, the proxy header and the log level,
  //     and has grown the mode, the proxy and worker settings since), and
  //     `Key material` and `Web security` beside it. Facts about the PROCESS
  //     rather than about anything it speaks, so there is no family page they
  //     would be less surprising on. They are drawn by the same
  //     `configSection()` every protocol page draws; SETTING_HOMES is the list.
  //   * **The INDEX**: every group, how many settings are in it, how many of
  //     those are overridden right now, and the page that edits it. Derived
  //     from SETTING_HOMES and `config.groups()`, so a group cannot be added to
  //     config.js and go unlisted here, and a page cannot be renamed out from
  //     under a link.
  //
  // Two things did NOT move, and both are deliberate. `Reset all` stays here,
  // because clearing every runtime override in the service is not an act about
  // one protocol and a button that did it from the Kerberos page would be the
  // only control in this console whose blast radius was invisible from where it
  // was pressed. And `?format=json` still answers the WHOLE table — `GET
  // /admin-api/config` is the API's configuration resource and a caller asking
  // it for the settings should not have to visit twenty-one pages to assemble
  // them. The page narrowed; the resource did not.
  //
  // EVERY ROW SAYS WHERE ITS VALUE CAME FROM. That is the question this page
  // exists to answer and it is the one that used to require a grep: a value can
  // arrive from a runtime override, from an environment variable (its own or
  // the legacy STS_ISSUER), from the appconfig file this process was started
  // with, or from env/defaults.js under it — and the four are indistinguishable
  // once they have been read.
  //
  // THERE IS NO FIFTH, since 2026-08-24: a setting with a value in none of them
  // stops this service from starting rather than quietly taking a constant out
  // of a module. So a value shown here is a value somebody can find in a file,
  // which is what makes the Source column worth reading at all.
  //
  // A restart-only row is SHOWN and its input is DISABLED, with the reason
  // beside it. Both halves matter. Hiding it would answer "what is this service
  // configured with?" with three quarters of the answer; letting it be typed
  // into would accept a change that does nothing, which reads as having worked.
  //
  // No script here, like every other page in this console: each section is a
  // plain form that posts the whole section at once (`set-many`), and each row
  // has a Reset button of its own. See the shell's note above — `script-src
  // 'none'` is what makes reflected content moot for this service, and the API
  // explorer (at `/admin/api-explorer` since 2026-09-09) is the one console
  // page that is an exception.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // THE SETTINGS BLOCK EVERY PROTOCOL PAGE DRAWS, AND THE ONE FUNCTION THAT
  // DRAWS IT.
  //
  // `configFormsFor('/admin/kerberos')` is the whole of what a page has to say
  // to own its settings: it looks the page up in SETTING_HOMES, renders one
  // `configSection()` per group that lives there, and returns the markup. A
  // page therefore names no key, decides no order and repeats no prose — which
  // is the property that keeps twenty-one pages from coming to describe the
  // same table twenty-one ways, and it is why the block reads identically
  // wherever it appears.
  //
  // WHAT IT SAYS IS SAID ONCE, HERE. Each of these pages used to carry its own
  // sentence about the configuration page owning its settings, and the three
  // that existed had already drifted into three different claims. The lead note
  // below is the only one now, and everything in it is derived: which groups
  // these are, how many rows cannot be changed while the service runs, whether
  // the group is shared with another page, and which file to put a value in to
  // make it survive a restart.
  //
  // A PAGE WITH NO ROW IN SETTING_HOMES GETS AN EMPTY STRING, deliberately. The
  // alternative is a page that draws an empty *Settings* heading because
  // somebody added the call before adding the table row, which reads as "this
  // family has no settings" — a claim no page here should make by accident.
  // ---------------------------------------------------------------------------

  // The row for a group, or null. A page asks the other way round; both are
  // looked up in the same table.
  /**
   * Finds a settings group's row in SETTING_HOMES.
   *
   * @param group - the group's name
   * @returns the row, or null
   */
  settingHomeRowOf(group) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.settingHomeRowOf().");
    log.debug("Leaving AdminConsole.settingHomeRowOf().");
    return SETTING_HOMES.filter(function (row) {
      return row.group === group;
    })[0] || null;
  }

  // The described settings this page owns, grouped, in `config.js`'s
  // declaration order rather than SETTING_HOMES's. Two orders would be two
  // answers to "which comes first" and the table that already decides it is the
  // one that also carries the reasoning for what sits beside what.
  /**
   * Lists the settings groups a console page owns, in config.js's
   * declaration order.
   *
   * @param path - the page's path
   * @returns the described groups from config.groups()
   */
  settingsGroupsFor(path) {
    const { log, config } = this.deps;
    log.debug("Entering AdminConsole.settingsGroupsFor(). path=" + path);
    const mine = SETTING_HOMES.filter(function (row) {
      return row.pages.indexOf(path) >= 0;
    }).map(function (row) { return row.group; });
    const out = config.groups().filter(function (group) {
      return mine.indexOf(group.group) >= 0;
    });
    log.debug("Leaving AdminConsole.settingsGroupsFor(). " + out.length +
              " group(s).");
    return out;
  }

  // What `?format=json` and the management API answer for a page's settings.
  // The same described rows the form is drawn from — including `source`,
  // `editable` and `restartReason` — so a caller can see WHY a value is what it
  // is without fetching the whole table from /admin-api/config and filtering it
  // themselves.
  /**
   * Builds the JSON a page and the management API answer for that page's
   * settings: the groups, the counts, the overridden keys and where to POST
   * a change.
   *
   * @param path - the page's path
   * @returns the settings model
   */
  configSettingsJson(path) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.configSettingsJson(). path=" + path);
    const groups = this.settingsGroupsFor(path);
    const all = groups.reduce(function (rows, group) {
      return rows.concat(group.settings);
    }, []);
    const json = {
      page: path,
      groups: groups,
      settingCount: all.length,
      editableCount:
        all.filter(function (setting) { return setting.editable; }).length,
      overridden: all.filter(function (setting) { return setting.overridden; })
                     .map(function (setting) { return setting.key; }),
      // Where a caller POSTs a change. Named rather than left to be inferred:
      // these settings are edited through the configuration resource wherever
      // they are DRAWN, which is the whole of why there is no second store.
      setWith: 'POST /admin-api/config/set-many',
      // WHAT THE BLOCK'S PROSE SAYS ABOUT THIS PROCESS (#446): the two files
      // the Source column names and whether an override survives a restart.
      // A page drawn in a browser has no process to ask, so the block
      // carries what its own notes state. `configFile` and `defaultsFile`
      // are `GET /admin-api/config`'s members of those names.
      context: this.settingsContext(),
      // The other pages each group is also drawn on, by group; a group
      // drawn here alone has no member.
      sharedWith: groups.reduce(function (map, group) {
        const others = self.sharedSettingPages(group.group, path);
        if (others.length) {
          map[group.group] = others;
        }
        return map;
      }, {})
    };
    log.debug("Leaving AdminConsole.configSettingsJson(). " +
              json.settingCount + " " +
        "setting(s).");
    return json;
  }

  // What a settings block states about the process it was answered by. One
  // function, so the block on every page and the whole table on
  // /admin/config cannot name two files.
  /**
   * Reports the appconfig file names and the persistence facts a settings
   * block's prose states.
   *
   * @returns `{ configFile, defaultsFile, persistsAppconfig,
   *   persistenceMode }`; `configFile` is null when CONFIG_FILE is unset
   */
  settingsContext() {
    const { log, config, persistence } = this.deps;
    log.debug("Entering AdminConsole.settingsContext().");
    const status = persistence.status();
    log.debug("Leaving AdminConsole.settingsContext().");
    return {
      configFile: process.env.CONFIG_FILE || null,
      defaultsFile: config.DEFAULTS_FILE,
      persistsAppconfig: !!status.persistsAppconfig,
      persistenceMode: String(status.mode)
    };
  }

  // The other pages a group of these settings is also drawn on, each with
  // its label off NAV, or none. `web_settings.ts` words the sentence.
  /**
   * Lists the other console pages a settings group is drawn on.
   *
   * @param groupName - the group's name
   * @param path - the page it is being drawn on
   * @returns the other pages, each `{ path, label }`; empty when no other
   *   page draws the group
   */
  sharedSettingPages(groupName, path) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.sharedSettingPages().");
    const row = this.settingHomeRowOf(groupName);
    if (!row || row.pages.length < 2) {
      log.debug("Leaving AdminConsole.sharedSettingPages().");
      return [];
    }
    log.debug("Leaving AdminConsole.sharedSettingPages().");
    return row.pages.filter(function (other) { return other !== path; })
      .map(function (other) {
        return { path: other, label: self.labelOfPath(other) };
      });
  }

  // A page's own label, off NAV, so a cross-reference cannot name a tab that
  // has been renamed. `upTo()` does the same thing for a breadcrumb and for the
  // same reason; this one answers with the label alone.
  /**
   * Looks up a console page's label in NAV.
   *
   * @param path - the page's path
   * @returns the label, or the path when NAV has no such page
   */
  labelOfPath(path) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.labelOfPath().");
    const item = NAV.filter(function (row) { return row.path === path; })[0];
    log.debug("Leaving AdminConsole.labelOfPath().");
    return item ? item.label : path;
  }

  // The block itself — DRAWN BY `web_settings.ts` SINCE #446, from the page's
  // settings member PASSED THROUGH JSON: what this console draws is what a
  // browser handed the management API's answer draws, and nothing the block
  // says can come from this process by another road.
  // `tests/console_web_bundle.js` (F) compared the two renderers on every
  // settings page before this method became a call, and holds the bundle to
  // the same bytes now.
  //
  // THE THREE METHODS COMMENTS THROUGHOUT THIS FILE CITE WENT WITH IT, each
  // with its reasoning: `configSection()` is `SettingsForms.section()`,
  // `configRow()` is `SettingsForms.row()` — the `formaction` Reset and the
  // description-as-tooltip arguments are above it there — and
  // `orderedChoiceControl()` kept its name.
  /**
   * Draws the Settings block a console page carries: the lead notes on
   * persistence, restart-only rows and overrides, then one section form per
   * group the page owns.
   *
   * @param path - the page's path
   * @param only - optional; the names of the groups to draw, for a page that
   *   puts each of its groups on a tab of its own (/admin/listeners, #423)
   * @returns the block as HTML, or an empty string when the page owns no
   *   settings group (or none of `only`)
   */
  configFormsFor(path, only?) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.configFormsFor(). path=" + path);
    const block = JSON.parse(JSON.stringify(this.configSettingsJson(path)));
    log.debug("Leaving AdminConsole.configFormsFor(). " +
              block.settingCount + " setting(s) on " + path + ".");
    return SettingsForms.forms(block, path, only);
  }

  // The whole table, plus WHERE EACH GROUP IS EDITED. The snapshot is untouched
  // — this resource is still every setting this service has, because a caller
  // asking the API for the configuration should not have to visit twenty-one
  // pages to assemble it — and `homes` is what a caller needs to send a person
  // to the right console page, or to notice that a group has none.
  /**
   * Builds the whole configuration snapshot with, for each settings group,
   * the pages that edit it, and any SETTING_HOMES problems.
   *
   * @returns the configuration model
   */
  configJson() {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.configJson().");
    const json = config.snapshot();
    json.homes = SETTING_HOMES.map(function (row) {
      return { group: row.group, pages: row.pages,
               labels: row.pages.map(self.labelOfPath.bind(self)) };
    });
    // Empty on a service whose table and console agree, which is every service
    // that starts from a commit where they did. Present either way, so a caller
    // can assert on it.
    json.homeProblems = SETTING_HOME_PROBLEMS;
    // The rows that belong to no protocol, as the settings block every page
    // that owns settings answers (#446): the page draws its form from it.
    json.settings = this.configSettingsJson('/admin/config');
    log.debug("Leaving AdminConsole.configJson(). " + json.settingCount +
              " setting(s).");
    return json;
  }

  // ---------------------------------------------------------------------------
  // /admin/saml-assertions — HOW LONG AN ASSERTION IS VALID, AND HOW FAR THE
  // WINDOW IS WIDENED FOR SOMEBODY ELSE'S CLOCK.
  //
  // Three settings when it was written — sixteen now (`SAML_ASSERTION_SETTINGS`
  // in admin-core/admin_actions.ts), since it became the page for the
  // per-application SAML defaults on 2026-08-27 — all of them `config.js` rows,
  // on a page of their own under Protocols > SAML. It is the THIRD page of this
  // shape — /admin/token-lifetimes was the second and argues the form at length
  // — so the test that header sets is the one this page has to pass rather than
  // cite: a page like this earns its place when the reader's task is not the
  // one /admin/config serves, and it costs a reader nothing only while it
  // writes through the same function.
  //
  // It passes on both counts, and the specific reasons are:
  //
  //   * These three are a QUANTITY somebody sets to a number to watch something
  //     happen — "make it a minute and see whether that service provider checks
  //     NotOnOrAfter at all". Two of them are already drawn on /admin/saml2 and
  //     /admin/saml11, one on each, which means comparing them or changing both
  //     costs two pages and a scroll through everything else those pages
  //     configure. This is the one place both are visible at once.
  //   * They INTERACT, and interact in a way a flat table cannot say. A skew as
  //     long as the lifetime is an assertion valid for twice as long as its
  //     lifetime claims; a skew of zero against a relying party whose clock is
  //     behind is an assertion refused as not-yet-valid, which is the single
  //     most misdiagnosed failure in this protocol family because it reads from
  //     both ends as a signature or trust-store problem.
  //   * The two lifetimes are SEPARATE settings, and a page that shows them
  //     together is the only place that fact is visible. SAML 2.0 and SAML 1.1
  //     are separate implementations here, not one with a version flag.
  //
  // THERE IS NO STORE. This page holds nothing and writes through
  // `config.setOverride()` — the same function /admin/config's Save, the two
  // identity provider pages' own forms, and `POST /admin-api/config/set` all
  // call, against the same override map. A change made on any of them is one
  // change. That is what keeps the one-store rule intact while the same setting
  // appears on two pages.
  //
  // WHY THE SKEW IS ONE SETTING AND THE LIFETIMES ARE TWO. The lifetimes are
  // per profile because the two profiles are consumed differently and this
  // repository has argued that at length in config.js. The skew is not about a
  // profile at all: it is how far out the clocks in the estate this service
  // issues into are allowed to be, which a deployment decides once. It is
  // applied in both builders, so WS-Trust and WS-Federation — whose assertions
  // come out of those same two functions — get it without either module knowing
  // it exists.
  //
  // AND IT IS NOT oauth2.clockSkewS. That one is a TOLERANCE applied when this
  // service READS something back, including an inbound federation partner's
  // assertion (federation/federation_sp.ts, which argues there that a reading
  // tolerance is decided once). This one is what this service WRITES into a
  // document it issues. A deployment wanting a strict reading and a forgiving
  // issuance has to be able to say so, and with one setting it could not.
  //
  // NOTHING ALREADY ISSUED CHANGES, and the page says so. A validity window is
  // stamped into an assertion when it is signed.
  // ---------------------------------------------------------------------------





  /**
   * Installs the Shared Signals reporter and forwards it to the action and
   * read layers; one of the console's inverted hooks (root rule 3e).
   *
   * A reporter missing any required member is ignored whole and logged
   * under STS-ADMIN-0014, so the pages say it is not installed.
   *
   * @param reporter - the SSF reporter object from ssf/ssf.ts
   */
  setSignalsReporter(reporter) {
    const { log, errorCodes, adminActions, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setSignalsReporter().");
    const needed = ['report', 'deadLetters', 'action', 'actions', 'eventTypes',
                    'statuses', 'subjectFormats'];
    const missing = needed.filter(function (name) {
      return !reporter || reporter[name] === undefined;
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-ADMIN-0014') + 'admin: ' +
                                                   'setSignalsReporter() was ' +
                                                   'given something without ' +
                missing.join(', ') + ', and was ignored whole. /admin/ssf ' +
                'and /admin-api/ssf will say the reporter is not installed ' +
                'rather than half working.');
      log.debug("Leaving AdminConsole.setSignalsReporter(). Refused.");
      return;
    }
    signalsReporter = reporter;
    // AND THE ACTION LAYER, which needs the same object and is handed it
    // from here rather than asking for it — see the header of
    // admin-core/admin_actions.ts. One statement, two destinations: this is
    // the ONLY place either is written, which is what keeps it one answer.
    adminActions.setSignalsReporter(reporter);
    // AND THE READ LAYER: the /admin-api report of this stream is drawn there
    // while the controls beside it are actions. One statement, one writer.
    adminViews.setSignalsReporter(reporter);
    log.debug("Leaving AdminConsole.setSignalsReporter(). Installed.");
  }

  /**
   * Installs the client-certificate truststore and forwards it to the action
   * and read layers; filled by common/protocol_stack.ts.
   *
   * @param value - an object with `list`, `add` and `remove` functions
   * @returns true when installed; false, logged under STS-ADMIN-0014, when a
   *   function is missing and nothing was installed
   */
  setTruststore(value) {
    const { log, errorCodes, adminActions, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setTruststore().");
    const needed = ['list', 'add', 'remove'];
    const missing = needed.filter(function (name) {
      return !value || typeof value[name] !== 'function';
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-ADMIN-0014') + 'admin: setTruststore() ' +
                                                   'was given something ' +
                                                   'without ' +
                missing.join(', ') + ', and was ignored whole. ' +
                '/admin/tls/trust and /admin-api/tls/trust will say the ' +
                'truststore is not installed rather than half working.');
      log.debug("Leaving AdminConsole.setTruststore(). Refused.");
      return false;
    }
    truststore = value;
    // One statement, two destinations, and this is the only place either is
    // written — the arrangement every forwarded collaborator here keeps, and
    // what tests/admin_actions_layer.js asserts.
    adminActions.setTruststore(value);
    adminViews.setTruststore(value);
    log.debug("Leaving AdminConsole.setTruststore(). Installed.");
    return true;
  }

  /**
   * Installs the CAEP reporter and forwards it to the action and read
   * layers; one of the console's inverted hooks (root rule 3e).
   *
   * A reporter missing any required member is ignored whole and logged
   * under STS-ADMIN-0014.
   *
   * @param reporter - the CAEP reporter object
   */
  setCaepReporter(reporter) {
    const { log, errorCodes, adminActions, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setCaepReporter().");
    const needed = ['report', 'action', 'actions', 'eventTypes'];
    const missing = needed.filter(function (name) {
      return !reporter || reporter[name] === undefined;
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-ADMIN-0014') + 'admin: setCaepReporter() ' +
                                                   'was given something ' +
                                                   'without ' +
                missing.join(', ') + ', and was ignored whole. /admin/caep ' +
                'and /admin/caep-sessions will say the reporter is not ' +
                'installed rather than half working.');
      log.debug("Leaving AdminConsole.setCaepReporter(). Refused.");
      return;
    }
    caepReporter = reporter;
    // AND THE ACTION LAYER, which needs the same object and is handed it
    // from here rather than asking for it — see the header of
    // admin-core/admin_actions.ts. One statement, two destinations: this is
    // the ONLY place either is written, which is what keeps it one answer.
    adminActions.setCaepReporter(reporter);
    // AND THE READ LAYER: the /admin-api report of this stream is drawn there
    // while the controls beside it are actions. One statement, one writer.
    adminViews.setCaepReporter(reporter);
    log.debug("Leaving AdminConsole.setCaepReporter(). Installed.");
  }

  /**
   * Installs the RISC reporter and forwards it to the action and read
   * layers; one of the console's inverted hooks (root rule 3e).
   *
   * A reporter missing any required member is ignored whole and logged
   * under STS-ADMIN-0014.
   *
   * @param reporter - the RISC reporter object
   */
  setRiscReporter(reporter) {
    const { log, errorCodes, adminActions, adminViews } = this.deps;
    log.debug("Entering AdminConsole.setRiscReporter().");
    const needed = ['report', 'action', 'actions', 'eventTypes'];
    const missing = needed.filter(function (name) {
      return !reporter || reporter[name] === undefined;
    });
    if (missing.length) {
      log.error(errorCodes.tag('STS-ADMIN-0014') + 'admin: setRiscReporter() ' +
                                                   'was given something ' +
                                                   'without ' +
                missing.join(', ') + ', and was ignored whole. /admin/risc ' +
                'and /admin/risc-accounts will say the reporter is not ' +
                'installed rather than half working.');
      log.debug("Leaving AdminConsole.setRiscReporter(). Refused.");
      return;
    }
    riscReporter = reporter;
    // AND THE ACTION LAYER, which needs the same object and is handed it
    // from here rather than asking for it — see the header of
    // admin-core/admin_actions.ts. One statement, two destinations: this is
    // the ONLY place either is written, which is what keeps it one answer.
    adminActions.setRiscReporter(reporter);
    // AND THE READ LAYER: the /admin-api report of this stream is drawn there
    // while the controls beside it are actions. One statement, one writer.
    adminViews.setRiscReporter(reporter);
    log.debug("Leaving AdminConsole.setRiscReporter(). Installed.");
  }

  // ---------------------------------------------------------------------------
  // THE EIGHT PROTOCOL SETTINGS PAGES ADDED ON 2026-08-27, AND WHY THEY ARE A
  // TABLE AND A LOOP RATHER THAN EIGHT ROUTE HANDLERS.
  //
  // Five protocol families here had settings and no page in this console —
  // OAuth 2.0 / OIDC, WS-Trust, WS-Federation, Kerberos, LDAP, TLS, OpenID4VCI
  // and OpenID4VP, eight pages across six of them — so their configuration was
  // only ever reachable at /admin/config among a hundred and fifty-four rows.
  // Every one of these pages is therefore the SAME page: a paragraph or two
  // saying what the family is and where it answers, the links to the surfaces
  // it already has, and `configFormsFor()`. The differences between them are
  // PROSE.
  //
  // Eight handlers would have been eight copies of one four-line body, and the
  // copy nobody edited is the one a reader believes — the defect this
  // repository warns about everywhere else. So the prose is a table and the
  // handler is written once. Three things follow and each is deliberate:
  //
  //   * **REGISTRATION IS STILL IN THE ONE REGISTRATION PASS** (rule 1). The
  //     loop runs inside `registerRoutes()` — while this module was being
  //     required until #50's R1, and when `common/protocol_stack.ts` calls
  //     that method since — so these routes are registered in the order they
  //     appear here, are behind the gate registered above them, and are
  //     visible to `sts_metadata.js` reading the router — a page built in a
  //     loop is not a page built differently.
  //   * **THE SETTINGS ARE NOT IN THIS TABLE.** A row names a `path`, and
  //     SETTING_HOMES says what lives there. Naming keys here would be the
  //     second list that disagrees with the first.
  //   * **A ROW MAY SAY WHAT ITS FAMILY DOES NOT DO**, and several do. These
  //     are the pages a person lands on when they are deciding whether this
  //     service can stand in for a real one, and the answer "it speaks the
  //     protocol" without "it checks nothing" is the misleading half of a true
  //     sentence — which is the same rule `sts_metadata.js`'s coverage notes
  //     follow.
  //
  // WHAT IS DELIBERATELY NOT ON THEM IS AN ENDPOINT LIST. Every one of these
  // families answers on paths this file would have to keep in step by hand, and
  // `/admin/sts-metadata` already derives exactly that list from the running
  // router. A hand-written table here would be the drift that page exists to
  // catch, on a page that cannot be checked. The links below are to the
  // family's own surfaces — pages that explain themselves — and to the
  // service metadata for the rest.
  //
  // **REVERSED 2026-09-13, AND STILL NOT IN THIS TABLE**: every Protocols page
  // now lists its realm's endpoints, drawn by `respond()` from
  // `admin-core/protocol_endpoints.ts`, which names ROUTES and takes names and
  // methods from `sts_metadata.js` and the router, so both drifts fail
  // `tests/protocol_endpoints.js`. admin-ui/CLAUDE.md argues it.
  // ---------------------------------------------------------------------------
  // WHAT THE PERSISTENT STORE IS ACTUALLY DOING, as HTML and as JSON at once.
  //
  // ONE FUNCTION RETURNING BOTH, for the reason `config.describe()` is one
  // shape: a console and a management API that compute the same answer
  // separately are a console and an API that will one day disagree about
  // whether the last write worked, and that is the single worst thing either of
  // them could disagree about.
  //
  // **IT COMPUTES NOTHING.** Every number and every sentence comes out of
  // `persistence.status()`, which is that module's own account of itself and is
  // the same object `GET /admin/ldap/service` publishes. This function chooses
  // what to SHOW and how to phrase it; it does not decide anything, so there is
  // no second opinion here to go stale.
  // ---------------------------------------------------------------------------
  /**
   * Describes what the persistent store is doing right now, from
   * `persistence.status()`; it computes nothing of its own.
   *
   * @returns `html`, the block for /admin/persistence, and `json`, the
   *   status it was drawn from
   */
  persistenceStatusBlock() {
    const { log, persistence } = this.deps;
    log.debug("Entering AdminConsole.persistenceStatusBlock().");
    const info = persistence.status();
    // DRAWN BY `web_protocol_settings.ts` (#446) from the JSON this block
    // answers, passed through JSON.
    const html = ProtocolSettingsPage.persistenceStatus(
      JSON.parse(JSON.stringify(info)));
    return { html: html, json: info };
  }

  // ===========================================================================
  // /admin/cluster's STATUS BLOCK (2026-09-14, #46).
  //
  // The `status` member of a row in PROTOCOL_SETTINGS_PAGES, for the reason
  // `/admin/persistence` has one: `cluster.mode` SET and a cluster WORKING are
  // two facts. It computes nothing — `cluster.status()` and
  // `cluster.snapshot()` are that module's own account of itself — and it draws
  // four answers: what this node is, who else is a member and who holds which
  // lease, what active-active mode is still waiting for, and which secrets
  // every node shares.
  //
  // **THE NODE AND LEASE TABLES ARE A SNAPSHOT**, read on every heartbeat by a
  // front process and at most once a heartbeat by the process drawing this
  // page, and the page says how old it is. A synchronous page cannot wait for a
  // query, and a page that silently showed an hour-old membership would be
  // worse than one that says "as of two seconds ago".
  // ===========================================================================
  /**
   * The Cluster page's section on every OTHER cell's cluster (#361), from
   * what `prepareClusterPage()` read: each cell's running members (folded
   * by name, with their restarts), its leases and each node's worker
   * pools; a cell that did not answer is drawn as unreachable, with why.
   * Times are the answering cell's database clock, shown relative to the
   * moment it answered.
   *
   * @returns `{ html, json }`; both empty in single-cell mode
   */
  otherCellsBlock() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.otherCellsBlock().");
    const held = this.peerClustersNow;
    if (!held) {
      log.debug("Leaving AdminConsole.otherCellsBlock(). Single cell.");
      return { html: '', json: null };
    }
    const agoFrom = function (at, t) {
      if (!t) {
        return '—';
      }
      const ms = at - t;
      return ms >= 0 ? self.esc(self.durationText(ms)) + ' ago'
                     : 'in ' + self.esc(self.durationText(-ms));
    };
    const sections = (held.rows || []).map(function (row) {
      const head = '<h3>Cell <code>' + self.esc(row.cell) + '</code> (' +
        self.esc(row.jurisdiction || '?') + ')</h3>';
      if (!row.reachable) {
        return head + self.warn('<strong>This cell did not answer.</strong> ' +
          self.esc(row.error || '') + ' Its members may be running; the ' +
          'inter-cell channel could not ask them.');
      }
      const sum = row.summary || {};
      const at = Number(sum.at) || 0;
      if (!sum.clustered) {
        return head + self.note('Answered in ' +
          self.esc(String(row.answeredMs)) + 'ms; it is not clustered ' +
          '(<code>cluster.mode</code> ' + self.esc(sum.mode || 'off') +
          ').');
      }
      const members = sum.members || { live: [], restarts: {}, gone: [] };
      const restarts = members.restarts || {};
      const live = (members.live || []).map(function (n) {
        const r = restarts[n.name] || null;
        return '<tr><td><strong>' + self.esc(n.name) + '</strong></td><td>' +
          self.esc(n.mode) + '</td><td>' + self.esc(n.version || 'unknown') +
          '</td><td>' + (n.uptimeMs
            ? self.esc(self.durationText(n.uptimeMs)) : '—') +
          (r ? '<br><span class="sub">restarted ' + self.esc(String(r.count)) +
               ' time(s), the last life ended ' + agoFrom(at, r.lastEndedAt) +
               '</span>' : '') +
          '</td><td>' + agoFrom(at, n.heartbeatAt) +
          (n.lastStallMs ? '<br><strong>last stall ' +
            self.esc(String(Math.round(n.lastStallMs / 100) / 10)) +
            's</strong>' : '') +
          '</td><td>' + self.esc(String(n.workers || 0)) + '</td><td>' +
          ((n.leases || []).map(function (l) {
            return '<code>' + self.esc(l) + '</code>';
          }).join('<br>') || 'none') + '</td><td>' +
          (n.agrees === null ? 'not known there'
            : n.agrees ? 'yes' : '<strong>NO</strong>') + '</td></tr>';
      }).join('');
      const gone = (members.gone || []).map(function (n) {
        return '<tr><td>' + self.esc(n.name || '(no name)') + '</td><td>' +
          self.esc(n.version || 'unknown') + '</td><td>' +
          (n.how === 'left' ? 'left cleanly ' : '<strong>expired</strong> ') +
          agoFrom(at, n.endedAt) + (n.earlierLives
            ? '<br><span class="sub">and ' + self.esc(String(n.earlierLives)) +
              ' earlier life/lives</span>' : '') + '</td></tr>';
      }).join('');
      const pools = (sum.pools || []).map(function (node) {
        return (node.pools || []).map(function (p) {
          return '<tr><td>' + self.esc(node.name) +
            (node.state && node.state !== 'live'
              ? ' <em>(' + self.esc(node.state) + ')</em>' : '') +
            '</td><td>' + self.esc(p.title || p.id) + '</td><td>' +
            self.esc(p.state || '') + '</td><td>' +
            self.esc(String(p.currentWorkers)) + '</td><td>' +
            self.esc(String(p.busyWorkers)) + '</td><td>' +
            self.esc(String(p.freeWorkers)) + '</td><td>' +
            self.esc(String(p.crashed)) + '</td><td>' +
            self.esc(String(p.failedStarts)) + '</td></tr>';
        }).join('');
      }).join('');
      return head + '<div class="tiles">' +
        self.tile((members.live || []).length, 'running') +
        self.tile((sum.leases || []).length, 'leases held') +
        self.tile((members.gone || []).length, 'left or expired') +
        '</div><p class="sub">Mode ' + self.esc(sum.mode) +
        '; answered in ' + self.esc(String(row.answeredMs)) + 'ms. Times ' +
        'are that cell\'s database clock, relative to when it answered.</p>' +
        self.wideTable('Running members of cell ' + row.cell,
          '<table><tr><th>Node</th><th>Mode</th><th>Version</th><th>Up</th>' +
          '<th>Last seen</th><th>Request workers</th><th>Leases</th>' +
          '<th>Settings agree</th></tr>' +
          (live || '<tr><td colspan="8">no running members</td></tr>') +
          '</table>') +
        (gone ? '<details class="fold"><summary>' +
          self.esc(String((members.gone || []).length)) + ' node name(s) ' +
          'that have left or expired</summary><div class="foldbody">' +
          self.wideTable('Left or expired in cell ' + row.cell,
            '<table><tr><th>Node</th><th>Version</th><th>Ended</th></tr>' +
            gone + '</table>') + '</div></details>' : '') +
        (pools ? self.wideTable('Worker pools of cell ' + row.cell,
          '<table><tr><th>Node</th><th>Pool</th><th>State</th>' +
          '<th>Workers</th><th>Busy</th><th>Free</th><th>Crashed</th>' +
          '<th>Failed starts</th></tr>' + pools + '</table>')
          : (sum.poolsError ? self.note('Its worker pools could not be ' +
              'read: ' + self.esc(sum.poolsError)) : ''));
    }).join('');
    const html = '<h2>The other cells</h2>' +
      self.note('This service runs as several cells, each its own cluster ' +
        'against its own database; the list above is this cell\'s. Each ' +
        'other cell was asked over the inter-cell channel for its members ' +
        'and pools when this page was drawn — names and counts only, never ' +
        'an address.') +
      (held.error ? self.warn(self.esc(held.error)) : '') +
      (sections || self.note('No other cell is configured.'));
    log.debug("Leaving AdminConsole.otherCellsBlock().");
    return { html: html, json: { askedAt: held.at, cells: held.rows || [],
                                 error: held.error || null } };
  }

  /**
   * Describes this node, the cluster's members and leases, what
   * active-active still waits for and the shared secrets, for
   * /admin/cluster. The member tables are a snapshot, and say how old.
   *
   * @returns `html`, the block, and `json`, the status, snapshot and
   *   secrets it was drawn from
   */
  clusterStatusBlock() {
    const { log, cluster, clusterSecrets, clusterBarrier } = this.deps;
    const consoleSelf = this;
    log.debug("Entering AdminConsole.clusterStatusBlock().");
    const self = cluster.status();
    const snap = cluster.snapshot();
    const state = snap.state;
    const secrets = clusterSecrets.describe();
    const barrier = clusterBarrier.report();
    const off = self.mode === 'off';
    const nameOf = {};
    ((state && state.nodes) || []).forEach(function (node) {
      nameOf[node.nodeId] = node.name;
    });
    // A TIME AGAINST THE DATABASE'S CLOCK, never this process's. Tenths of a
    // second up to two minutes, because every lifetime and every heartbeat on
    // this page is seconds long and a tenth is the difference between a node
    // that is late and one that is dead; past two minutes it is a duration,
    // because "7200s ago" is a number a reader has to divide (2026-09-17, the
    // roster — a node that left hours ago is on this page now).
    const ago = function (at) {
      if (!state || !at) {
        return '—';
      }
      const ms = state.now - at;
      const size = Math.abs(ms);
      const much = size >= 120000
        ? consoleSelf.durationText(size)
        : String(Math.round(size / 100) / 10) + 's';
      return ms >= 0 ? consoleSelf.esc(much) + ' ago'
                     : 'in ' + consoleSelf.esc(much);
    };

    const rows = [
      ['Mode',
       '<strong>' + this.esc(self.mode) + '</strong> — ' + this.esc(self.why) +
        (self.refused ? '. ' + this.warn(this.esc(self.refused)) : '')],
      ['This node', off ? 'not a member of anything'
        : '<code>' + this.esc(self.nodeId) + '</code> (' + this.esc(self.name) +
          '), ' +
          this.esc(self.role === 'worker' ? 'a request worker of that node'
                                          : 'the front process') +
          (self.joinedAt ? ', joined ' + this.esc(self.joinedAt) : '')],
      ['Heartbeat', off ? '—'
        : 'every ' + this.esc(String(self.heartbeatMs)) + 'ms, lifetime ' +
          this.esc(String(self.ttlMs)) + 'ms by the database clock' +
          (self.msSinceRenewal !== null
            ? '; last renewed ' + this.esc(String(self.msSinceRenewal)) +
              'ms ago'
            : '') +
          (self.heartbeatFailures
            ? '. <strong>' + this.esc(String(self.heartbeatFailures)) +
              ' consecutive failure(s)</strong>: ' +
              this.esc(String(self.lastHeartbeatError)) +
              '. A node that cannot renew within its lifetime exits.'
            : '')],
      ['Leases held here', off || !self.leases.length ? 'none'
        : self.leases.map(function (lease) {
          return '<code>' + consoleSelf.esc(lease.name) + '</code> at token ' +
                 consoleSelf.esc(String(lease.token));
        }).join(', ')],
      ['Read barrier', barrier.active
        ? this.esc(String(barrier.requests)) + ' request(s) waited a mean ' +
          this.esc(String(Math.round(barrier.meanWaitMs * 10) / 10)) + 'ms ' +
          'to catch up; ' + this.esc(String(barrier.gaveUp)) + ' were served ' +
          'before catching up; ' + this.esc(String(barrier.heldForCommit)) +
          ' response(s) were held a mean ' +
          this.esc(String(Math.round(barrier.meanHoldMs * 10) / 10)) + 'ms ' +
          'for their writes to commit' + (barrier.commitFailures
            ? ', <strong>' + this.esc(String(barrier.commitFailures)) +
              ' of which failed</strong>' : '')
        : 'off — only active-active nodes wait for each other\'s writes']
    ];

    // =======================================================================
    // THE ROSTER (2026-09-17): WHO IS RUNNING, AND WHEN ANYTHING LAST HEARD
    // FROM THEM.
    //
    // The first question an operator brings to this page is whether the other
    // container is up and when it was last seen, and until this it was
    // answered by one table that mixed the live members in with every row the
    // store has kept and left out everything the membership row's `info`
    // carries. So the LIVE members come first, one row each, with what only
    // that node can say about itself — where it runs, how long its process has
    // been up, how many processes answer requests there, whether its event
    // loop has stalled — and the rows that have left or expired are folded
    // underneath rather than thrown away, because #46's own failure mode is a
    // node whose row expired while its process kept running and the operator
    // needs to see that it was here.
    //
    // **EVERY TIME HERE IS THE DATABASE'S CLOCK** (`state.now`), never this
    // process's: two containers' clocks differ, and `cluster.js` measures a
    // lease against the store's clock for exactly that reason. `info.uptimeMs`
    // is the one exception and is labelled as the node's own, because no other
    // clock can state how long a process has been running.
    //
    // **AND IT IS DRAWN EVEN WHEN THIS PROCESS IS NOT CLUSTERED.** A section
    // that disappears in `off` mode reads as a page that has not loaded; one
    // that says there is no membership to list answers the question.
    // =======================================================================
    const nodes = state ? state.nodes : [];
    const now = state ? state.now : 0;
    // FOLDED BY NAME (2026-09-30, `cluster.foldMembers()`): a dead row whose
    // name has a live row is that node's restart history and is counted on
    // its live row; only a name with no live row has left or expired, drawn
    // once. A snapshot from an older build carries no `members`, so it is
    // folded here from the rows.
    const folded = (state && state.members) ||
                   cluster.foldMembers(nodes, now);
    const live = folded.live;
    const gone = folded.gone;
    const restarts = folded.restarts || {};

    // WHICH LEASES EACH NODE STILL HOLDS, by holder. A lapsed row is left out:
    // a released lease is expired and never deleted (the fencing token must
    // never go back to 1), so a page that listed every row would say a node
    // holds what it gave up.
    const leasesOf = {};
    ((state && state.leases) || []).forEach(function (lease) {
      if (lease.expiresAt <= now) {
        return;
      }
      if (!leasesOf[lease.holder]) {
        leasesOf[lease.holder] = [];
      }
      leasesOf[lease.holder].push(lease);
    });

    // WHAT A LIVE NODE IS DOING is not the same question as whether it is
    // alive, and the difference is the whole of active-passive mode: one
    // member holds the service lease and serves, and every other one is a
    // standby that has restored nothing and bound nothing. The LEASE TABLE is
    // the only thing that says which, so it is read rather than guessed from
    // the node's own mode.
    const roleOf = function (node) {
      const mine = leasesOf[node.nodeId] || [];
      const serving = node.mode === 'active-active' || mine.some(
        function (lease) {
          return lease.name === cluster.SERVICE_LEASE;
        });
      return serving ? { label: 'serving', cls: 'state-valid' }
                     : { label: 'standby', cls: 'state-none' };
    };

    // WHERE THE CONTAINER IS, out of the membership row's `info` — the only
    // channel a node has to tell the others anything about itself, rewritten
    // on its join and on every heartbeat (`cluster/cluster.js`, `nodeInfo()`).
    // A row written by an older build simply has fewer members in it, so
    // nothing below assumes any one of them is there.
    const whereOf = function (node) {
      const info = node.info || {};
      const parts = [];
      if (info.host) {
        parts.push('<code>' + consoleSelf.esc(String(info.host)) +
                   (info.port ? ':' + consoleSelf.esc(String(info.port)) : '') +
                   '</code>');
      }
      if (info.pid) {
        parts.push('pid ' + consoleSelf.esc(String(info.pid)));
      }
      if (info.workers) {
        parts.push(consoleSelf.esc(String(info.workers)) +
                   ' request worker(s)');
      }
      return parts.length ? parts.join('<br>') : '—';
    };

    // HOW LONG THE PROCESS HAS BEEN UP, which the node states itself, falling
    // back to how long its membership row has existed. They are different
    // facts and the second is the weaker one — a row is written after the
    // process starts and survives a restart that reuses no node id — so it is
    // only used where the node said nothing.
    const upOf = function (node) {
      const info = node.info || {};
      const r = restarts[node.name || ''];
      const history = r
        ? '<br><span class="sub">restarted ' +
          consoleSelf.esc(String(r.count)) + ' time(s), the last life ended ' +
          ago(r.lastEndedAt) + '</span>'
        : '';
      if (info.uptimeMs) {
        return consoleSelf.esc(consoleSelf.durationText(info.uptimeMs)) +
               history;
      }
      return 'joined ' + ago(node.startedAt) + history;
    };

    // WHEN ANYTHING LAST HEARD FROM IT, and — where the node reported one —
    // the stall that explains a late heartbeat. A blocked event loop cannot
    // heartbeat, so the last stall a node saw is the first thing to look at
    // when its row is close to expiring, and it is the reason `cluster.js`
    // logs `STS-CLUSTER-0025` at all. It is the MOST RECENT stall rather than
    // the worst one, which is what `status()` reports as `lastStallMs` too.
    const seenOf = function (node) {
      const info = node.info || {};
      const stall = Number(info.lastStallMs) || 0;
      return ago(node.heartbeatAt) + (stall
        ? '<br><strong>last stall ' +
          consoleSelf.esc(String(Math.round(stall / 100) / 10)) + 's</strong>'
        : '');
    };

    const leasesCell = function (node) {
      const mine = leasesOf[node.nodeId] || [];
      if (!mine.length) {
        return 'none';
      }
      return mine.map(function (lease) {
        return '<code>' + consoleSelf.esc(lease.name) + '</code> at token ' +
               consoleSelf.esc(String(lease.token));
      }).join('<br>');
    };

    const agreesCell = function (node) {
      if (node.agrees === null) {
        return 'not known here';
      }
      return node.agrees ? 'yes'
        : '<strong>NO</strong> — two nodes with different values answer ' +
          'the same request two ways';
    };

    const liveRows = live.map(function (node) {
      const role = roleOf(node);
      return '<tr><td><strong>' + consoleSelf.esc(node.name) +
        '</strong>' + (node.nodeId === self.nodeId
          ? ' <em>(this node)</em>' : '') +
        '<br><code>' + consoleSelf.esc(node.nodeId) + '</code></td><td>' +
        whereOf(node) + '</td><td><span class="' + role.cls + '">' +
        consoleSelf.esc(role.label) + '</span><br>' +
        consoleSelf.esc(node.mode) + '</td><td>' +
        consoleSelf.esc(node.version || 'unknown') + '</td><td>' +
        upOf(node) + '</td><td>' + seenOf(node) + '</td><td>' +
        ago(node.expiresAt) + '</td><td>' + leasesCell(node) + '</td><td>' +
        agreesCell(node) + '</td></tr>';
    }).join('');

    const goneRows = gone.map(function (node) {
      return '<tr><td><strong>' + consoleSelf.esc(node.name) +
        '</strong><br><code>' + consoleSelf.esc(node.nodeId) +
        '</code></td><td>' + whereOf(node) + '</td><td>' +
        consoleSelf.esc(node.mode) + '</td><td>' +
        consoleSelf.esc(node.version || 'unknown') + '</td><td>' +
        ago(node.startedAt) + '</td><td>' + ago(node.heartbeatAt) +
        '</td><td>' + (node.leftAt
          ? 'left cleanly ' + ago(node.leftAt)
          : '<strong>expired</strong> ' + ago(node.expiresAt)) +
        (node.earlierLives
          ? '<br><span class="sub">and ' +
            consoleSelf.esc(String(node.earlierLives)) +
            ' earlier life/lives under this name</span>'
          : '') +
        '</td></tr>';
    }).join('');

    const goneTable = !gone.length ? ''
      : '<details class="fold"><summary>' + this.esc(String(gone.length)) +
        ' node(s) that have left or expired</summary><div class="foldbody">' +
        '<p>One row per NODE NAME with no running member: a name that is ' +
        'running again is that node restarted, counted on its running row ' +
        'above rather than listed here, and a name that ended several ' +
        'times is shown once, as its latest life.</p>' +
        '<p>A node that stopped cleanly released its leases on the way out, ' +
        'so another member took them over within one heartbeat. A node that ' +
        'EXPIRED did not, and its leases waited out their lifetime — and it ' +
        'is dead for good either way: the heartbeat refuses to renew an ' +
        'expired row, so its process exits rather than come back quietly.</p>' +
        this.wideTable('Nodes that have left or expired',
          '<table><tr><th>Node</th><th>Where</th><th>Mode</th>' +
          '<th>Version</th><th>Started</th><th>Last seen</th><th>Ended</th>' +
          '</tr>' + goneRows + '</table>') + '</div></details>';

    // TWO DIFFERENT REASONS FOR NO LIST, AND THEY MUST NOT SHARE A SENTENCE
    // (2026-09-18). `off` is a fact about the configuration. No `state` on a
    // clustered process is a fact about THIS PROCESS: it has not read the
    // member list yet — a request worker reads it when it attaches and then
    // at most once a heartbeat, and a page drawn in the gap has nothing to
    // show. The first version said "cluster.mode resolved to off" for both,
    // and on testidp, where `/admin` is served by a worker, told somebody
    // looking at a healthy three-node cluster that it was not clustered.
    const noList = off
      ? this.note('There is no membership to list: <code>cluster.mode</code> ' +
                  'resolved to <code>off</code>, so this process is not a ' +
                  'node of anything and writes nothing another node could ' +
                  'fence. What runs here is one container, which is correct ' +
                  'for one container and WRONG for several against one store.')
      : this.note('<strong>This process has not read the member list ' +
                  'yet.</strong> The node is clustered (' +
                  this.esc(self.mode) + '); the ' +
                  (self.role === 'worker' ? 'request worker' : 'process') +
                  ' drawing this page reads the membership from the store ' +
                  'when it starts and then at most once a heartbeat, and ' +
                  'this page was drawn before the first read came back. ' +
                  'Reload it.');
    const nodeTable = '<h2>Members</h2>' + (off || !state
      ? noList
      : '<div class="tiles">' +
        this.tile(live.length, 'running') +
        this.tile(Object.keys(leasesOf).length, 'nodes holding a lease') +
        this.tile(gone.length, 'left or expired') +
        '</div><p>As of ' +
        this.esc(String(Math.round((snap.ageMs || 0) / 100) / 10)) +
        's ago, read at most one heartbeat apart by whichever process drew ' +
        'this page. <strong>Every time below is the database\'s ' +
        'clock</strong>, which a lifetime is measured against — two ' +
        'containers\' clocks differ, and a lease that expires by ' +
        'whoever-is-asking\'s ' +
        'clock is a lease two nodes both hold. <em>Up</em> is the exception: ' +
        'it is the node\'s own process uptime, which no other clock can ' +
        'state.</p>' +
        this.wideTable('Running cluster members',
          '<table><tr><th>Node</th><th>Where</th><th>State</th>' +
          '<th>Version</th><th>Up</th><th>Last seen</th><th>Expires</th>' +
          '<th>Leases</th><th>Settings agree</th></tr>' +
          (liveRows || '<tr><td colspan="9">no live member rows — this ' +
           'node\'s own row arrives on its first heartbeat</td></tr>') +
          '</table>') + goneTable +
        '<h2>Leases</h2><p>A lease is a named role ONE node holds, with a ' +
        'fencing token that goes up every time it changes hands. A released ' +
        'lease is expired and never deleted, so the token never goes back ' +
        'to 1.</p><table><tr><th>Lease</th><th>Holder</th>' +
        '<th>Token</th><th>Expires</th></tr>' +
        (state.leases.length ? state.leases.map(function (lease) {
          const lapsed = lease.expiresAt <= now;
          return '<tr><td><code>' + consoleSelf.esc(lease.name) +
                 '</code></td><td>' +
            consoleSelf.esc(nameOf[lease.holder] || lease.holder) +
            '</td><td>' +
            consoleSelf.esc(String(lease.token)) + '</td><td>' +
            (lapsed ? 'released or expired' : ago(lease.expiresAt)) +
            '</td></tr>';
        }).join('') : '<tr><td colspan="4">none</td></tr>') + '</table>');

    const caps = self.capabilities;
    const capabilityTable = '<h2>What active-active depends on</h2><p>' +
      (caps.ready
        ? 'Every capability is provided' + (caps.acceptedMissing.length
          ? ' or accepted as missing (<code>' +
            this.esc(caps.acceptedMissing.join(', ')) + '</code>)' : '') + '.'
        : '<strong>' + this.esc(String(caps.missing.length)) + ' of ' +
          this.esc(String(caps.rows.length)) + ' are missing</strong>, so ' +
          '<code>cluster.mode=active-active</code> refuses to start. Each is ' +
          'a way two nodes give different answers, described under the ' +
          'section of issue #46 named beside it.') +
      (caps.unknownAccepted.length
        ? ' <strong>cluster.acceptMissingCapabilities names ids this build ' +
          'does not know:</strong> <code>' +
          this.esc(caps.unknownAccepted.join(', ')) + '</code>.' : '') +
      '</p><table><tr><th>Capability</th><th>#46</th><th>State</th>' +
      '<th>What</th><th>Where</th></tr>' +
      caps.rows.map(function (row) {
        return '<tr><td><code>' + consoleSelf.esc(row.id) + '</code></td><td>' +
          consoleSelf.esc(row.section) + '</td><td>' +
          (row.provided ? 'provided'
            : (row.accepted ? '<strong>accepted as missing</strong>'
                            : '<strong>missing</strong>')) + '</td><td>' +
          consoleSelf.esc(row.what) + '</td><td><code>' +
          consoleSelf.esc(row.by) + '</code></td></tr>';
      }).join('') + '</table>';

    const secretTable = '<h2>Shared secrets</h2><table><tr><th>Secret</th>' +
      '<th>Where this process\'s value came from</th><th>What</th></tr>' +
      secrets.secrets.map(function (one) {
        return '<tr><td><code>' + consoleSelf.esc(one.name) +
               '</code></td><td>' +
          consoleSelf.esc(one.source) + '</td><td>' +
          consoleSelf.esc(one.what) + '</td></tr>';
      }).join('') + '</table>';

    const otherCells = this.otherCellsBlock();
    const html = '<h2>Right now</h2>' +
      (off ? this.note('This process is not clustered: ' +
                       '<code>cluster.mode</code> resolved to ' +
                       '<code>off</code>. That is correct for one container ' +
                       'and WRONG for several against one store — see the ' +
                       'first paragraph above.') : '') +
      '<table class="key"><tr><th>What</th><th>Answer</th></tr>' +
      rows.map(function (row) {
        return '<tr><th>' + consoleSelf.esc(row[0]) + '</th><td>' + row[1] +
               '</td></tr>';
      }).join('') + '</table>' + nodeTable + otherCells.html + capabilityTable +
      secretTable;

    log.debug("Leaving AdminConsole.clusterStatusBlock(). mode=" + self.mode);
    return {
      html: html,
      json: { self: self, snapshotAgeMs: snap.ageMs,
              nodes: state ? state.nodes : [],
              // The page's reading of `nodes`, folded by name (rule 7).
              members: state ? {
                running: live.map(function (node) {
                  return node.nodeId;
                }),
                restarts: restarts,
                leftOrExpired: gone.map(function (node) {
                  return { nodeId: node.nodeId, name: node.name,
                           earlierLives: node.earlierLives || 0 };
                })
              } : null,
              leases: state ? state.leases : [],
              databaseNow: state ? state.now : null,
              otherCells: otherCells.json,
              secrets: secrets, barrier: barrier }
    };
  }

  // ===========================================================================
  // THE TWO SECOND-FACTOR PAGES' STATUS BLOCKS (2026-09-10).
  //
  // Each is the `status` member of a row in PROTOCOL_SETTINGS_PAGES below — the
  // same optional function `/admin/persistence` has, and for the same reason it
  // was invented: a settings page describes what this service is CONFIGURED to
  // do, and these two also have to say what the MECHANISM is, which is a
  // different fact. Which digests exist as against which one is in use; which
  // COSE algorithms this relying party can verify as against which two it is
  // offering. **Every table below is READ FROM THE MODULE THAT PERFORMS THE
  // ALGORITHM** — `common/totp.ts`'s `report()` and
  // `authn/webauthn_policy.ts`'s — which is the rule `/admin/crypto-metadata`
  // is built on, one layer down. A page that wrote the list out would describe
  // something this service does not do the first time one was added.
  // ===========================================================================
  /**
   * Describes the TOTP mechanism, read from `totp.report()`, for the TOTP
   * settings page.
   *
   * @returns `html`, the block, and `json`, the report
   */
  totpMechanismBlock() {
    const { log, totp } = this.deps;
    log.debug("Entering AdminConsole.totpMechanismBlock().");
    const info = totp.report();
    // DRAWN BY `web_protocol_settings.ts` (#446) from the JSON this block
    // answers, passed through JSON.
    const html = ProtocolSettingsPage.totpStatus(
      JSON.parse(JSON.stringify(info)));
    return { html: html, json: info };
  }

  // ---------------------------------------------------------------------------
  // THE ATTESTATION POLICY (#105): what `authn/webauthn_attestation.ts` does
  // with a registration's statement, and where its trust anchors come from —
  // this realm's `webauthn.attestationTrustAnchors` and the FIDO Metadata
  // Service BLOB, whose state is read from what this process holds
  // (`risk_datasets.mdsSnapshot()`, since a status block is drawn
  // synchronously). The BLOB is uploaded on Monitoring → Risk and its
  // `/admin-api/risk` twin, where #62 P5 put it; it is not uploaded twice.
  // ---------------------------------------------------------------------------
  // The FIDO Metadata Service's snapshot, for the WebAuthn block's JSON
  // (#446): read here so that its drawing reads only the JSON.
  /**
   * Reads the FIDO Metadata Service snapshot the attestation rows draw.
   *
   * @returns the snapshot, or null when it cannot be read
   */
  attestationMds() {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.attestationMds().");
    let mds = null;
    try {
      mds = require('../risk/risk_datasets').mdsSnapshot();
    } catch (e) {
      log.debug("Caught in AdminConsole.attestationMds(): " +
                ((e && e.message) || e));
      // Drawn as "not read": the policy rows above do not depend on it.
      mds = null;
    }
    log.debug("Leaving AdminConsole.attestationMds().");
    return mds;
  }


  /**
   * Describes the WebAuthn ceremony, read from `webauthnPolicy.report()`,
   * for the WebAuthn settings page.
   *
   * @returns `html`, the block, and `json`, the report
   */
  webauthnMechanismBlock() {
    const { log, webauthnPolicy } = this.deps;
    log.debug("Entering AdminConsole.webauthnMechanismBlock().");
    const info = Object.assign(webauthnPolicy.report(),
                               { mds: this.attestationMds() });
    // DRAWN BY `web_protocol_settings.ts` (#446) from the JSON this block
    // answers, passed through JSON.
    const html = ProtocolSettingsPage.webauthnStatus(
      JSON.parse(JSON.stringify(info)));
    return { html: html, json: info };
  }

  // ---------------------------------------------------------------------------
  // THE RECOVERY CODE MECHANISM, for `/admin/backup-codes` (2026-09-10).
  //
  // Read from `common/backup_codes.ts` — the module that generates and compares
  // a code — rather than written down here, which is the design every `status`
  // block on this page follows: the table lives with the code that performs the
  // thing, so this cannot describe something the service does not do.
  //
  // **IT IS THE ONE BLOCK HERE WITH NO SPECIFICATION COLUMN**, because there is
  // no specification. Everything in it is a decision this service made, and the
  // page says which decision and why rather than citing a document.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // WHAT THE KDC DOES ABOUT PRE-AUTHENTICATION, IN THIS REALM (#173,
  // 2026-09-22) — the `status` member of `/admin/kerberos`, and so of
  // `GET /admin-api/kerberos` (rule 7). Whether a password alone gets a
  // two-factor account a ticket is `global.mode`'s answer
  // (`mode.issuesTicketsOnPasswordAlone()`), and it is drawn here rather than
  // left to the mode page because it is the KDC's behaviour somebody comes to
  // this page to find. The FAST provider is `kerberos/krb5_fast.ts`, reached
  // through the principal database's key source; a process without the
  // directory has none, and says so.
  // ---------------------------------------------------------------------------
  /**
   * Describes what the KDC does about pre-authentication in this realm:
   * whether a password alone gets a two-factor account a ticket, the FAST
   * provider's policy and the krbtgt keys.
   *
   * @returns `html`, the block for /admin/kerberos, and `json`, the facts
   */
  kerberosPreauthStatusBlock() {
    const { log, mode } = this.deps;
    log.debug("Entering AdminConsole.kerberosPreauthStatusBlock().");
    const provider = krb5Principals.preauthProvider();
    const refuses = !mode.issuesTicketsOnPasswordAlone();
    const base = provider ? provider.policy() : {
      fast: false,
      passwordAloneForSecondFactorAccounts: refuses ? 'refused' : 'accepted',
      note: 'no FAST provider is installed in this process (it arrives with ' +
            'the directory), so FAST and OTP pre-authentication are not ' +
            'offered'
    };
    // THE KRBTGT KEY (#169): its kvno, last rotation and next scheduled one,
    // drawn here as well as on Principals (where its controls are) because
    // it is the KDC's state somebody comes to this page to find. Read
    // lazily: the view lives in `admin-core/`, loaded after this file.
    let krbtgt: any = null;
    try {
      krbtgt = krb5Principals.kerberosRealmOf().enabled
        ? require('../admin-core/admin_views').krbtgtView() : null;
    } catch (e) {
      log.debug("Caught in AdminConsole.kerberosPreauthStatusBlock(): " +
                ((e && e.message) || e));
      krbtgt = null;
    }
    // PKINIT (#179): a certificate as the pre-authentication, and anonymous
    // PKINIT as FAST armor — `kerberos/krb5_pkinit.ts`'s policy().
    const pkinitProvider = krb5Principals.pkinitProvider();
    const pkinit = pkinitProvider ? pkinitProvider.policy() : null;
    // THE BLOCK'S JSON FIRST (#446), and the drawing from it alone.
    const info = Object.assign({ passwordAloneRefused: refuses }, base,
                               { krbtgt: krbtgt, pkinit: pkinit });
    // DRAWN BY `web_protocol_settings.ts` (#446) from the JSON this block
    // answers, passed through JSON.
    const html = ProtocolSettingsPage.kerberosPreauthStatus(
      JSON.parse(JSON.stringify(info)));
    return { html: html, json: info };
  }

  /**
   * Describes the recovery code mechanism, read from
   * `backupCodes.report()`, for /admin/backup-codes. It never shows a code.
   *
   * @returns `html`, the block, and `json`, the report
   */
  backupCodesMechanismBlock() {
    const { log, backupCodes } = this.deps;
    log.debug("Entering AdminConsole.backupCodesMechanismBlock().");
    const info = backupCodes.report();
    // DRAWN BY `web_protocol_settings.ts` (#446) from the JSON this block
    // answers, passed through JSON.
    const html = ProtocolSettingsPage.backupCodesStatus(
      JSON.parse(JSON.stringify(info)));
    return { html: html, json: info };
  }

  // What one of these pages answers over `?format=json`, and what the
  // management API mirrors. The settings are `configSettingsJson()` — the same
  // described rows the form is drawn from — and the rest is what the page SAYS,
  // in the text it says it in: a caller driving this console without a browser
  // should be able to read the caveats too, since on these pages the caveats
  // are most of the content.
  /**
   * Builds what a protocol settings page answers as JSON: its prose as
   * plain text, its links, its settings, and its status block's JSON when
   * the row has one.
   *
   * @param row - the page's row of PROTOCOL_SETTINGS_PAGES
   * @returns the page's JSON
   */
  protocolSettingsJson(row) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.protocolSettingsJson(). path=" + row.path);
    const json: Record<string, any> = {
      page: row.path,
      title: row.title,
      what: this.plainTextOf(row.lead),
      notes: (row.also || []).map(this.plainTextOf.bind(this)),
      links: (row.links || []).map(function (link) {
        return { href: link[0], what: link[1] };
      }),
      settings: this.configSettingsJson(row.path),
      // THE SAME PROSE AS MARKUP (#446): `what` and `notes` are its plain
      // text for a reader of the JSON, and a page drawn from this answer
      // draws the lead and the warnings as this console wrote them.
      leadHtml: row.lead,
      alsoHtml: (row.also || []).slice()
    };
    // ONE OPTIONAL MEMBER, invented for `/admin/persistence` and carried by
    // five rows now (persistence, cluster and the three second-factor mechanism
    // pages). A settings page describes what this service is CONFIGURED to do;
    // `/admin/persistence` also has to say what it is ACTUALLY doing right now
    // — which store is open, whether the last write worked, how much is in it —
    // because a persistence setting that is set and a persistence store that is
    // working are two different facts and the gap between them is the whole
    // failure mode. It is a function on the row rather than a second kind of
    // page, so the JSON and the HTML stay one thing. See
    // `persistenceStatusBlock()`.
    if (typeof row.status === 'function') {
      json.status = row.status().json;
    }
    log.debug("Leaving AdminConsole.protocolSettingsJson(). " +
              json.settings.settingCount +
              " setting(s).");
    return json;
  }


  // What `mgmt-api/admin_api.ts` calls for each of these. It takes the PATH
  // rather than an index or a title, because that is what SETTING_HOMES and NAV
  // are keyed by and it is what the API's own route already carries.
  /**
   * Builds the JSON of the protocol settings page at a path, for
   * mgmt-api/admin_api.ts.
   *
   * @param path - the page's console path
   * @returns the page's JSON
   * @throws Error when no protocol settings page has that path
   */
  protocolSettingsJsonFor(path) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.protocolSettingsJsonFor().");
    const row = PROTOCOL_SETTINGS_PAGES.filter(function (item) {
      return item.path === path;
    })[0];
    if (!row) {
      // A caller asking for a page this table does not have is a wiring mistake
      // in this repository rather than anything a request can cause, so it
      // throws rather than answering an empty object that would read as "this
      // family has no settings".
      throw new Error('No protocol settings page at ' + path + '.');
    }
    log.debug("Leaving AdminConsole.protocolSettingsJsonFor().");
    return this.protocolSettingsJson(row);
  }

  /**
   * `protocolSettingsJsonFor()` after the row's `prepare` step, for a page
   * whose status block draws something asynchronous (the Cluster page's
   * other cells, #361). A failed step is the block's to report.
   *
   * @param path - the page's console path
   * @returns a promise of the page's JSON
   */
  preparedSettingsJsonFor(path) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.preparedSettingsJsonFor().");
    const row = PROTOCOL_SETTINGS_PAGES.filter(function (item) {
      return item.path === path;
    })[0];
    const ready = row && typeof row.prepare === 'function'
      ? Promise.resolve().then(function () {
        return row.prepare();
      }).catch(function (e) {
        log.debug("Caught in AdminConsole.preparedSettingsJsonFor(): " +
                  ((e && e.message) || e));
      })
      : Promise.resolve();
    log.debug("Leaving AdminConsole.preparedSettingsJsonFor().");
    return ready.then(function () {
      return self.protocolSettingsJsonFor(path);
    });
  }

  /**
   * The Cluster page's `prepare` (#361): asks every other cell for its
   * cluster summary, for `clusterStatusBlock()` to draw. Single-cell
   * mode asks nothing.
   *
   * @returns a promise settled when the answers (or failures) are held
   */
  prepareClusterPage() {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.prepareClusterPage().");
    const cells = require('../common/cells');
    if (!cells.isMulti()) {
      self.peerClustersNow = null;
      log.debug("Leaving AdminConsole.prepareClusterPage(). Single cell.");
      return Promise.resolve();
    }
    // A LAZY require: cells_admin draws with this module's shell, so it is
    // loaded by the time any page is asked for, and a load-time require
    // would close that cycle.
    const cellsAdmin = require('./cells_admin');
    log.debug("Leaving AdminConsole.prepareClusterPage().");
    return Promise.resolve(cellsAdmin.peerClusters()).then(function (rows) {
      self.peerClustersNow = { at: Date.now(), rows: rows || [] };
    }, function (e) {
      log.debug("Caught in AdminConsole.prepareClusterPage(): " +
                ((e && e.message) || e));
      self.peerClustersNow = { at: Date.now(), rows: [],
                               error: String((e && e.message) || e) };
    });
  }

  // ---------------------------------------------------------------------------
  // /admin/spiffe, /admin/spiffe/entries, /admin/spiffe/agents — THE SPIFFE
  // SECTION.
  //
  // Three pages rather than one, and the split is by what the reader is doing
  // rather than by what the data is:
  //
  //   /admin/spiffe           the TRUST DOMAIN — its authorities, the bundle,
  //                           the four gRPC listeners, the federated bundles.
  //                           The forms here rotate an authority and set or
  //                           remove a federated bundle.
  //   /admin/spiffe/entries   the REGISTRATION ENTRIES: a list with a filter
  // and
  //                           paging, a drill-down per entry, and the forms
  //                           that create, change and delete one.
  //   /admin/spiffe/agents    the ATTESTED AGENTS: the same shape, and the
  // forms
  //                           ban, unban and delete.
  //
  // **The second and third are separate sections rather than drill-downs**,
  // which is why each has its own NAV row and its own LIST_PARAMS whitelist. A
  // drill-down's section crumb points at the list it came from, and an entries
  // list hanging under /admin/spiffe would make the crumb point at a page that
  // does not hold that list — the exact defect rule 7a describes.
  //
  // **THIS PAGE DECIDES NOTHING.** Every form posts to an action function that
  // calls into `spiffe_registry.js` or `spiffe_ca.js` — the same functions the
  // SPIRE Server API's `BatchCreateEntry`, `BanAgent` and
  // `BatchSetFederatedBundle` call, and the same store an `ldapmodify` under
  // `ou=spiffe` writes to. Three doors, one store, which is the one-store rule
  // this service already applies to revocation, to the applications registry
  // and to SCIM.
  //
  // **AND IT SAYS, ON EVERY PAGE, THAT NOTHING IS ATTESTED.** A console that
  // listed registration entries beside the tokens page without saying so would
  // let somebody conclude that a selector on an entry restricts who can get
  // that identity. Nothing here restricts anything: any caller that reaches the
  // Workload API socket is handed every identity in the trust domain.
  // ---------------------------------------------------------------------------

  // Drawn by `web_federation.ts` (#446).
  /**
   * Draws the links at the foot of the federation pages.
   *
   * @param base - the federation index's path (`federation.PATHS.base`)
   * @returns the links as HTML
   */
  federationLinks(base) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.federationLinks().");
    log.debug("Leaving AdminConsole.federationLinks().");
    return FederationPage.federationLinks(base);
  }

  // Drawn by `web_federation.ts` (#446).
  /**
   * Reads a boolean attribute as the federation register reads it.
   *
   * @param value - the attribute's value, as stored
   * @param dflt - what an absent or unreadable value means
   * @returns the boolean
   */
  boolOf(value, dflt) {
    const { log } = this.deps;
    log.debug("Entering AdminConsole.boolOf().");
    log.debug("Leaving AdminConsole.boolOf().");
    return FederationPage.boolOf(value, dflt);
  }

  // ---------------------------------------------------------------------------
  // GET /admin/federation/map — THE SAME REGISTER, AS A PICTURE.
  //
  // `/admin/federation` above is a table: one row per relationship, each row a
  // complete description of one arrangement and none of them saying anything
  // about the others. That is the right shape for CONFIGURING a partner and the
  // wrong shape for three questions an operator actually arrives with, all of
  // which are facts about two registers at once and none of which a row has
  // anywhere to put:
  //
  //   * HOW MANY APPLICATIONS ARE BEHIND THIS PARTNER, and which. It is
  //     `appFederationRelationship` on entries under `ou=applications` pointing
  //     BACK at a relationship, so the relationship's own entry has never
  //     known.
  //   * HOW MANY PEOPLE HAVE ACTUALLY COME THROUGH IT, PER APPLICATION.
  //     `fedAuthentications` has always answered the first half; the split by
  //     application is `fedApplicationUse`, which exists because a partner
  //     shared by two applications makes one number into two different
  //     questions.
  //   * WHAT HAPPENS TO SOMEBODY WHO ARRIVES AT THE IDENTITY-PROVIDER SIDE —
  //     `fedAuthnMechanism`, and the onward relationship when it says
  //     `federation`. A table can print the attribute; only a picture can show
  //     that the onward relationship is the one two rows down and that the two
  //     together are a BRIDGE.
  //
  // THE PICTURE IS OF ONE TRUST REALM, which is the console's rule everywhere
  // and is a real constraint here rather than a convention followed for
  // tidiness: the register is per realm, an id that names a relationship in
  // another realm names nothing here, and the realm switcher at the top of the
  // page is how you get to the other one. The hexagon carries the realm for the
  // same reason — a saved `?format=svg` document with no realm on it is a
  // picture of somewhere.
  //
  // IT IS DRAWN ON THE SERVER, and that is the root CLAUDE.md's second CSP rule
  // being honoured rather than argued again: `federation_diagram.js`'s header
  // makes the case in full. Nothing here relaxes `script-src 'none'`, which is
  // why the picture does not pan or zoom — the page says so out loud below
  // rather than leaving somebody to wonder why dragging does nothing, and
  // `?format=svg` hands over a document for something that does zoom.
  // ---------------------------------------------------------------------------

  // THE ROUTES, registered in the order they always were: the composition
  // root (`common/protocol_stack.ts`) calls this through the export at the
  // foot of the file, at 18, where requiring this module used to register
  // them (#50, R1) — the file header says why the transitional call sat where
  // the LAST of them was rather than the first — so the route order is
  // unchanged (rule 1).
  /**
   * Registers the console's routes and middleware on the shared app; called
   * by common/protocol_stack.ts, where the route order is kept (rule 1).
   *
   * @param app - the shared express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, oidcRp, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AdminConsole.registerRoutes().");
    // -------------------------------------------------------------------------
    // THE STATIC CONSOLE (#446, the cutover). FIRST, ABOVE EVERYTHING ELSE
    // UNDER /admin, because it answers ALL of it.
    //
    // The console is a static application since #446: `/admin` and every
    // path under it answer the SAME document — the shell, which loads
    // `/admin/console.js` (`web_runtime.ts`) and `/admin/console.css` (this
    // console's one stylesheet, `stylesheet()`) — and the runtime signs in
    // as the public client, fetches each page's answer from `/admin-api`
    // and draws it in the browser. The path still names the page (a deep
    // link, the history), but it is the BROWSER that reads it.
    //
    // So nothing here is gated: the shell is public, carries nothing, and
    // every fact the console shows arrives from `/admin-api` behind the API's
    // own token check, which is the only gate there is. A method other than
    // GET under /admin is answered 404: the console's acts are the API's
    // operations, and a form post here is something that has not moved.
    //
    // Registered first, the routes below it — the server-rendered pages,
    // their gate, the relying-party session, CSRF — are no longer reachable,
    // and they go in the commits that follow this one.
    // -------------------------------------------------------------------------
    app.get('/admin/console.js', function (req, res) {
      log.debug("Entering the static console's script.");
      res.set('Cache-Control', 'no-cache')
         .type('application/javascript').send(self.consoleScript());
      log.debug("Leaving the static console's script.");
    });
    app.get('/admin/console.css', function (req, res) {
      log.debug("Entering the static console's stylesheet.");
      res.set('Cache-Control', 'no-cache').type('text/css')
         .send(self.stylesheet());
      log.debug("Leaving the static console's stylesheet.");
    });
    // ONE HANDLER, ON TWO PATHS — `/admin` itself and everything under it —
    // registered apart so that the router lists each by its own name.
    const shell = function (req, res, next) {
      log.debug("Entering the static console shell. " + req.method + " " +
                req.path);
      // The explorer's own script is a file of its own, loaded by the
      // runtime once the explorer is drawn (`web_explorer.ts`).
      if (req.method === 'GET' && req.path === '/admin/api-explorer/explorer.js') {
        log.debug("Leaving the static console shell. The explorer's script.");
        next();
        return;
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        errorCodes.mark(res, 'STS-ADMIN-0843');
        res.status(404).type('text/plain').set('Cache-Control', 'no-store')
           .send('The admin console is a static application: what it does ' +
                 'is done through /admin-api, and nothing is posted here.');
        log.debug("Leaving the static console shell. Not a GET.");
        return;
      }
      // WHICH REALM FIRST (2026-09-14, #32), for a bare /admin on a service
      // with realms defined, as the console's gate asked before the cutover:
      // `common/realm_chooser.ts` says when, a choice is a redirect to that
      // realm's own console, and `?realm=default` is the default realm's.
      // The chooser is a page of the server's — a list of realms and a form,
      // no script — and it carries nothing a token guards.
      //
      // ASKED ONLY OF A BROWSER SIGNED IN NOWHERE, as the gate asked only
      // one with no console session: a browser that already holds a sign-on
      // session here has answered the question, and a reload of `/admin`
      // should draw the console rather than ask again.
      const signedIn = !!authn.sessionOf(req);
      const choice = signedIn ? null : loginRealmChooser.decide(req, 'admin');
      if (choice && choice.kind === 'redirect') {
        res.set('Cache-Control', 'no-store').redirect(303, choice.location);
        log.debug("Leaving the static console shell. To the chosen realm.");
        return;
      }
      if (choice && choice.kind === 'page') {
        if (choice.error) {
          errorCodes.mark(res, 'STS-ADMIN-0790');
        }
        res.status(choice.error ? 400 : 200)
           .set('Cache-Control', 'no-store')
           .type('text/html').send(self.page('Choose your realm', null,
             '<div class="card"><h2>Choose your realm</h2>' +
             loginRealmChooser.form(req, 'admin', choice.error) + '</div>',
             null, null, req));
        log.debug("Leaving the static console shell. The realm chooser.");
        return;
      }
      // The callback is the address a sign-in comes back to: registered on
      // the console's client entry the way the relying party registered it,
      // in the realm the request is under.
      const registered = oidcRp.ensureConsoleCallback(req);
      res.set('Content-Security-Policy', app.contentSecurityPolicy({
        'script-src': "'self'",
        'connect-src': "'self'",
        'style-src': "'self' 'unsafe-inline'"
      }));
      res.status(200).type('text/html').set('Cache-Control', 'no-store')
         .send(self.shellDocument(registered));
      log.debug("Leaving the static console shell.");
    };
    // GET (and with it HEAD) for the document, and the methods a form or a
    // script could send for the refusal — named one by one rather than
    // through `app.all()`, which the router reports as EVERY method,
    // CONNECT and TRACE among them, so `/admin/sts-metadata` listed methods
    // nothing could call.
    ['get', 'post', 'put', 'patch', 'delete'].forEach(function (method) {
      app[method]('/admin', shell);
      app[method]('/admin/*', shell);
    });
    log.debug("Leaving AdminConsole.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`, which runs `AdminConsole.wire()`. Every name this
// module exports that the instance answers is a FACADE that forwards to it,
// for the JavaScript that still calls this module through `require()`; a
// process that never runs the root gets a default instance, built from
// `defaultDeps()` (see `common/instance_slot.ts`).
//
// `WIRE_STEPS` is the work loading this module used to do with its own
// instance — the sidebar's flattening, the setting-homes check, the module
// constants drawn with `note()` and `warn()`, and the read layer's settings
// block. Each step stays beside the declaration it fills, and
// `AdminConsole.wire()` runs them in the order they are written, once, for
// whichever instance is installed.
// ---------------------------------------------------------------------------
const WIRE_STEPS: Array<(instance: AdminConsole) => void> = [];

const slot = new InstanceSlot<AdminConsole>(
  'admin-ui/admin',
  () => new AdminConsole(AdminConsole.defaultDeps()),
  AdminConsole.wire,
  log);

// Every page in every section, flattened, with the section it belongs to on
// each row. Derived rather than typed for the reason above; the `section`
// member is what lets the sidebar bold the right heading without a second
// lookup. A page inside a group is flattened to the same shape as one outside
// it, so nothing downstream of here can tell them apart.
const NAV = [];
WIRE_STEPS.push(function (instance: AdminConsole): void {
  SECTIONS.forEach(function (section) {
    instance.sectionPages(section).forEach(function (item) {
      NAV.push({ path: item.path, label: item.label, section: section.title });
    });
  });
});

// ---------------------------------------------------------------------------
// WHICH PAGE OWNS WHICH SETTINGS, AND THE ONE TABLE THAT DECIDES IT.
//
// Until 2026-08-27 every one of `config.js`'s settings was drawn on
// `/admin/config` and nowhere else, and each protocol page that cared about
// its own — `/admin/saml2`, `/admin/saml11`, `/admin/scim` — showed them as
// READINGS with a link to that page, saying in three different sets of words
// that the configuration page owned them. That was one page of a hundred and
// fifty-four rows: somebody who came to the console to change the Kerberos
// realm found the Kerberos page, read what a ticket carries, and was then sent
// somewhere else to type it.
//
// So the settings moved to the page for the protocol they configure, and this
// table is the whole of the mapping. Four rules about it, and each is the
// reason the table exists rather than the placements being spread over twenty
// route handlers:
//
//   * **A GROUP HAS EXACTLY ONE ROW HERE AND A ROW MAY NAME MORE THAN ONE
//     PAGE.** `config.js`'s `group` is the unit — it is already the thing the
//     table declares, the thing `config.groups()` buckets by and the thing a
//     reader looking for "the Kerberos settings" is thinking of — so a page
//     never names individual keys. A page that wanted half a group would be
//     asking for the group to be split in `config.js`, where the reasoning for
//     what belongs together lives.
//   * **`SAML` IS THE ONE ROW WITH TWO PAGES, and it is not an untidiness.**
//     `saml.issuer` is the Issuer of every assertion this service builds — SAML
//     2.0's, SAML 1.1's, and WS-Federation's, which are built by the same two
//     functions — so there is no one page it belongs to. It is drawn on both
//     SAML pages, each form writing through `config.setOverride()` like every
//     other, and `configFormsFor()` says so on both rather than letting a
//     reader discover that the value they set on one page had appeared on the
//     other. The WS-Federation page names it too, as a link: three forms onto
//     one setting is where "shown in more than one place" stops being useful.
//   * **THE PAGE IS NOT A SECOND STORE, which is what makes any of this
//     allowed.** Every form these pages draw is `configSection()`, posting
//     `set-many` to `POST /admin/config` — the same action function, the same
//     override map, the same validation — with a hidden `from` naming the page
//     to come back to. That is the rule `/admin/token-lifetimes` argued when it
//     took four of these rows onto a page of its own: a second DOOR onto one
//     value is fine and a second PLACE THE VALUE LIVES is not.
//   * **DRIFT IS CHECKED AT STARTUP, not trusted.** A group added to
//     `config.js` with no row here would silently stop being editable anywhere
//     — the settings would exist, answer on `GET /admin-api/config`, and appear
//     on no page at all. `checkSettingHomes()` below refuses to let that be
//     quiet: it logs, and `/admin/config` shows it in the same spirit as
//     `/admin/sts-metadata` reporting a route nobody described.
//
// The pages named here are ordinary console pages and every one of them is in
// SECTIONS above. Eight of them were created for this: the OAuth2 / OIDC,
// OpenID4VCI, OpenID4VP, WS-Trust, WS-Federation, Kerberos, LDAP / LDAPS and
// TLS families had settings and no page, which is exactly the gap that made
// them invisible on a console organised by protocol.
const SETTING_HOMES = [
  // The one group with no protocol to belong to, and the reason /admin/config
  // still has a form on it. A bind address and a log level are facts about the
  // PROCESS; there is no family whose page they would be less surprising on.
  { group: 'Global', pages: ['/admin/config'] },

  // KEY MATERIAL lives on /admin/config for the same reason Global does: where
  // this service's signing keys come from and what encrypts them at rest are
  // facts about the PROCESS, not about any one protocol — every family here
  // signs with the same key.
  { group: 'Key material', pages: ['/admin/config'] },
  // WEB SECURITY, on /admin/config for the same reason: a rate limit and a
  // CSRF scheme are facts about the PROCESS and every browser-facing surface
  // shares them.
  { group: 'Web security', pages: ['/admin/config'] },

  { group: 'Trust realms', pages: ['/admin/realms'] },
  { group: 'OAuth 2.0 / OIDC', pages: ['/admin/oauth2'] },
  { group: 'Admin console', pages: ['/admin/rbac'] },
  // The embedded protocol debugger's rows are drawn on its own page, which is
  // also where its listener and api process are reported: a setting like
  // `debugger.port` beside the port it actually bound is the one reading that
  // answers "why is it not where I set it".
  { group: 'Protocol debugger', pages: ['/admin/debugger'] },
  // THE MANAGEMENT API'S THREE SETTINGS SIT BESIDE THE CONSOLE'S, and that is
  // an argument rather than a convenience. /admin/rbac is the page that
  // answers "who may reach the administrative surfaces of this service"; the
  // console's half of that answer has always been drawn there, and since
  // 2026-09-08 /admin-api has a half of its own — whether it demands a token
  // at all, which audience that token must carry, and the secret its client
  // authenticates with. A page of its own would have split one question across
  // two screens, and /admin/config was wrong for the reason its own comment
  // gives: these are not facts about the PROCESS, they are the access policy
  // of one named surface.
  //
  // `adminApi.clientSecret` is drawn here as a SECRET, so the page shows
  // whether one is set and never the value. That matters more here than
  // anywhere else in this table: it is the credential that mints the token
  // this very console's gate would otherwise be the only way to obtain.
  { group: 'Management API', pages: ['/admin/rbac'] },
  { group: 'Applications', pages: ['/admin/applications'] },
  { group: 'Federation', pages: ['/admin/federation'] },
  { group: 'OpenID Federation', pages: ['/admin/oidfed'] },
  { group: 'XACML', pages: ['/admin/xacml'] },
  // THE CERTIFICATE AUTHORITY'S FOUR SETTINGS, on the page that builds one.
  // They are DEFAULTS FOR A FORM rather than a policy — what a hierarchy was
  // built with is stored on the hierarchy — so the page that takes each of
  // them as a field is the only place they read as anything but trivia.
  { group: 'PKI', pages: ['/admin/pki'] },
  // Two pages, deliberately. See the header above.
  { group: 'SAML', pages: ['/admin/saml2', '/admin/saml11'] },
  { group: 'SAML 2.0', pages: ['/admin/saml2'] },
  { group: 'SAML 1.1', pages: ['/admin/saml11'] },
  // THE TEN THAT BECAME PER-APPLICATION DEFAULTS ON 2026-08-27, and the two
  // groups exist to say exactly that. Every one of them was a `SAML 2.0` or
  // `SAML 1.1` row drawn on that profile's identity provider page, and every
  // one is now the DEFAULT an application inherits when its own entry says
  // nothing — `saml2AssertionLifetimeMin` and its nine siblings on the entry
  // win where they are set. They are off the two identity provider pages
  // because those pages configure THIS SERVICE as an identity provider, and
  // these ten no longer describe what it does: they describe what it does for
  // an application that has not been told otherwise. `/admin/applications` is
  // where the exception is typed.
  //
  // The pages here are what makes them leave those two screens: a group is
  // drawn where its row says and nowhere else, so moving the rows moved the
  // settings. Nothing about the KEYS or their environment variables changed,
  // which is what keeps every appconfig file and every `STS_SAML*` variable
  // working exactly as it did.
  { group: 'SAML 2.0 assertions', pages: ['/admin/saml-assertions'] },
  { group: 'SAML 1.1 assertions', pages: ['/admin/saml-assertions'] },
  // WS-FEDERATION'S ONE ASSERTION SETTING IS DRAWN WITH THE SAML ONES, and
  // that is not a filing error. A WS-Federation sign-in response CARRIES a
  // SAML 1.1 assertion, built by the same function the SAML 1.1 profiles use,
  // so this row governs the same kind of document as the ten above it. Drawing
  // it on /admin/wsfed would have put the only setting that decides how long a
  // WS-Federation token lives on a different page from every other assertion
  // lifetime in this service. `wsfed.entityId` stays over there because it is
  // this service's own name and no application can have an opinion about it.
  { group: 'WS-Federation assertions', pages: ['/admin/saml-assertions'] },
  // THE FIVE OAUTH SETTINGS A CLIENT MAY ANSWER FOR ITSELF, on the page that
  // already drew three of them. /admin/token-lifetimes was a bespoke page
  // naming its four keys and had no row here at all; it has one now because
  // these five had to LEAVE /admin/oauth2, and a group leaves a page by being
  // homed on another. The four global oauth2 rows — the issuer, RFC 9700 mode
  // and the two clock skews — stay in the `OAuth 2.0 / OIDC` group and stay
  // over there.
  { group: 'OAuth 2.0 / OIDC per-client', pages: ['/admin/token-lifetimes'] },
  { group: 'WS-Trust', pages: ['/admin/wstrust'] },
  { group: 'WS-Federation', pages: ['/admin/wsfed'] },
  // THE LISTENERS PAGE (#423, rcbj: "Put all the listener configuration,
  // including TLS on its own page under Server Settings->Listeners"): the
  // TLS group moved here from /admin/tls, which keeps the truststore and the
  // certificate, and so did the realm listener's rows (#99).
  { group: 'Listeners', pages: ['/admin/listeners'] },
  // ONE GROUP PER TLS LISTENER (#429): its own rows, generated in
  // common/config.js, and its client-certificate pair.
  { group: 'Listener: Main port', pages: ['/admin/listeners'] },
  { group: 'Listener: LDAPS', pages: ['/admin/listeners'] },
  { group: 'Listener: Protocol debugger', pages: ['/admin/listeners'] },
  { group: 'Listener: SPIRE Server API', pages: ['/admin/listeners'] },
  { group: 'Listener: SPIFFE Broker API', pages: ['/admin/listeners'] },
  { group: 'Listener: Channel between cells', pages: ['/admin/listeners'] },
  { group: 'Listener: Revocation (plain HTTP)', pages: ['/admin/listeners'] },
  // HTTP connection pooling's service-wide defaults (#429), on the
  // Service-wide defaults tab beside the TLS ones.
  { group: 'HTTP connections', pages: ['/admin/listeners'] },
  { group: 'TLS', pages: ['/admin/listeners'] },
  // A trust realm's own listener (#99): realm-only settings, edited on the
  // Listeners page read inside a realm (#423); the default realm refuses
  // them (STS-CORE-0145).
  { group: 'Realm listener', pages: ['/admin/listeners'] },
  { group: 'OID4VCI', pages: ['/admin/oid4vci'] },
  { group: 'OID4VP', pages: ['/admin/oid4vp'] },
  { group: 'Kerberos', pages: ['/admin/kerberos'] },
  { group: 'LDAP', pages: ['/admin/ldap'] },
  // A page of its own rather than a section of /admin/ldap, and the reason is
  // that these six settings are not about the directory. They decide whether
  // the TRUST REALM REGISTRY and the RUNTIME SETTING CHANGES are written down
  // as well — two things that have nothing to do with LDAP — and one of the
  // three modes involves no directory format at all. Putting them under
  // LDAP / LDAPS would have told a reader looking for "does my realm survive a
  // restart" to look at the wrong page.
  { group: 'Persistence', pages: ['/admin/persistence'] },
  // THE CLUSTER'S SETTINGS (2026-09-14, #46), on the page that shows the
  // members, the leases and the capabilities those settings decide about —
  // `cluster.acceptMissingCapabilities` read anywhere but beside the list of
  // what is missing would be a list of ids with no meaning.
  { group: 'Cluster', pages: ['/admin/cluster'] },
  // THE CELLS' SETTINGS (#98), on the page that shows the cell map they
  // configure and the realm's transfer choices they decide about.
  { group: 'Cells', pages: ['/admin/cells'] },
  // SIGNER ROTATION (2026-09-22, #42/#48), on /admin/keys — the page that
  // shows every unit's current, next and retired keys and carries the
  // Rotate controls (rcbj's D5).
  { group: 'Signing keys', pages: ['/admin/keys'] },
  // THE SCHEDULER'S SETTINGS (2026-09-22, #49), on the page that shows the
  // jobs they switch and the ticks they time.
  { group: 'Scheduler', pages: ['/admin/scheduler'] },
  { group: 'Mail', pages: ['/admin/mail'] },
  { group: 'Attribute sources', pages: ['/admin/attribute-sources'] },
  // THE DEVICE REGISTER'S BOUNDS (#218): on the page that says how a device
  // arrives, beside the enrolment methods those bounds limit.
  { group: 'Devices', pages: ['/admin/device-registration'] },
  { group: 'SCIM', pages: ['/admin/scim'] },
  // Shared Signals. A page of its own rather than a section of anything, for
  // the reason /admin/federation is ungrouped: SSF is not a variant of another
  // family here, it is the one that runs the other way round — this service
  // delivering an event to somebody who agreed to be told. A group of one
  // would be a heading that said the label twice.
  { group: 'SSF', pages: ['/admin/ssf'] },
  // CAEP. Its own group and its own page, for the reason the sidebar entry
  // gives: a vocabulary over SSF is a second specification and not a corner
  // of the first. The MONITORING page beneath it edits nothing, so it is not
  // named here — this table is about where a setting is EDITED.
  { group: 'CAEP', pages: ['/admin/caep'] },
  // RISK SCORING (#62): its datasets and failure history, on the Monitoring
  // page that shows them, because there is no protocol for them to belong to.
  { group: 'Risk', pages: ['/admin/risk'] },
  // RISC, on the CAEP group's terms: the second vocabulary over SSF is a
  // second specification and not a corner of the first, and the MONITORING
  // page beneath it edits nothing so it is not named here.
  { group: 'RISC', pages: ['/admin/risc'] },
  // The claim itself is an OAuth2/OIDC and SAML concern, but what it NAMES is a
  // directory group and what decides whether somebody is in one is the Groups
  // page. Somebody asking "why is this group not in my token" is looking at
  // that page's membership table when the question occurs to them.
  // Roles. Its own group and its own page: what these four settings configure
  // is the claim and whether the decision is asked for at all, and both halves
  // of a role — who holds one, and what requires one — are edited on that page
  // and on an application's page respectively rather than in a setting.
  { group: 'Roles', pages: ['/admin/roles'] },
  // THE TWO SECOND FACTORS, ONE GROUP AND ONE PAGE EACH, BOTH UNDER PROTOCOLS
  // (2026-09-10).
  //
  // **THIS WAS ONE ROW READING `Multi-factor authentication` -> `/admin/mfa`,
  // AND ITS COMMENT ARGUED FOR FILING IT UNDER IDENTITIES** — because the page
  // answered *who holds a second factor*, which is a question about people.
  // That was right about the ROSTER and wrong about the SETTINGS, and one page
  // could not be filed by both halves at once. The roster is columns on
  // /admin/users now; these two rows are the mechanisms.
  //
  // The old comment also said WebAuthn "has no settings at all and so has no
  // row here". It has had settings since 2026-09-10 — every parameter of the
  // ceremony, which had been literals in a string in `authn/authn.ts` — and
  // the attestation policy's seven since #105.
  { group: 'TOTP MFA', pages: ['/admin/totp'] },
  { group: 'GNAP', pages: ['/admin/gnap'] },
  // ===== certificate enrollment setting homes (2026-09-13) =====
  { group: 'ACME', pages: ['/admin/acme'] },
  { group: 'EST', pages: ['/admin/est'] },
  { group: 'SCEP', pages: ['/admin/scep'] },
  { group: 'WebAuthn', pages: ['/admin/webauthn'] },
  // THE THIRD (2026-09-10), and it is a mechanism like the two above it rather
  // than a policy about them — which is why it gets a group and a page of its
  // own instead of four more rows on the TOTP page. A recovery code stands in
  // for EITHER of those two, so filing its settings under one of them would
  // put them where half the readers would not look.
  { group: 'Backup codes', pages: ['/admin/backup-codes'] },
  // A POLICY ABOUT THE TWO MECHANISMS ABOVE (2026-09-13), and drawn on BOTH of
  // their pages — `saml.issuer`'s arrangement — because either one satisfies
  // it and a reader of either page must see that it is in force.
  // Since #101 (2026-09-22) the group also holds `authn.passwordAloneDoors`
  // and the two `appPasswords.*` settings: what the requirement does at the
  // five password-only doors, and what a person uses there instead.
  { group: 'Second-factor requirement',
    pages: ['/admin/totp', '/admin/webauthn'] },
  { group: 'Group claim', pages: ['/admin/groups'] },
  { group: 'Audit log', pages: ['/admin/audit'] },
  // On Protocols → Delegation since 2026-10-01, with the register's controls:
  // Monitoring → Delegation changes nothing.
  { group: 'Delegation', pages: ['/admin/delegation-settings'] },
  { group: 'Logout', pages: ['/admin/logout'] },
  { group: 'SPIFFE', pages: ['/admin/spiffe'] }
];

// Kept, not just logged: /admin/config renders it. A line in a log that scrolls
// past at startup is not a thing anybody reads twice.
let SETTING_HOME_PROBLEMS: ReturnType<AdminConsole['checkSettingHomes']>;
WIRE_STEPS.push(function (instance: AdminConsole): void {
  SETTING_HOME_PROBLEMS = instance.checkSettingHomes();
});

// The two measurements the folds below are decided by. They are declared
// HERE, above everything, rather than beside note() where they are read:
// several of this file's module-level constants are built by calling note()
// and warn() (at require time until #50's R2; in `WIRE_STEPS` now, which a
// default instance runs at the end of this module's load), and a `const` is
// in its temporal dead zone until the line that declares it runs — so a
// definition beside the function throws `Cannot access before
// initialization` while the module is still loading, which takes the whole
// service down (rule 1).
// The three measures a fold is decided against are `admin-ui/web_kit.ts`'s
// since #446; `bullet()` below still reads the first.
const ONE_LINE_CHARS = WebKit.ONE_LINE_CHARS;

// THE LIST PARAMETERS each section's drill-down carries back: the kit's
// since #446 (`web_kit.ts`, with its reasoning), so a page drawn in a
// browser carries the same names.
const LIST_PARAMS = WebKit.LIST_PARAMS;

// One page's link. Split out of navBar() when groups arrived so that a page
// draws the same way at either depth — the active-tab-is-a-link rule above is
// the kind that gets applied to one of two copies.
// WHAT SCROLLS THE SIDEBAR TO THE PAGE YOU ARE ON (2026-09-05).
//
// `nav` is its own scroll container — `.side` is sticky and the card inside it
// has `overflow-y:auto`, which is what stops a long list pushing the page down
// — and a scroll container starts at the TOP on every load. So navigating to a
// page low in the list left that page's own entry below the fold: the reader
// arrived somewhere and the list did not show where.
//
// **`autofocus` is the whole mechanism and it needs no script**, which is why
// this console can have it at all: a browser scrolls a focused element into
// view, including scrolling the ancestor container it lives in. It adds no
// scripted page to the root CLAUDE.md's list and `script-src 'none'` is
// untouched.
//
// **`tabindex="-1"` is what makes it safe.** The active item is a `<span>`
// when it is the page being drawn, and a span is not focusable without it — so
// autofocus alone would do nothing. `-1` rather than `0` because the element
// must be focusABLE without joining the TAB ORDER: it is the page you are
// already on, so a keyboard user tabbing through the nav should reach the
// links they can go to and not stop on the one they are standing on.
//
// **It is the only `autofocus` in this console**, which was checked rather
// than assumed: two of them and the first in document order wins, so one added
// to a form field on some page would silently stop working the day somebody
// added another. If a page ever needs to focus a field on load, that page has
// to opt this one OUT rather than compete with it.
//
// `scroll-margin` in the stylesheet keeps it off the container's own edge, so
// what is revealed is the item with its neighbours around it rather than the
// item flush against the top where it reads as the start of the list.
const ACTIVE_NAV_FOCUS = ' tabindex="-1" autofocus';

// ---------------------------------------------------------------------------
// THE BANNER EVERY PAGE CARRIES, AND IT NOW HAS THREE THINGS TO SAY RATHER THAN
// ONE.
//
// It is repeated on all of them rather than shown once on the index, because
// the pages are linkable and the one somebody arrives at directly is exactly
// the one that needs to say this. What it says depends on the state of the
// gate, and the three states are genuinely different warnings rather than one
// warning with a detail changed:
//
//   * THE GATE IS OFF. The old banner, unchanged. **THAT STATE IS NO LONGER
//     REACHABLE**: `admin.authRequired` was removed on 2026-09-06 and
//     `mode.gatesConsole()` answers `true` in both modes, so OPEN_BANNER and
//     every `!enforced` arm below are dead. They are kept rather than deleted
//     because what they say is "nothing here checks anything", and a banner of
//     that kind is the one sort of dead code whose quiet deletion would matter
//     if a third mode ever brought the state back.
//   * THE GATE IS ON AND NOBODY HOLDS A ROLE. The most dangerous state and the
//     one nothing else would report: a person has signed in, sees a working
//     console, and it is working because the roster is EMPTY rather than
//     because they were allowed. Said loudly, with what to do about it, because
//     the moment somebody grants the first role the door shuts behind whoever
//     is not in it — including, quite possibly, them.
//   * THE GATE IS ON AND THE ROSTER IS ENFORCED. Not a warning at all: who is
//     signed in and what they hold. It is still on every page, because "am I
//     read-only here" is the question behind every button a reader does not
//     find.
//
// It takes what `respond()` worked out rather than asking again, so the banner
// and the guard that let the request through cannot come to disagree about who
// somebody is.
// ---------------------------------------------------------------------------
let OPEN_BANNER: string;
WIRE_STEPS.push(function (instance: AdminConsole): void {
  OPEN_BANNER =
    instance.warn('<strong>This console is not protected.</strong> The ' +
    'gate is OFF, so nothing here checks a credential — and nothing else in ' +
    'this service does either: the username typed at the sign-in screen is ' +
    'the identity in every token it issues. Anyone who can reach this port ' +
    'can revoke every token and change what the next one contains. That is ' +
    'fine on a laptop or a compose network and is not fine on a public ' +
    'address. Say who may get in on <a href="/admin/rbac">Admin roles</a>, ' +
    'which draws ' +
    'every setting behind this page.');
});

// ---------------------------------------------------------------------------
// THE REALM CHOOSER, at the top of the sidebar's own card.
//
// A trust realm is a whole logical copy of this service (common/realms.js), and
// every page here shows exactly one of them — the one whose prefix the request
// arrived under. That is not something a reader can see from the content: an
// empty tokens table looks the same in a realm that has issued nothing as it
// does in a service that has issued nothing, and /admin/config in a realm both
// reads and WRITES that realm. So the realm is named on every page.
//
// It is INSIDE the nav card and above the sections rather than in a card of its
// own. It was its own card, and that was one surface too many in a column whose
// whole job is to be one list: a reader looking for where they are should find
// it at the top of the thing they are already reading.
//
// **IT IS A FORM AND NOT AN onchange, BECAUSE THIS CONSOLE RUNS NO SCRIPT.**
// `script-src 'none'` (common/app.js) is what makes the whole js/reflected-xss
// family moot here rather than merely unlikely, and a select that navigated on
// change would need an inline handler the browser would refuse to run — so the
// control would silently do nothing. A select and a button is the same shape
// every filter on this console already uses.
//
// **THE ACTION IS AN ABSOLUTE URL, and that is required rather than tidy.**
// app.js rewrites every root-relative `href`, `action` and `src` in an HTML
// response to carry the current realm's prefix, which is what makes this file's
// several hundred hand-written links work inside a realm without one of them
// being edited — and it is exactly wrong for the one control whose job is to
// LEAVE the current realm. An absolute URL names a host, so it passes through
// untouched, and the route it reaches is the one at the root.
//
// It draws NOTHING AT ALL when no realm is defined. This console had no such
// control before realms existed and a service that is not using them should not
// grow one — the row would be a permanent "default", which is a control that
// only ever says the same thing.
// ---------------------------------------------------------------------------
// The static console's bundle, read once (`consoleScript()`).
let consoleScriptText: string | null = null;

const REALM_SWITCH_PATH = '/admin/realm-switch';

// WHERE THE PERSON READING THIS CONSOLE FINDS THEIR OWN ACCOUNT (2026-09-10).
//
// The user portal is the other surface this service hosts, and it is the one
// place an administrator changes their OWN password, enrols their OWN
// authenticator app or removes their OWN security key. Until now the console
// named it in prose on a page or two and linked it nowhere in its shell, so
// the way there was to know the path.
//
// **IT IS THE DEFAULT REALM'S PORTAL AND NOT THE ONE BEING READ, WHICH IS THE
// WHOLE OF THE DECISION HERE.** The console's session is the DEFAULT realm's
// whichever realm the page was reached in — see `consoleRpSession()` — while
// `/portal` runs in the AMBIENT one. So a link to `/portal` from a page read at
// `/realm/acme/admin` would be rewritten to `/realm/acme/portal` by app.js's
// realm rewrite and would land this person in a portal where they are nobody:
// the flow would run in `acme`, meet no sign-on session, and ask them to sign
// in again — as an account in another realm that has nothing to do with the
// one they hold.
//
// `realmRoot()` is what takes the prefix back off, and the result is an
// ABSOLUTE URL rather than a root-relative one. That is not cosmetic either:
// the rewrite matches `href="/` and leaves `https://…` alone, so an absolute
// URL is the one form that cannot be prefixed again on the way out.
//
// **SINCE #32 THAT REALM IS THE ONE THE PERSON SIGNED IN THROUGH** (fixed
// 2026-09-16). A realm's own administrator runs the console's flow in their
// realm, so their sign-on session — and their account — is there, and the
// default realm's portal was one where they were nobody: the very outcome
// the paragraph above describes. The link now goes to the portal of the
// gate's `identityRealm`, which is the default realm for a service
// administrator and so the same link as before for them.
const PORTAL_PATH = '/portal';


// ---------------------------------------------------------------------------
// BOTH CHOOSERS ARE A SEARCH NOW, AND WHAT DECIDES THE SHAPE IS THE ONE THING
// THIS CONSOLE CANNOT DO.
//
// Each of them was a `<select>` holding EVERY entry. That is fine at thirty and
// it is what a register looks like after an afternoon; it is not what one looks
// like after a week, and the two things a reader actually does with a long list
// — type the first few letters of a name, or read the handful that match — are
// the two a native select does worst. It also spends the same screen whether it
// holds three names or three hundred, which is the complaint that started this.
//
// **THERE IS NO SCRIPT AND THERE MUST NOT BE ONE**, which is why this is not a
// type-ahead. `script-src 'none'` holds over the whole service (common/app.js)
// and the parent suite asserts it against this console's live headers
// (tests/vendored/admin_api.js) — so there is no keystroke handler, no fetch
// and no debounce to build one out of, and anything written as though there
// were would be a control that silently does nothing rather than one that half
// works. What a browser gives for free is a GET form submitted by the Enter
// key: type, press Enter, and the page comes back around the matches. The cost
// is a round trip per attempt instead of per keystroke, and the reader keeps
// typing until the list is what they wanted, which is the same loop.
//
// **A RESULT IS A LINK AND THE LINK IS THE SELECTION.** A select needed a
// button beside it because a `<select>` chooses nothing until something submits
// the form it is in. A list of matches needs none: clicking a row IS choosing
// that application or that person, which is one click where there were two.
//
// **TWENTY AT A TIME, IN A PANE THAT SCROLLS.** A wall of matching links would
// be the select's own fault with the browser's scrolling taken away, so the
// pane has a fixed maximum height and a scrollbar of its own: the control is
// the same size showing one match or twenty. The line under it says how many
// matched and offers the next twenty, because a list that silently stops at
// twenty is one that has told the reader the twenty-first does not exist.
//
// **AN EMPTY BOX MATCHES EVERYTHING**, so this is useful before anybody types —
// the first twenty with the total beside them, which is what the select showed
// in one line rather than in a column.
// ---------------------------------------------------------------------------
// The number itself lives in admin-core/admin_views.ts since 2026-09-13, so
// that /admin-api/rbac's `candidates` pages by the same twenty the pane does.
const CHOOSER_HITS = adminViews.CHOOSER_HITS;

// ---------------------------------------------------------------------------
// GET /admin/users — who this service has authenticated, and one of them in
// full.
//
// One route and two pages: without `?user=` it is the list, with it the
// drill-down. That is deliberate rather than lazy. A path parameter would have
// been the obvious shape and cannot be used here, because the identities this
// service holds contain the characters a path is made of — a Kerberos service
// principal is `HTTP/host` and a subject is a `urn:` — so
// `/admin/users/HTTP/web.example.com` is a two-segment path naming nobody. A
// query parameter carries any of them unaltered and keeps the console to one
// row in the metrics table for the whole feature.
//
// **What "a user" means here, and the two ways it can surprise you.** The list
// is built in admin_stats.js from the authentications this service recorded,
// PLUS every subject that appears on something it issued — so a subject that
// never authenticated here (an exchanged foreign token, a WS-Trust OnBehalfOf,
// a Kerberos S4U2Self) is listed and marked as such, rather than being absent
// from a page whose whole job is to answer "who has this service seen". And the
// identity is keyed on the local name, so one row covers `alice`,
// `urn:uuid:<entryUUID>` and `alice@STS.MOCK`, which is right on a mock where
// the name you type is who you are everywhere — and would be wrong on a real
// system with two realms. The Realms column exists so that collapse is visible.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE EMBEDDED DIRECTORY'S VIEW OF ONE USER, AND WHY IT ARRIVES THROUGH A SLOT.
//
// ldap_server.js grows an entry under `ou=users` for everybody who
// authenticates anywhere in this service, so by the time a person has a page
// here they usually have a directory object too — and showing it beside their
// tokens is the point: the two are the same authentication seen from two sides.
//
// This module does NOT require ldap_server.js to get at it, and the reason is
// the route order as much as a cycle (`ldap_server.js` requires this file to
// fill its slots). `common/protocol_stack.ts` requires this file at 18 and
// `ldap/ldap_server.js` at 21 (rule 6), so a require from here would pull the
// directory's routes into the router AHEAD of the console's — and
// /admin/sts-metadata is built by walking that router. So the direction is
// inverted the same way admin_stats.js's user observer is: this file offers a
// slot, and ldap_server.js fills it at its own require time.
//
// It stays null when that module was never required. That is a real state — the
// directory is the newest thing here and a build without it must still render
// this page — so the section says "no directory is loaded" rather than being
// absent, which would read as "this user has no entry".
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// The two things every LDAP section of this console draws, in one place each
// because there are now three such sections — a user's entry, the groups list
// and one group in full.
// ---------------------------------------------------------------------------

// The subjects a listener warning names are `web_groups.ts`'s (#446).
let directoryReader = null;

// The groups pages read through their own slot, installed the same way and by
// the same module, for the reason above: this file must not require
// ldap_server.js.
//
// Two slots rather than one object with two functions, because they were added
// at different times and a single slot would mean an ldap_server.js that filled
// it with only one of them silently disabling the other. A missing slot is
// already handled — each page says "no directory is loaded" — and two of those
// are cheaper than one half-filled reader nothing reports.
let groupReader = null;

// The SPIFFE listeners, through a slot for the reason given beside the
// requires above: this file must not require spiffe_server.js. What it holds
// is that module's `bindings()` and its bundle path — two facts about
// SOCKETS, which neither this page nor /admin/sts-metadata can see any other
// way, so a page without this reports "nothing bound" and cannot tell that
// from a listener whose port was taken.
let spiffeReader = null;


// ---------------------------------------------------------------------------
// AND THE SIXTH, WHICH IS THE PROTOCOL-INDEPENDENT LOGOUT.
//
// Same direction and both halves of rule 3e's test at once — see the note
// beside the requires at the top of this file. `logout.ts` requires
// `ldap_server.js`, which requires THIS module, so a require in the obvious
// direction closes a cycle; and it would drag every `/ldap` route into the
// router ahead of the console's own.
//
// It holds THREE things and they are one object, validated when it is
// installed: `FAMILIES` (the prose about what a logout reaches, so this page
// does not carry a second copy that goes stale the day a family is added),
// `inventoryFor` (what is live for one identity) and `terminate` (ending it).
// One object rather than three slots for the reason the directory writer's note
// gives one screen up: a module that filled a combined slot with only the
// readers would silently disable the action with nothing reporting it, so the
// object is checked whole and refused whole.
// ---------------------------------------------------------------------------
// THE SEVENTH SLOT, filled by `./crypto_metadata.js` at its own require time,
// and rule 3e's test answers yes in both directions at once.
//
//   * a require from `mgmt-api/admin_api.ts` (19) to that module (20a) would
//     MOVE ROUTES — `tls/tls_server.js`'s three, which it requires for the
//     server certificate, ahead of the management API's own routes and of
//     ldap, scim and spiffe. (Its own page moved too until #50's R1; since
//     then `common/protocol_stack.ts` registers that at 20a wherever the
//     module is loaded, but `tls_server.js` is still JavaScript.)
//   * a require from THIS file to it would CLOSE A CYCLE: it requires this one
//     for the shell, exactly as `../sts_metadata.js` does.
//
// So `/admin-api/crypto` reaches it the way `/admin-api/logout` reaches the
// sign-out inventory: through a function this console holds. What is carried is
// ONE function — the whole report — because the page and the API must not be
// able to disagree about what this service's cryptography is, which is the
// parity rule's entire subject.
//
// A build where nothing fills it draws no page here and answers the API with a
// 503 that says which module is missing. That is deliberate rather than a 404:
// a route that is registered and cannot answer is a different fact from a route
// that does not exist, and only one of them is a wiring mistake somebody can
// fix.
// ---------------------------------------------------------------------------
let cryptoReporter = null;

let logoutReader = null;

// ---------------------------------------------------------------------------
// THE NINTH SLOT: THE DIRECTORY PAGES' OWN VIEWS, FOR THE MANAGEMENT API —
// FIVE WHEN IT WAS WRITTEN, EIGHT SINCE 2026-09-05 (`DIRECTORY_PAGE_NAMES`).
//
// It is filled by `ldap/ldap_server.js` at its require time, and rule 3e's test
// answers yes both ways round.
//
//   * A require from THIS file to `ldap_server.js` would CLOSE A CYCLE — that
//     module requires this one for the shell and the gate — and it would drag
//     every `/ldap`, `/admin/ldap/*` and (through it) every `/scim` and
//     `/spiffe` route into the router ahead of this console's own.
//   * A require from `mgmt-api/admin_api.ts` (19) to it would MOVE ROUTES for
//     the same reason: that module sits two positions above `ldap_server.js`
//     (21) precisely so that the management API's routes are registered first.
//
// WHY THE API NEEDS IT AT ALL is rule 7, the parity: every page of this console
// has an operation on `/admin-api` that mirrors it, and the first five became
// pages of this console on 2026-09-01. The API answers them by calling exactly
// the function that draws them, so the page and the operation cannot come to
// disagree about what is in the directory.
//
// IT IS ONE SLOT CARRYING EVERY VIEW AND IT IS VALIDATED WHOLE, for the reason
// `setLogoutReader()` gives: a filler that installed all but one of them would
// leave one operation answering "no directory is loaded" on a service whose
// directory is plainly loaded, which is worse than all of them saying so. Each
// view takes the request and returns `{ title, inner, json }` — the same shape
// every view function in this file returns, so `respond()` and the API read
// them the same way.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE TENTH SLOT, `setXacmlPages()`, FILLED BY `xacml/xacml_admin.ts`, AND IT
// IS THE SIXTH TO PASS RULE 3e's TEST BOTH WAYS ROUND.
//
// A require from THIS file to `xacml/xacml_admin.ts` would CLOSE A CYCLE — it
// requires this one for the shell, the settings block, the gate and the action
// responder. And a require from `mgmt-api/admin_api.ts` (19) to it would MOVE
// ROUTES: every `/xacml` endpoint and all six `/admin/xacml*` pages would be
// registered ahead of the management API's own, and ahead of ldap, scim and
// spiffe. So the slot is the only arrangement left, and it is the same one SSF
// and the directory pages already take.
//
// **THE ROUTE HALF OF THAT WAS WRITTEN WHILE A REQUIRE WAS A REGISTRATION.**
// Since #50's R1 (2026-09-16) `common/protocol_stack.ts` registers the XACML
// family's routes at 23c with its own `register()` calls, wherever the
// modules were first loaded, so a require from `admin_api.ts` would no longer
// move them. It would still load the family — and arm `issuance_gate.js`
// through `xacml_role_pep.ts` — at 19 instead of 23c, which is a load-time
// effect out of order, and the cycle half stands; so the slot stays.
//
// IT CARRIES SEVEN FUNCTIONS — `XACML_PAGE_PARTS` below, `monitor` being the
// seventh (2026-09-06) — AND IS VALIDATED WHOLE, for `setLogoutReader()`'s
// reason: a filler that installed the views without the action would leave
// `/admin-api` able to LIST policies and unable to change any of them, which
// reads as a management API that is working and is not. It was four until
// phase five, which added TWO — `peps` for the remote PEP register, and
// `decide`, which `/admin/xacml/decide` had needed since phase three and had
// silently gone without (rule 7; `tests/vendored/admin_api.js` reads the
// console's OWN page list rather than a list in the test, which is why the
// omission was catchable at all). Both went into THIS set rather than into
// slots of their own because it is the same module filling it and a second
// slot would have been a second indirection for no second reason (rule 3e).
//
// `actionNames` is one more, outside the validated list (`xacmlActionNames()`
// below answers `[]` without it), and is not decoration. The refusal sentence
// for an unknown action names every action and counts them, and that sentence
// is READ by `tests/vendored/admin_api.js` — so the API has to be able to ask
// the module what its actions are rather than keeping a second list that
// could disagree.
// ---------------------------------------------------------------------------
const XACML_PAGE_PARTS = ['overview', 'policies', 'editor', 'peps', 'decide',
                          'monitor', 'action'];

let xacmlPages = null;

// EIGHT SINCE 2026-09-05. The three added that day — `roles`, `policies` and
// `peps` — are the containers whose owning modules published a SCHEMA that
// nothing drew: `common/roles.js`, `xacml/xacml_store.ts` and
// `xacml/xacml_pep_registry.ts` each carried the same comment claiming a page
// under `/admin/ldap/*`, and none of the three had one. The list is checked
// WHOLE below, so adding a name here without adding the view is a refused
// install rather than one operation answering as though no directory were
// loaded.
const DIRECTORY_PAGE_NAMES = ['service', 'directory', 'applications',
                              'federations', 'spiffe', 'roles', 'policies',
                              'peps', 'devices'];

let directoryPages = null;

// The SCIM slot (the FOURTH, and the third of the ones that READ). Same
// direction and same reason as the directory readers above, and it passes
// rule 3e's test for the same two grounds: requiring scim.js from here would
// pull every /scim route — and, since that module requires ldap_server.js,
// every /ldap route too — into the express router ahead of the console's own,
// and /admin/sts-metadata is built by walking that router.
//
// What it holds is scim.js's description(), which is the same object GET
// /scim?format=json answers with. So /admin/scim shows what that page shows
// rather than a second account of the same feature: the endpoint list, what
// SCIM deliberately does not do, and the reachable negatives are written ONCE,
// in the module that implements them, and this page renders them. A console
// page carrying its own copy of what "active: false" does would be the copy
// that stops being true — as "deactivates nobody" did on 2026-09-17.
let scimReader = null;

// And the one that WRITES, which is the third of these and the only one of the
// three that changes anything. Same direction and same reason as the two above
// — this file must not require ldap_server.js — and a third slot rather than a
// member on one of theirs, for the reason stated there: a module that filled a
// combined slot with only the readers would silently disable creation with
// nothing reporting it.
//
// It holds createUser() and NOT a way to write an arbitrary entry. The console
// is not a second definition of what a user is: what a name may be, and the
// refusal of one that is already here, live in that function so that this form,
// the management API and an `ldapadd` cannot come to disagree about the same
// name.
let directoryWriter = null;

// ---------------------------------------------------------------------------
// AND THE GROUP HALF (2026-09-06) — THE TWELFTH SLOT ON THIS FILE.
//
// It exists because /admin/groups was a READ and nothing else. This console
// could report a dangling member, a claimed membership and the two groups that
// decide who may use it, and could not create the group any of that is about:
// the only two doors onto a group in this directory were an `ldapadd` on the
// raw socket and `POST /scim/v2/Groups`. Rule 7 then owed the management API
// nothing, because there was no control to mirror — which is how a hole stays
// open in a repository that checks console/API parity on every run.
//
// SAME DIRECTION AND SAME REASON AS THE THREE ABOVE: this file must not require
// ldap_server.js. It passes rule 3e's test both ways round — a require from
// here would close a cycle (that module requires this one for the page shell
// and the gate), and a require from mgmt-api/admin_api.ts (19) to it would MOVE
// ROUTES, since ldap_server.js sits at 21 precisely so the management API's own
// are registered first.
//
// IT CARRIES BOTH FUNCTIONS AND IS VALIDATED WHOLE. A filler that installed
// `createGroup` alone would leave the Add member button answering "no directory
// is loaded" on a service whose directory plainly is — which is
// `setLogoutReader()`'s argument, and the reason that slot refuses a partial
// object rather than half-installing one.
//
// AND IT HOLDS NEITHER A DELETE NOR A REMOVE, deliberately. Taking a member out
// of a group is `admin_rbac.js`'s revoke() for the two console roles and an
// `ldapmodify` or a SCIM PATCH for every other group; deleting a group is a
// SCIM DELETE or an `ldapdelete`. Those doors exist and work. What did not
// exist anywhere but SCIM and the socket was CREATION, and a slot that grew the
// operations nobody asked for would be four more things for the two doors onto
// it to disagree about.
// ---------------------------------------------------------------------------
const GROUP_WRITER_MEMBERS = ['createGroup', 'addGroupMember'];
let groupWriter = null;

// The rule cell, the caveat and the links both groups pages carry are
// `web_groups.ts`'s (#446).

// ---------------------------------------------------------------------------
// GET /admin/applications
//
// The other side of /admin/users. That page lists every identity that has
// authenticated here; this one lists what they authenticated TO — every OAuth
// client, OpenID Connect relying party, SAML 2.0 or 1.1 service provider,
// WS-Federation application, WS-Trust relying party, OpenID4VP verifier and
// Kerberos service this instance has been asked about.
//
// **It reads the directory and holds nothing.** The registry IS the
// ou=applications container (see applications.js), so this page cannot come to
// disagree with what an LDAP client sees — there is no second copy for it to
// disagree with. An `ldapmodify` made a second ago shows up on the next
// refresh.
//
// **It had no form when it was written, and that was argued as a decision.**
// The write paths into this registry were the protocol endpoints and LDAP
// itself: a client is recorded because it turned up, and an operator changed
// one with `ldapmodify` — which is what makes the directory the source of
// truth rather than a display of one. That argument was about a second STORE,
// and it survived the reversal: the page now carries an *Add an application*
// row, per-entry actions (`APPLICATION_ACTIONS` in
// admin-core/admin_actions.ts, POSTed to the handler below)
// and `/admin/applications/new`, every one of them a DOOR onto the same
// entries through `applications.js` and mirrored on
// `POST /admin-api/applications/{action}` (rule 7).
// ---------------------------------------------------------------------------
// The caveat the applications pages carry is `applicationsCaveat()`.

// The three attributes that say where a service provider's key comes from
// are `admin_views.ts`'s `SAML_KEY_SOURCE_FIELDS` (#446).

// The notes at the foot of New application are `web_applications.ts`'s
// `newApplicationNotes()`.

// ---------------------------------------------------------------------------
// GET /admin/authorization-servers, POST /admin/authorization-servers
//
// RFC 9700 section 2.6 asks an authorization server to PUBLISH its metadata so
// that clients stop hard-coding security capabilities. This page is the other
// side of that: it decides what the published document SAYS, per authorization
// server, so that a client which reads the metadata can be shown reading it —
// and a client which does not can be shown not to.
//
// **A profile changes the document and not the endpoints**, and the page says
// so three times because it is the one thing here that could mislead badly.
// Everywhere else in this service a document disagreeing with the code is a
// defect — /admin/sts-metadata exists to report exactly that — and here it is
// the feature. So every view computes the DRIFT: which overridden members
// disagree with what this service would actually publish, and which removals
// hide something real.
// ---------------------------------------------------------------------------
// The caveat both authorization-server pages carry is `asCaveat()`.

// ---------------------------------------------------------------------------
// GET /admin/rbac, POST /admin/rbac — WHO MAY USE THIS CONSOLE.
//
// The page behind the gate above, and the second page here (after
// /admin/groups) whose content comes from the directory rather than from this
// service's own memory. It renders and decides nothing: `admin_rbac.js` holds
// the two roles, the empty-roster rule and both writes, and this draws them —
// the same division /admin/groups keeps with `ldap_server.js`, and for the same
// reason. A second opinion here about who is an administrator is the one bug in
// this feature that would be genuinely dangerous.
//
// **ONE TABLE OF GRANTS RATHER THAN ONE TABLE PER ROLE**, which is a rendering
// decision with a reason. Two tables would each need their own filter, their
// own page parameter and their own per-page control — three sets of controls
// for a list that is usually four rows long — and a reader's question is "who
// has access", not "who is in cn=admin-read". So a row is one GRANT: a person
// and a role. Somebody holding both roles is two rows, which is honest — they
// were granted twice and can be revoked once.
//
// **THE GRANT FORM IS TWO FORMS AND THAT IS DELIBERATE.** One picks from a list
// of people this service knows about, which is what somebody wants nine times
// in ten and is the only one that can be used without knowing how names are
// spelt here. The other takes a typed name, because the interesting case for a
// mock is granting a role to somebody who has NEVER been here — then watching
// them arrive already holding it. A single control doing both would have to be
// a text box with a datalist, and the list would then look like a set of
// options while silently accepting anything, which is a control that lies about
// what it takes.
//
// **THE PICKING HALF STOPPED BEING A `<select>` ON 2026-09-13.** It held every
// candidate, and once the default realm held thousands of people it could not
// be used. It is a search with a paged results pane — chooserPane(), the
// control /admin/delegation already uses for people and applications — whose
// results are links that PICK a person, and picking opens the grant form for
// them. The argument above survives intact, because the two halves are still
// two forms: the picked form's username is a hidden input that can only hold
// somebody the list offered (the view resolves `person` against the
// candidates rather than echoing it), and the typed form is still the one that
// takes anything.
// ---------------------------------------------------------------------------

// The caveat, on the page rather than only in a comment. It is the exact
// counterpart of GROUPS_CAVEAT and it says the opposite thing about two named
// groups, which is why it is worded to leave the general claim standing.
// The caveat of Admin roles is `rbacCaveat()`.

// ---------------------------------------------------------------------------
// GET /admin/roles, POST /admin/roles — WHO HOLDS A ROLE, AND WHO REQUIRES ONE.
//
// **IT IS NOT `/admin/rbac`, WHICH IS THE PAGE NEXT DOOR, AND THE TWO ARE ONE
// KEYSTROKE APART IN THE SIDEBAR.** That one has two roles, they are ordinary
// directory GROUPS, and they grant exactly one thing: this console. This one
// has as many roles as somebody makes, they live in `ou=roles`, and what they
// grant is being ISSUED something — a token, an assertion, a ticket, a
// session. Both headings say so, because a reader who confused them would
// grant somebody the console while meaning to let them sign in to an
// application.
//
// **AND IT IS NOT `/admin/groups`.** A group here still grants nothing; that
// sentence is written in six places and is still true. What changed is that a
// role may NAME a group, so adding somebody to `cn=developers` can now give
// them a role — through this register and only through it. The group is still
// inert; the row on a role entry is what does the work.
//
// TWO RELATIONS, TWO TABLES, AND THEY ARE OPPOSITE:
//
//   * MEMBERSHIP — role -> the users, groups and applications that HOLD it.
//     Stored on the ROLE entry, edited here.
//   * REQUIREMENT — application -> the roles it DEMANDS before this service
//     issues anything for it. Stored on the APPLICATION entry, in
//     `appRequiredRole`, and edited THERE. It is drawn here read-only, which
//     is the same arrangement `applicationPermissionsSection()` has in
//     reverse: one store, one door that writes it, and a second surface that
//     RESOLVES it — this page can say which role an application requires and
//     whether anybody holds it, which the application page cannot.
//
// An application appears in both tables and means opposite things in each: in
// the first it HOLDS the role (which is what a `client_credentials` grant is
// decided on, where there is no person), and in the second it DEMANDS one.
// `common/roles.js` argues that split at length and it is not repeated here.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// THE ELEVENTH SLOT ON THIS MODULE, AND IT PASSES RULE 3e'S TEST BOTH WAYS
// ROUND.
//
// `/admin/roles` can answer "would alice be issued a token for this
// application" without anybody having to try it, and the only thing that can
// answer that is `xacml/xacml_role_pep.ts` — the embedded PEP, which asks the
// PDP against the issuance policy. A require from here to that module would
// LOAD THE XACML ENGINE AT 18 and, worse, fill `issuance_gate.js`'s decider
// from the console rather than from the family that owns it, so a process that
// loaded this file and not `xacml/xacml.ts` would gate issuance with half the
// family present. A require the other way — the PEP reaching this module — is
// not a candidate either: it would close a cycle, since `xacml_admin.js`
// requires this file for the page shell.
//
// It carries TWO functions, `preview()` and `policy()`, and is validated
// whole, for `setLogoutReader()`'s reason: a preview installed without the
// thing that says WHICH POLICY answered would be a page able to ask a question
// and unable to explain the answer.
//
// AN EMPTY SLOT IS A SENTENCE AND NOT A BLANK. The section draws anyway and
// says the XACML family is not loaded in this process, which is the honest
// answer and the same one `issuance_gate.check()` gives: nothing is gated.
// ---------------------------------------------------------------------------
let rolePreviewer = null;



// ---------------------------------------------------------------------------
// /admin/realms — SEVERAL LOGICAL COPIES OF THIS SERVICE, IN ONE PROCESS.
//
// A TRUST REALM is a whole mock identity service: its own configuration, its
// own signing key, its own sessions, authorization codes, tokens, offers,
// service providers, statistics and audit log — answering on the SAME sockets
// as every other and told apart by a segment at the front of the path.
//
//   https://host:8081/oauth2/token               the default realm
//   https://host:8081/realm/acme/oauth2/token    the realm `acme`
//
// WHAT THIS PAGE IS FOR, and it is not "somewhere to keep a list". Two things
// nothing else here can tell you:
//
//   * WHAT A REALM'S ENDPOINTS ACTUALLY ARE. The prefix segment is a setting,
//     the ids are whatever somebody typed, and a client being pointed at a
//     realm has no way to derive either. Every row here carries the realm's
//     base URL, and the drill-down carries the four URLs a client asks for
//     first.
//   * WHICH FAMILIES ARE REALM-AWARE AND WHICH ARE NOT, WHICH IS NOT A TIDY
//     ANSWER. What a realm separates completely is what it ISSUES and what it
//     is holding while it issues it. This paragraph used to say the embedded
//     DIRECTORY was not separated at all; it has been a subtree per realm
//     since 2026-08-25, and the two admin roles (2026-09-14, #32), SPIFFE's
//     trust domains and sockets (2026-09-12) and Kerberos (a KDC per realm on
//     the shared port 88, 2026-09-15, #33) have followed it. What is still the
//     process's is what has no name inside its protocol to carry a realm —
//     the certificate the main port and LDAPS 636 present, a client
//     certificate at the handshake, and the Kerberos and directory SOCKETS
//     themselves. `common/realms.js`'s per-family rows are the current answer
//     and are what the table at the foot of this page draws: a person who
//     assumed a realm was a boundary everywhere would otherwise find out the
//     hard way.
//
// **IT KEEPS NOTHING OF ITS OWN.** The registry is common/realms.js's, the
// per-realm settings are config.js's — set through the same
// `config.setOverride()` that /admin/config, /admin/token-lifetimes and
// POST /admin-api/config/set call, against the realm's own override map — and
// the signing key is helpers.js's. That is the one-store rule this console
// follows everywhere: a page holding its own copy of what a realm sets would be
// a second answer to "what is this realm configured with" that the protocol
// endpoints could not see.
//
// **THE DEFAULT REALM IS NOT A ROW SOMEBODY CREATED** and cannot be removed,
// renamed or re-prefixed. Every URL this service published before realms
// existed is a URL in it, so an operator who could delete it could delete the
// service.
// ---------------------------------------------------------------------------
// The caveat of Trust realms is `web_realms.ts`'s `realmsCaveat()`.

// THE SIXTH THING THE READ LAYER IS HANDED, and the only one that is not an
// inverted hook: `scimJson()` embeds this console's settings block in its
// answer, and the alternative was for the page and /admin-api/scim to
// assemble that block separately — which is the drift rule 7 exists to
// prevent. It is handed over once, when the instance is installed (at require
// time until #50's R2), because it is defined here and never replaced.
WIRE_STEPS.push(function (instance: AdminConsole): void {
  adminViews.setConfigSettingsJson(
    instance.configSettingsJson.bind(instance));
});

// ---------------------------------------------------------------------------
// /admin/token-lifetimes — HOW LONG WHAT THIS SERVICE ISSUES IS GOOD FOR.
//
// Four settings when it was written — six now (`TOKEN_LIFETIME_KEYS`, with the
// refresh idle timeout and the sign-out revocation) — all of them `config.js`
// rows, on a page of their own under Protocols › OAuth2 / OIDC. The first
// three were module-level `const`s in
// `../oauth-oidc/oauth2.ts` until 2026-08-24 and could not be changed at all
// without a restart.
//
// WHY THIS IS A PAGE AND NOT JUST FOUR MORE ROWS ON /admin/config, which is the
// question `/admin/scim`'s header answers the other way — it has no form
// precisely because everything about SCIM that can be changed is a config row
// and "a second form here would be a second door to one setting". The rule that
// header is applying is the ONE-STORE rule, and it is untouched here: there is
// no store. This page holds nothing, decides nothing, and writes through
// `config.setOverride()` — the same function `/admin/config`'s Save and
// `POST /admin-api/config/set` call, against the same override map. What would
// break the rule is a second PLACE THE VALUE LIVES, and there is none. What is
// different from SCIM's case is what the reader is doing:
//
//   * These four are a QUANTITY somebody sets to a specific number to watch
//     something happen, over and over, in a session — "make it a minute so I
//     can see my client refresh". `/admin/config`'s form was then a table of
//     forty-nine settings with a text box each; finding four of them in it,
//     every time, is the cost this page removes.
//   * They INTERACT, and a page can say so where a flat table cannot. An access
//     token that outlives the refresh token is a grant that can never be
//     renewed; a clock skew larger than the lifetime is a token that is never
//     expired. Both are legal here — this service refuses nothing it can
//     merely explain — and both are worth being told about before the client
//     author debugs their own code for an hour.
//   * The answer to "why is my client being refused" is usually "the token
//     expired", and the numbers that decide it are worth having beside the
//     count of what already has.
//
// The test for a THIRD page like this one is the same as rule 3e's for a hook:
// it earns its place when the reader's task is not the one /admin/config
// serves, and it costs a reader nothing only while it writes through the same
// function. A page that started keeping its own copy of a value would be the
// thing both rules exist to prevent.
//
// NOTHING ALREADY ISSUED CHANGES, and the page says so twice. A lifetime is
// stamped into a token as `exp` when it is signed, so a change here reaches the
// NEXT token. That is a fact about signed statements, not a limitation, and
// somebody who did not expect it will read the tokens table below and conclude
// the setting did not take.
// ---------------------------------------------------------------------------


// THE DEAD LETTERS' COLOURS are the renderer's since #446
// (`ssf/web_ssf_dead_letters.ts`), with their reasoning.

// ---------------------------------------------------------------------------
// THE EIGHTH SLOT, filled by `../ssf/ssf.ts` at its own require time, and rule
// 3e's test answers yes in both directions at once.
//
//   * a require from THIS file to `../ssf/ssf.ts` would CLOSE A CYCLE: that
//     module requires this one for the page shell and the gate, exactly as
//     `../sts_metadata.js` and `./crypto_metadata.js` do.
//   * a require the other way round — from `mgmt-api/admin_api.ts` (19) to
//     `../ssf/ssf.ts` — would MOVE ROUTES: every `/ssf` endpoint, and the
//     `/.well-known/ssf-configuration` document, ahead of the management API's
//     own and of ldap, scim and spiffe. **Since #50's R1 (2026-09-16) those
//     are not the routes it would move** — `common/protocol_stack.ts`
//     registers SSF's own at 23b wherever the module is loaded — but
//     `ssf.ts` requires `ldap/ldap_server.js`, which is still JavaScript and
//     registers when required, so the require would still pull the
//     directory's routes (21) ahead of the management API's (19).
//
// So `/admin/ssf` and `/admin-api/ssf` reach it through a function this console
// holds, the way `/admin-api/crypto` reaches the crypto report.
//
// **IT CARRIES ONE OBJECT AND IS VALIDATED WHOLE**, which is the rule
// `setLogoutReader()` and `setCryptoReporter()` follow: a filler that installed
// the reader without the action would leave this page able to LIST streams and
// unable to change any of them, and rule 7's parity would be failing silently
// rather than loudly.
//
// **`action` RETURNS A PROMISE AND IT IS THE ONLY SLOT HERE THAT DOES.** Every
// other action function in this console answers from memory; transmitting a
// Security Event Token signs a JWS — which may be ML-DSA or SLH-DSA on the
// worker pool — and then POSTs it to somebody else's endpoint. Neither can be
// done synchronously, and pretending otherwise would mean this page reporting
// "sent" before anything had been.
// ---------------------------------------------------------------------------
let signalsReporter = null;

// ---------------------------------------------------------------------------
// THE THIRTEENTH SLOT: THE CLIENT-CERTIFICATE TRUSTSTORE (2026-09-12), and it
// passes rule 3e's test both ways round like the eighth above it.
//
//   * a require from THIS file to `../tls/tls_server.js` would MOVE ROUTES on
//     the order this repository documents — `/tls`, `/tls/server-certificate`
//     and `/tls/trust` belong at 20, after the management API — and would make
//     the console the reason they are where they are.
//   * a require the other way round, from `tls_server.js` to this file at its
//     own top level, would CLOSE A CYCLE — and not a theoretical one: that
//     module is really first loaded from inside THIS file's require, through
//     `admin-core/admin_views.ts` → `spiffe/spiffe_auth.ts`, so it would be
//     handed this module's half-built exports and find no `setTruststore` on
//     them. That is why `common/protocol_stack.ts` fills this, on the line
//     after it requires `tls_server.js`, rather than the filler being the
//     module that owns the array. It is the one slot here filled that way.
//
// **IT CARRIES ONE OBJECT AND IS VALIDATED WHOLE**, for `setLogoutReader()`'s
// reason: a truststore that could be LISTED and not changed would be a page
// drawing the anchors under two controls that answer "not installed", and one
// that could be changed and not listed would be a write nothing reads back.
//
// **AND IT IS A PAGE OF A PROCESS'S SOCKETS**, which decides where it is
// answered: `common/request_pool.js` pins `/admin/tls/trust` and
// `/admin-api/tls/trust` to the front process, because the array is the
// configuration of listeners only that process holds. A worker installs this
// slot too — it runs the same stack — and is never asked.
// ---------------------------------------------------------------------------
let truststore = null;


// ---------------------------------------------------------------------------
// THE NINTH SLOT, filled by `../ssf/caep.ts`'s host `../ssf/ssf.ts` at its own
// require time, for exactly the reasons the eighth exists and with the same
// test answering yes in both directions:
//
//   * a require from THIS file to `../ssf/ssf.ts` would CLOSE A CYCLE — that
//     module requires this one for the page shell and the gate;
//   * a require from `mgmt-api/admin_api.ts` would MOVE ROUTES, putting every
//     `/ssf` endpoint and the well-known document ahead of the management
//     API's own and of ldap, scim and spiffe — the directory's routes, since
//     #50's R1; see the eighth.
//
// **A SECOND SLOT RATHER THAN MORE MEMBERS ON THE EIGHTH**, and that is a
// decision rather than a habit. The signals reporter answers "what streams
// exist and what is on them"; this one answers "what has been said about which
// SESSION". They are two questions with two pages, and one object carrying
// both would mean `/admin/ssf` failing whole when the CAEP half was not
// installed — which is precisely the half-working state `setSignalsReporter()`
// refuses a partial filler in order to avoid.
//
// `action` RETURNS A PROMISE, like the eighth's: emitting a CAEP event signs a
// JWS — possibly on libuv's thread pool — and then POSTs it to somebody else's
// endpoint.
// ---------------------------------------------------------------------------
let caepReporter = null;


// ---------------------------------------------------------------------------
// THE TENTH SLOT, filled by `../ssf/risc.ts`'s host `../ssf/ssf.ts` at its own
// require time, for exactly the reasons the eighth and ninth exist and with
// the same test answering yes in both directions:
//
//   * a require from THIS file to `../ssf/ssf.ts` would CLOSE A CYCLE;
//   * a require from `mgmt-api/admin_api.ts` would MOVE ROUTES (the
//     directory's, since #50's R1; see the eighth).
//
// **A THIRD SLOT RATHER THAN MORE MEMBERS ON THE NINTH.** The signals reporter
// answers *what streams exist and what is on them*; the CAEP one answers *what
// has been said about which SESSION*; this one answers *what has been said
// about which ACCOUNT*. Those are three questions with five pages between
// them, and the reason they are three objects rather than one is the reason
// `setSignalsReporter()` refuses a partial filler: an object carrying all
// three would mean /admin/ssf failing whole when the RISC half was not
// installed.
//
// It is also the honest shape of the two registers behind them. A session and
// an account are not the same thing — a session begins, is used and ends,
// there are many per person, and an account IS the person and outlives every
// session on it — so a reporter that served both would be one object whose row
// is sometimes one and sometimes the other.
// ---------------------------------------------------------------------------
let riscReporter = null;

const PROTOCOL_SETTINGS_PAGES = [
  // -------------------------------------------------------------------------
  // THE TWO SECOND FACTORS, ONE PAGE EACH, BOTH UNDER PROTOCOLS (2026-09-10).
  //
  // **THERE WAS ONE PAGE AND IT WAS FILED UNDER IDENTITIES.** `/admin/mfa`
  // drew the eight `totp.*` settings AND a roster of who held a second factor,
  // and the argument for putting it beside Users was that it answered a
  // question about PEOPLE. That argument was right about the roster and wrong
  // about the settings, and the page could not be filed by both halves at
  // once: a reader looking for the skew window and a reader looking for *who
  // has no second factor* landed on the same screen and read past each other.
  //
  // So it is split by the question each half answers, which is the rule
  // `/admin/xacml/monitor` established. **The MECHANISMS are protocols** — RFC
  // 6238 and W3C WebAuthn are specifications this service implements, and they
  // belong beside SCIM and Kerberos. **The PEOPLE are the directory** — the
  // roster is columns on <a href="/admin/users">Users</a> now and the
  // per-person detail, including the Clear buttons, is on that person's own
  // row.
  //
  // **WEBAUTHN HAD NO SETTINGS AT ALL UNTIL THIS DAY**, which is why nothing
  // like this page ever existed for it. `common/config.js`'s own comment said
  // *what it does is decided by the specification and by the browser, and
  // there is nothing an operator could usefully turn* — true of the
  // cryptography and false of the ceremony, every parameter of which was a
  // literal inside a string in `authn/authn.ts`.
  // -------------------------------------------------------------------------
  { path: '/admin/totp', title: 'TOTP MFA',
    lead: '<strong>An authenticator app as a second factor — RFC 6238 over ' +
          'RFC 4226 — and the eight parameters the specification leaves ' +
          'open.</strong> A person enrols one at <code>/portal/mfa</code> or ' +
          'while spending an activation link: a QR code this server drew, ' +
          'and the same secret in base32 beside it. <strong>Codes are ' +
          'checked FOR REAL in both modes</strong>, which almost nothing ' +
          'else on this service is. Who actually holds one is <a ' +
          'href="/admin/users">Users</a>, and clearing an enrolment is on ' +
          'that person\'s own row.',
    also: ['<strong>Changing the digest, the digits or the period affects ' +
           'NEW enrolments only.</strong> An existing secret is verified ' +
           'with the parameters it was enrolled under — the ones the QR code ' +
           'told the app — because this service cannot change them ' +
           'retrospectively and a setting that silently locked out everybody ' +
           'who had already enrolled would be the worst kind of knob. ' +
           '<strong>The skew window is the exception and applies to ' +
           'everybody</strong>: how much a deployment forgives a drifting ' +
           'clock is a policy rather than something the app was told.',
           '<strong>LEAVE THE DIGEST AT SHA1 UNLESS YOU ARE TESTING EXACTLY ' +
           'THAT.</strong> Several widely used authenticator apps — Google ' +
           'Authenticator among them — IGNORE the <code>algorithm</code> ' +
           'parameter in the QR code and always compute SHA-1, so any other ' +
           'value produces a code that scans perfectly and then generates ' +
           'codes this service refuses, with nothing anywhere saying why. ' +
           'SHA-1 is not a weakness here: this is a keyed MAC over a ' +
           'counter, not a collision-resistant digest.',
           '<strong>A shared secret can be read back and a password ' +
           'cannot.</strong> Verifying a code means COMPUTING it, so the ' +
           'secret is stored in a form this service can recover — unlike ' +
           '<code>userPassword</code>, which is a scrypt hash. In PRODUCT ' +
           'mode it is sealed under the same key-encryption key that ' +
           'protects the signing keys, so <a ' +
           'href="/admin/ldap/directory">the directory page</a> shows ' +
           'ciphertext; in DEVELOPMENT mode it is stored as base32, because ' +
           'the key-encryption key there is generated per run and sealing ' +
           'would mean an authenticator that silently stopped working at the ' +
           'next restart. That is also the whole reason this mechanism is a ' +
           'SECOND factor and can never be made a first one.',
           '<strong>A code can only be used once</strong> (RFC 6238 section ' +
           '5.2). The step this service last accepted is stored on the ' +
           'enrolment, so somebody signing in twice inside one window is ' +
           'asked to wait for the next code. That is correct and it ' +
           'surprises people, which is why the sign-in screen says which of ' +
           'the two happened rather than answering &ldquo;wrong code&rdquo; ' +
           'to both.'],
    status: slot.forward('totpMechanismBlock'),
    links: [['/admin/webauthn', 'the other second factor'],
            ['/admin/users', 'who holds one, and how to clear it'],
            ['/admin/crypto-metadata', 'every algorithm this service performs'],
            ['/portal/mfa', 'where a person enrols one']] },

  // -------------------------------------------------------------------------
  // THE THIRD MECHANISM PAGE (2026-09-10), AND THE ONLY ONE ON THIS CONSOLE
  // THAT IMPLEMENTS NO SPECIFICATION.
  //
  // It is a page of its own rather than a section of `/admin/totp` because a
  // recovery code stands in for EITHER of the two mechanisms above it. Filing
  // it under one of them would put it where half the people looking for it
  // would not look, and the console's own rule — where a page goes is decided
  // by the question it answers — says the question here is *how does somebody
  // get back in*, which is neither of those two pages' question.
  // -------------------------------------------------------------------------
  { path: '/admin/backup-codes', title: 'Recovery codes',
    lead: '<strong>The way back in when the second factor is not to ' +
          'hand.</strong> A set of single-use codes that a person generates ' +
          'for themselves on <code>/portal/mfa</code>, is shown once, and ' +
          'which is stored — one scrypt hash per code — only when they ' +
          'confirm they have kept it. Generating again REPLACES the set. ' +
          'There is no control here or on <code>/admin-api</code> that ' +
          'issues a set or shows a code. Who holds one is <a ' +
          'href="/admin/users">Users</a>, and clearing a set is on that ' +
          'person\'s own row.',
    also: ['<strong>THIS IS THE ONLY MECHANISM ON THIS CONSOLE THAT NO ' +
           'SPECIFICATION DEFINES.</strong> Everything else here implements ' +
           'somebody\'s document and can be checked against it; there is no ' +
           'RFC for a recovery code. What every identity provider does ' +
           'converges anyway — a handful of random strings, shown once, each ' +
           'accepted once — and the decisions that are left are this ' +
           'service\'s own. <code>common/backup_codes.ts</code> argues each ' +
           'of them, and the four settings below are what it leaves open.',
           '<strong>THEY ARE HASHED, ONE SCRYPT HASH PER CODE, AS ' +
           '<code>userPassword</code> IS (SINCE 2026-09-11).</strong> This ' +
           'repository\'s own rule is that a secret this service only ' +
           'VERIFIES is hashed. Until 2026-09-11 the codes were encrypted ' +
           'instead, so that a person could read their remaining codes back; ' +
           'the set is now shown exactly once, when it is generated, and ' +
           'nothing — the person included — can see a stored code again.',
           '<strong>A PERSON GENERATES THEIR OWN SET, AND GENERATING AGAIN ' +
           'REPLACES IT.</strong> Until 2026-09-11 a set was issued ' +
           'automatically, once, the first time a second factor was ' +
           'enrolled. Now it is generated on <code>/portal/mfa</code>, held ' +
           'apart from the entry until the person confirms they have kept ' +
           'it, and REPLACES any earlier set whole — a set is never topped ' +
           'up. A person who holds a second factor and no set is prompted ' +
           'to generate one. An operator\'s Clear deletes a set.',
           '<strong>CHANGING THESE SETTINGS AFFECTS NEW SETS ONLY, AND ' +
           'NOTHING HERE SAYS "NEW ENROLMENTS ONLY" THE WAY <a ' +
           'href="/admin/totp">TOTP</a> DOES.</strong> That page has to, ' +
           'because its parameters were TOLD TO AN APP this service cannot ' +
           'reach. Nothing here is told to anybody: a recovery code is ' +
           'compared against its stored hash, so shortening the ' +
           'length changes what the next set looks like and leaves an ' +
           'existing set matching exactly as it did.'],
    status: slot.forward('backupCodesMechanismBlock'),
    links: [['/admin/totp', 'one of the two factors these stand in for'],
            ['/admin/webauthn', 'the other'],
            ['/admin/users', 'who holds a set, and how to clear one'],
            ['/portal/mfa', 'where a person generates their own set']] },

  { path: '/admin/webauthn', title: 'WebAuthn',
    lead: '<strong>Security keys — W3C WebAuthn Level 3 over FIDO CTAP2 — as ' +
          'a second factor OR as the only credential on an account.</strong> ' +
          'This service is the relying party: it builds the ceremony\'s ' +
          'options, and it verifies the challenge, the origin, the RP ID ' +
          'hash, the flags and the signature when the result comes back. Who ' +
          'holds a key is <a href="/admin/users">Users</a>, and removing one ' +
          'is on that person\'s own row.',
    also: ['<strong>NOT ONE of these settings existed until 2026-09-10, and ' +
           'the sentence they replace is worth knowing.</strong> This ' +
           'service said WebAuthn had nothing an operator could usefully ' +
           'turn — true of the cryptography and false of the ceremony. The ' +
           'RP name, the algorithms offered, the user verification ' +
           'requirement, the attestation conveyance and the timeout were ' +
           'literals in a string, so a client author trying to find out what ' +
           'their client does with <code>attestation: "none"</code> or with ' +
           'a resident key had no way to ask this service for one.',
           '<strong>ONE of them is enforced and the rest are ' +
           'requests.</strong> <code>webauthn.userVerification</code> is ' +
           'sent to the browser AND checked against the UV flag when the ' +
           'ceremony returns, because that flag is inside the bytes the ' +
           'authenticator signed. Nothing signed says what the browser was ' +
           'asked about the attestation conveyance, the resident key or the ' +
           'attachment — so a check on those would be a comparison against ' +
           'a value this service itself supplied. What it does instead is ' +
           'RECORD what came back.',
           '<strong>THE ATTESTATION STATEMENT IS VERIFIED (SINCE ' +
           '#105)</strong> ' +
           'under <code>webauthn.attestationPolicy</code> — in product mode ' +
           'by default, all eight formats of WebAuthn Level 3 section 8, the ' +
           'chain against this realm\'s anchors and the FIDO Metadata ' +
           'Service\'s roots, revocation, and MDS status reports. What each ' +
           'key\'s statement proved is on its row under <a ' +
           'href="/admin/users">Users</a>.',
           '<strong>Raising user verification does not change what a session ' +
           'CLAIMS.</strong> A passwordless sign-in still records <code>amr ' +
           '["hwk"]</code> and <code>acr "1"</code> — one factor — even ' +
           'under <code>required</code>. RFC 8176 has no value for <em>the ' +
           'authenticator verified the user</em> that this service could ' +
           'honestly assert, and claiming <code>mfa</code> because the ' +
           'ceremony was phishing-resistant would be the exact fake this ' +
           'profile refuses everywhere else.',
           '<strong>The RP ID is the host this service was reached on, and ' +
           '<code>webauthn.rpId</code> can only widen it to a registrable ' +
           'domain suffix.</strong> That is WebAuthn\'s own rule and ' +
           'browsers enforce it; this service enforces it too, refusing ' +
           'anything else by name in the log — because a browser refuses it ' +
           'with a <code>SecurityError</code> the ceremony reports as one of ' +
           'its several indistinguishable failures, so a wrong value looks ' +
           'like a broken authenticator. Widening it means every host under ' +
           'that suffix can assert these credentials.'],
    status: slot.forward('webauthnMechanismBlock'),
    links: [['/admin/totp', 'the other second factor'],
            ['/admin/users', 'who holds a key, and how to remove one'],
            ['/admin/crypto-metadata', 'every algorithm this service performs'],
            ['/portal/keys', 'where a person enrols one']] },

  { path: '/admin/oauth2', title: 'OAuth 2.0 / OIDC settings',
    lead: '<strong>The authorization server\'s own settings.</strong> ' +
          'Everything about what this service will ACCEPT at ' +
          '<code>/oauth2/authorize</code> and <code>/oauth2/token</code> and ' +
          'what it puts into what comes back — separately from which ' +
          'authorization server a flow runs against, which is ' +
          '<a href="/admin/authorization-servers">Authorization servers</a>, ' +
          'and from what a token CARRIES, which is ' +
          '<a href="/admin/claims">Custom claims</a> and ' +
          '<a href="/admin/userinfo-claims">UserInfo claims</a>.',
    also: ['<strong><code>oauth2.rfc9700</code> is a MODE, and so is ' +
           '<code>oauth2.oauth21</code></strong>; both are off unless turned ' +
           'on. With them off ' +
           'nothing below is enforced: no PKCE is required, no redirect URI ' +
           'is matched exactly, no client is authenticated. That is what ' +
           'this service is for — a client\'s error paths cannot be ' +
           'exercised against a server that refuses nothing — and it is why ' +
           'the mode exists rather than the checks being on. It is ' +
           'restart-only, because <code>global.https</code> derives from it ' +
           'and a listener\'s scheme is settled when the socket is bound; a ' +
           'TRUST REALM can be in the mode while the process is not, which ' +
           'is the way to have both at once.',
           '<strong><code>oauth2.oauth21</code> is OAuth 2.1 ' +
           '(draft-ietf-oauth-v2-1-16), and it turns RFC 9700 mode ' +
           'on</strong> — everything that mode enforces is part of 2.1 — ' +
           'then adds the rest: PKCE for confidential clients too, a client ' +
           'that has registered its own redirect URI ' +
           '(<code>oauth2.redirectUris</code> below is not read), a ' +
           'presented credential that must verify, a JWT client assertion ' +
           'addressed to the issuer alone, and no SAML client ' +
           'authentication. It also lets a token request leave out ' +
           '<code>redirect_uri</code>, which RFC 9700 mode refuses — so a ' +
           'client written for 2.1 is exercised in this mode and not in that ' +
           'one. Restart-only and realm-settable for the same reason.',
           '<strong>The five sender-constraint settings ask for MORE than ' +
           'either specification does (#34, 2026-09-15).</strong> Neither ' +
           'OAuth 2.1 (section 4.3.1) nor RFC 9700 requires DPoP: section ' +
           '4.3.1 asks a public client\'s refresh token to be ' +
           'sender-constrained <em>or</em> rotated with replay detection, ' +
           'and a sender-constrained access token is a SHOULD. So all five ' +
           'are off unless set, and no mode turns one on. ' +
           '<code>oauth2.refreshTokenRotation</code> takes the rotation ' +
           'answer with both modes off — the modes already rotate for every ' +
           'client. The four <code>Require</code> rows REFUSE rather than ' +
           'downgrade: a token request that would hand out an unconstrained ' +
           'refresh token is refused WHOLE, access token included, because ' +
           'half a token set is discovered an hour later at a refresh that ' +
           'cannot be made; and an unbound refresh token is refused at the ' +
           'refresh grant rather than bound to whoever presents it first.',
           '<strong>The two access-token rows refuse at the RESOURCE, not at ' +
           'the token endpoint.</strong> This service goes on issuing bearer ' +
           'tokens, which every surface that accepts a presented access ' +
           'token then refuses — UserInfo, the step-up resource, the three ' +
           'OpenID4VCI endpoints, <code>/scim/v2</code>, the Shared Signals ' +
           'endpoints, <a href="/admin-api">the management API</a> and the ' +
           'embedded debugger\'s listener. That is deliberate: a client ' +
           'under test needs to MEET the refusal. What they do not cover is ' +
           'what is not a presented OAuth access token — GNAP\'s own tokens, ' +
           'an RFC 7592 registration access token, and the endpoints that ' +
           'take a token as a parameter (introspection, revocation, token ' +
           'exchange). <strong>Two consequences worth knowing before you ' +
           'turn one on</strong>: <a href="/admin/api-explorer">the API ' +
           'explorer</a> stops working while DPoP is required, because its ' +
           'script sends a plain <code>Bearer</code> header; and the mutual ' +
           'TLS rows need <code>global.https</code>, without which every ' +
           'affected request is refused rather than waved through.',
           '<strong>This console and the user portal keep working, and the ' +
           'debugger is an ordinary client.</strong> <code>/admin</code> and ' +
           '<code>/portal</code> are OpenID Connect clients of this service; ' +
           'since 2026-09-15 they carry a DPoP key of their own and prove it ' +
           'on every back-channel token call, so the DPoP rows do not lock ' +
           'you out. They are EXEMPT from ' +
           '<code>oauth2.refreshTokenRequireMtls</code> alone, because their ' +
           'token requests are loopback calls from this process to itself ' +
           'and there is no certificate story to tell about one. The ' +
           'debugger\'s client is not exempt from anything: point it at a ' +
           'realm that requires a constraint and configure it to meet one, ' +
           'the same as any other client here.',
           '<strong><code>oauth2.breakIdTokenNonce</code> makes this service ' +
           'wrong on purpose.</strong> Turn it on and every ID Token carries ' +
           'a <code>nonce</code> that is not the one the client sent, so a ' +
           'client that does not check gets a token it should have refused. ' +
           'It is the same device as the reserved password ' +
           '<code>invalid</code> and the Kerberos names that stay unknown: a ' +
           'permissive server is hard to write error handling against, so ' +
           'the errors have to be reachable deliberately. <strong>In ' +
           'development mode only</strong>: a realm in product mode ' +
           'ignores it where the ID Token is built, logs that once ' +
           '(STS-CORE-0106), and refuses turning it on (STS-CORE-0103).'],
    links: [['/.well-known/openid-configuration', 'the discovery document'],
            ['/oauth2/rfc9700', 'what RFC 9700 mode enforces'],
            ['/oauth2/oauth21', 'what OAuth 2.1 mode enforces'],
            ['/oauth2/fapi',
             'which FAPI profile is in force, and what it enforces'],
            ['/admin/token-lifetimes', 'how long what it issues lasts'],
            ['/admin/tokens', 'what has been issued']] },

  { path: '/admin/oid4vci', title: 'OpenID4VCI',
    lead: '<strong>The credential issuer at <code>/issuer</code>, and the ' +
          'settings around it.</strong> What a credential CONTAINS is <a ' +
          'href="/admin/vc">Credential claims</a> next door; these are the ' +
          'ones about the exchange — where a holder is sent, which ' +
          'authorization server the credential endpoint will take a token ' +
          'from, how big a batch may be, and how long a deferred issuance ' +
          'pretends to take.',
    also: ['<strong>Every credential names its status.</strong> A ' +
           'dc+sd-jwt and a jwt_vc_json credential carry a Token Status ' +
           'List reference and a jwt_vc_json and an ldp_vc a Bitstring ' +
           'Status List entry, served at <code>/oid4vci/status-lists</code> ' +
           'and signed with the credential key — which may be post-quantum. ' +
           '<code>oid4vci.statusListTtlS</code> is how long a verifier may ' +
           'keep a list; <a href="/admin/vc-status">Credential status</a> ' +
           'suspends and revokes.',
           '<strong>Key attestations.</strong> A wallet may say how its key ' +
           'is kept (OpenID4VCI Appendix D); one signed by a certificate in ' +
           '<code>oid4vci.keyAttestationTrustedCertificates</code> is ' +
           'recorded, and decides whether a wallet sign-in claims ' +
           '<code>hwk</code> and <code>acr "mfa"</code>. ' +
           '<code>oid4vci.keyAttestationRequired</code> requires one.',
           '<strong>The two DID settings change what a VERIFIER has to ' +
           'resolve, and they are restart-only.</strong> With ' +
           '<code>oid4vci.sdJwtIssuerDid</code> or ' +
           '<code>oid4vci.ldpVcIssuerDid</code> on, the issuer names itself ' +
           'with a <code>did:web</code> identifier instead of an https URL, ' +
           'so the key a verifier fetches comes from a DID document rather ' +
           'than from JWKS. They are read while the issuer metadata is being ' +
           'built, which is why they cannot be changed while the service ' +
           'runs.',
           '<strong>Nothing in an issued credential is verified.</strong> ' +
           'The values come off the holder\'s directory entry and the entry ' +
           'is created for anybody who asks; a diploma issued here says ' +
           'whatever <a href="/admin/vc">Credential claims</a> selected. ' +
           'What is real is the signature, the proofs and the formats — ' +
           'which is the half a wallet has to get right.'],
    links: [['/issuer', 'the issuer, for a person'],
            ['/issuer/offer', 'a Credential Offer'],
            ['/.well-known/openid-credential-issuer', 'the issuer metadata'],
            ['/admin/vc', 'what a credential carries']] },

  { path: '/admin/oid4vp', title: 'OpenID4VP',
    lead: '<strong>The mock Verifier at <code>/oid4vp/verifier</code>, and ' +
          'the settings around its request.</strong> The DCQL query — which ' +
          'credential, which claims — is ' +
          '<a href="/admin/vc-verifier-config">Verifier request</a> next ' +
          'door; these settings are the client identifier it presents as, ' +
          'where it sends a holder to present, how fresh a Key Binding JWT ' +
          'has to be, the claims it asks for when nothing else has been ' +
          'chosen — the settings that govern signing in with a wallet, and ' +
          'how long a status list another issuer published is kept.',
    also: ['<strong>A presentation can sign somebody in, at <code>' +
           '/authn/wallet</code>.</strong> <code>oid4vp.signIn</code> offers ' +
           '"Sign in with a wallet" on the sign-in screen: a holder-bound ' +
           'credential <em>this realm</em> issued — in any format ' +
           '<code>oid4vp.signInFormats</code> names: SD-JWT VC, JWT VC or ' +
           'LDP VC — on an access token it verified and nobody has ' +
           'disowned since, presented with a fresh holder proof, signs in ' +
           'the directory entry it was issued for, with <code>amr ' +
           '["pop"]</code> (and <code>hwk</code>, and <code>acr ' +
           '"mfa"</code>, where a verified key attestation says so). A ' +
           'credential from a trusted foreign issuer, another realm or a ' +
           'foreign access token still verifies, is recorded on ' +
           '<a href="/admin/users">/admin/users</a> as a presentation, and ' +
           'signs nobody in. The bar door at <code>/oid4vp/verifier</code> ' +
           'signs nobody in whatever it is shown: nobody there asked to be ' +
           'signed in.',
           '<strong>The Digital Credentials API is the default way in, and ' +
           'the plain QR code is off.</strong> A browser that has the API ' +
           'asks a wallet on this device or a nearby one, which the browser ' +
           'checks is near it; <code>oid4vp.signInDcApiResponseMode</code> ' +
           'decides whether the answer is encrypted. <code>' +
           'oid4vp.signInCrossDevice</code> adds a plain QR code for a ' +
           'wallet the browser cannot reach — the one path somebody can ' +
           'relay to a victim, which is why it is off.',
           '<strong>Every credential\'s status is consulted.</strong> One ' +
           'this realm issued is read from <a href="/admin/vc-status">' +
           'Credential status</a>; one a trusted foreign issuer signed has ' +
           'its status list fetched, kept for its ttl and at most <code>' +
           'oid4vp.statusListMaxCacheS</code>, and a credential whose status ' +
           'cannot be read is refused. <strong>So is one that names no ' +
           'status</strong> (<code>oid4vp.requireStatusReference</code>, ' +
           '<code>all</code> by default in both modes), and an ldp_vc whose ' +
           'presentation withheld its <code>credentialStatus</code>, which ' +
           'the request asks for; a trusted issuer that publishes no status ' +
           'is exempted by its certificate\'s thumbprint in <code>' +
           'oid4vp.statusOptionalIssuers</code>. The result page names the ' +
           'rule that refused.'],
    links: [['/oid4vp/verifier', 'the verifier, for a person'],
            ['/admin/vc-verifier-config', 'what it asks for']] },

  { path: '/admin/kerberos', title: 'Kerberos settings',
    lead: '<strong>The KDC on raw TCP and UDP 88, the same exchange over ' +
          'MS-KKDCP at <code>/KdcProxy</code>, the Kerberos-protected ' +
          'service, and SPNEGO over HTTP.</strong> Most of these settings ' +
          'are restart-only and the reason is one fact: the principal ' +
          'database — every long-term key in it — is built from them when ' +
          'the process starts, so a realm or a password changed at runtime ' +
          'would leave every existing ticket undecryptable by the service ' +
          'that issued it.',
    also: ['<strong>This is the one family here that cannot be permissive ' +
           'the way the rest of this service is.</strong> A Kerberos ' +
           'password IS the key: pre-authentication and the AS-REP\'s ' +
           'enc-part are both encrypted under it, so a KDC that accepted ' +
           'anything would still have to pick a key the client could not ' +
           'guess. The permissiveness moved into the ACCOUNT POLICY instead ' +
           '— one password shared by every user account ' +
           '(<code>krb5.userPassword</code>), an account created for any ' +
           'name on first sight — and the acceptor still decrypts a real ' +
           'ticket under a real key and refuses a replay. So the ' +
           'verification is real and the account policy is not, and those ' +
           'are two different sentences.',
           '<strong><code>krb5.unknownUsers</code> is how a client\'s error ' +
           'path is reached.</strong> Every other name gets an account, so ' +
           'these are the only ones that can produce ' +
           '<code>KDC_ERR_C_PRINCIPAL_UNKNOWN</code>. ' +
           '<code>krb5.clockOffset</code> is the same device for skew: it ' +
           'moves this KDC\'s idea of now so that a client can be shown ' +
           '<code>KRB_AP_ERR_SKEW</code> without anybody touching a system ' +
           'clock.',
           '<strong><code>krb5.spnegoAuthentication</code> is a door and not ' +
           'a mode.</strong> With it on, a ticket presented at ' +
           '<code>/authn/spnego</code> starts a browser sign-on session — ' +
           'the same session <code>/oauth2/authorize</code>, ' +
           '<code>/wsfed</code>, <code>/saml2/sso</code> and this console ' +
           'read — which makes Kerberos an authentication mechanism for ' +
           'every application here. With it off that endpoint answers 403 ' +
           'naming this setting, and <code>/spnego/protected</code> still ' +
           'performs the whole handshake and gives no session.'],
    status: slot.forward('kerberosPreauthStatusBlock'),
    links: [['/krb5/principals', 'the principal database'],
            ['/krb5/service', 'the protected service'],
            ['/spnego', 'what SPNEGO is, for a person'],
            ['/authn/spnego', 'sign in with a ticket'],
            ['/admin/delegation', 'what S4U and a forwarded TGT did here']] },

  // -------------------------------------------------------------------------
  // /admin/persistence — THE PAGE THAT REVERSES THE OLDEST CLAIM IN THIS
  // REPOSITORY.
  //
  // Every document here said this service persists nothing and that everything
  // is gone on restart. Since 2026-08-27 three things are not: the embedded
  // directory, the trust realm registry and the runtime appconfig overrides —
  // and since 2026-09-06, in product mode on postgres, what this service MINTS
  // (persistence/CLAUDE.md has the current list). The page says which is which
  // rather than leaving a reader to infer a boundary — because "it persists
  // now" is exactly the kind of half-sentence that gets somebody expecting
  // their access token back.
  //
  // IT IS IN THIS TABLE RATHER THAN BEING A PAGE OF ITS OWN because it is
  // overwhelmingly a settings page: appconfig rows (six when it was written,
  // nineteen `persistence.*` now) and the sentences that
  // explain them, which is what every other row here is. What it has that they
  // do not is a STATUS block, and that is one optional member on the row rather
  // than a second kind of page — see protocolSettingsJson().
  // -------------------------------------------------------------------------
  { path: '/admin/persistence', title: 'Persistence',
    lead: '<strong>Whether anything here survives a restart, and where it is ' +
          'written.</strong> Three things can be: the embedded LDAP ' +
          'directory — which is also where applications, federation ' +
          'relationships and the SPIFFE registry live — the trust realm ' +
          'registry, and the runtime setting changes made on pages like this ' +
          'one — and, in <strong>product mode</strong> on a Postgres store, ' +
          'a fourth: everything this process MINTS. ' +
          '<code>persistence.mode</code> decides where: <code>memory</code> ' +
          'writes nothing and is what this service did until 2026-08-27, ' +
          '<code>ldif</code> writes an RFC 2849 file per realm and needs no ' +
          'database, <code>postgres</code> writes six tables.',
    also: ['<strong>WHAT THIS SERVICE MINTS IS PERSISTED IN PRODUCT MODE, ' +
           'AND IN NO OTHER CONFIGURATION.</strong> Sessions, access tokens, ' +
           'ID Tokens, refresh tokens, authorization codes, pre-authorized ' +
           'codes, SAML artifacts, Kerberos principals and tickets, the ' +
           'replay caches, <a href="/admin/metrics">the statistics</a> and ' +
           '<a href="/admin/audit">the audit log</a> all survive a restart ' +
           'when <code>global.mode</code> is <code>product</code> and the ' +
           'store is <code>postgres</code>. Every row is encrypted with the ' +
           'same key-encryption key that protects the signing keys, because ' +
           'a session id is a cookie value and an authorization code is ' +
           'redeemable — so a database dump is not a set of usable ' +
           'credentials.',
           '<strong>DEVELOPMENT MODE PERSISTS NONE OF IT, and that is not ' +
           'unfinished either.</strong> <strong>The signing key is ' +
           'regenerated on every start there</strong>, so a restored token ' +
           'would verify against nothing and an assertion restored from a ' +
           'disk would be a lie. Product mode keeps its keys — which is why ' +
           'it requires a store — and that single fact is what makes ' +
           'restoring the rest of it honest. The <code>ldif</code> store ' +
           'does not hold minted state either, whatever the mode: it writes ' +
           'WHOLE FILES per flush, which is right for a directory somebody ' +
           'types into and wrong for a session table that changes on every ' +
           'request. The service says so once at startup rather than letting ' +
           'it be discovered one restart later.',
           '<strong>SEVERAL PROCESSES AGAINST ONE STORE NOW AGREE, and this ' +
           'paragraph said the opposite until 2026-09-06.</strong> It read ' +
           '"persistence is not coordination… one process per database", and ' +
           'that was the honest description of what existed. Every change is ' +
           'now written to a monotonic log INSIDE the transaction that made ' +
           'it, and each process applies what the others committed — the ' +
           'directory, the realms, the settings and the minted rows alike. A ' +
           '<code>LISTEN</code>/<code>NOTIFY</code> nudge only makes that ' +
           'prompt: <strong>the log is the contract</strong>, so a missed ' +
           'notification costs latency and never a change. ' +
           '<code>persistence.coordinate</code> turns it off, which is what ' +
           'this service did before.',
           '<strong>It shares STATE and not SOCKETS, and the difference is ' +
           'where the surprises are.</strong> The KDC, the two LDAP ' +
           'listeners, the main port and SPIFFE\'s four are bound per ' +
           'process and always will be. And the <strong>replay caches and ' +
           'DPoP <code>jti</code> sets converge rather than ' +
           'synchronise</strong>: between a write in one process and its ' +
           'arrival in another there is a window the size of ' +
           '<code>persistence.pollInterval</code> in which a proof one ' +
           'process refused is accepted by another. Sticky sessions at the ' +
           'load balancer close it; nothing here does.',
           '<strong>A restored person shows on ' +
           '<a href="/admin/users">Users</a> as restored rather than as ' +
           'having authenticated.</strong> They exist — an entry, searchable ' +
           'over 389, readable over SCIM, and a token issued to them carries ' +
           'their attributes — and they have not signed in during THIS ' +
           'process, so they are not counted among the sign-ins. The counts, ' +
           'the protocols and the per-person event list are statistics and ' +
           'start at zero with everything else.',
           '<strong>A write that fails is logged and never thrown.</strong> ' +
           'If the database goes away, the LDAP operation that triggered the ' +
           'write still succeeds, this service keeps answering out of ' +
           'memory, and the status below turns red with the reason. Nothing ' +
           'is lost by the failure: the next change recomputes the same ' +
           'difference and writes it. A database outage taking down ' +
           'seventeen protocol families that do not need a database is the ' +
           'one failure mode a mock must not have. <strong>The same is true ' +
           'of coordination</strong>: a process that cannot read the change ' +
           'log keeps answering out of its own copy, says so, and catches up ' +
           'when the database comes back — it does not refuse anything in ' +
           'the meantime.'],
    status: slot.forward('persistenceStatusBlock'),
    links: [['/admin/ldap/service', 'the directory, and this same status'],
            ['/admin/ldap/directory', 'every entry in it'],
            ['/admin/realms', 'the realms that are written down with it'],
            ['/admin/config', 'the whole settings table'],
            ['/admin/users', 'the people, restored and otherwise']] },

  // -------------------------------------------------------------------------
  // /admin/cluster (2026-09-14, #46) — several containers against one store.
  // A settings page with a status block, for /admin/persistence's reason: the
  // five cluster.* settings, and what the membership, the leases and the
  // capability table actually say right now.
  // -------------------------------------------------------------------------
  { path: '/admin/cluster', title: 'Cluster',
    lead: '<strong>Whether several copies of this service against one ' +
          'postgres store behave as one service.</strong> Inside one ' +
          'container the processes agree because the front process ' +
          'coordinates them; between containers the only link used to be the ' +
          'change log, so a second container started, looked healthy and ' +
          'gave wrong answers — a code redeemed twice, a signing key one ' +
          'node did not publish, a revocation another node\'s save threw ' +
          'away. <code>cluster.mode</code> decides what happens instead: ' +
          '<code>active-passive</code> (the default in product mode on ' +
          'postgres) lets ONE node serve and makes the others wait before ' +
          'they restore or bind anything; <code>active-active</code> lets ' +
          'every node serve and refuses to start while anything in the ' +
          'capability table below is missing.',
    also: ['<strong>EVERY WRITE IS FENCED.</strong> A clustered node renews ' +
           'a membership row by the database\'s clock, and every transaction ' +
           'it opens checks that row — and, in active-passive mode, the ' +
           'service lease at the token it was acquired with — before it ' +
           'writes anything. A node that paused past its lifetime, lost its ' +
           'lease or lost its database EXITS rather than carrying on, ' +
           'because a node that has lost its right to write and keeps ' +
           'running would try again on every change.',
           '<strong>A TAKEOVER IS ONE HEARTBEAT AFTER A CLEAN STOP</strong> ' +
           '— a stopping node releases its leases — and one lifetime ' +
           '(<code>cluster.nodeTtlMs</code>) after a crash. A standby has ' +
           'restored nothing while it waited, so it restores the store when ' +
           'it takes over; that is seconds, and it is the price of a standby ' +
           'that can never write to a store another node owns.',
           '<strong>THE SETTINGS EVERY NODE MUST SHARE ARE CHECKED.</strong> ' +
           'The Kerberos keys, the mode, the public address and the rest of ' +
           'the list below are compared, as a digest keyed by the ' +
           'key-encryption key, with every live node\'s at startup; a node ' +
           'that differs does not start, because two nodes with different ' +
           'krbtgt keys seal tickets neither can open for the other.'],
    status: slot.forward('clusterStatusBlock'),
    // EVERY OTHER CELL'S CLUSTER (#361): asked before the page is drawn,
    // because the status block is synchronous and the other cells are not.
    prepare: slot.forward('prepareClusterPage'),
    links: [['/admin/persistence', 'the store the cluster is built on'],
            ['/admin/database', 'the database itself'],
            ['/admin/secrets', 'where the key-encryption key comes from'],
            ['/admin/config', 'the whole settings table']] },

  { path: '/admin/ldap', title: 'LDAP / LDAPS',
    lead: '<strong>The embedded directory: RFC 4511 on raw TCP 389, and the ' +
          'same handlers behind TLS on 636.</strong> One store behind both, ' +
          'and it is not a copy of anything — it IS where people, groups, ' +
          'applications, federation relationships and the SPIFFE registry ' +
          'live, so what a SCIM POST writes and what an <code>ldapadd</code> ' +
          'writes are one entry.',
    also: ['<strong>No bind is ever refused.</strong> Any DN, any password, ' +
           'anonymous, on 389 and 636 alike — there is no setting below that ' +
           'changes it, which is why none of them is called ' +
           '<code>authRequired</code>. What the directory is for here is ' +
           'being READ by a client that expects a directory, and a bind that ' +
           'failed would only ever stop that.',
           '<strong>The base DN is the DEFAULT realm\'s directory, and every ' +
           'other realm is a subtree beneath it.</strong> A search scoped to ' +
           '<code>dc=example,dc=com</code> answers from the default realm ' +
           'only; <code>-b "dc=acme,dc=example,dc=com"</code> answers from ' +
           'acme\'s. The realm is in the DN because a socket has no path to ' +
           'put a segment in — see <a href="/admin/realms">Trust realms</a>.'],
    links: [['/admin/ldap/service', 'the directory, and whether both sockets ' +
                                    'came up'],
            ['/admin/ldap/directory', 'every entry, as a tree'],
            ['/admin/users', 'the people in it'],
            ['/admin/groups', 'the groups in it']] },

  { path: '/admin/wstrust', title: 'WS-Trust',
    lead: '<strong>The security token service at <code>/sts</code>, ' +
          'WS-Trust 1.0 through 1.4.</strong> It answers ' +
          '<code>RequestSecurityToken</code> over SOAP for Issue, Validate, ' +
          'Renew and Cancel, in whichever of the four namespace versions the ' +
          'request used, and it will issue a SAML 1.1 or a SAML 2.0 ' +
          'assertion. One setting is its own: who its tokens say issued them.',
    also: ['<strong>What an assertion CONTAINS is configured on the SAML ' +
           'pages</strong>, because it is built by the same two functions ' +
           'the two identity providers use — <a ' +
           'href="/admin/saml-attributes">Custom SAML attributes</a> adds ' +
           'attributes to it, and <code>saml.issuer</code> on <a ' +
           'href="/admin/saml2">SAML 2.0</a> is the Issuer inside the ' +
           'assertion. <code>wstrust.issuer</code> here is the token ' +
           'service\'s own name and they share a default rather than being ' +
           'one setting: they were one until they had to differ, which is ' +
           'the kind of thing that is discovered the hard way.',
           '<strong>Nothing about a request is checked.</strong> An ' +
           '<code>OnBehalfOf</code> or <code>ActAs</code> element names ' +
           'anybody and gets an assertion for them — this service polices no ' +
           'delegation in WS-Trust, which <a href="/admin/delegation">' +
           'Delegation</a> says beside every act it recorded.'],
    links: [['/sts', 'the token service, for a person'],
            ['/sts/cert', 'the certificate its assertions verify against'],
            ['/admin/saml-attributes', 'what goes into the assertion'],
            ['/admin/delegation', 'what was asked for on whose behalf']] },

  { path: '/admin/wsfed', title: 'WS-Federation',
    lead: '<strong>The passive requestor profile at <code>/wsfed</code>, ' +
          'WS-Federation 1.2.</strong> A browser arrives with ' +
          '<code>wa=wsignin1.0</code> and leaves with a SAML 1.1 assertion ' +
          'in a self-submitting form; <code>wa=wsignout1.0</code> ends the ' +
          'session. One setting is its own — the entity ID its metadata and ' +
          'its responses name this service by.',
    also: ['<strong>The assertion is a SAML 1.1 one, so its issuer and its ' +
           'attributes are configured next door.</strong> ' +
           '<code>saml.issuer</code> is on <a href="/admin/saml11">SAML ' +
           '1.1</a> and <a href="/admin/saml2">SAML 2.0</a>, and it is the ' +
           'same setting in both places; <a ' +
           'href="/admin/saml-attributes">Custom SAML attributes</a> decides ' +
           'what the assertion carries. This page links to them rather than ' +
           'drawing a third form onto one value.',
           '<strong>Single sign-on with OAuth 2.0 / OIDC is the point of the ' +
           'require order.</strong> This module is loaded after the ' +
           'authorization server so that both read one session: sign in at ' +
           '<code>/oauth2/authorize</code> and <code>/wsfed</code> knows it, ' +
           'and the other way round.',
           '<strong><code>wauth</code> is honoured, and ' +
           '<code>wreqptr</code> is never dereferenced.</strong> A relying ' +
           'party that demands a security key or two factors the session ' +
           'does not have sends the person to sign in again with the second ' +
           'factor required (a step-up, since 2026-09-17), and is refused ' +
           'only if that one attempt still does not produce it. And this ' +
           'service fetches nothing from a URL a request names.'],
    links: [['/wsfed', 'the profile, for a person'],
            ['/wsfed/rp', 'the mock relying party'],
            ['/FederationMetadata/2007-06/FederationMetadata.xml', 'its ' +
                'metadata'],
            ['/admin/saml-attributes', 'what goes into the assertion']] },

  { path: '/admin/tls', title: 'TLS / mutual TLS',
    lead: '<strong>This service has no TLS listener of its own since ' +
          '2026-09-16: 8443, which asked every connection for a client ' +
          'certificate, and 9443, which required one at the handshake, were ' +
          'both deleted.</strong> The main port already asks and requires ' +
          'none, so the first was a second socket with the same posture as ' +
          'the one every other protocol answers on; what this page ' +
          'configures is the certificate that port and LDAPS 636 present, ' +
          'and what this service makes of a certificate a CLIENT presents.',
    also: ['<strong>What each listener does at the handshake is on <a ' +
           'href="/admin/listeners">Listeners</a> since #423</strong>: TLS ' +
           '1.2 on or off, the TLS 1.3 cipher suites, post-quantum only, ' +
           'and whether a listener asks for a client certificate, requires ' +
           'one, or neither — a required one is verified against the ' +
           'truststore on this page. The TLS settings that were drawn here ' +
           'are drawn there.',
           '<strong>A verified client certificate IS a login since ' +
           '2026-09-05, and it is now <a href="/tls/sign-in">GET ' +
           '/tls/sign-in</a> on the main port.</strong> Presenting a ' +
           'certificate is the CLIENT\'s decision here — this port asks for ' +
           'one and requires none — and the route signs in whoever presented ' +
           'a verified one, for its common name, with the response carrying ' +
           'the cookie. What verification proved is unchanged: a chain to an ' +
           'anchor somebody POSTed to <code>/tls/trust</code>. No token is ' +
           'issued. The session is on <a ' +
           'href="/admin/sessions">Sessions</a> and ends like any other.',
           '<strong>The handshake refusal 9443 performed has no successor, ' +
           'and that is deliberate.</strong> Refusing during the handshake ' +
           'is a property of a SOCKET, and this socket carries OAuth, SAML, ' +
           'SCIM, the console and everything else, so it cannot refuse every ' +
           'caller who has no certificate. A certificate that does not ' +
           'verify is refused where it is USED instead: RFC 8705 client ' +
           'authentication at the token endpoint, <code>/xacml</code>, ' +
           '<code>/scim/v2</code> and the sign-in above.',
           '<strong>One self-signed certificate, regenerated on every start, ' +
           'is shared by two sockets</strong> — LDAPS 636, and the main port ' +
           'when <code>global.https</code> is on — so a caller trusts this ' +
           'service once rather than twice. The names and ' +
           'addresses below are what goes into it, which is why they are ' +
           'restart-only: it is minted before anything is listening.',
           '<strong>Whether the MAIN port is HTTPS is not here.</strong> ' +
           '<code>global.https</code> is on <a ' +
           'href="/admin/config">Configuration</a> with the rest of the ' +
           'process\'s own settings, and it defaults to whatever ' +
           '<code>oauth2.rfc9700</code> is — RFC 9700 section 2.1 says an ' +
           'authorization response must not travel over an unencrypted ' +
           'connection, and the authorization endpoint is on that port.'],
    links: [['/tls', 'the certificate, the truststore and the main port\'s ' +
                'posture'],
            ['/tls/trust', 'the certificate, to trust it'],
            ['/tls/forwarded', 'what a proxy said about the connection'],
            ['/admin/spiffe', 'the one place a certificate authenticates']] }
];


// ---------------------------------------------------------------------------
// GET /admin/federation, POST /admin/federation
//
// THE ONE PAGE IN THIS CONSOLE THAT CONFIGURES A REFUSAL.
//
// Every other page here either reports what happened or widens what this
// service will accept. This one is the opposite in both directions, and the
// page says so at the top rather than leaving it to be discovered: a
// relationship is created DISABLED, an assertion is refused unless it verifies
// against the certificate configured on it, and a relationship that is enabled
// but half-configured refuses rather than half-working.
//
// It reads and writes ONE store — `ou=federations`, through
// `federation/federation.js` — and holds nothing of its own, like every other
// page in this file. What it deliberately does NOT hold is anything the
// applications registry already holds: an identity-provider-side relationship
// NAMES an application and stops, so its entityID, its redirect URIs and its
// certificate stay on `/admin/applications` where every protocol module reads
// them.
// ---------------------------------------------------------------------------
// The caveat and the links of the federation pages are `federationCaveat()`
// and `federationLinks()`.


// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The admin console: its pages, its shell and furniture for pages drawn in
 * other modules, the views `/admin-api` answers from, and the slots other
 * modules fill.
 *
 * The functions forward to the AdminConsole instance the composition root
 * installs; `registerRoutes` is called by `common/protocol_stack.ts`.
 * @namespace
 */
const consoleExports = {
  registerRoutes: slot.forward('registerRoutes'),
  AdminConsole: AdminConsole,
  /** Installs the instance the composition root built. */
  installInstance: (instance: AdminConsole): void =>
    slot.install(instance),
  /** Says where the installed instance came from. */
  instanceOrigin: (): string => slot.origin(),
  // THE SHELL, written for the first module outside this file that drew a
  // console page (many do now — `crypto_metadata.js`, `pki_admin.js`, the
  // `*_admin.js` of several families, `ldap_server.js`):
  // `../sts_metadata.js`, which builds `/admin/sts-metadata` from the live
  // express router and cannot live in here (it must be the LAST module
  // server.js loads, or it would be the reason a route is missing from its own
  // list). `respond()` is what it calls; `page()` is exported beside it because
  // a caller that needed the shell without the ?format=json half would
  // otherwise reimplement respond() badly. Neither decides anything: what that
  // page SAYS is entirely that module's.
  // The notice or error a redirect brought back, for the family pages drawn
  // outside this file (EST, SCEP, GNAP). Unexported until #70, so those pages
  // tested for it, found nothing and never showed one.
  // For `tests/protocol_endpoints.js`: which Protocols pages the endpoint
  // table and `SECTIONS` disagree about. See above respond().
  protocolEndpointDrift: slot.forward('protocolEndpointDrift'),
  page: slot.forward('page'),
  // /admin/realms, list and drill-down, as the route draws it: read by
  // tests/realm_retiring.js, which has no console session to reach the page
  // over HTTP with, to see a realm stuck half removed (#294).
  // AND FOR A SECOND MODULE SINCE THE XACML WORK: `xacml/xacml_admin.ts`
  // draws the /admin/xacml pages (four then, six now) the way
  // `ldap/ldap_server.js` draws its (then five, now eight). Those two helpers
  // were private only because nothing outside this file had needed them — a
  // page drawn elsewhere still wants the settings
  // block for its own group, and still has to answer a form POST the way every
  // other action here does. Keeping them private would have meant a second
  // settings renderer and a second redirect-or-JSON rule, and two of either is
  // how a console starts behaving differently on different pages.
  configFormsFor: slot.forward('configFormsFor'),
  // The tab panels an application's page is drawn in, for a page drawn
  // elsewhere that wants the same tabs (/admin/listeners, #423).
  setXacmlPages: slot.forward('setXacmlPages'),
  // The JSON counterpart of the block above, so that a page drawn
  // elsewhere can answer ?format=json with the SAME settings it just
  // rendered. `protocolSettingsJsonFor()` is not that function — it is
  // keyed by PROTOCOL_SETTINGS_PAGES and throws for a path that table
  // does not carry, which is correct for the pages this file generates
  // and wrong for one somebody else draws.
  configSettingsJson: slot.forward('configSettingsJson'),
  // ---------------------------------------------------------------------
  // THE ACTIONS ARE NOT HERE ANY MORE (2026-09-12). All thirty-one live in
  // `admin-core/admin_actions.ts`, which `mgmt-api/admin_api.ts` requires
  // directly — so the management API no longer reaches its decisions through
  // the console module.
  //
  // They are deliberately NOT re-exported from here. Aliasing them back into
  // this file's scope (see the block below the requires) is what keeps the
  // several hundred call sites in this file unchanged; re-exporting them as
  // well would publish a SECOND way to reach the same function, and the
  // second way is the one that goes stale.
  // ---------------------------------------------------------------------
  // A claim set's section, for tests/attribute_claims.js (#94).
  claimSetSection: slot.forward('claimSetSection'),
  // For `admin-ui/pki_admin.ts`, whose key-pair controls are drawn on an
  // application's page too — see applicationReturnTo().
  // And the trail a page drawn there hangs under, so the one-time key page an
  // issue from a person's own page answers with is `Users › Signing key pair`
  // rather than a page with no way up.
  // THE FOLDS AND THE TOOLTIPS, for the same one module. They are exported for
  // the reason page() is: `sts_metadata.js` draws a console page, and a page
  // drawn in this console's shell whose prose did not fold would be the one
  // page here that is still a wall of text — which is exactly what it was,
  // being the longest page in the service. See the block above note().
  note: slot.forward('note'),
  warn: slot.forward('warn'),
  bullet: slot.forward('bullet'),
  tip: slot.forward('tip'),
  // Filled by ldap_server.js at its require time; see the note above it.
  setDirectoryReader: slot.forward('setDirectoryReader'),
  // THE NINTH SLOT, filled by the same module, and the views behind it. See
  // the block above setDirectoryPages().
  setDirectoryPages: slot.forward('setDirectoryPages'),
  // ---------------------------------------------------------------------
  // THE LIST-PAGE FURNITURE, WRITTEN FOR THE FIRST MODULE OUTSIDE THIS
  // DIRECTORY THAT DREW LIST PAGES IN THIS SHELL (the certificate-enrollment,
  // GNAP and OAuth monitor pages use it too now).
  //
  // `ldap/ldap_server.js` has drawn its /admin/ldap/* pages since 2026-09-01
  // (five then, eight now), and they are real list pages: the directory dump
  // is one row per entry over a store with a cap in the hundreds, so it pages
  // exactly the way
  // /admin/applications and /admin/tokens page. Exported for the same reason
  // page(), note() and tip() are exported to sts_metadata.js — a page drawn
  // in this console's shell with a paging control of its own invention would
  // be the one control here that behaves differently, and the reader would
  // have no way to know which one it was.
  //
  // What crosses is the FURNITURE and never the data: nothing in this list
  // decides what a page contains. `esc` goes with them because every one of
  // them returns markup and a caller building a cell beside them needs the
  // same escaping — ldap_server.js's own xmlEscape() is the same function,
  // and passing this one keeps a single answer to "what is escaped how" on
  // pages that mix the two.
  // ---------------------------------------------------------------------
  esc: slot.forward('esc'),
  tile: slot.forward('tile'),
  clipped: slot.forward('clipped'),
  clippedValues: slot.forward('clippedValues'),
  pageNavPair: slot.forward('pageNavPair'),
  // For `admin-ui/pki_admin.ts`, whose two key-pair tables share one `per`
  // (2026-09-13) — the same control every multi-list page here draws.
  // For the same page's four kinds of section (2026-09-30): a search box over
  // each paged list, the one every multi-list page here draws.
  queryWith: queryWith,
  // Filled by spiffe_server.js at its require time, for the reason beside the
  // requires at the top: this file must not require that module.
  setSpiffeReader: slot.forward('setSpiffeReader'),
  setScimReader: slot.forward('setScimReader'),
  setGroupReader: slot.forward('setGroupReader'),
  setDirectoryWriter: slot.forward('setDirectoryWriter'),
  setGroupWriter: slot.forward('setGroupWriter'),
  // Filled by logout/logout.ts at ITS require time — the sixth slot, and rule
  // 3e's test answers yes for the same two reasons at once. See the block above
  // setLogoutReader().
  setLogoutReader: slot.forward('setLogoutReader'),
  // Filled by ./crypto_metadata.js at ITS require time — the seventh, and the
  // third to pass rule 3e's test both ways round. See the block above
  // setCryptoReporter().
  setCryptoReporter: slot.forward('setCryptoReporter'),
  // Filled by ../ssf/ssf.ts at ITS require time — the eighth, and the fourth
  // to pass rule 3e's test both ways round. See the block above
  // setSignalsReporter().
  setSignalsReporter: slot.forward('setSignalsReporter'),
  // Filled by ../common/protocol_stack.ts on the line after it requires
  // ../tls/tls_server.js — the thirteenth, and the one slot here NOT filled by
  // the module that owns what it carries. See the block above setTruststore().
  setTruststore: slot.forward('setTruststore'),
  // The Shared Signals page's view and its four actions, for admin_api.js.
  // Rule 7: the API calls exactly these, so an action added to that switch is
  // most of adding it there. `ssfAction` RESOLVES rather than returning — it
  // is the only action function in this console that does, because
  // transmitting a Security Event Token signs a JWS and POSTs it to somebody
  // else's endpoint.
  /**
   * Returns the Shared Signals page's action names, or none while the SSF
   * reporter slot is empty.
   *
   * @returns the action names
   */
  ssfActionNames: function () {
    log.debug("Entering ssfActionNames().");
    log.debug("Leaving ssfActionNames().");
    return signalsReporter ? signalsReporter.actions.slice() : [];
  },
  // Filled by ../ssf/ssf.ts at ITS require time — the ninth, and the fifth to
  // pass rule 3e's test both ways round. A SECOND slot rather than more
  // members on the eighth, because "what streams exist" and "what has been
  // said about which session" are two questions with two pages, and one
  // object carrying both would make /admin/ssf fail whole when the CAEP half
  // was not installed. See the block above setCaepReporter().
  setCaepReporter: slot.forward('setCaepReporter'),
  // THE TENTH SLOT, filled by the same module for RISC. See
  // setRiscReporter()'s header on why it is a third object rather than
  // more members on the ninth.
  setRiscReporter: slot.forward('setRiscReporter'),
  // The CAEP view and its three actions, for admin_api.js. Rule 7: the API
  // calls exactly these. `caepAction` RESOLVES, like `ssfAction` and for the
  // same reason — emitting a CAEP event signs a JWS and POSTs it.
  // EVERY LIVE SESSION, for admin_api.js — the same function the page draws
  // from, so the console and the management API cannot come to disagree about
  // who is signed in. It takes the whole request because the filter and the
  // paging are query parameters, which is the shape every list view here has.
  // The sessions register as /admin/caep-sessions draws it — the list, or one
  // session with `?session=`. Rule 7: that page is a page of this console and
  // owed an operation of its own.
  /**
   * Returns the CAEP page's action names, or none while the CAEP reporter
   * slot is empty.
   *
   * @returns the action names
   */
  caepActionNames: function () {
    log.debug("Entering caepActionNames().");
    log.debug("Leaving caepActionNames().");
    return caepReporter ? caepReporter.actions.slice() : [];
  },
  // The RISC view and its three actions, on exactly the CAEP pair's terms.
  // `riscAction` RESOLVES for the same reason: emitting a RISC event signs a
  // JWS and POSTs it.
  // The account register as /admin/risc-accounts draws it — the list, or one
  // account with `?account=`.
  /**
   * Returns the RISC page's action names, or none while the RISC reporter
   * slot is empty.
   *
   * @returns the action names
   */
  riscActionNames: function () {
    log.debug("Entering riscActionNames().");
    log.debug("Leaving riscActionNames().");
    return riscReporter ? riscReporter.actions.slice() : [];
  },
  // The crypto report, for admin_api.js. One function, so the page and the API
  // cannot disagree about what this service's cryptography is.
  // The key inventory and the export, for admin_api.js. Two functions rather
  // than one because LISTING what this process holds and HANDING A KEY OVER
  // are different acts, and only the second needs Admin Write.
  // For crypto_metadata.js's export route, which is the only caller.
  // The sign-out page's view and its four actions, for admin_api.js. Rule 7:
  // the API calls exactly these, so an action added to that switch is most of
  // adding it there — and the refusal sentence that names the four is what the
  // repository's own tests/vendored/admin_api.js reads to check the parity.
  jtiFrom: jtiFrom,
  // The four action functions. admin_api.js calls exactly these — it decides
  // nothing about a revocation or a claim that this console does not — which is
  // what makes "every /admin control has an /admin-api operation" a property of
  // the code rather than a promise in a comment.
  // The trust realm registry's five writes and its whole view, for
  // mgmt-api/admin_api.ts. Rule 7 — every page of this console and every action
  // of its handlers has an operation on /admin-api, driven through the SAME
  // function, so that a realm created over the API and a realm created on the
  // form cannot come to mean two different things.
  // The token-lifetimes page's own action. It writes through config.js like
  // configAction does — see the header above it for why it is a page of its own
  // and not four more rows on /admin/config — and it is exported separately
  // because rule 7 is about the CONTROL: the form on that page has two actions,
  // so the API has two operations, and pointing them at configAction instead
  // would give a caller a door that took any setting config.js holds under a
  // name that promised six (`TOKEN_LIFETIME_KEYS`).
  // THE TWO NARROW DOORS' KEY LISTS, for mgmt-api/admin_api.ts to BUILD their
  // request schemas from rather than to keep a second copy of.
  //
  // Both had gone stale in exactly the way a second copy does. The document
  // named four token-lifetime settings where the handler accepted six, and
  // THREE assertion settings where it accepted sixteen — and these are the two
  // operations whose whole claim is that they refuse anything outside their
  // own list BY NAME, so a caller reading the document is refused for
  // following it, and a caller reading the refusal finds settings the document
  // never mentioned. Derived, that cannot happen: adding a row to either table
  // adds the property.
  // The JSON views, one per page, for the same reason. See the block comment
  // The protocol settings pages (PROTOCOL_SETTINGS_PAGES — eight when this was
  // written, thirteen as of 2026-09-16), through ONE export keyed by path.
  // Rule 7 wants an operation per page, all answering the same shape — one
  // exported function per page would have been that many names for one call.
  // There is no action beside it, and that is the rule read exactly: every
  // form on those pages posts `set-many` to /admin/config, which
  // `POST /admin-api/config/set-many` already mirrors. A second POST per page
  // would be that many more doors onto one function.
  protocolSettingsJsonFor: slot.forward('protocolSettingsJsonFor'),
  preparedSettingsJsonFor: slot.forward('preparedSettingsJsonFor'),
  // Where each group of settings is drawn, for the API's own /config resource
  // and for anything that wants to send a person to the right page.
  /**
   * Lists where each group of settings is drawn: the group, its pages and
   * their labels.
   *
   * @returns one `{ group, pages, labels }` per settings group
   */
  settingHomes: function () {
    log.debug("Entering settingHomes().");
    const instance = slot.get();
    log.debug("Leaving settingHomes().");
    return SETTING_HOMES.map(function (row) {
      return { group: row.group, pages: row.pages,
               labels: row.pages.map(instance.labelOfPath.bind(instance)) };
    });
  },
  // above consoleJson().
  consoleJson: slot.forward('consoleJson'),
  dashboardJson: slot.forward('dashboardJson'),
  shellJson: slot.forward('shellJson'),
  stylesheet: slot.forward('stylesheet'),
  // The audit log's view is the whole function rather than a JSON builder, for
  // the reason the block above consoleJson() gives: the filtering and the
  // paging are work both the page and the API need, and two copies of it would
  // be two answers that each looked right alone. The delegation page's view,
  // and the whole function for the same reason the audit log's is: the
  // filtering, the paging and the collapse to chains are work both the page and
  // the API need. It is the second read-only resource here — rule 7 asks for an
  // operation per CONTROL, and this page has none. THE CONFIGURED HALF OF THAT
  // PAGE, and the reason the sentence above it no longer describes the whole
  // route. `/admin/delegation` has five controls now, all of them on this
  // register, so rule 7 asks for five operations — `admin_api.js` calls exactly
  // this function for all of them, which is what keeps the API from deciding
  // anything the console does not. The view is exported beside it for the same
  // reason `delegationView` is: the walk of the registry and the resolution of
  // both directions are work both need, and two copies of it would be two
  // answers that each looked right alone. The action names, read by
  // admin_api.js so that its operations and this console's switch cannot come
  // to name different things. Built from the same constant the refusal sentence
  // is built from.
  /**
   * Returns the delegated permission register's action names.
   *
   * @returns a copy of PERMISSION_ACTIONS
   */
  permissionActionNames: function () {
    log.debug("Entering permissionActionNames().");
    log.debug("Leaving permissionActionNames().");
    return PERMISSION_ACTIONS.slice();
  },
  // The consent register, its four actions and their names — the same three
  // exports the delegated permission register has, for rule 7's reason: the
  // management API mirrors the page and reads the action list to check it.
  /**
   * Returns the consent register's action names.
   *
   * @returns a copy of CONSENT_ACTIONS
   */
  consentActionNames: function () {
    log.debug("Entering consentActionNames().");
    log.debug("Leaving consentActionNames().");
    return CONSENT_ACTIONS.slice();
  },
  // The role register, its five actions, their names and the two closed
  // vocabularies they take — the same shape the consent register above has,
  // for rule 7's reason: the management API mirrors the page and reads the
  // action list to check it. `rolesPreview` is exported too, because the dry
  // run is a control on that page and rule 7 gives every control an operation.
  /**
   * Returns the role register's action names.
   *
   * @returns a copy of ROLE_ACTIONS
   */
  rolesActionNames: function () {
    log.debug("Entering rolesActionNames().");
    log.debug("Leaving rolesActionNames().");
    return ROLE_ACTIONS.slice();
  },
  /**
   * Returns the kinds of member a role may have.
   *
   * @returns a copy of ROLE_MEMBER_KINDS
   */
  roleMemberKinds: function () {
    log.debug("Entering roleMemberKinds().");
    log.debug("Leaving roleMemberKinds().");
    return ROLE_MEMBER_KINDS.slice();
  },
  // The ELEVENTH slot, filled by `xacml/xacml_role_pep.ts` at 23c. See its
  // header: a require in either direction fails rule 3e's test.
  setRolePreviewer: slot.forward('setRolePreviewer'),
  // A person's page and the new-user form, for tests/person_fields.js.
  // The create page's own view, for GET /admin-api/users/new. Rule 7, and the
  // same argument `newApplicationView` makes below: what it answers is the
  // CATALOGUE the create takes — every attribute a person here may be given,
  // with the claim each one reaches — so a caller of POST
  // /admin-api/users/create learns what may go in `attributes` from the
  // service rather than from a copy of the list in a document. There is no
  // `newUserAction` beside it, on purpose: that page's form posts
  // `action=create`, which `usersAction()` already answers, and a second
  // operation would be a second door onto one function pretending to be two.
  // The create page's own view, for GET /admin-api/applications/new. Rule 7:
  // every page of this console has an operation, and this one is worth more
  // than most as an API — what it answers is the two CLOSED VOCABULARIES the
  // create takes (the kinds and the protocol families), so a caller learns what
  // it may send from the service rather than from a copy in a document. There
  // is no `newApplicationAction` beside it on purpose: this page's form posts
  // `action=create` to /admin/applications, so the operation that mirrors its
  // control already exists and a second one would be a second door onto one
  // function pretending to be two.
  // The three SPIFFE views and their three action handlers. admin_api.js calls
  // exactly these — rule 7 again: the API decides nothing the console does not,
  // and an action added to one of these switches is most of adding it there.
  // The SAML 2.0 identity provider page and its four writes. Rule 7 again: the
  // API calls exactly these, so an action added to that switch is most of
  // adding it to /admin-api.
  // The roles page and its two writes. Rule 7 again — and this one is the page
  // most in need of the API half rather than least: `POST
  // /admin-api/rbac/grant` is gated by an access token rather than by the
  // console's roles (since 2026-09-09; `adminApi.authRequired`), so it is a
  // door onto the roster that does not depend on anybody already holding a
  // console role — which is what it was written for when the API was ungated
  // and `admin.openWhenEmpty` was off.
  // `mfaView` is gone (2026-09-12): the page it belonged to split into
  // /admin/totp and /admin/webauthn and its columns moved onto /admin/users,
  // so nothing here drew from it. It is `adminViews.mfaRosterJson()` now —
  // the resource, and only the resource.
  // The federation register's page and its seven writes. Rule 7 again: the API
  // calls exactly these, so an action added to that switch is most of adding it
  // to /admin-api. This one matters more than most —
  // `POST /admin-api/federation/create`, with an access token (the API is
  // gated since 2026-09-09), is how a test configures a partner with no
  // browser at all, which is the only way the feature can be exercised
  // automatically.
  // The gate's answer for one request, so admin_api.js's own /rbac view can say
  // WHO IS ASKING without a second reading of the cookie that could disagree
  // with this one.
  // The SAML half of the same store, as its own view, because it is its own
  // page: GET /admin-api/saml-attributes answers this and GET /admin-api/claims
  // answers the one above. There is no third function underneath them — both
  // are claimSetsJson() with a different list of set ids and the one rule that
  // is theirs alone.
  // The third view onto the same store, for GET /admin-api/userinfo-claims.
  // Same reasoning as the line above it: it is its own page, so it is its own
  // operation, and underneath the three of them is one claimSetsJson() with a
  // different list of set ids and the one rule that is each family's alone.
  // The `request` query parameter /admin/userinfo-claims previews a claims
  // request from. Exported for the reason claimsPreviewUser is: the API takes
  // the same parameter, and a second reader of that query string would be a
  // second cap.
  // Which person the claims page shows attribute values for. Exported for the
  // same reason vcPreviewUser is: GET /admin-api/claims takes the same `user`
  // parameter, and a second reader of that query string would be a second cap
  // and a second default.
  // The TRAFFIC view, for GET /admin-api/scim/monitor. Rule 7: every page
  // of this console has an operation that mirrors it, and this one has no
  // POST beside it because the page has no control — the reset was
  // refused rather than forgotten. See the header on scimMonitorJson().
  // THIS CONSOLE'S OWN SHARED SIGNALS INBOX. Rule 7: `/admin/signals` is a
  // page, so `/admin-api/signals` mirrors it, and both answer with this one
  // function — the reason every parity pair here does.
  SIGNALS_CONSOLE_ACTIONS: SIGNALS_CONSOLE_ACTIONS,
  configJson: slot.forward('configJson'),
  // It takes the REQUEST, unlike most of the views here, and for a reason worth
  // the line: every URL it prints is built from the one the call arrived on —
  // that is what makes a realm's base URL correct through a published port, on
  // a compose network and behind a proxy alike, and a snapshot built without a
  // request could only ever name localhost.
  // A body field that may appear more than once. Exported because the
  // management API takes the same two spellings of a list (`attribute` and
  // `attributes`), and reading a repeated form field is not something
  // helpers.parseBody() can answer.
  listField: slot.forward('listField'),
  // The console's own paging rules, so that /admin-api reports and clamps `per`
  // and `page` the way every page here does rather than inventing a second
  // ceiling. The drill-downs' session blocks start smaller, and the API
  // documents that number rather than repeating it: a document saying 50 beside
  // a service doing 5 is worse than a document that says nothing.
  DEFAULT_BLOCKS_PER_PAGE: DEFAULT_BLOCKS_PER_PAGE
};

export = consoleExports;
