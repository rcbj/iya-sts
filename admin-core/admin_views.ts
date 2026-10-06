// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_views.ts
//
// ===========================================================================
// WHAT THE TWO ADMIN SURFACES BOTH READ. The other half of `admin_actions.ts`,
// and the half that could not simply be moved.
//
// The actions came across on 2026-09-12 verbatim, because not one of them had
// ever touched `req`, `res` or markup. **The views were not like that**: a
// `*View()` on the console returns `{ json, inner }` — the machine answer and
// the HTML — computed together from one pass over the data, which is the
// strongest form of rule 7 there is. A page and its operation cannot disagree
// when one function computes both.
//
// So the split had to be made on a measurement rather than a hunch. Of the
// eighty-nine view-shaped functions in `admin-ui/admin.ts`, forty-six return a
// json half, and **only three of those separate at a clean boundary** — the
// other forty-three build row markup part-way through the computation, inside
// the `.map()` that walks the rows. Splitting those is real surgery on
// interleaved code and is NOT what this file is.
//
// **THIS FILE IS THE PART THAT NEEDED NO SURGERY.** Thirty-seven functions
// that were already pure: they compute a JSON answer and reach no markup at
// all, directly or through anything they call. They moved exactly as the
// actions did, with the comments that argued them, and the behaviour is
// intended to be identical to the line.
//
// ---------------------------------------------------------------------------
// WHAT STAYED BEHIND, AND THE LINE IS NOT "IS IT PURE".
//
// Two kinds of thing are still on `admin-ui/admin.ts` and belong there:
//
//   * **Anything that builds HTML**, which is the forty-three above plus the
//     views that wrap them. That is the next increment and it is bespoke.
//   * **THE CONSOLE'S OWN STRUCTURE**, even though it is perfectly pure:
//     `consoleJson()` (which pages exist, from `NAV`), `configJson()` and
//     `settingsGroupsFor()` (where a settings group is edited, from
//     `SETTING_HOMES`), `protocolSettingsJsonFor()` and
//     `configSettingsJson()`. A caller asking *what pages does this console
//     have* and *where is this setting edited* is asking the console about
//     itself, and the answer is not a thing a layer beneath it could know.
//     Purity was not the test; ownership was.
//
// `scimJson()` is the one function here that reaches back for that knowledge —
// it embeds the SCIM settings block in its answer — and it does so through
// `configSettingsJson`, which the console hands over like any other
// collaborator. The alternative was for the console page and
// `/admin-api/scim` to assemble that block separately, which is precisely the
// drift rule 7 exists to prevent.
//
// ---------------------------------------------------------------------------
// THE SAME TWO RULES AS `admin_actions.ts`, FOR THE SAME REASONS.
//
// No route may be registered here — two modules require this file, so a route
// would have been registered twice while a require was a registration (rule
// 1, until #50's R1) and the second could never win; since R1 it would belong
// to neither surface's `registerRoutes()`. And
// nothing here may build markup: the moment one of these functions returns a
// string with a tag in it, the console is no longer the only thing that
// renders and there are two places a page can come from.
//
// It may be required at 18 or later and nowhere earlier, for
// `admin_actions.ts`'s reason: the modules below include route-registering
// ones, and from `common/` or from anything earlier in the order this file
// would pull them into the router ahead of themselves — or, for the ones
// converted by #50's R1, which register nothing when required, run their
// load-time work ahead of the order `common/protocol_stack.ts` argues.
// `tests/admin_actions_layer.js` pins every one of these.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AdminViews` takes every module this file used to require, the
// helpers it destructured, the two session readers of `authn.ts` and the
// three functions it borrows from `admin_actions.ts` through its constructor,
// typed as `typeof` each. Every view is a method. Since R2 the composition
// root (`common/protocol_stack.ts`) builds the instance, and the module's old
// names are FACADES that forward to it, for the console, the management API,
// the view/action layers of the other families and the tests; a process
// without the root builds a default at load. `AdminViews` is exported beside
// them for the root.
//
// **THE FORWARDED COLLABORATORS STAY MODULE-LEVEL `let`s**, each with ONE
// writer — its setter, a method the console still calls through the module's
// exports — which is what `tests/admin_actions_layer.js` asserts. The tables
// shared with the action half stay module-level constants read from it.
// ---------------------------------------------------------------------------

// The helpers this half reaches for. `baseUrlOf` builds the issuer and endpoint
// URLs `realmsJson()` reports and `stsKeysFor` is the per-realm key set
// `keysView()` describes. Both were missed on the first pass — the
// destructure they come from in admin-ui/admin.ts is spread over thirty
// comment-interleaved lines, which is the same trap that cost the action
// half `numberWord` and `signJwt`. The symptom was `GET /admin-api/realms`
// answering 500 with `baseUrlOf is not defined`, found by the job that
// drives all 273 operations and by nothing else.
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// The credential store, for the ways-in list the new-person form offers.
import credentials = require('../common/credentials');
// The two second factors, for the roster columns on /admin/users.
import totp = require('../common/totp');
import webauthnPolicy = require('../authn/webauthn_policy');
import backupCodes = require('../common/backup_codes');
// App passwords (#101): a LIBRARY, for the scope catalogue and the settings.
import appPasswords = require('../common/app_passwords');
import identityAssurance = require('../common/identity_assurance');
import siop = require('../oid4vc/siop');
import devices = require('../common/devices');
// #221: service accounts, tagged on the people list and described on a
// person's page, and the policy that governs them.
import serviceAccounts = require('../common/service_accounts');
import serviceAccountPolicy = require('../common/service_account_policy');
// THE SIGN-ON SESSION MAP, which `signOnSessionRows()` walks. It is the same
// destructured-require trap one module along: admin.js pulls fourteen names
// out of two modules through multi-line destructures, and a name taken from
// the second one is exactly as invisible to a move as one taken from the
// first. `authn` is position 8 in the require order, so this is a cache hit
// wherever this file is legitimately loaded.
import authn = require('../authn/authn');
import config = require('../common/config');
// The store's own status, for what a page says about whether its state
// survives a restart (#446). A library, required in the ordinary direction.
import persistence = require('../persistence/persistence');
import mode = require('../common/mode');
import realms = require('../common/realms');
import stats = require('../common/admin_stats');
import oidcRp = require('../common/oidc_rp');
import rbac = require('../admin-ui/admin_rbac');
import vcClaims = require('../oid4vc/vc_claims');
import vpConfig = require('../oid4vc/vc_verifier_config');
import claimAttributes = require('../common/claim_attributes');
import scimMap = require('../scim/scim_map');
import groupClaims = require('../common/group_claims');
import applications = require('../common/applications');
// A PERSON's assertion key pairs, for the Credentials section of their own
// page (2026-09-13). A library: it holds no store and registers no route.
import personAssertions = require('../common/person_assertions');
// Whether a private key written onto an entry is sealed at rest, which is
// `persists()` and not `sealed()` — `person_assertions.js` argues why.
import keystore = require('../common/keystore');
// THE CERTIFICATE AUTHORITY, for the Credentials section of an application's
// page: whether this realm can issue a key pair at all, and from what. A
// LIBRARY (rule 3) — it registers no route — so requiring it here moves
// nothing.
import pki = require('../common/pki');
import nodeCrypto = require('crypto');
import appPermissions = require('../common/app_permissions');
import consent = require('../common/consent');
import roles = require('../common/roles');
// THE PASSWORD POLICY REGISTER (2026-09-12), for /admin/policies. A leaf that
// registers no route, so this require is a cache hit wherever it is reached.
import passwordPolicy = require('../common/password_policy');
// THE KINDS OF POLICY ON THAT PAGE (#64): the password policy, the
// authentication policy, and whatever is defined next. A library.
import policyKinds = require('./policy_kinds');
// THE DELEGATION PICTURE'S RENDERER (#446), for `delegationMapModel()`. A
// LIBRARY (rule 3): it registers nothing and requires nothing of this
// service but `helpers.js`, so it cannot move a route or join a cycle —
// the terms `admin_rbac` above is required on.
import WebKit = require('../admin-ui/web_kit');
import delegationMap = require('../admin-ui/delegation_map');
// THE UNION OF THE IDENTITY AND DELEGATION REGISTERS (#446), for the
// delegation pages' person chooser. A library (rule 3p) that registers no
// route.
import userGraph = require('../common/user_graph');
// ONE CREDENTIAL'S LINEAGE (#446), for `/admin/tokens/credential`. A
// library in `common/` that registers no route.
import credentialGraph = require('../common/credential_graph');
// THE FEDERATION PICTURE (#446): the graph and its renderer, libraries that
// register no route.
import federationGraph = require('../federation/federation_graph');
import federationDiagram = require('../admin-ui/federation_diagram');
import authnPolicy = require('../common/authn_policy');
// Four more with the second batch: the audit log the audit view pages, the
// delegation register the delegation view reads, the Kerberos principal
// database beside it, and the token registry /admin/tokens lists.
import auditLog = require('../common/audit');
// THE ERROR CODE TABLE. A leaf that requires nothing, so it cannot close a
// cycle from here; `errorCodesView()` below is its one reader in this layer.
import errorCodes = require('../common/error_codes');
// THE USED-ASSERTION HISTORY (2026-09-13), for `/admin/used-assertions` and
// `GET /admin-api/used-assertions`. A LIBRARY in `common/` that requires
// nothing here, so the require moves no route and closes no cycle.
import usedAssertions = require('../common/used_assertions');
import delegation = require('../common/delegation');
// WHO MAY ACT FOR WHOM AT WS-TRUST AND THE TOKEN EXCHANGE (#108), for the
// policy section of /admin/delegation and GET /admin-api/delegation/policy.
// A library in `common/` that registers nothing.
import delegationPolicy = require('../common/delegation_policy');
import krb5Principals = require('../kerberos/krb5_principals');
// Stored Kerberos keys (2026-09-12), a plain require for the reason
// `admin_actions.ts` gives beside its own.
import krb5PersonKeys = require('../kerberos/krb5_person_keys');
// A PERSON'S ATTRIBUTE EDITOR (#228): which attributes an administrator may
// change, with what the entry holds. A library whose directory arrives
// through its own slot, so this require loads no route module.
import personEditor = require('../ldap/person_editor');
// RFC 9728's well-known path, which the new-application form names (#446).
import resourceMetadata = require('../oauth-oidc/protected_resource_metadata');
import oauth2 = require('../oauth-oidc/oauth2');
// The recent back-channel logout deliveries (2026-09-17, #36), which the
// sign-out page lists so a delivery queued as `pending` can be seen to have
// arrived or not. A library that registers no route.
import backchannel = require('../oauth-oidc/backchannel_logout');
// RFC 7591 section 2.3 (2026-09-13): what a statement on an entry says, and the
// settings that decide what one is worth. A library that registers no route.
import softwareStatement = require('../oauth-oidc/software_statement');
import assertionGrant = require('../oauth-oidc/assertion_grant');
// RFC 8705 (2026-09-13): the TLS client certificates an application holds, the
// five subject parameters it may register instead, and whether the main port
// can bind a token at all. Three libraries that register no route.
import tlsClientCertificates = require('../common/tls_client_certificates');
import certificateSubject = require('../common/certificate_subject');
import mtls = require('../oauth-oidc/mtls');
// The two SAML profiles, for the artifact and pending-request counts their
// pages publish.
import saml2 = require('../saml/saml2_sso');
import saml11 = require('../saml/saml11_sso');
// Whether a service provider's requests must be signed (#37), for the
// drill-down. A library that registers nothing.
import requestSignature = require('../saml/request_signature');
// How current a service provider's consumed metadata is, and what the
// background refresher last found (#37 follow-up). Already required by
// `admin_actions.ts`, so this closes no cycle.
import spMetadata = require('../saml/sp_metadata');
import authorizationServers = require('../oauth-oidc/authorization_servers');
import federation = require('../federation/federation');
// A federationLink's format (#109): a static utility class.
import fedLinks = require('../federation/federation_links');
// What a partner encrypts to (#168), for the relationship's page and API.
import fedEncryption = require('../federation/federation_encryption');
// The receiver half of Shared Signals, which the three reports below draw
// this service's own registered streams from.
import signals = require('../ssf/ssf_receivers');
// The SPIFFE libraries the three reports below read: the registry that holds
// the entries, the authority that signs an SVID, and the authenticator whose
// per-method table the SPIRE Server API is authorized against.
import spiffeRegistry = require('../spiffe/spiffe_registry');
import spiffeCa = require('../spiffe/spiffe_ca');
import spiffeAuth = require('../spiffe/spiffe_auth');

// ---------------------------------------------------------------------------
// THE TABLES AND HELPERS THIS HALF SHARES WITH THE OTHER ONE. They went to
// `admin_actions.ts` when the actions moved, because that is where they are
// DISPATCHED on — and a view reads the same table to draw the buttons, or to
// report which settings a page owns. One table, two readers, which is the
// arrangement that stops a page offering a control its action does not have.
//
// This is the only require between the two halves and it goes ONE WAY:
// nothing in `admin_actions.ts` reaches back here, and it must not — a view
// is a thing an action has no business consulting.
// ---------------------------------------------------------------------------
import adminActions = require('./admin_actions');
import issuanceGate = require('../common/issuance_gate');
// The signing-key history (#42's follow-up). A LIBRARY over `realms` and
// `error_codes` that reaches `helpers` and `pki` lazily, so requiring it here
// closes no cycle and moves no route.
import signingHistory = require('../common/signing_history');
const SAML2_SP_KIND = adminActions.SAML2_SP_KIND;
const SAML11_RP_KIND = adminActions.SAML11_RP_KIND;
const SAML_ASSERTION_KEYS = adminActions.SAML_ASSERTION_KEYS;
const SAML_ASSERTION_SETTINGS = adminActions.SAML_ASSERTION_SETTINGS;
const TOKEN_LIFETIME_KEYS = adminActions.TOKEN_LIFETIME_KEYS;

// ---------------------------------------------------------------------------
// WHAT THE CONSOLE HANDS OVER. The first five to arrive are inverted hooks on
// `admin-ui/admin.ts` (rule 3e) filled by the module that owns the subsystem
// — `crypto_metadata.js`, `xacml_admin.js`, `ldap_server.js`, `scim.js` and
// `xacml_role_pep.js`. The sixth is the console's own settings-block builder,
// which `scimJson()` embeds; see the header for why it is asked for rather
// than reimplemented. The rest arrived later, each noted below.
//
// The slots do not move: every filler in the tree names the console module,
// and so does every rule 3e sentence in CLAUDE.md. The console forwards from
// inside the setter it already had.
// ---------------------------------------------------------------------------
// `logoutReader` is the SECOND collaborator both halves need — sessionsView()
// reads what is live and sessionsAction() ends it — so the console's one
// setter now writes here as well as into admin_actions.ts.
// THE THREE REPORTERS, filled by ssf/ssf.ts. They are the same slots the
// action half holds — the reports READ what the actions ACT on — so the
// console's one setter writes into both.
// Filled by spiffe/spiffe_server.ts through the console, like the rest.
// The two directory slots the new-person answer needs: the writer says
// whether an entry can be created at all, the reader finds the container.
// The group slots: the reader lists them, the writer says whether the page
// may offer a control. Both are the console's, forwarded like the rest.
let groupReader = null;
let groupWriter = null;
let directoryWriter = null;
let directoryReader = null;
let spiffeReader = null;
let signalsReporter = null;
let caepReporter = null;
let riscReporter = null;
let logoutReader = null;
let cryptoReporter = null;
let xacmlPages = null;
let directoryPages = null;
let scimReader = null;
let rolePreviewer = null;
let configSettingsJson = null;
// The client-certificate truststore (2026-09-12). Forwarded by
// `admin-ui/admin.ts`'s `setTruststore()`, which `common/protocol_stack.ts`
// fills; that setter carries the argument.
let truststore = null;

// How many results a chooser pane shows at a time. One number for the console
// (chooserPane()) and for the replies that page the same list, so a page and
// its resource cannot come to show different twenties.
/**
 * The most matches a chooser lists: the kit's, which the chooser it draws
 * reads (#446).
 */
const CHOOSER_HITS = WebKit.CHOOSER_HITS;

// Rows per page when nobody said. Small enough that the table is the first
// thing on screen rather than the last, and the paging controls above and below
// it say what the rest of the list is.
/**
 * Rows per page when the query names none.
 */
const DEFAULT_PER_PAGE = 50;

// Rows per page for EVERY list on /admin/delegation, which is the one page here
// that carries seven of them at once.
//
// It is a tenth of DEFAULT_PER_PAGE and that is the point rather than a tuning
// choice. The other pages in this console are ONE list under one heading, where
// fifty rows is a table somebody scrolls; this page is seven — the acts, the
// chains, the permissions a resource exposes, the grants between two
// applications, the two Kerberos policy tables and the mechanism catalogue —
// with several screens of prose between them, so fifty rows apiece is a
// document tens of thousands of pixels long in which the seventh heading is
// unreachable by anything but the scrollbar. Ten keeps every section's control
// within a screen of its heading, which is what makes the page navigable at
// all; everything above ten is one click away and the control says how much.
//
// `?per=` still overrides it for all seven together, exactly as it does on the
// drill-downs, and perPageOptions() offers this value because it offers
// whatever is in force. A number somebody typed is a number they meant.
/**
 * Rows per page for every list on `/admin/delegation`.
 */
const DELEGATION_PER_PAGE = 10;

// How many rows of a list a page will draw. A cap is needed — 5,000 token rows
// is a page no browser enjoys — and what it hid is always stated underneath,
// because a truncated table that does not say it was truncated reads as the
// whole truth.
//
// On the tokens page this is now the ceiling on ONE PAGE rather than on the
// whole list: everything held is reachable by paging, so nothing is hidden any
// more. The cap stays because the reason for it never went away — `?per=` is a
// number a caller types, and without a ceiling `?per=5000` is the page the cap
// existed to prevent.
/**
 * The most rows of a list a page draws.
 */
const MAX_ROWS = 300;

// The credential choice, as four radios. A RADIO GROUP rather than a select for
// once, because each option needs a paragraph beside it: what an operator is
// choosing between here is not four values of one thing but four different
// stories about how this person first gets in, and three of them have a
// consequence that cannot be undone from this console.
//
// **`generate` IS THE DEFAULT SINCE 2026-09-12, AND `none` WAS BEFORE IT** —
// at rcbj's request, on both doors: this form preselects it and
// `POST /admin-api/users/create` uses it when `credential` is not sent. `none`
// was the default because it was what this door did before there were any
// choices, and in development it is enough to sign in; but a person created by
// hand with no credential is, in PRODUCT mode, a person who cannot sign in, and
// the default should be the thing that works in the mode this service is
// becoming. `none` is still one click or one field away.
/**
 * What a create that names no credential gets, from `admin_actions.ts`.
 */
const DEFAULT_CREDENTIAL = adminActions.DEFAULT_CREDENTIAL;

// THE THREE ATTRIBUTES THAT SAY WHERE A SERVICE PROVIDER'S KEY COMES FROM.
//
// They were the console's until #446, when the new-application form's
// answer began saying which fields its simplified view offers. They are not
// setting overrides — nothing in config.js corresponds to them —
// so they are not in `overridableSettings()` and would otherwise appear on no
// form at all. They are conditional on SAML 2.0 like everything else in that
// family.
//
// `samlSpMetadata` is a TEXTAREA and the other two are inputs, which is the
// same shape rule the field grid follows: a document is not something
// anybody types on one line, and offering a single-line box for one invites a
// paste that loses its newlines.
const SAML_KEY_SOURCE_FIELDS = [
  { attribute: 'samlSpMetadataUrl', label: 'Metadata URL',
    what: 'Where this service provider publishes its metadata. Nothing is ' +
          'fetched until you press Refresh on the entry — an assertion never ' +
          'waits on somebody else\'s web server.' },
  { attribute: 'samlEncryptionCertificate', label: 'Encryption certificate',
    what: 'The certificate an assertion is encrypted to, base64 or PEM. ' +
          'Consuming the metadata writes this; set it by hand for a service ' +
          'provider whose metadata cannot be reached. With none here a ' +
          'registered signing certificate is used, then (development only) ' +
          'the one a signed AuthnRequest carried.' },
  { attribute: 'samlSpMetadata', label: 'Metadata document', multi: true,
    what: 'The metadata itself. Pasted here, it is CONSUMED when the ' +
          'application is created — endpoints, signing and encryption ' +
          'certificates, NameIDFormats — exactly as a refresh would, which ' +
          'is the way to configure an air-gapped service provider, or one ' +
          'behind a proxy this service cannot dial.' }
];

/**
 * The credential choices the new-user form offers, each with what it means.
 */
const CREDENTIAL_CHOICES = [
  { id: 'none', label: 'No credential at all',
    what: 'The entry exists and nothing is set on it. <strong>In development ' +
          'mode this is enough to sign in</strong> — no password is checked ' +
          'anywhere in this service — so it is the right choice for a test ' +
          'subject. In PRODUCT mode a person with no credential cannot sign ' +
          'in at all, and the way to give them one afterwards is an ' +
          'activation link.' },
  { id: 'password', label: 'A password I type',
    what: 'Hashed with scrypt by <code>credentials.js</code> and written to ' +
          '<code>userPassword</code> on the entry. <strong>It is never shown ' +
          'again by anything</strong>, including this console and an ' +
          '<code>ldapsearch</code>, because what is stored is the hash. ' +
          'Typed twice, because a mistyped password that nobody can read ' +
          'back is a person who cannot sign in and nobody who can say why.' },
  { id: 'generate', label: 'A password generated for me (the default)',
    what: 'Drawn from node\'s cryptographically secure generator, each ' +
          'character uniformly, until it satisfies this ' +
          'realm\'s <a href="/admin/policies">password policy</a>, set the ' +
          'same way, and <strong>shown to you exactly once</strong> on the ' +
          'page that comes back. This service cannot produce it a second ' +
          'time — only replace it. It is the same generator the product-mode ' +
          'bootstrap account uses.' },
  { id: 'activation', label: 'No credential, and an activation link',
    what: 'The person holds nothing, and you are given a single-use, ' +
          'time-limited URL <strong>once</strong> to send them by whatever ' +
          'channel you already use. At it they choose a password, a security ' +
          'key, or both. <strong>Anybody holding that link can complete this ' +
          'account</strong>, so it is a credential and is treated as one: ' +
          'this service stores only a hash of it, issuing another ' +
          'invalidates the first, and it is spent when the setup FINISHES ' +
          'rather than when the link is opened — a link burned by a mail ' +
          'scanner would strand the person it was for.' }
];

// The parameters every control on a drill-down has to carry.
//
// The list views name theirs one by one, and they can: their parameter set is
// the filter form beside them and it is written down two lines above the call.
// A drill-down's is not written down anywhere — one of its lists has a page
// parameter PER SESSION BLOCK, so the set depends on what the reader has been
// clicking — and listing the ones that exist today is how paging the artifacts
// comes to reset the members six months from now. So the current query is
// carried through whole and each control overrides its own key.
//
// Three things are dropped and each for its own reason. `format`, for the
// reason the tokens page gives about its own links: JSON has no page to click,
// so a nav link carrying it would answer a click with a download. And `notice`
// and `error`, which are the message a revoke's redirect brought back — they
// belong to the act that has just happened and not to the view, so carrying
// them would leave "Revoked …" at the top of every page the reader clicked to
// afterwards, and would put a stale one in the `back` field of the next revoke,
// which answers with two.
/**
 * The query parameters that are not part of a view: `format`, `notice` and
 * `error`.
 */
const NOT_A_VIEW = ['format', 'notice', 'error'];

// Rows per page for a list whose ROW IS A TABLE. There is one of those — the
// session blocks on the users drill-down, where each row of the list is a
// session heading, a facts table and a token table under it — and giving it
// DEFAULT_PER_PAGE would put fifty tables on one page, each of which is itself
// paged at fifty rows. The list pages get away with one number because a row
// there is a row.
//
// `?per=` still overrides it, for the same reason it overrides everything else:
// a number somebody typed is a number they meant.
/**
 * Rows per page for a list whose row is itself a table.
 */
const DEFAULT_BLOCKS_PER_PAGE = 5;

interface AdminViewsDeps {
  log: typeof helpers.log;
  baseUrlOf: typeof helpers.baseUrlOf;
  stsKeysFor: typeof helpers.stsKeysFor;
  userFor: typeof helpers.userFor;
  subjectForName: typeof helpers.subjectForName;
  credentials: typeof credentials;
  totp: typeof totp;
  webauthnPolicy: typeof webauthnPolicy;
  backupCodes: typeof backupCodes;
  appPasswords: typeof appPasswords;
  identityAssurance: typeof identityAssurance;
  siop: typeof siop;
  devices: typeof devices;
  serviceAccounts: typeof serviceAccounts;
  serviceAccountPolicy: typeof serviceAccountPolicy;
  sessions: typeof authn.sessions;
  sessionStartedAt: typeof authn.sessionStartedAt;
  config: typeof config;
  mode: typeof mode;
  realms: typeof realms;
  stats: typeof stats;
  oidcRp: typeof oidcRp;
  rbac: typeof rbac;
  vcClaims: typeof vcClaims;
  vpConfig: typeof vpConfig;
  claimAttributes: typeof claimAttributes;
  scimMap: typeof scimMap;
  groupClaims: typeof groupClaims;
  applications: typeof applications;
  personAssertions: typeof personAssertions;
  keystore: typeof keystore;
  pki: typeof pki;
  nodeCrypto: typeof nodeCrypto;
  appPermissions: typeof appPermissions;
  consent: typeof consent;
  roles: typeof roles;
  passwordPolicy: typeof passwordPolicy;
  policyKinds: typeof policyKinds;
  auditLog: typeof auditLog;
  errorCodes: typeof errorCodes;
  usedAssertions: typeof usedAssertions;
  delegation: typeof delegation;
  delegationMap: typeof delegationMap;
  userGraph: typeof userGraph;
  credentialGraph: typeof credentialGraph;
  federationGraph: typeof federationGraph;
  federationDiagram: typeof federationDiagram;
  delegationPolicy: typeof delegationPolicy;
  krb5Principals: typeof krb5Principals;
  krb5PersonKeys: typeof krb5PersonKeys;
  personEditor: typeof personEditor;
  // The krbtgt rotation (#169), lazily, for `admin_actions.ts`'s reason.
  krbtgtRotation: () => any;
  oauth2: typeof oauth2;
  backchannel: typeof backchannel;
  softwareStatement: typeof softwareStatement;
  assertionGrant: typeof assertionGrant;
  tlsClientCertificates: typeof tlsClientCertificates;
  certificateSubject: typeof certificateSubject;
  mtls: typeof mtls;
  saml2: typeof saml2;
  requestSignature: typeof requestSignature;
  spMetadata: typeof spMetadata;
  saml11: typeof saml11;
  authorizationServers: typeof authorizationServers;
  federation: typeof federation;
  fedEncryption: typeof fedEncryption;
  // A federation partner's Shared Signals (#373), lazily: the receiver
  // registers a scheduler job when built.
  loadSignals: () => any;
  // GNAP's view layer (#432 phase 7), lazily: GNAP is 23d in the require
  // order and this file is loaded at 18, as `mgmt-api/admin_api.ts` reaches
  // it. Optional, so a test building these views without it still draws.
  loadGnapConsole?: () => any;
  fedLinks: typeof fedLinks;
  signals: typeof signals;
  spiffeRegistry: typeof spiffeRegistry;
  spiffeCa: typeof spiffeCa;
  spiffeAuth: typeof spiffeAuth;
  adminActions: typeof adminActions;
  signingHistory: typeof signingHistory;
  configSettingFor: typeof adminActions.configSettingFor;
  noXacml: typeof adminActions.noXacml;
  samlAssertionRowFor: typeof adminActions.samlAssertionRowFor;
}

/**
 * What the two admin surfaces both read: the pure JSON views behind the
 * console's pages and the `/admin-api` operations that mirror them (rule 7).
 *
 * Each view computes the machine answer and reaches no markup, so a page and
 * its operation cannot disagree.
 */
class AdminViews {
  /**
   * Builds the views over their dependencies.
   *
   * @param deps - the domain modules, registers and helpers the views read
   */
  constructor(private readonly deps: AdminViewsDeps) {
    deps.log.debug("Entering AdminViews.constructor().");
    deps.log.debug("Leaving AdminViews.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AdminViewsDeps {
    helpers.log.debug("Entering AdminViews.defaultDeps().");
    helpers.log.debug("Leaving AdminViews.defaultDeps().");
    return {
      log: helpers.log,
      baseUrlOf: helpers.baseUrlOf,
      stsKeysFor: helpers.stsKeysFor,
      userFor: helpers.userFor,
      subjectForName: helpers.subjectForName,
      credentials: credentials,
      totp: totp,
      webauthnPolicy: webauthnPolicy,
      backupCodes: backupCodes,
      appPasswords: appPasswords,
      identityAssurance: identityAssurance,
      siop: siop,
      devices: devices,
      serviceAccounts: serviceAccounts,
      serviceAccountPolicy: serviceAccountPolicy,
      sessions: authn.sessions,
      sessionStartedAt: authn.sessionStartedAt,
      config: config,
      mode: mode,
      realms: realms,
      stats: stats,
      oidcRp: oidcRp,
      rbac: rbac,
      vcClaims: vcClaims,
      vpConfig: vpConfig,
      claimAttributes: claimAttributes,
      scimMap: scimMap,
      groupClaims: groupClaims,
      applications: applications,
      personAssertions: personAssertions,
      keystore: keystore,
      pki: pki,
      nodeCrypto: nodeCrypto,
      appPermissions: appPermissions,
      consent: consent,
      roles: roles,
      passwordPolicy: passwordPolicy,
      policyKinds: policyKinds,
      auditLog: auditLog,
      errorCodes: errorCodes,
      usedAssertions: usedAssertions,
      delegation: delegation,
      delegationMap: delegationMap,
      userGraph: userGraph,
      credentialGraph: credentialGraph,
      federationGraph: federationGraph,
      federationDiagram: federationDiagram,
      delegationPolicy: delegationPolicy,
      krb5Principals: krb5Principals,
      krb5PersonKeys: krb5PersonKeys,
      personEditor: personEditor,
      krbtgtRotation: function () {
        return require('../kerberos/krb5_krbtgt_rotation');
      },
      oauth2: oauth2,
      backchannel: backchannel,
      softwareStatement: softwareStatement,
      assertionGrant: assertionGrant,
      tlsClientCertificates: tlsClientCertificates,
      certificateSubject: certificateSubject,
      mtls: mtls,
      saml2: saml2,
      requestSignature: requestSignature,
      spMetadata: spMetadata,
      saml11: saml11,
      authorizationServers: authorizationServers,
      federation: federation,
      fedEncryption: fedEncryption,
      loadGnapConsole: function () {
        return require('../gnap/gnap_console');
      },
      loadSignals: function () {
        return require('../ssf/ssf_transmitters');
      },
      fedLinks: fedLinks,
      signals: signals,
      spiffeRegistry: spiffeRegistry,
      spiffeCa: spiffeCa,
      spiffeAuth: spiffeAuth,
      adminActions: adminActions,
      signingHistory: signingHistory,
      configSettingFor: adminActions.configSettingFor,
      noXacml: adminActions.noXacml,
      samlAssertionRowFor: adminActions.samlAssertionRowFor
    };
  }

  /**
   * Fills the slot for the directory's group reader; the module that owns it
   * fills it (rule 3e).
   *
   * @param value - the filler
   */
  setGroupReader(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setGroupReader().");
    groupReader = value;
    log.debug("Leaving AdminViews.setGroupReader().");
  }

  /**
   * Fills the slot for the directory's group writer; the module that owns it
   * fills it (rule 3e).
   *
   * @param value - the filler
   */
  setGroupWriter(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setGroupWriter().");
    groupWriter = value;
    log.debug("Leaving AdminViews.setGroupWriter().");
  }

  /**
   * Fills the slot for the directory writer; the module that owns it fills it
   * (rule 3e).
   *
   * @param value - the filler
   */
  setDirectoryWriter(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setDirectoryWriter().");
    directoryWriter = value;
    log.debug("Leaving AdminViews.setDirectoryWriter().");
  }

  /**
   * Fills the slot for the directory reader; the module that owns it fills it
   * (rule 3e).
   *
   * @param value - the filler
   */
  setDirectoryReader(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setDirectoryReader().");
    directoryReader = value;
    log.debug("Leaving AdminViews.setDirectoryReader().");
  }

  /**
   * Fills the slot for the SPIFFE listener reader; the module that owns it
   * fills it (rule 3e).
   *
   * @param value - the filler
   */
  setSpiffeReader(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setSpiffeReader().");
    spiffeReader = value;
    log.debug("Leaving AdminViews.setSpiffeReader().");
  }

  /**
   * Fills the slot for the Shared Signals report; the module that owns it fills
   * it (rule 3e).
   *
   * @param value - the filler
   */
  setSignalsReporter(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setSignalsReporter().");
    signalsReporter = value;
    log.debug("Leaving AdminViews.setSignalsReporter().");
  }

  /**
   * Fills the slot for the CAEP report; the module that owns it fills it (rule
   * 3e).
   *
   * @param value - the filler
   */
  setCaepReporter(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setCaepReporter().");
    caepReporter = value;
    log.debug("Leaving AdminViews.setCaepReporter().");
  }

  /**
   * Fills the slot for the RISC report; the module that owns it fills it (rule
   * 3e).
   *
   * @param value - the filler
   */
  setRiscReporter(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setRiscReporter().");
    riscReporter = value;
    log.debug("Leaving AdminViews.setRiscReporter().");
  }

  /**
   * Fills the slot for the logout model; the module that owns it fills it (rule
   * 3e).
   *
   * @param value - the filler
   */
  setLogoutReader(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setLogoutReader().");
    logoutReader = value;
    log.debug("Leaving AdminViews.setLogoutReader().");
  }

  /**
   * Fills the slot for the crypto report; the module that owns it fills it
   * (rule 3e).
   *
   * @param value - the filler
   */
  setCryptoReporter(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setCryptoReporter().");
    cryptoReporter = value;
    log.debug("Leaving AdminViews.setCryptoReporter().");
  }

  /**
   * Fills the slot for the XACML pages; the module that owns it fills it (rule
   * 3e).
   *
   * @param value - the filler
   */
  setXacmlPages(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setXacmlPages().");
    xacmlPages = value;
    log.debug("Leaving AdminViews.setXacmlPages().");
  }

  /**
   * Fills the slot for the directory pages; the module that owns it fills it
   * (rule 3e).
   *
   * @param value - the filler
   */
  setDirectoryPages(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setDirectoryPages().");
    directoryPages = value;
    log.debug("Leaving AdminViews.setDirectoryPages().");
  }

  /**
   * Fills the slot for the SCIM reader; the module that owns it fills it (rule
   * 3e).
   *
   * @param value - the filler
   */
  setScimReader(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setScimReader().");
    scimReader = value;
    log.debug("Leaving AdminViews.setScimReader().");
  }

  /**
   * Fills the slot for the role previewer; the module that owns it fills it
   * (rule 3e).
   *
   * @param value - the filler
   */
  setRolePreviewer(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setRolePreviewer().");
    rolePreviewer = value;
    log.debug("Leaving AdminViews.setRolePreviewer().");
  }

  /**
   * Fills the slot for the configuration settings view; the module that owns it
   * fills it (rule 3e).
   *
   * @param value - the filler
   */
  setConfigSettingsJson(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setConfigSettingsJson().");
    configSettingsJson = value;
    log.debug("Leaving AdminViews.setConfigSettingsJson().");
  }

  // A page's settings block (#446), for a view layer outside this module —
  // the certificate enrollment pages' — whose page is drawn from its view
  // alone and so must answer the block every page that owns settings
  // answers, rather than a bare list of rows.
  /**
   * Returns the settings block of a console page, as every page that owns
   * settings answers it.
   *
   * @param path - the page's path
   * @returns the block, or null before the console has filled the slot
   */
  settingsBlockOf(path) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.settingsBlockOf(). path=" + path);
    log.debug("Leaving AdminViews.settingsBlockOf().");
    return configSettingsJson ? configSettingsJson(path) : null;
  }

  /**
   * Fills the slot for the client-certificate truststore; the module that owns
   * it fills it (rule 3e).
   *
   * @param value - the filler
   */
  setTruststore(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.setTruststore().");
    truststore = value;
    log.debug("Leaving AdminViews.setTruststore().");
  }

  // ---------------------------------------------------------------------------
  // THE SESSION THIS CONSOLE READS (2026-09-06), AND IT IS NO LONGER THE
  // SIGN-ON SESSION.
  //
  // This console is a RELYING PARTY of this service's own authorization server:
  // it holds a session of its own, established from an ID Token, in its own
  // cookie. `authn.ts`'s `consoleSession()` reads the SIGN-ON session — what a
  // person has with the identity provider — and the two are different facts
  // with different lifetimes, which is the whole reason this move was worth
  // making.
  //
  // **THE RETURN SHAPE IS `consoleSession()`'s ON PURPOSE.** Every caller in
  // this file wants `{ session, realm, foreign }` and none of them cares which
  // of the two it is looking at; keeping the shape is what made this a change
  // to one function rather than to seventy pages. `foreign` is now always false
  // — a relying-party session belongs to the surface that minted it and there
  // is no realm to be foreign to — and the member is kept because the banner
  // reads it.
  //
  // The realm is the DEFAULT one whatever realm is being read, which is the
  // rule this console has had since realms existed and is unchanged: the roster
  // is the default realm's `ou=groups`, so a session minted in `acme` must not
  // open this console. `oidc_rp.js` runs the console's whole flow in that realm
  // for exactly that reason.
  // ---------------------------------------------------------------------------
  /**
   * Returns the console's relying-party session for a request, which is always
   * in the default realm.
   *
   * @param req - the request
   * @returns the session with its realm, or null when not signed in
   */
  consoleRpSession(req) {
    const { log, realms, oidcRp } = this.deps;
    log.debug("Entering AdminViews.consoleRpSession().");
    const session = oidcRp.sessionFor(req, 'admin');
    log.debug("Leaving AdminViews.consoleRpSession(). " +
              (session ? "Signed in as " + session.user.username + "." :
               "None."));
    return session
      ? { session: session, realm: realms.DEFAULT_REALM, foreign: false }
      : null;
  }

  // ---------------------------------------------------------------------------
  // THE GATE AS A TOKEN DECIDED IT (#446). `/admin-api`'s gate verifies the
  // caller's token, decides the roles its subject holds in the realm that
  // issued it, and leaves that caller on the request (`adminApiCaller`). A
  // view drawn for such a request is drawn for THAT caller: the token's
  // realm is the realm the person is of — a realm administrator's own
  // realm, confined there — and its roles are the console's two. Without
  // this every view asked about an API request found no console session
  // and answered as for the service.
  // ---------------------------------------------------------------------------
  /**
   * Describes the gate for a request the management API authenticated.
   *
   * @param caller - the API gate's caller: `kind`, `name`, `realm`, `roles`
   * @returns the gate state, in `gateStateFor()`'s shape
   */
  apiGateStateOf(caller) {
    const { log, config, realms, rbac } = this.deps;
    log.debug("Entering AdminViews.apiGateStateOf().");
    const identityRealm = String(caller.realm || realms.DEFAULT_ID);
    const authority = identityRealm === realms.DEFAULT_ID ? 'service'
                                                          : 'realm';
    const outsideRealm = authority === 'realm' &&
                         realms.currentId() !== identityRealm;
    const roles = (caller.roles || []).map(function (role) {
      return role === 'ADMIN_READ' ? 'read'
        : (role === 'ADMIN_WRITE' ? 'write' : String(role).toLowerCase());
    });
    const read = !outsideRealm && roles.indexOf('read') >= 0;
    const write = !outsideRealm && roles.indexOf('write') >= 0;
    log.debug("Leaving AdminViews.apiGateStateOf(). " + authority + ".");
    return {
      enforced: true, available: rbac.available(), session: true,
      username: String(caller.name || ''), authority: authority,
      identityRealm: identityRealm, outsideRealm: outsideRealm,
      readGroup: config.value('admin.readGroup'),
      writeGroup: config.value('admin.writeGroup'),
      sessionRealm: identityRealm, foreignSession: false,
      read: read || write, write: write,
      roles: outsideRealm ? [] : roles,
      open: false, closed: false, windowOpens: true, empty: false,
      bootstrapPasswordRequired: false, windowWithheld: false,
      bootstrap: null, viaApi: true
    };
  }

  // Everything the banner and the guard both need, worked out ONCE per request.
  //
  // Both were written separately at first and disagreed within the hour: the
  // guard let somebody through on the empty-roster rule and the banner, asking
  // again, found a roster that a concurrent grant had just filled — so the page
  // said "signed in, holding no role" above a console it had just allowed. One
  // function, one answer.
  /**
   * Works out the console gate's state for a request in one pass: who is signed
   * in, which roles they hold, and whether the gate lets them in.
   *
   * @param req - the request
   * @returns the gate's state
   */
  gateStateFor(req) {
    const { log, config, mode, realms, rbac } = this.deps;
    log.debug("Entering AdminViews.gateStateFor().");
    if (req && req.adminApiCaller) {
      log.debug("Leaving AdminViews.gateStateFor(). The API's caller.");
      return this.apiGateStateOf(req.adminApiCaller);
    }
    // THE MODE, since 2026-09-06, where this read `admin.authRequired`. That
    // setting is gone: "is authentication required here" had four answers
    // across this service and now has one. See common/mode.js.
    const enforced = mode.gatesConsole();
    // THE CONSOLE'S OWN RELYING-PARTY SESSION, whichever realm is being read —
    // see consoleRpSession() above for why it is looked up in the default realm
    // and why it is no longer the sign-on session.
    const found = this.consoleRpSession(req);
    const session = found ? found.session : null;
    const username = session ? session.user.username : '';
    // ---------------------------------------------------------------------
    // WHOSE ROSTER DECIDES, AND WHERE ITS ANSWER HOLDS (2026-09-14, #32).
    //
    // The console's own session lives in the default realm's partition and its
    // SIGN-ON session lives wherever the code flow ran — `derivedFromRealm`
    // names that realm, and an absent value means the default realm. That realm
    // is who this person IS, so it is whose roster is asked:
    //
    //   * signed in through the DEFAULT realm: the default realm's roster,
    //     which is the SERVICE roster — its answer holds in every realm,
    //     exactly as before;
    //   * signed in through realm `acme`: acme's roster, whose answer holds
    //     while acme is the realm being read and in no other. Reaching the
    //     default realm or another realm with that session grants nothing, and
    //     service pages are refused even in acme (`admin-ui/admin_scope.ts`).
    //
    // Until #32 every console session was asked the default realm's roster BY
    // NAME, so a person in any realm who shared a service administrator's
    // username held that administrator's roles. Asking the roster of the realm
    // the person authenticated in is what closes that.
    // ---------------------------------------------------------------------
    const identityRealm = session
      ? String(session.derivedFromRealm || realms.DEFAULT_ID) : '';
    const authority = !session ? null
      : (identityRealm === realms.DEFAULT_ID ? 'service' : 'realm');
    const ambientRealm = realms.currentId();
    const outsideRealm = authority === 'realm' && ambientRealm !==
                         identityRealm;
    const asked = rbac.rolesOf(username, identityRealm || realms.DEFAULT_ID);
    // ---------------------------------------------------------------------
    // THE BOOTSTRAP ADMINISTRATOR BEFORE ITS CLAIM, IN PRODUCT (2026-09-22,
    // #103). `rolesOf()` answers what the account holds by membership; the
    // session says how it signed in, and before the claim only a password
    // this service verified is honoured (`rbac.passwordSignIn()`). Any other
    // sign-in as that account — a federation partner asserting it, a
    // certificate naming it, a wallet, a Kerberos ticket — holds nothing
    // here, and the gate says why (STS-ADMIN-0796). Decided HERE, for the
    // reason this function exists: the console, `/admin-api`'s session
    // fallback and the banner all read this one answer.
    // ---------------------------------------------------------------------
    const passwordRequired = !!(asked.claimPending &&
                                !rbac.passwordSignIn(session));
    const held = outsideRealm || passwordRequired
      ? Object.assign({}, asked, { roles: [], read: false, write: false,
                                   open: false, openable: outsideRealm
                                     ? false : asked.openable })
      : asked;
    const state = {
      enforced: enforced,
      available: rbac.available(),
      session: session,
      username: username,
      // `service` for a default-realm identity and `realm` for any other; null
      // when nobody is signed in.
      authority: authority,
      identityRealm: identityRealm || null,
      // A realm administrator reading a realm that is not theirs holds nothing
      // here; the gate says why rather than drawing a page of refusals.
      outsideRealm: outsideRealm,
      readGroup: config.value('admin.readGroup'),
      writeGroup: config.value('admin.writeGroup'),
      // With the gate OFF everybody may do everything, which is what this
      // console did before any of this existed. Said as `true` here rather than
      // checked separately at each call site, so a caller cannot ask "may they
      // write" and get an answer that ignores the setting.
      // WHICH REALM'S MAP HOLDS THE SESSION, and whether that is the realm
      // being read. Carried on the state rather than worked out again in the
      // banner, for the reason the whole of this function exists: two answers
      // to one question drift within the hour. `sessionRealm` is null when
      // nobody is signed in, and `foreignSession` is false in a service with no
      // realms — which is what keeps every banner in that service the sentence
      // it was.
      sessionRealm: found ? found.realm : null,
      foreignSession: !!(found && found.foreign),
      read: enforced ? held.read : true,
      write: enforced ? held.write : true,
      roles: enforced ? held.roles : rbac.ROLE_IDS.slice(0),
      open: enforced && held.open,
      closed: enforced && held.empty && !held.open && !held.roles.length,
      // Whether the mode opens the window in the roster's realm at all (#103):
      // false in product, which the banners say rather than blaming
      // `admin.openWhenEmpty`.
      windowOpens: held.windowOpens !== false,
      empty: held.empty,
      // PRODUCT, BEFORE THE CLAIM (#103): this session is the bootstrap
      // account signed in by something other than a password, and holds
      // nothing — or it is somebody holding no role whom development's window
      // would have let in. Each has a refusal of its own at the gate.
      bootstrapPasswordRequired: enforced && passwordRequired,
      windowWithheld: enforced && !outsideRealm && !!held.withheld,
      // The bootstrap administrator (2026-09-13), for the banner that says
      // whose arrival closes the open console. See admin_rbac.js's
      // bootstrapState().
      bootstrap: held.bootstrap || null
    };
    log.debug("Leaving AdminViews.gateStateFor(). enforced=" + enforced +
              ", read=" +
              state.read +
              ", write=" + state.write + ".");
    return state;
  }

  // The browser sign-on sessions, as rows. Expired ones are still in the map
  // until something reads them (sessionOf() drops one when it finds it stale),
  // so the state is computed here rather than assumed — otherwise the console
  // would report a session that no request would honour.
  /**
   * Lists the browser sign-on sessions as rows, computing whether each is still
   * live.
   *
   * @returns the rows
   */
  signOnSessionRows() {
    const { log, sessions, sessionStartedAt } = this.deps;
    log.debug("Entering AdminViews.signOnSessionRows().");
    const nowMs = Date.now();
    const rows = [];
    sessions.forEach(function (session, id) {
      rows.push({
        id: id,
        username: (session.user && session.user.username) || '',
        sub: (session.user && session.user.sub) || '',
        amr: (session.amr || []).join(', '),
        acr: session.acr || '',
        // TWO INSTANTS SINCE 2026-09-14, and they stopped being one when a
        // session learned to hold several authentications: `startedAt` is when
        // it BEGAN (its first event) and `authTime` the MOST RECENT
        // authentication, which a step-up or `max_age` moves. A column called
        // "Signed in" drawn from `authTime` showed an hour-old session as a
        // minute old.
        startedAt: sessionStartedAt(session),
        authTime: (session.authTime || 0) * 1000,
        authentications: (Array.isArray(session.events)
          ? session.events.length : 1) + (session.eventsDropped || 0),
        expires: session.expires || 0,
        expired: !!session.expires && session.expires <= nowMs,
        // Which WS-Federation relying parties this session signed into. It is
        // the list wsignout1.0 has to fan out to, and seeing it is the only way
        // to know in advance what a sign-out is about to do.
        wsfedRealms: Object.keys(session.wsfedRealms || {})
      });
    });
    rows.sort(function (a, b) { return b.startedAt - a.startedAt; });
    log.debug("Leaving AdminViews.signOnSessionRows(). " + rows.length +
              " session(s).");
    return rows;
  }

  // The metrics reply: the whole snapshot, with the sign-on sessions beside it.
  // The snapshot's own keys are at the TOP LEVEL of it rather than under a
  // `snapshot` member, which is what /admin/metrics?format=json has always
  // answered and what the parent project's tests read — so the console's route
  // uses this object for the markup too rather than taking a second snapshot a
  // few microseconds later.
  /**
   * Takes one metrics snapshot, for `/admin/metrics` and its JSON.
   *
   * @returns the snapshot and what the page draws from it
   */
  metricsJson() {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.metricsJson().");
    const snap = stats.snapshot();
    const signOn = this.signOnSessionRows();
    const live = signOn.filter(function (s) { return !s.expired; });
    const json = Object.assign({}, snap, {
      startedAtIso: new Date(snap.startedAt).toISOString(),
      signOnSessions: { held: signOn.length, active: live.length, rows: signOn }
    });
    log.debug("Leaving AdminViews.metricsJson(). " + signOn.length +
              " sign-on session(s).");
    return json;
  }

  // ---------------------------------------------------------------------------
  // GET /admin/tokens/set?id=… — THE CREDENTIALS THAT CAME BACK IN ONE REPLY.
  //
  // **THE TOKENS PAGE'S SECOND DRILL-DOWN, AND IT IS THE OLD TABLE SCOPED TO
  // ONE ISSUANCE.** Since 2026-09-05 that list draws a row per reply rather
  // than a row per credential, which is what the reader wants nineteen times
  // out of twenty and exactly wrong the twentieth: when somebody is chasing ONE
  // token they need its own jti, its own expiry and its own button back. So the
  // members are drawn here by `issuedRow()` — the very function the list used
  // to call — and the column legend on the list describes this table without a
  // word changing.
  //
  // It hangs under /admin/tokens the way /admin/tokens/credential does and for
  // the same reasons: no `NAV` row, `active` is '/admin/tokens', and `up`
  // carries the filter and the page the reader left, so the trail reads `Tokens
  // › One issuance` and the way back is the row they clicked on.
  //
  // **IT IS ADDRESSED BY `setKey` AND NOT BY THE SET ID**, and the difference
  // matters for exactly one case. A grouped set's key is `set:<id>`; a set of
  // one has no id at all and its key is `one:<this service's own row handle>`.
  // The list only ever links here from a group — for one credential this page
  // would be a click that added nothing, so those rows still open the lineage
  // directly — but the KEY space covers both, so `GET /admin-api/tokens/set`
  // can open any row of that table and a test need not know which kind it has
  // in its hand.
  // ---------------------------------------------------------------------------
  /**
   * Opens one token set by its key, for `GET /admin-api/tokens/set`.
   *
   * @param query - the query, whose `id` names the set
   * @returns the key asked, the set, and the JSON answer saying why when it is
   *   not found
   */
  tokenSetView(query) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.tokenSetView().");
    const asked = String((query && query.id) || '').trim();
    const set = asked ? stats.issuedSetByKey(asked) : null;
    log.debug("Leaving AdminViews.tokenSetView(). " +
              (set ? set.size + " member(s)." : "No " +
        "such set."));
    return {
      asked: asked,
      set: set,
      json: {
        // The key that was ASKED FOR, echoed even when nothing holds it,
        // because a caller walking a list it drew a minute ago needs to know
        // which of its keys came back empty and not merely that one did.
        setKey: asked || null,
        // Null rather than an empty object for a set nothing holds — which is
        // the ORDINARY answer for one forgotten to the cap, not an error — and
        // the sentence beside it says which of the two happened.
        set: set,
        found: !!set,
        why: set ? null : (asked
          ? 'Nothing here is called "' + asked + '". Either it was never a ' +
            'set, or it has been forgotten to the cap since the list naming ' +
            'it was drawn.'
          : 'Name a set. Every grouped row of GET /admin-api/tokens carries ' +
            'its `setKey`, and so does every row of `sets`.')
      }
    };
  }

  // The register and its picture, in one place so that the page, `?format=json`
  // and `GET /admin-api/permissions` cannot come to disagree about what is in
  // it — the same property `delegationView()` gives the acts half.
  /**
   * Builds the delegated permission register and its picture.
   *
   * @returns the register and its clusters
   */
  permissionsView() {
    const { log, appPermissions } = this.deps;
    log.debug("Entering AdminViews.permissionsView().");
    const register = appPermissions.register();
    const graph = appPermissions.graph(register.grants);
    // THE GROUPINGS, off the register that has just been read rather than off a
    // second walk of `ou=applications`. `appPermissions.clusters()` will do the
    // walk itself when it is handed nothing, and every caller here has the
    // answer in hand already — so passing it is what keeps the whole-register
    // picture, the group list under it and `GET /admin-api/permissions`
    // describing ONE reading of the registry rather than three taken a few
    // milliseconds apart.
    const groups = appPermissions.clusters(register);
    log.debug("Leaving AdminViews.permissionsView(). " +
              register.counts.grants + " " +
        "grant(s) in " +
              groups.counts.clusters + " group(s).");
    return { register: register, graph: graph, clusters: groups };
  }

  // The crypto report as JSON, for `admin_api.js`. It calls exactly this, so
  // the API cannot compute an answer the console does not draw — which is what
  // makes "every /admin page has an /admin-api operation" a property of the
  // code.
  /**
   * Builds the crypto report as JSON.
   *
   * @param req - the request; only its query and realm are read
   * @returns the report
   */
  cryptoView(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering AdminViews.cryptoView().");
    if (!cryptoReporter) {
      log.debug("Leaving AdminViews.cryptoView(). No reporter.");
      return null;
    }
    const report = cryptoReporter.report(baseUrlOf(req));
    log.debug("Leaving AdminViews.cryptoView(). " +
              ((report.families || []).length) + " identity service(s).");
    return report;
  }

  // The key inventory, for admin_api.js. A LIST and never key material: the
  // export is the other function, so a caller that only wanted to know what
  // this process holds cannot be handed a private key by accident.
  /**
   * Lists the keys this process holds; never key material.
   *
   * @param req - the request; only its query and realm are read
   * @returns the inventory
   */
  keysView(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering AdminViews.keysView().");
    if (!cryptoReporter) {
      log.debug("Leaving AdminViews.keysView(). No reporter.");
      return null;
    }
    const report = cryptoReporter.keys(baseUrlOf(req));
    log.debug("Leaving AdminViews.keysView(). " + ((report.keys || []).length) +
              " key(s).");
    return report;
  }

  // The export, for admin_api.js. Returns the vendored exporter's own answer —
  // `{ok, files, status}` or `{ok: false, errors}` — and decides nothing, so
  // the API and the page cannot refuse different things.
  /**
   * Exports one key through the vendored exporter, deciding nothing itself.
   *
   * @param key - which key
   * @param format - the export format
   * @param password - the password to protect it with, where the format takes
   *   one
   * @returns `{ ok, files, status }` or `{ ok: false, errors }`
   */
  keysExport(key, format, password) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.keysExport(). key=" + key + ", format=" +
              format);
    if (!cryptoReporter) {
      log.debug("Leaving AdminViews.keysExport(). No reporter.");
      return null;
    }
    log.debug("Leaving AdminViews.keysExport().");
    return cryptoReporter.exportKey(key, format, password);
  }

  /**
   * Returns the XACML overview from the XACML pages.
   *
   * @param req - the request
   * @returns the view, or the no-XACML answer when the module is not loaded
   */
  xacmlView(req) {
    const { log, noXacml } = this.deps;
    log.debug('Entering AdminViews.xacmlView().');
    const json = xacmlPages ? xacmlPages.overview(req) : noXacml();
    log.debug('Leaving AdminViews.xacmlView().');
    return json;
  }

  /**
   * Returns the XACML policy list from the XACML pages.
   *
   * @param req - the request
   * @returns the view, or the no-XACML answer when the module is not loaded
   */
  xacmlPoliciesView(req) {
    const { log, noXacml } = this.deps;
    log.debug('Entering AdminViews.xacmlPoliciesView().');
    const json = xacmlPages ? xacmlPages.policies(req) : noXacml();
    log.debug('Leaving AdminViews.xacmlPoliciesView().');
    return json;
  }

  /**
   * Returns one policy in the XACML editor, named by the `policy` query.
   *
   * @param req - the request
   * @returns the view, or the no-XACML answer when the module is not loaded
   */
  xacmlEditorView(req) {
    const { log, noXacml } = this.deps;
    log.debug('Entering AdminViews.xacmlEditorView().');
    const json = xacmlPages
      ? xacmlPages.editor(String((req.query || {}).policy || '')) : noXacml();
    log.debug('Leaving AdminViews.xacmlEditorView().');
    return json;
  }

  /**
   * Returns the remote PEPs from the XACML pages.
   *
   * @param req - the request
   * @returns the view, or the no-XACML answer when the module is not loaded
   */
  xacmlPepsView(req) {
    const { log, noXacml } = this.deps;
    log.debug('Entering AdminViews.xacmlPepsView().');
    const json = xacmlPages ? xacmlPages.peps(req) : noXacml();
    log.debug('Leaving AdminViews.xacmlPepsView().');
    return json;
  }

  /**
   * Returns the XACML decision tester's answer for the query.
   *
   * @param req - the request
   * @returns the view, or the no-XACML answer when the module is not loaded
   */
  xacmlDecideView(req) {
    const { log, noXacml } = this.deps;
    log.debug('Entering AdminViews.xacmlDecideView().');
    const json = xacmlPages ? xacmlPages.decide(req.query || {}) : noXacml();
    log.debug('Leaving AdminViews.xacmlDecideView().');
    return json;
  }

  // THE SEVENTH, and the only one of them that reports TRAFFIC rather than
  // configuration. It takes no argument at all — there is nothing to filter and
  // nothing to name — which is why it is the shortest of the seven and not a
  // sign that something was left out.
  /**
   * Returns the XACML decision counts from the XACML pages.
   *
   * @param req - the request (unused)
   * @returns the view, or the no-XACML answer when the module is not loaded
   */
  xacmlMonitorView(req) {
    const { log, noXacml } = this.deps;
    log.debug('Entering AdminViews.xacmlMonitorView().');
    const json = xacmlPages ? xacmlPages.monitor() : noXacml();
    log.debug('Leaving AdminViews.xacmlMonitorView().');
    return json;
  }

  // What `mgmt-api/admin_api.ts` calls. The `?format=json` half of each page,
  // which is the same object the page itself is built from.
  /**
   * Returns the JSON half of one `/admin/ldap/*` page.
   *
   * @param name - the directory page's name
   * @param req - the request
   * @returns the page's JSON, or a no-directory answer when none is loaded
   */
  directoryPageJson(name, req) {
    const { log } = this.deps;
    log.debug('Entering AdminViews.directoryPageJson(). name=' + name);
    if (!directoryPages) {
      log.debug('Leaving AdminViews.directoryPageJson(). No directory is ' +
                'loaded.');
      return { directory: false,
               message: 'No LDAP directory is loaded in this process, so ' +
                        'there ' +
                        'is no store to report. ldap/ldap_server.js fills ' +
                        'this reader when it is required.' };
    }
    const view = directoryPages[name](req);
    log.debug('Leaving AdminViews.directoryPageJson().');
    return view.json;
  }

  // The register, in one place so that the page, `?format=json` and
  // `GET /admin-api/consent` cannot come to disagree about what is in it — the
  // same property `permissionsView()` gives the delegated permission register.
  /**
   * Builds the consent register: the overrides and the recorded consents.
   *
   * @returns the register
   */
  consentView() {
    const { log, consent } = this.deps;
    log.debug("Entering AdminViews.consentView().");
    const register = consent.register();
    log.debug("Leaving AdminViews.consentView(). " + register.counts.globals +
              " " +
        "override(s), " +
              register.counts.consents + " recorded.");
    return register;
  }

  // ---------------------------------------------------------------------------
  // THE CONSENT REGISTER, ONE PAGE OF EACH HALF (2026-09-18).
  //
  // What `/admin/consent` draws and what `GET /admin-api/consent` answers,
  // computed ONCE, for `usedAssertionsView()`'s reason: two doors onto one
  // list come to disagree the first time either of them grows a filter the
  // other does not have.
  //
  // **BOTH HALVES GROW WITHOUT A BOUND, AND ONLY ONE OF THEM WAS PAGED WHERE IT
  // MATTERED.** The console page paged both tables; the API returned
  // `consentView()` whole — every recorded consent is one row per (person,
  // application, scope), so a service driven for an afternoon holds thousands,
  // and every read of the API carried all of them. So the reply is the page
  // asked for of each half, with the paging beside it, and `counts` still says
  // how many there are in total.
  //
  // **TWO PAGERS AND ONE SIZE.** `globalsPage` and `usersPage` move their
  // own tables and not each other's (the console's links carry both, through
  // `pageParamsOf()`), and `per` sizes both — the arrangement `/admin/pki`'s
  // two tables have. **Each pager is named after the ARRAY it pages** —
  // `globals` by `globalsPage`/`globalsPaging`, `users` by
  // `usersPage`/`usersPaging` — which is the management API's rule for a reply
  // holding several lists (`detailPagingParameters()`): a caller that can read
  // the reply can write the request. The recorded half's pager was
  // `consentsPage` until this change, beside an array called `users`.
  //
  // The search `q` narrows the RECORDED half only, over the person, the
  // application and the scope; the overrides are configuration, one row per
  // thing somebody typed, and are paged rather than searched.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/consent`: the register paged, the recorded half searched by
   * `q`.
   *
   * @param query - the request's query
   * @returns the page's JSON
   */
  consentPageView(query) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.consentPageView().");
    const asked = query || {};
    const register = this.consentView();
    const q = String((Array.isArray(asked.q) ? asked.q[0] : asked.q) || '')
      .trim().toLowerCase();
    const matched = q
      ? register.users.filter(function (one) {
          return String(one.username).toLowerCase().indexOf(q) >= 0 ||
                 String(one.client).toLowerCase().indexOf(q) >= 0 ||
                 String(one.scope).toLowerCase().indexOf(q) >= 0;
        })
      : register.users;
    const globalPage = this.pagedRows(asked, register.globals,
      { name: 'globals', noun: 'overrides',
        defaultPer: DELEGATION_PER_PAGE });
    const consentPage = this.pagedRows(asked, matched,
      { name: 'users', noun: 'consents',
        defaultPer: DELEGATION_PER_PAGE });
    // The register's own members with its two lists REPLACED by one page of
    // each — never beside them, which would be every row twice and the reply
    // exactly as unbounded as before.
    const json = Object.assign({}, register, {
      globals: globalPage.shown,
      users: consentPage.shown,
      matched: matched.length,
      globalsPaging: this.pagingJson(globalPage.paging),
      usersPaging: this.pagingJson(consentPage.paging),
      query: { q: q },
      // Where a withdrawal is recorded on a person's entry, which the page
      // names (#446).
      withdrawnAttribute: consent.WITHDRAWN_ATTRIBUTE,
      // The applications the page's forms offer (#446), as the page read
      // the register for them while it drew.
      applicationChoices: applications.list().map(function (row) {
        return { identifier: row.identifier, name: row.name || '' };
      })
    });
    log.debug("Leaving AdminViews.consentPageView(). " +
              globalPage.shown.length + " of " + register.globals.length +
              " override(s), " + consentPage.shown.length + " of " +
              matched.length + " consent(s).");
    return { json: json, register: register, q: q, matched: matched,
             globalPage: globalPage, consentPage: consentPage };
  }

  // ---------------------------------------------------------------------------
  // THE REGISTER, IN ONE PLACE so that the page, `?format=json` and
  // `GET /admin-api/roles` cannot come to disagree about what is in it — the
  // same property `consentView()` and `permissionsView()` give their registers.
  // ---------------------------------------------------------------------------
  /**
   * Builds the role register: the built-in and configured roles and who holds
   * them.
   *
   * @returns the register
   */
  rolesRegister() {
    const { log, config, applications, roles } = this.deps;
    log.debug("Entering AdminViews.rolesRegister().");
    const configured = roles.all();
    // WHICH APPLICATIONS REQUIRE WHAT, computed from the applications registry
    // rather than kept anywhere: the requirement lives on the application entry
    // and this is a READING of it. `requiresNarrowedRoles()` is what tells an
    // application somebody has deliberately restricted from one that merely has
    // the default — and the difference matters, because every application in
    // this service requires EVERYBODY and listing all of them would bury the
    // handful that were narrowed.
    //
    // ONE `list()`, AND THE REQUIREMENT READ OFF THE ROW (#352): this asked
    // `requiresNarrowedRoles()` and `requiredRolesOf()` by identifier, each
    // of which read the entry out of the directory again — two reads per
    // application for a register the list had already read whole.
    const listed = applications.list();
    const requiring = listed.filter(function (row) {
      return applications.narrowedRoles(applications.requiredRolesFrom(row));
    }).map(function (row) {
      const required = applications.requiredRolesFrom(row);
      return {
        application: row.identifier,
        name: row.name || row.identifier,
        required: required,
        // WHETHER ANYBODY AT ALL COULD SATISFY IT. A role named on an
        // application entry that no role entry defines and that is not built in
        // is a requirement NOBODY can hold — which refuses everybody, silently
        // and correctly, and looks exactly like the application being broken.
        // This is the one thing this page can say that neither the application
        // page nor the role table can.
        // A requirement is met by a realm-wide role of that name or by
        // this application's own role of that name inside it (#310) —
        // never another application's.
        unknown: required.filter(function (name) {
          return !roles.isBuiltIn(name) && !configured.some(function (role) {
            return role.application
              ? role.application === row.identifier && role.localName === name
              : role.name === name;
          });
        })
      };
    });
    const permissions = [];
    // `roleGatingFor()` is a Map lookup now (#352), not a `list()` per
    // permission.
    listed.forEach(function (row) {
      applications.permissionsOf(row).forEach(function (one) {
        if (one.id) {
          const gating = applications.roleGatingFor(one.id);
          permissions.push({ id: one.id, application: row.identifier,
                             name: one.name,
                             gated: !!(gating && gating.gated) });
        }
      });
    });
    const out = {
      // The store, so a reader can say where these entries are and reach them
      // with an ldapsearch.
      container: roles.directoryInstalled() ? 'ou=roles' : '',
      storable: !!roles.directoryInstalled(),
      defaultRequired: roles.DEFAULT_REQUIRED_ROLE,
      claim: config.value('roles.claim') !== false,
      claimName: String(config.value('roles.claimName') || 'roles'),
      enforced: config.value('roles.enforceIssuance') !== false,
      gated: !!rolePreviewer,
      policy: rolePreviewer ? rolePreviewer.policy() : null,
      builtIn: roles.builtInCatalogue(),
      roles: configured,
      // EVERY PERMISSION A ROLE MAY AUTHORIZE (#303): each application
      // permission defined in this realm, by the identifier a client asks
      // for, marked `gated` where its resource opted in. The console's
      // suggestions and the API's answer to "what could I name".
      permissions: permissions,
      permissionIds: permissions.map(function (one) {
        return one.id;
      }),
      requiring: requiring,
      counts: {
        builtIn: roles.BUILT_IN_NAMES.length,
        configured: configured.length,
        members: configured.reduce(function (n, one) {
          return n + one.users.length + one.groups.length +
                 one.applications.length;
        }, 0),
        requiring: requiring.length,
        unsatisfiable: requiring.filter(function (one) {
          return one.unknown.length > 0;
        }).length
      }
    };
    log.debug("Leaving AdminViews.rolesRegister(). " + out.counts.configured +
              " configured role(s).");
    return out;
  }

  // THE ROLES PAGE'S VIEW, AND `GET /admin-api/roles`' (#446). It was the
  // register alone for the API and the register with the page's own members
  // for the page, built in the route; one function now, so the page is drawn
  // from the answer a caller of the API receives. The register's members are
  // its first members, as they were. **The preview is not in it**: it is
  // `GET /admin-api/roles/preview`, an operation of its own for the reason
  // argued above that one, and the page composes it in as `preview` (the
  // route here; the page table's `compose` in the browser).
  /**
   * Returns the roles page's view: the register, the roles a query matched
   * and its page of them, the menus the forms offer, and the page's
   * settings.
   *
   * @param query - the query: `q` and the roles' paging
   * @returns the view
   */
  rolesView(query?) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.rolesView().");
    const q0 = query || {};
    const register = this.rolesRegister();
    const q = String((Array.isArray(q0.q) ? q0.q[0] : q0.q) || '')
      .trim().toLowerCase();
    const matched = q
      ? register.roles.filter(function (one) {
          return [one.name, one.description].concat(one.users, one.groups,
                                                    one.applications)
            .some(function (text) {
              return String(text).toLowerCase().indexOf(q) >= 0;
            });
        })
      : register.roles;
    const rolePage = this.pagedRows(q0, matched,
      { name: 'roles', noun: 'roles', defaultPer: 25 });
    const json = Object.assign({}, register, {
      matched: matched.length,
      shown: rolePage.shown.length,
      paging: this.pagingJson(rolePage.paging),
      query: { q: q },
      memberKinds: adminActions.ROLE_MEMBER_KINDS,
      issuanceKinds: issuanceGate.KINDS,
      actions: adminActions.ROLE_ACTIONS.slice(),
      settings: configSettingsJson ? configSettingsJson('/admin/roles') : null,
      // The page's own rows and its application menu.
      shownRoles: rolePage.shown,
      applicationChoices: applications.list().map(function (row) {
        return { identifier: row.identifier, name: row.name || '' };
      })
    });
    log.debug("Leaving AdminViews.rolesView(). " + register.roles.length +
              " role(s).");
    return json;
  }


  // ---------------------------------------------------------------------------
  // WHAT /admin/policies AND GET /admin-api/policies ANSWER (2026-09-12).
  //
  // ONE COMPUTATION, TWO RENDERINGS, which is this file's whole reason: the
  // page draws its form, its schema table and its sentence about enforcement
  // from the model below, and the operation hands the same model back as JSON.
  //
  // **THE PAGE IS "POLICIES" AND THE FIRST KIND ON IT IS THE PASSWORD POLICY**,
  // which is why the answer is shaped as KINDS of policy each holding PROFILES
  // rather than as a password policy with a page wrapped round it: the next
  // kind is a row in `kinds` and a member beside `password`, not a new
  // resource. **#64 MADE THAT TRUE**: the kinds are `admin-core/
  // policy_kinds.ts`'s list — the password policy, then the authentication
  // policy — and `policiesView()` draws every one from its module.
  //
  // **IT IS NOT THE XACML POLICY REPOSITORY.** `/admin/xacml/policies` and
  // `/admin/ldap/policies` draw `ou=policies`, which holds documents a PDP
  // evaluates; this draws `ou=passwordPolicies`, which holds numbers
  // `credentials.setPassword()` checks. `kinds[].container` says which
  // container each kind lives in so that a reader does not have to take the
  // page's word.
  //
  // The profile list is PAGED like every list this console draws, though it has
  // one row today: nothing assigns a second profile yet, and a list whose
  // paging arrives the day a second row does is a list somebody has to remember
  // to page.
  // ---------------------------------------------------------------------------
  private passwordGeneratorFacts() {
    const { log } = this.deps;
    log.debug("Entering AdminViews.passwordGeneratorFacts().");
    log.debug("Leaving AdminViews.passwordGeneratorFacts().");
    // `module` names where the draw is made. It was the generate-password
    // package, with its version, until #65 put the draw in crypto.js's
    // section 13; there is no version of this service's own to print, so
    // the member is empty rather than gone, for a reader that expects it.
    return {
      module: 'common/crypto.js randomString()',
      version: '',
      source: 'node\'s crypto.randomInt, rejection-sampled so that no ' +
              'character of the pool is likelier than another',
      pools: ['lowercase letters', 'uppercase letters', 'digits', 'symbols'],
      excluded: ['"', '`'],
      drawsUntil: 'the password satisfies the profile, so every generated ' +
                  'password is uniform over the passwords the profile accepts'
    };
  }

  // THE MEMBERS EVERY KIND HAS (#64): the profile in force, the rules as
  // sentences, the field table and the schema — built from the kind's module,
  // so a kind registered in `policy_kinds.ts` appears here with no edit.
  private policyKindMember(kind) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.policyKindMember(). " + kind.id);
    const module = kind.module;
    const profile = module.read(module.DEFAULT_PROFILE);
    const out = {
      profile: profile,
      rules: module.describe(profile),
      defaults: Object.assign({}, module.DEFAULTS),
      fields: module.FIELDS.map(function (field) {
        return { key: field.key, attribute: field.attribute,
                 label: field.label,
                 type: field.type, min: field.min, max: field.max,
                 values: field.values, unit: field.unit || '',
                 default: field.dflt,
                 value: profile[field.key],
                 source: profile.sources[field.key],
                 mechanism: field.mechanism, role: field.role,
                 email: !!field.email,
                 what: field.what };
      }),
      schema: module.SCHEMA
    };
    log.debug("Leaving AdminViews.policyKindMember().");
    return out;
  }

  // What only the password policy has to say: the generator and the doors.
  private passwordPolicyExtras() {
    const { log } = this.deps;
    log.debug("Entering AdminViews.passwordPolicyExtras().");
    log.debug("Leaving AdminViews.passwordPolicyExtras().");
    return {
      generator: this.passwordGeneratorFacts(),
      // THE DOORS, named so that "enforced" is a claim a reader can check
      // rather than one they have to take. Every one ends in
      // `credentials.preparePassword()`.
      doors: [
        { door: '/admin/users/new and /admin/users (Set password)',
          via: 'credentials.setPassword()' },
        { door:
            'POST /admin-api/users/create and /admin-api/users/set-password',
          via: 'credentials.setPassword()' },
        { door: '/portal/password', via: 'credentials.setPassword()' },
        { door: '/portal/activate (the first password a person sets)',
          via: 'credentials.setPassword()' },
        { door: 'an LDAP add or modify of userPassword on 389 or 636',
          via: 'credentials.preparePassword()' }
      ],
      notDoors: 'SCIM carries no password (this service advertises ' +
                'changePassword: false), and a password is never set by ' +
                'signing in. Passwords stored BEFORE a rule changed are ' +
                'not re-checked: nothing here holds a password in a form ' +
                'that could be, and the rule applies from the next change.'
    };
  }

  // What only the authentication policy has to say: its mechanisms, and
  // whether the two email ones CAN be on in this realm (#64, D1).
  private authnPolicyExtras(member) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.authnPolicyExtras().");
    const authn = authnPolicy;
    const mailUsable = authn.mailUsable();
    const mailWhy = mailUsable ? ''
      : 'This realm cannot send mail, so the two email mechanisms cannot be ' +
        'turned on and are never offered. Configure a transport on Server ' +
        'configuration > Mail.';
    member.fields.forEach(function (field) {
      field.disabled = !!(field.email && !mailUsable);
      field.disabledWhy = field.disabled ? mailWhy : '';
    });
    const profile = member.profile;
    const out = {
      from: profile.from,
      inherited: profile.inherited,
      mail: { usable: mailUsable, why: mailWhy },
      nistWarning: authn.NIST_EMAIL_WARNING,
      mechanisms: authn.MECHANISMS.map(function (m) {
        const primary = m.primary === null ? null
          : !!authn.allows(m.id, 'primary', profile);
        const second = m.secondFactor === null ? null
          : !!authn.allows(m.id, 'second-factor', profile);
        return { id: m.id, label: m.label, email: !!m.email,
                 primary: primary, secondFactor: second,
                 active: (primary || second) ? (!m.email || mailUsable)
                   : false,
                 what: m.what };
      })
    };
    log.debug("Leaving AdminViews.authnPolicyExtras().");
    return out;
  }

  /**
   * Builds Directory → Policies: every kind of policy and its profiles.
   *
   * @param query - the request's query
   * @returns the page's JSON
   */
  policiesView(query) {
    const { log, mode, policyKinds } = this.deps;
    log.debug("Entering AdminViews.policiesView().");
    const q = query || {};
    const kinds = policyKinds.list();
    const rows = [];
    const out: Record<string, any> = {
      mode: mode.current(),
      kinds: [],
      profiles: [],
      paging: null,
      actions: policyKinds.actions()
    };
    kinds.forEach((kind) => {
      const member: Record<string, any> = this.policyKindMember(kind);
      if (kind.id === 'password') {
        Object.assign(member, this.passwordPolicyExtras());
      } else if (kind.id === 'authn') {
        Object.assign(member, this.authnPolicyExtras(member));
      }
      out[kind.id] = member;
      const profiles = kind.module.list();
      out.kinds.push({ id: kind.id, label: kind.label,
                       container: kind.container, governs: kind.governs,
                       profiles: profiles.length,
                       actions: [policyKinds.saveAction(kind),
                                 policyKinds.resetAction(kind)] });
      profiles.forEach(function (one) {
        rows.push({ kind: kind.id, name: one.name, stored: one.stored,
                    inherited: !!one.inherited, dn: one.dn,
                    problems: one.problems });
      });
    });
    // THE PASSWORD POLICY'S ENFORCEMENT stays at the top level, where it has
    // been since 2026-09-12: it is a sentence about the MODE, which only
    // that kind depends on.
    const enforced = mode.verifiesCredentials();
    out.enforced = enforced;
    out.enforcement = enforced
      ? 'ENFORCED. This realm is in product mode, so every password set ' +
        'here — at every door below — must meet the profile, and a new ' +
        'password may not repeat a remembered one.'
      : 'NOT ENFORCED. This realm is in development mode, where no password ' +
        'is checked at any door, so a rule about one would be a rule about ' +
        'a credential nothing reads. The history is still RECORDED, so a ' +
        'realm switched to product mode starts with one. A GENERATED ' +
        'password meets the profile in both modes.';
    const listed = this.pagedRows(q, rows);
    out.profiles = listed.shown;
    out.paging = this.pagingJson(listed.paging);
    log.debug("Leaving AdminViews.policiesView(). " + kinds.length +
              " kind(s), " + rows.length + " profile(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE DRY RUN. Asked through the SAME call the nine issuance sites make, so a
  // preview that agreed with the enforcement only by coincidence is impossible
  // — which is the property that makes it worth having at all.
  // ---------------------------------------------------------------------------
  /**
   * Previews an issuance decision through the same call the issuance sites
   * make: the dry run on `/admin/roles`.
   *
   * @param query - the query, naming the application and the subject
   * @returns the decision and what it rested on
   */
  rolesPreview(query) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.rolesPreview().");
    const asked = query || {};
    const application = String(asked.application || '').trim();
    const who = String(asked.subject || asked.username || '').trim();
    const kind = String(asked.subjectKind || 'user') === 'application'
      ? 'application' : 'user';
    const issuance = String(asked.kind || '');
    if (!application || !who) {
      log.debug("Leaving AdminViews.rolesPreview(). Nothing asked.");
      return null;
    }
    if (!rolePreviewer) {
      log.debug("Leaving AdminViews.rolesPreview(). No previewer.");
      return { asked: { application: application, subject: who,
                        subjectKind: kind, kind: issuance },
               available: false,
               why: 'The XACML family is not loaded in this process, so ' +
                    'there ' +
                    'is no PDP to ask and nothing is gated: every issuance ' +
                    'is ' +
                    'allowed. That is what issuance_gate.check() answers ' +
                    'with an empty decider, and it is why a process without ' +
                    'the engine is a smaller service rather than a broken ' +
                    'one.' };
    }
    const answer = rolePreviewer.preview({
      application: application,
      kind: issuance || undefined,
      subject: { kind: kind, name: who, authenticated: true }
    });
    log.debug("Leaving AdminViews.rolesPreview(). " +
              (answer.allowed ? 'Permit.' : 'Refused.'));
    return Object.assign({ asked: { application: application, subject: who,
                                    subjectKind: kind, kind: issuance },
                           available: true }, answer);
  }

  // Which person the four tables show values for, and where the page sends
  // itself back to. Capped because the string is echoed, and defaulted to
  // somebody the directory actually holds from startup so a fresh process shows
  // real values rather than an invented person nobody can look up — the same
  // rule and the same default /admin/vc uses, deliberately, so the two pages
  // preview the same person unless somebody says otherwise.
  /**
   * Returns the person the claims pages preview.
   *
   * @param query - the request's query
   * @returns the username
   */
  claimsPreviewUser(query) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.claimsPreviewUser().");
    const asked = String((query && query.user) || 'alice').trim();
    log.debug("Leaving AdminViews.claimsPreviewUser().");
    return asked.slice(0, 64) || 'alice';
  }

  // ---------------------------------------------------------------------------
  // ATTRIBUTE CLAIMS' THREE HELPS (#94): the attributes worth offering, what
  // each row would carry for the previewed person, and which federation
  // partners' release lists would withhold a claim. One computation each,
  // for the three claim pages and their three /admin-api replies.
  // ---------------------------------------------------------------------------
  /**
   * The attributes an attribute claim can name that the catalogue cannot:
   * what this realm's attribute sources and inbound federation mappings
   * write, each with who writes it.
   *
   * @returns `[{ attribute, from: [..] }]`, sorted by attribute
   */
  attributeClaimChoices() {
    const { log, federation } = this.deps;
    log.debug("Entering AdminViews.attributeClaimChoices().");
    const by: Record<string, { attribute: string; from: string[] }> = {};
    const add = function (attribute: unknown, from: string) {
      const name = String(attribute || '').trim();
      if (!name) {
        return;
      }
      const key = name.toLowerCase();
      by[key] = by[key] || { attribute: name, from: [] };
      if (by[key].from.indexOf(from) < 0) {
        by[key].from.push(from);
      }
    };
    let sources: any[] = [];
    try {
      sources = require('../attribute-sources/attribute_sources').list();
    } catch (e) {
      log.debug("Caught in AdminViews.attributeClaimChoices(): " +
                ((e && e.message) || e));
      // No attribute sources in this process: the list is federation's.
      sources = [];
    }
    sources.forEach(function (source) {
      Object.keys(source.columns || {}).forEach(function (column) {
        add(source.columns[column], 'attribute source ' + source.id);
      });
    });
    (federation.list() || []).forEach(function (record) {
      [].concat(record.fedAttributeMap || []).forEach(function (value) {
        const text = String(value);
        const at = text.indexOf('=');
        if (at > 0) {
          add(text.slice(at + 1), 'federation ' + record.fedId);
        }
      });
    });
    const out = Object.keys(by).sort().map(function (key) {
      return by[key];
    });
    log.debug("Leaving AdminViews.attributeClaimChoices(). " + out.length +
              ".");
    return out;
  }

  /**
   * What each attribute claim of a set would carry for one person, built by
   * the issuance path (`jwtClaims()` / `samlAttributes()`).
   *
   * @param id - the claim set
   * @param user - the person
   * @returns `[{ name, attribute, carried, value }]`; `value` is the JWT
   *   value or the SAML values
   */
  attributeClaimPreview(id, user) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.attributeClaimPreview(). " + id);
    const rows = stats.claimSet(id).filter(function (claim) {
      return !!claim.attribute;
    });
    if (!rows.length) {
      log.debug("Leaving AdminViews.attributeClaimPreview(). None.");
      return [];
    }
    const saml = id === 'saml2' || id === 'saml11';
    const issued = saml ? stats.samlAttributes(id, { subject: user })
                        : stats.jwtClaims(id, { username: user });
    log.debug("Leaving AdminViews.attributeClaimPreview().");
    return rows.map(function (claim) {
      if (saml) {
        const found = (issued as any[]).filter(function (one) {
          return one.name === claim.name;
        })[0];
        const values = found
          ? (Array.isArray(found.values) ? found.values : [found.value]) : [];
        return { name: claim.name, attribute: claim.attribute,
                 carried: values.length > 0, value: values };
      }
      const carried = Object.prototype.hasOwnProperty.call(issued,
                                                           claim.name);
      return { name: claim.name, attribute: claim.attribute,
               carried: carried,
               value: carried ? (issued as any)[claim.name] : null };
    });
  }

  /**
   * The federation partners with a release list, each with the claim names
   * it releases: a claim that is not on a partner's list is withheld from
   * that partner.
   *
   * @returns `[{ id, names }]`
   */
  releaseWithholding() {
    const { log, federation } = this.deps;
    log.debug("Entering AdminViews.releaseWithholding().");
    const out = (federation.list() || []).filter(function (record) {
      return [].concat(record.fedRelease || []).length > 0;
    }).map(function (record) {
      return { id: String(record.fedId),
               names: [].concat(record.fedRelease || []).map(String) };
    });
    log.debug("Leaving AdminViews.releaseWithholding(). " + out.length +
              " partner(s) with a list.");
    return out;
  }

  /**
   * For each claim of a set, the partners whose release list withholds it.
   *
   * @param claims - the set's claims
   * @param lists - `releaseWithholding()`
   * @returns `{ <claim name>: [partner ids] }`, only names withheld somewhere
   */
  withheldFor(claims, lists) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.withheldFor().");
    const out: Record<string, string[]> = {};
    (claims || []).forEach(function (claim) {
      const from = (lists || []).filter(function (one) {
        return one.names.indexOf(claim.name) < 0;
      }).map(function (one) {
        return one.id;
      });
      if (from.length) {
        out[claim.name] = from;
      }
    });
    log.debug("Leaving AdminViews.withheldFor().");
    return out;
  }

  // One family of sets and the rules that govern them. The rules are in the
  // reply and not only on the page because the first thing a caller of POST
  // .../claims/add needs is the list of names it will refuse.
  //
  // THREE CALLERS, ONE BUILDER, for the reason claimsAction() has one: the
  // three pages (JWT claims, SAML attributes, UserInfo claims) differ in WHICH
  // sets they carry and in a rule or two each — the reserved JWT names apply to
  // a token and a UserInfo response, the default SAML 1.1 namespace to an
  // assertion — and everything else about the reply is the same fact answered
  // again. Separate builders would have been previews that could disagree about
  // one person, which is precisely the thing every preview here is built
  // through the issuance path to prevent.
  /**
   * Builds the JSON of some claim sets, each with one person's values as they
   * would be issued.
   *
   * @param ids - the claim set ids
   * @param previewUser - the person to preview
   * @returns the sets
   */
  claimSetsJson(ids, previewUser) {
    const { log, stats, claimAttributes, groupClaims } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.claimSetsJson(). " + ids.length +
              " set(s).");
    const user = previewUser || 'alice';
    const withheld = this.releaseWithholding();
    const json = {
      placeholders: stats.PLACEHOLDERS,
      // The catalogue every set chooses from, so a caller can discover the
      // legal values of `attributes` without reading this service's source or
      // guessing at LDAP spellings. `sets` says which of the FIVE carries each
      // — all five, not only the ones in this reply, because the catalogue is
      // one list and a per-page view of it would answer "which sets carry mail"
      // with half the truth.
      attributeCatalogue: claimAttributes.catalogueRows(),
      // Stated rather than left to be discovered, because the two halves of a
      // set are one screen apart and the precedence only shows up when both
      // name one claim.
      precedence: 'A typed claim wins over a directory attribute of the same ' +
                  'name.',
      sets: ids.map(function (id) {
        const preview = claimAttributes.previewFor(id, user);
        return { id: id, label: stats.CLAIM_SETS[id].label,
                 claims: stats.claimSet(id),
                 attributes: claimAttributes.selectedNames(id),
                 // What those attributes would actually put in this set right
                 // now, built by the function the ISSUANCE path calls. A caller
                 // with no browser has no other way to ask "what would this
                 // issue", and a preview built by a second walk of the
                 // catalogue would be a preview that can disagree with the
                 // token.
                 attributeClaims: preview.claims,
                 attributeReport: preview.report,
                 // THE SET'S OWN ROWS FOR THIS PERSON (#94): what each
                 // attribute claim would carry, built by the issuance path.
                 attributeClaimPreview: self.attributeClaimPreview(id, user),
                 // WHO WOULD NOT GET EACH CLAIM (#94): the federation
                 // partners whose release list does not name it.
                 withheldFrom: self.withheldFor(stats.claimSet(id), withheld)
               };
      }),
      // THE ATTRIBUTES AN ATTRIBUTE CLAIM CAN NAME THAT THE CATALOGUE CANNOT
      // (#94): what this realm's attribute sources and federation mappings
      // write onto people, each with who writes it — the console's pick-list,
      // and a caller's.
      attributeChoices: this.attributeClaimChoices(),
      // Whether the directory holds this person at all, and what every
      // attribute in the catalogue would say about them — selected or not, so a
      // caller can see what ticking a box would do before ticking it. Read
      // through catalogueValuesFor() rather than off one of the previews above,
      // because a set with nothing selected reports no entry: that is the right
      // answer to "what does this set carry" and the wrong answer to "is this
      // person in the directory".
      preview: Object.assign({ user: user },
                             claimAttributes.catalogueValuesFor(user)),
      // The groups claim, which is the one thing here that is not chosen per
      // set: all five carry it or none does — which is also why it is reported
      // by ALL THREE pages' replies rather than by the one it was written on.
      // Its settings are config.js's, so this is a report and there is no
      // operation beside it — POST /admin-api/config/set is the door, and a
      // second one would be a second store for one setting.
      //
      // `preview` is built by the function the ISSUANCE path calls, for the
      // reason every other preview here is: a caller with no browser has no
      // other way to ask "what would this token carry", and a second walk of
      // the directory would be a preview that can disagree with the token.
      groups: Object.assign(groupClaims.state(),
                            { preview: groupClaims.groupsOf(user) }),
      // The federation partners whose release list holds anything back
      // (#94), which each set's section warns about; per claim, it is the
      // set's `withheldFrom`.
      withholding: withheld
    };
    log.debug("Leaving AdminViews.claimSetsJson(). " + json.sets.length +
              " set(s).");
    return json;
  }

  // The two JWT sets, and the one rule that is theirs alone: the claim names
  // this service sets itself and refuses. It is in the reply rather than only
  // in the document because the first thing a caller of POST
  // /admin-api/claims/add needs is the list of names it will be refused for.
  /**
   * Builds `/admin/claims`'s JSON: the two JWT sets and the reserved claim
   * names.
   *
   * @param previewUser - the person to preview
   * @returns the JSON
   */
  claimsJson(previewUser) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.claimsJson(). previewUser=" + previewUser);
    const json = Object.assign(
      { reservedJwtClaims: stats.RESERVED_JWT_CLAIMS },
      this.claimSetsJson(stats.JWT_CLAIM_SET_IDS, previewUser));
    log.debug("Leaving AdminViews.claimsJson(). " + json.sets.length +
              " set(s).");
    return json;
  }

  // The two SAML sets, and the one rule that is theirs: the namespace a SAML
  // 1.1 attribute gets when nobody names one. THERE IS NO `reservedJwtClaims`
  // HERE and its absence is the honest answer rather than an oversight — that
  // list is enforced for the JWT and UserInfo sets only (admin_stats.js's
  // setClaimSet() asks `reservedNames()`), because an assertion attribute
  // called `exp` collides with nothing. Reporting
  // it here would have told a caller their call would be refused when it will
  // succeed.
  /**
   * Builds `/admin/saml-attributes`'s JSON: the two SAML attribute sets.
   *
   * @param previewUser - the person to preview
   * @returns the JSON
   */
  samlAttributesJson(previewUser) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.samlAttributesJson(). previewUser=" +
              previewUser);
    const json = Object.assign(
      { defaultSaml11Namespace: stats.DEFAULT_SAML11_NAMESPACE },
      this.claimSetsJson(stats.SAML_CLAIM_SET_IDS, previewUser));
    log.debug("Leaving AdminViews.samlAttributesJson(). " + json.sets.length +
              " set(s).");
    return json;
  }

  // The claims request being previewed, as the characters somebody typed.
  // Capped because it is echoed and because it is parsed — and the cap is
  // larger than the other echoed fields on this console for one reason: this
  // one is a JSON document rather than a name, and a cap that truncated a
  // legitimate request would produce a parse error that pointed at this service
  // instead of at the request.
  /**
   * Returns the `claims` request parameter the UserInfo page previews, capped.
   *
   * @param query - the request's query
   * @returns the parameter
   */
  claimsRequestParameter(query) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.claimsRequestParameter().");
    const asked = String((query && query.request) || '').trim();
    log.debug("Leaving AdminViews.claimsRequestParameter().");
    return asked.slice(0, 2048);
  }

  // Somebody the directory actually holds, so the page shows real values on a
  // fresh start rather than an invented person nobody can look up. The
  // parameter wins where it is given; the cap is there because this string is
  // echoed.
  /**
   * Returns the person `/admin/vc` previews.
   *
   * @param query - the request's query
   * @returns the username
   */
  vcPreviewUser(query) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.vcPreviewUser().");
    const asked = String((query && query.user) || 'alice').trim();
    log.debug("Leaving AdminViews.vcPreviewUser().");
    return asked.slice(0, 64) || 'alice';
  }

  // The catalogue, the selection, and one person's claims as they would be
  // minted right now. The preview is in the JSON as well as on the page because
  // "what would this issue" is the question the selection exists to answer, and
  // a caller with no browser has no other way to ask it.
  /**
   * Builds `/admin/vc`'s JSON: the catalogue, the selection, and one person's
   * claims as they would be minted now.
   *
   * @param previewUser - the person to preview
   * @returns the JSON
   */
  vcJson(previewUser) {
    const { log, vcClaims } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.vcJson(). previewUser=" + previewUser);
    // WHAT EACH ATTRIBUTE WOULD SAY ABOUT THE PERSON PREVIEWED (#446), the
    // page's last two columns: the value a credential would carry and where
    // it comes from — the entry, the persona's generator, or nothing.
    const persona = vcClaims.personaFor(previewUser);
    const built = vcClaims.subjectClaimsFor(previewUser, {});
    const byLdap: Record<string, any> = {};
    built.report.forEach(function (item) {
      byLdap[item.ldap.toLowerCase()] = item;
    });
    const json = {
      selected: vcClaims.selectedNames(),
      defaults: vcClaims.DEFAULT_SELECTION,
      ldpOmitted: vcClaims.ldpOmitted(),
      attributes: vcClaims.VC_ATTRIBUTES.map(function (row) {
        return { ldap: row.ldap, claim: row.claim.join('.'), label: row.label,
                 schema: row.schema, ldpTerm: row.ldpTerm || '',
                 selected: vcClaims.isSelected(row.ldap),
                 example: self.vcExampleOf(row, persona, byLdap) };
      }),
      preview: { user: previewUser, claims: built }
    };
    log.debug("Leaving AdminViews.vcJson().");
    return json;
  }

  // What the bar door asks for, and the dcql_query that carries it. The query
  // is built by the function that builds the REAL one — see the note in
  // vc_verifier_config.js — so a caller reading this reply is reading the next
  // Authorization Request rather than a description of one.
  // The one preview row as data: what an attribute would put in a credential
  // for the person previewed, and where that value came from. It was the
  // console's `vcExampleCell()`, which drew it; the page draws this (#446).
  /**
   * Says what one credential attribute would carry for the person previewed.
   *
   * @param row - the catalogue row
   * @param persona - the invented person for the preview user
   * @param byLdap - the built claims, keyed by lower-case attribute name
   * @returns `{ value, source }`; `value` is null where there is none
   */
  vcExampleOf(row, persona, byLdap) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.vcExampleOf().");
    const found = byLdap[row.ldap.toLowerCase()];
    if (found) {
      log.debug("Leaving AdminViews.vcExampleOf(). From the claims.");
      return { value: String(found.value), source: found.source };
    }
    if (!row.from) {
      // The only row with no generator: `description`, which this service
      // already writes on every entry to record the protocols that person has
      // used. Saying so is the point — it is the one attribute whose value is
      // a real fact.
      log.debug("Leaving AdminViews.vcExampleOf(). The entry's own.");
      return { value: null, source: 'the entry\'s own' };
    }
    // Shown in the form the CLAIM would take rather than the form the
    // attribute holds, because that is what the column above it is showing for
    // the selected rows and a table with two conventions in one column is a
    // table nobody can read. The two differ for exactly two attributes — a
    // date and a postal address — and both differences are punctuation.
    const raw = persona[row.from] == null ? '' : String(persona[row.from]);
    log.debug("Leaving AdminViews.vcExampleOf(). Generated.");
    return { value: row.toClaim ? row.toClaim(raw) : raw,
             source: 'would be generated' };
  }

  /**
   * Builds `/admin/vc-verifier-config`'s JSON: what the Verifier asks for and
   * the `dcql_query` that carries it.
   *
   * @returns the JSON
   */
  vpConfigJson() {
    const { log, vpConfig } = this.deps;
    log.debug("Entering AdminViews.vpConfigJson().");
    const format = vpConfig.defaultFormatId();
    const json = {
      requested: vpConfig.requestedClaims(),
      defaults: vpConfig.defaultRequested(),
      format: format,
      formats: vpConfig.FORMATS.map(function (item) {
        return { id: item.id, label: item.label,
                 identifiedBy: item.identifiedBy,
                 identifier: item.identifier,
                 selectiveDisclosure: item.selectiveDisclosure,
                 holderBinding: item.holderBinding,
                 configurations: item.configs,
                 // The page's wording of each (#446).
                 identifierText: item.identifierText, what: item.what };
      }),
      ldpOmitted: vpConfig.ldpOmitted(),
      catalogue: vpConfig.REQUESTABLE.map(function (row) {
        return { claim: row.claim, label: row.label, nested: row.nested,
                 attributes: row.members.map(function (member) {
                   return { ldap: member.ldap, schema: member.schema };
                 }),
                 ldpTerms: row.ldpTerms,
                 paths: vpConfig.dcqlPathsFor(format, row.claim),
                 requested: vpConfig.isRequested(row.claim),
                 issued: vpConfig.carriedNow(row.claim) };
      }),
      dcqlQuery: vpConfig.dcqlQuery(format),
      // What is asked for and not in the catalogue, with each one's DCQL
      // path (#446): the page lists them under the table.
      extras: vpConfig.requestedRows().filter(function (row) {
        return !row.inCatalogue;
      }).map(function (row) {
        return { claim: row.claim,
                 paths: vpConfig.dcqlPathsFor(format, row.claim) };
      })
    };
    log.debug("Leaving AdminViews.vpConfigJson(). Asking for " +
              json.requested.length +
              " claim(s).");
    return json;
  }

  // The base URL of this service WITHOUT any realm prefix. Every URL this page
  // prints is built from it, because a page read inside `acme` still has to be
  // able to name `default`'s endpoints — and baseUrlOf() adds the ambient
  // prefix by design.
  /**
   * Returns this service's base URL without any realm prefix.
   *
   * @param req - the request
   * @returns the URL
   */
  realmRootUrl(req) {
    const { log, baseUrlOf, realms } = this.deps;
    log.debug("Entering AdminViews.realmRootUrl().");
    const withRealm = baseUrlOf(req);
    log.debug("Leaving AdminViews.realmRootUrl().");
    return withRealm.slice(0, withRealm.length - realms.currentPrefix().length);
  }

  // What a realm sets, as rows. `config.describe()` is not used here and the
  // reason is worth a line: describing a setting means RESOLVING it, and
  // resolving it answers for the realm that is ambient rather than for the
  // realm being listed. So the raw value the realm carries is shown, beside
  // what that setting is called — which is what a person checking a realm's
  // configuration is actually reading.
  /**
   * Lists a realm's own settings as rows, with each setting's label.
   *
   * @param realm - the realm's record
   * @returns the rows
   */
  realmSettingRows(realm) {
    const { log, configSettingFor } = this.deps;
    log.debug("Entering AdminViews.realmSettingRows(). realm=" + realm.id);
    const rows = Object.keys(realm.overrides).sort().map(function (key) {
      const setting = configSettingFor(key);
      return { key: key, value: String(realm.overrides[key]),
               label: setting ? setting.label : key,
               group: setting ? setting.group : '' };
    });
    log.debug("Leaving AdminViews.realmSettingRows(). " + rows.length +
              " setting(s).");
    return rows;
  }

  // One realm as JSON. The same shape the list and the drill-down both answer
  // with, and the same shape GET /admin-api/realms answers with, so that a test
  // reading one has read all three.
  /**
   * Describes one realm, in the shape the list, the drill-down and the API
   * share.
   *
   * @param req - the request
   * @param realm - the realm's record
   * @returns the realm
   */
  realmJson(req, realm) {
    const { log, stsKeysFor, realms, config } = this.deps;
    log.debug("Entering AdminViews.realmJson().");
    const prefix = realms.prefixOf(realm);
    // A REALM WITH A LISTENER OF ITS OWN (#99) is reached on its own base,
    // whichever listener this page was read on.
    const own = realms.run(realm, function () {
      return {
        port: Number(config.value('listener.port')) || 0,
        publicBaseUrl: String(config.value('listener.publicBaseUrl') || '')
          .trim().replace(/\/+$/, ''),
        hostnames: [].concat(config.value('listener.hostnames') || []),
        certificateFile: String(config.value('listener.certificateFile') ||
                                '')
      };
    });
    const base = (own.publicBaseUrl || this.realmRootUrl(req)) + prefix;
    let bound: any[] = [];
    try {
      bound = require('../tls/realm_listeners').status(realm.id);
    } catch (e) {
      log.debug("Caught in AdminViews.realmJson(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving AdminViews.realmJson().");
    return {
      id: realm.id,
      name: realm.name,
      description: realm.description,
      // The realm's DNS domain and the directory tree it roots (2026-09-18).
      // Fixed when the realm was created; `common/realms.js` argues it.
      domain: realms.domainOf(realm),
      baseDn: realms.baseDnOf(realm),
      builtin: !!realm.builtin,
      // A REALM BEING REMOVED (#262, #294): null, or when the mark was set,
      // whether the removal is still in progress or was INTERRUPTED (the
      // process doing it stopped), what that refuses and how to finish it.
      // `common/realms.js`'s retiringState() is the one place that decides.
      retiring: realms.retiringState(realm),
      pathPrefix: prefix,
      baseUrl: base,
      // ITS OWN LISTENER (#99): what the realm configured, and what THIS
      // process holds — the listener is the front process's, so a page drawn
      // by a request worker reports the configuration and no socket.
      listener: {
        configured: own.port > 0,
        port: own.port,
        publicBaseUrl: own.publicBaseUrl,
        hostnames: own.hostnames,
        certificateSource: own.port > 0
          ? (own.certificateFile ? 'file' : 'issued') : '',
        here: bound[0] || null
      },
      // The kid of the realm's signing key. It is the one fact on this page
      // that PROVES the realms are separate rather than asserting it — two
      // realms showing one kid would be two names for one authorization server.
      //
      // Reading it MINTS it for a realm that has not signed anything yet, which
      // is a 2048-bit RSA generation and about a tenth of a second. That is
      // accepted deliberately: a console page that could not show a realm's key
      // identifier until something had used the realm would be showing a blank
      // for exactly the realm somebody had just created and was checking.
      kid: stsKeysFor.of(realm.id).kid,
      settings: this.realmSettingRows(realm),
      // The four a client asks for first, in this realm.
      endpoints: {
        openidConfiguration: base + '/.well-known/openid-configuration',
        authorizationServerMetadata: base +
                                     '/.well-known/oauth-authorization-server',
        jwks: base + '/oauth2/jwks',
        samlMetadata: base + '/saml2/metadata'
      }
    };
  }

  /**
   * Builds `/admin/realms`'s JSON.
   *
   * @param req - the request
   * @returns the JSON
   */
  realmsJson(req) {
    const { log, config, realms } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.realmsJson().");
    // A REALM ADMINISTRATOR SEES THEIR OWN REALM (2026-09-14, #32). The
    // registry is the service's and so is the list of who else is on it; a
    // realm administrator's page lists the one row they administer.
    const gate = req ? this.gateStateFor(req) : null;
    const onlyRealm = gate && gate.authority === 'realm' ? gate.identityRealm
                                                         : '';
    const out: Record<string, any> = {
      // The SETTING, and whether any prefix is actually answering. They differ
      // in the one case that matters — the feature on with no realm defined —
      // and a single flag reported that as "off". See GET /realms, which
      // answers the same pair.
      enabled: config.value('realms.enabled'),
      active: realms.active(),
      pathSegment: realms.pathSegment(),
      current: realms.currentId(),
      // The ids a realm may not be called, read off the live router. It is here
      // rather than only in the refusal because somebody choosing a name wants
      // to know before they type it, not after.
      reserved: realms.reserved().sort(),
      realms: realms.list()
                    .filter(function (realm) {
                      return !onlyRealm || realm.id === onlyRealm;
                    })
                    .map(function (realm) { return self.realmJson(req,
                                                                  realm); }),
      support: realms.realmSupport()
    };
    // WHAT THE PAGE DRAWS BESIDE THE LIST (#446): its settings, which the
    // console used to add to this answer after building it, the domain the
    // default realm's directory is rooted at, and the paging of the list.
    out.settings = configSettingsJson('/admin/realms');
    out.defaultDomain = realms.domainOf(realms.DEFAULT_ID);
    out.count = realms.count();
    out.currentName = realms.current().name;
    // Whether a realm defined here comes back after a restart, which the
    // caveat says — it was read once, when the console was wired.
    const store = persistence.status();
    out.persistence = { persistsRealms: !!store.persistsRealms,
                        mode: store.mode };
    out.paging = req
      ? this.pagingJson(this.pagedRows(req.query, out.realms,
                                       { path: '/admin/realms' }).paging)
      : null;
    log.debug("Leaving AdminViews.realmsJson(). " + out.realms.length +
              " realm(s).");
    return out;
  }

  // The JSON view, answered by GET /admin/token-lifetimes?format=json and by
  // GET /admin-api/token-lifetimes. Built here rather than in the route so the
  // page and the API cannot come to describe different settings — the rule
  // usersView() and groupsView() follow for the same reason.
  /**
   * Builds `/admin/token-lifetimes`'s JSON.
   *
   * @returns the JSON
   */
  tokenLifetimesJson() {
    const { log, config, stats, configSettingFor, applications } = this.deps;
    log.debug("Entering AdminViews.tokenLifetimesJson().");
    const snapshot = stats.snapshot();
    const settings = TOKEN_LIFETIME_KEYS.map(function (key) {
      return config.describe(configSettingFor(key));
    });
    const json = {
      // The effective seconds, flat, for a caller that wants the number and not
      // the provenance. The `settings` array beside it is the whole row —
      // bounds, source, default, description — which is what a console or an
      // explorer needs and what a test asserting "it is 3600" does not.
      lifetimes: {
        accessTokenTtlS: config.value('oauth2.accessTokenTtlS'),
        idTokenTtlS: config.value('oauth2.idTokenTtlS'),
        refreshTokenTtlS: config.value('oauth2.refreshTokenTtlS'),
        clockSkewS: config.value('oauth2.clockSkewS')
      },
      settings: settings,
      // What is already out there, per kind, against the same clock the
      // endpoints use — stats.tokenStateOf() applies oauth2.clockSkewS, so a
      // token this says is expired is one /oauth2/introspect will call
      // inactive.
      tokens: {
        held: snapshot.tokens.held, forgotten: snapshot.tokens.forgotten,
        cap: snapshot.tokens.cap, revoked: snapshot.tokens.revoked,
        byKind: snapshot.tokens.byKind
      },
      now: snapshot.now
    };
    log.debug("Leaving AdminViews.tokenLifetimesJson(). " + settings.length +
              " setting(s).");
    // What the Source column names (#446): the two appconfig files, which
    // a page drawn from this answer cannot ask the process for.
    const block = this.settingsBlockOf('/admin/token-lifetimes');
    (json as any).context = (block && block.context) || null;
    // Which of these an application may override, and with which attribute
    // (`applications.js`'s own table): the page's per-client column.
    (json as any).overridable = applications.overridableSettings();
    return json;
  }

  // The setting's value in SECONDS, whatever unit its row is written in. Every
  // comparison on this page — skew against lifetime, the warnings below — has
  // to be made in one unit, and doing it at each comparison is how two of them
  // come to disagree.
  /**
   * Returns a SAML assertion setting's value in seconds, whatever its unit.
   *
   * @param key - the setting's name
   * @returns seconds
   */
  samlAssertionSeconds(key) {
    const { log, config, samlAssertionRowFor } = this.deps;
    log.debug("Entering AdminViews.samlAssertionSeconds().");
    const row = samlAssertionRowFor(key);
    const value = Number(config.value(key)) || 0;
    log.debug("Leaving AdminViews.samlAssertionSeconds().");
    return row && row.unit === 'min' ? value * 60 : value;
  }

  // The JSON view, answered by GET /admin/saml-assertions?format=json and by
  // GET /admin-api/saml-assertions. Built here rather than in the route so the
  // page and the API cannot come to describe different settings.
  /**
   * Builds `/admin/saml-assertions`'s JSON.
   *
   * @returns the JSON
   */
  samlAssertionsJson() {
    const { log, config, stats, configSettingFor } = this.deps;
    log.debug("Entering AdminViews.samlAssertionsJson().");
    const snapshot = stats.snapshot();
    const settings = SAML_ASSERTION_KEYS.map(function (key) {
      return config.describe(configSettingFor(key));
    });
    // Only the two SAML kinds. `artifacts.byKind` also carries Kerberos tickets
    // and verifiable credentials, and a page about assertions reporting those
    // would be answering a question nobody asked it.
    const kinds = SAML_ASSERTION_SETTINGS.filter(function (
        row) { return row.kind; })
      .map(function (row) {
        return snapshot.artifacts.byKind.filter(function (k) {
          return k.kind === row.kind;
        })[0] || { kind: row.kind, issued: 0, valid: 0, expired: 0,
                   noExpiry: 0 };
      });
    const json = {
      // The effective numbers, flat, for a caller that wants the value and not
      // the provenance — and `windowS`, which is the thing a caller actually
      // has to reason about and which no single setting states: the whole width
      // of the window written into an assertion, skew included at both ends.
      assertions: {
        saml2LifetimeMin: config.value('saml2.assertionLifetimeMin'),
        saml11LifetimeMin: config.value('saml11.assertionLifetimeMin'),
        clockSkewS: config.value('saml.clockSkewS'),
        saml2WindowS: this.samlAssertionSeconds('saml2.assertionLifetimeMin') +
                      2 * this.samlAssertionSeconds('saml.clockSkewS'),
        saml11WindowS:
          this.samlAssertionSeconds('saml11.assertionLifetimeMin') +
                       2 * this.samlAssertionSeconds('saml.clockSkewS')
      },
      // WHICH OF THESE AN APPLICATION MAY OVERRIDE, AND WHAT THE ATTRIBUTE IS
      // CALLED. Read off the same table the form is drawn from, so a caller
      // that wants to write the exception does not have to be told the
      // attribute names in prose somewhere else — and so that a row added to
      // that table cannot reach the page without reaching this reply.
      perApplication: SAML_ASSERTION_SETTINGS.filter(function (row) {
        return row.field;
      }).map(function (row) {
        return { setting: row.key, attribute: row.field, profile: row.profile };
      }),
      settings: settings,
      // What is already out there, per profile. Counted against this service's
      // own clock with no allowance applied — the skew above is written INTO an
      // assertion rather than applied when one is read here, so an assertion
      // this calls expired is one whose stated NotOnOrAfter has passed.
      assertionsIssued: {
        held: snapshot.artifacts.held, forgotten: snapshot.artifacts.forgotten,
        cap: snapshot.artifacts.cap, byKind: kinds
      },
      now: snapshot.now
    };
    log.debug("Leaving AdminViews.samlAssertionsJson(). " + settings.length +
              " setting(s).");
    // What the Source column names (#446): the two appconfig files, which
    // a page drawn from this answer cannot ask the process for.
    const block = this.settingsBlockOf('/admin/saml-assertions');
    (json as any).context = (block && block.context) || null;
    // The table the page lays its rows out by, and each lifetime in seconds
    // (#446): what the page asked `admin_actions` and the settings while it
    // drew.
    const self = this;
    (json as any).rows = SAML_ASSERTION_SETTINGS.map(function (row) {
      return Object.assign({}, row);
    });
    (json as any).seconds = {};
    SAML_ASSERTION_SETTINGS.forEach(function (row) {
      (json as any).seconds[row.key] = self.samlAssertionSeconds(row.key);
    });
    return json;
  }

  // ---------------------------------------------------------------------------
  // /admin/scim — WHAT THE PROVISIONING SURFACE HAS DONE.
  //
  // The one page here that reports a protocol family rather than an artifact
  // this service issued, and it reports two different kinds of thing on
  // purpose:
  //
  //   * the COUNTERS, from admin_stats.js. Which SCIM operation was performed
  //     how many times, on which resource type, and what was refused with which
  //     `scimType`. Every row of both vocabularies is drawn INCLUDING the
  //     zeroes, because "does this server do PATCH" is the question somebody
  //     comes here with and a table that only listed what had happened would
  //     answer it by omission.
  //   * the SURFACE, from scim.js through the reader slot — the endpoints, what
  //     it deliberately does not do, and the things you can make fail. Written
  //     once, in the module that implements them, and rendered here. See
  //     setScimReader().
  //
  // **IT HAS NO CONTROLS OF ITS OWN, AND THAT IS WHY IT NEEDS ONLY A GET ON
  // /admin-api.** Everything about SCIM that can be changed is a `config.js`
  // row — `scim.enabled`, the three limits, and the seventeen authentication
  // settings (which scheme is offered, the two scope names, the realm, the
  // shared Digest password, the Digest and HOBA lifetimes and caps) — so the
  // page draws the console's ordinary settings form for its group
  // (`SETTING_HOMES`) and POST /admin-api/config/set already has the operation.
  // A SCIM-specific form here would be a second door to one setting, which is
  // the mistake rule 5 exists for and the same argument group_claims.js makes
  // about `groups.claim`.
  //
  // **THE BULK COUNT DOES NOT TALLY WITH THE REST, ON PURPOSE.** One
  // POST /scim/v2/Bulk carrying five creates is one `bulk` row AND five
  // `create` rows, because each operation inside really is performed. Said on
  // the page, because a reader adding the column up will otherwise conclude the
  // counting is broken.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/scim`'s JSON.
   *
   * @param req - the request
   * @returns the JSON
   */
  scimJson(req) {
    const { log, stats, scimMap } = this.deps;
    log.debug("Entering AdminViews.scimJson().");
    const counters = stats.scimSnapshot();
    const surface = scimReader ? scimReader(req) : null;
    const out = {
      // Distinguished from `enabled` deliberately: a process whose scim.js
      // never loaded is a different thing from one where scim.enabled is false,
      // and a page that reported both as "off" would send somebody to the wrong
      // setting.
      installed: !!surface,
      enabled: surface ? surface.enabled : false,
      baseUrl: surface ? surface.baseUrl : null,
      specifications: surface ? surface.specifications :
                      ['RFC 7642', 'RFC 7643', 'RFC ' +
          '7644'],
      store: surface ? surface.store : null,
      identifiers: surface ? surface.identifiers : null,
      // The six schemes, whether each is on, and the access control policy —
      // from scim_auth.js's table by way of scim.js's description(). Null when
      // SCIM is not loaded, which is a different thing from every scheme being
      // off and is why it is not defaulted to an empty list.
      authentication: surface ? surface.authentication : null,
      endpoints: surface ? surface.endpoints : [],
      doesNotDo: surface ? surface.doesNotDo : [],
      reachableNegatives: surface ? surface.reachableNegatives : [],
      mapping:
        { user: scimMap.USER_ATTRIBUTES.map(this.scimMappingRow.bind(this)),
                 group: scimMap.GROUP_ATTRIBUTES.map(this.scimMappingRow.bind(
                     this)) },
      counters: counters,
      // The twenty-one scim.* rows this page now edits, described. It answers
      // the question the rest of this reply cannot: not what the server does,
      // but where the value that decides it came from.
      settings: configSettingsJson('/admin/scim')
    };
    log.debug("Leaving AdminViews.scimJson(). " + counters.total +
              " request(s) counted.");
    return out;
  }

  // ---------------------------------------------------------------------------
  // /admin/scim/monitor — WHAT THE PROVISIONING SURFACE IS ACTUALLY DOING.
  //
  // **IT IS UNDER MONITORING AND NOT UNDER PROTOCOLS**, which is the same
  // filing decision `/admin/xacml/monitor` records and is made on the same
  // test: where a page goes is decided by the QUESTION IT ANSWERS and never by
  // the module that draws it or the path space it sits in. `/admin/scim`
  // answers "what is this surface, and what will it do" — the schemes, the
  // endpoints, the attribute mapping, the twenty-one settings. This one answers
  // "how much traffic is there, from whom, and how much of it is failing",
  // which is the question somebody has when a provisioning client is
  // misbehaving, and it is a monitoring question.
  // It shares a path prefix with the protocol page because the path is where
  // the module's other page is; `SECTIONS` is the only place placement is
  // stated.
  //
  // ---------------------------------------------------------------------------
  // ONE STORE, TWO VIEWS, AND THAT IS WHY THE TWO PAGES CANNOT DISAGREE.
  //
  // `/admin/scim` carries the headline counts already and goes on carrying
  // them: a page about a surface with no evidence anything ever called it is a
  // page about a hypothesis. What it does NOT carry is anything on this page
  // below the tiles, and the division is deliberate rather than incidental —
  // those two pages read `stats.scimSnapshot()` and
  // `stats.scimMonitorSnapshot()`, which are two functions over ONE set of
  // counters in `common/admin_stats.js`. There is no second tally anywhere and
  // there must never be one: a second tally is a second answer to "how many
  // SCIM calls have there been", and this repository has the same rule about
  // that as it has about everything else it counts once.
  //
  // ---------------------------------------------------------------------------
  // FOUR THINGS ON THIS PAGE ARE EASY TO MISREAD AND EACH IS SAID ON IT.
  //
  //   * **A CLIENT IS AN AUTHENTICATED PRINCIPAL, NOT A CONNECTION.** SCIM is
  //     stateless HTTP — no session, no registration, nothing to be connected —
  //     so the only honest reading of "how many clients" is how many distinct
  //     names have successfully authenticated since this process started. The
  //     figure never goes down, because a provisioning client that has stopped
  //     calling looks exactly like one that is between calls.
  //   * **A REFUSED CALLER IS NOT A CLIENT.** Basic and Digest both put a name
  //     on the wire and the gate can still turn it away; those calls are
  //     counted under `refused` and appear in no client row. Attributing
  //     traffic to an identity this service declined to believe is the one
  //     mistake this page could make that would matter.
  //   * **THE OPERATION COLUMN DOES NOT TALLY WITH THE CALL TOTAL.** One `POST
  //     /scim/v2/Bulk` carrying five creates is one `bulk` row AND five
  //     `create` rows, because each of the five really is performed.
  //     `/admin/scim` already says this about its own table and it is said
  //     again here rather than cross-referenced, because a reader adding a
  //     column up is not going to another page first.
  //   * **A LATENCY IS ABSENT AND NOT ZERO WHERE NOTHING WAS MEASURED.** An
  //     operation nothing has called shows `—`, never `0.0ms`, which would read
  //     as a service answering instantly.
  //
  // ---------------------------------------------------------------------------
  // NO RESET BUTTON, AND IT WAS REFUSED RATHER THAN FORGOTTEN.
  //
  // `admin_stats.js` exports `resetScimForTests()` and nothing on this console
  // calls it. A console that could zero its own monitoring would make every
  // number on this page a number somebody might have zeroed — and the durable
  // record of what SCIM was asked to do is the audit log, which cannot be reset
  // either. Same argument as `/admin/xacml/monitor`'s, made again rather than
  // cited, because the second refusal is not cheaper than the first.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/scim/monitor`'s JSON: what SCIM has been asked to do.
   *
   * @param req - the request
   * @returns the JSON
   */
  scimMonitorJson(req) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.scimMonitorJson().");
    const counters = stats.scimMonitorSnapshot();
    const surface = scimReader ? scimReader(req) : null;
    const out = {
      // Distinguished from `enabled` deliberately, exactly as scimJson() does
      // it: a process whose scim.js never loaded has no /scim routes at all,
      // where one with scim.enabled false has routes answering 501. Reporting
      // both as "off" would send a reader to the wrong setting — and on THIS
      // page it would also make a call total of zero mean two different things.
      installed: !!surface,
      enabled: surface ? surface.enabled : false,
      baseUrl: surface ? surface.baseUrl : null,
      // THE SCHEME VOCABULARY, so that the by-scheme table can draw the ones at
      // zero. It is scim_auth.js's own table by way of scim.js's description(),
      // for the reason admin_stats.js's comment on `byAuthScheme` gives: the
      // counters are a plain tally and this module cannot require the module
      // that owns the list, so the ZEROES are supplied by the reader. A scheme
      // that is turned off and has never been used is the most interesting row
      // on that table for somebody asking why a client cannot get in.
      schemes: surface && surface.authentication
        ? surface.authentication.schemes : [],
      authRequired: !!(surface && surface.authentication &&
                       surface.authentication.required),
      // What SCIM wrote, which is the other half of "is provisioning working".
      // It is not a counter — it is the directory counted now — and it is here
      // because a page reporting 400 successful creates beside a directory
      // holding three people is reporting something worth knowing.
      store: surface ? surface.store : null,
      counters: counters
    };
    log.debug("Leaving AdminViews.scimMonitorJson(). " + counters.calls +
              " request(s), " +
              counters.authentication.distinct + " client(s).");
    return out;
  }

  // One row of the mapping, as the page and the API both want it. The `note` is
  // carried through because several of them are the whole reason the row is not
  // obvious — `groups` being read-only, `active` deactivating nobody, `manager`
  // being passed through rather than resolved.
  // ONE PROJECTION, AND IT IS scim_map.js's SINCE 2026-09-06.
  //
  // This function used to build the row itself, and `scim.js`'s `description()`
  // built a DIFFERENT one for `GET /scim` — the same table, published by one
  // service at two endpoints, describing itself with different members. Nothing
  // failed, because nothing read either of them; that changed when a job
  // started building SCIM resources out of the published mapping rather than
  // out of a copy, and needed `type` and `parent` that neither projection
  // carried.
  //
  // It is kept as a named function rather than passing `scimMap.describeRow`
  // straight to `.map()`: `Array.prototype.map` hands the callback an INDEX as
  // its second argument, and a projection that later grew a second parameter
  // would start receiving row numbers.
  /**
   * Describes one row of the SCIM attribute mapping.
   *
   * @param row - the mapping row
   * @returns its description
   */
  scimMappingRow(row) {
    const { log, scimMap } = this.deps;
    log.debug("Entering AdminViews.scimMappingRow().");
    log.debug("Leaving AdminViews.scimMappingRow().");
    return scimMap.describeRow(row);
  }

  // ---------------------------------------------------------------------------
  // THE SECOND BATCH (2026-09-12), and it is here because a false positive was
  // keeping it on the console.
  //
  // The first pass classified these as markup-reaching and left them behind.
  // They are not: the taint was `page` — which is this console's HTML SHELL and
  // also the commonest local variable name in the file it came from, a page
  // NUMBER — so `pagingOf(query, total)` computing a `page` read as a call to
  // the shell. Six views and the nine helpers they share were held back by a
  // name collision.
  //
  // The lesson is in the analysis rather than the code: a reachability check
  // over a file this size has to know a local from a module-scope name, or it
  // reports that everything renders and nothing can move.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // Paging.
  //
  // There is no script on these pages — `script-src 'none'`, see the shell in
  // `admin-ui/admin.ts` — so paging is links and a query parameter and nothing
  // else. That is also why every number is settled server-side before the
  // markup is built: a page that renders "page 4 of 2" and leaves the browser
  // to sort it out has nothing to sort it out with.
  //
  // Both parameters are read defensively. `?page=abc`, `?page=-3` and
  // `?page=999` all have to land somewhere sensible, because they arrive from
  // hand-edited URLs and from a stale bookmark taken when the list was longer —
  // a revocation sweep can shorten it between two clicks, and an out-of-range
  // page must be the last page rather than an empty table that reads as
  // "nothing matched".
  //
  // ONE PAGE CAN HOLD SEVERAL LISTS, and that is what `options.name` is for.
  // The three list views have one list each and read the bare `page`, which is
  // what they have always done and what every bookmark and every caller of the
  // management API already says. The two DRILL-DOWNS have five and two: a users
  // page holds its sessions, the tokens under each of them, the tokens on ended
  // sessions, the tokens on no session and the artifacts, and a group page
  // holds its members and the entries claiming it. A single `page` cannot serve
  // those — clicking "next" under the artifacts would silently advance the
  // sessions above it — so each list gets a page parameter named after itself
  // and `per` stays shared, because "rows per table" is one choice a reader
  // makes for the whole page rather than seven.
  //
  // `per` is shared for a second reason worth stating: it is the parameter with
  // the cap on it, and one capped parameter is one place the cap can be got
  // right.
  // ---------------------------------------------------------------------------
  /**
   * Works out one list's paging from the query: the page, the rows per page
   * (capped) and the offset.
   *
   * @param query - the query
   * @param total - how many rows the list has
   * @param options - the list's name, when a page has several, its default
   *   rows per page and, optionally, its most rows per page
   * @returns the paging
   */
  pagingOf(query, total, options?) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.pagingOf().");
    const opts = options || {};
    const param = opts.name ? opts.name + 'Page' : 'page';
    log.debug("Entering AdminViews.pagingOf(). total=" + total + ", param=" +
              param);
    const askedPer = parseInt(String(query.per || ''), 10);
    // `options.maxPer` is a list's own ceiling under MAX_ROWS, for a page
    // whose owner has said how long a section may be (Protocols → PKI's five,
    // 2026-09-30): a hand-typed `?per=` can shorten such a list and never
    // lengthen it.
    const ceiling = Math.min(MAX_ROWS, opts.maxPer || MAX_ROWS);
    const perPage = (isFinite(askedPer) && askedPer > 0)
      ? Math.min(askedPer, ceiling)
      : Math.min(opts.defaultPer || DEFAULT_PER_PAGE, ceiling);
    // At least one page even when nothing matched, so "page 1 of 1" is what an
    // empty list says rather than "page 1 of 0".
    const pages = Math.max(1, Math.ceil(total / perPage));
    const askedPage = parseInt(String(query[param] || ''), 10);
    const page = Math.min(Math.max(isFinite(askedPage) ? askedPage : 1, 1),
                          pages);
    const offset = (page - 1) * perPage;
    log.debug("Leaving AdminViews.pagingOf(). page=" + page + " of " + pages +
              ", perPage=" +
              perPage + ".");
    return {
      page: page, perPage: perPage, pages: pages, offset: offset, total: total,
      // 1-based and inclusive, for the "rows 51–100 of 312" line. Zero and zero
      // when nothing matched, which is what the line then has to say.
      firstRow: total ? offset + 1 : 0,
      lastRow: Math.min(offset + perPage, total),
      // Which query parameter this list moves on, carried on the result rather
      // than passed to pageNavPair() a second time: the one place that decides
      // the name is the one place that builds the links, so a control cannot
      // come to page a list other than the one it is drawn under.
      param: param,
      // What a row of this list IS, for the summary line. Seven controls on one
      // page all saying "rows" would leave the reader counting tables to work
      // out which number belongs to which.
      noun: opts.noun || 'rows'
    };
  }

  // The paging members of a reply, for a page that carries more than one list
  // and therefore cannot put them at the top level the way the three list views
  // do. Same names one level down, deliberately: a caller that has learned to
  // walk `page`/`pages` on /admin-api/tokens reads `sessionsPaging.page`
  // without being told anything new. `total` is here and not up there because
  // up there it is `matched`, which is the count AFTER a filter — there is no
  // filter on a drill-down's lists, so the honest name for the number is the
  // plain one.
  /**
   * Returns the paging a JSON answer publishes.
   *
   * @param pg - the paging from `pagingOf()`
   * @returns the published members
   */
  pagingJson(pg) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.pagingJson().");
    log.debug("Leaving AdminViews.pagingJson().");
    return {
      page: pg.page, pages: pg.pages, perPage: pg.perPage,
      firstRow: pg.firstRow, lastRow: pg.lastRow, total: pg.total,
      // WHAT THE PAGING CONTROL IS DRAWN FROM (#446): the query parameter
      // that moves this list and the noun its rows are counted in. They
      // were on the paging object the console's own renderer was handed and
      // not on this answer, so a page drawn from the answer alone — which
      // is every page of the static console — could not draw the control.
      param: pg.param, noun: pg.noun
    };
  }

  // ONE RETIRED KEY'S CERTIFICATE, as the chain a reader saves (#446): what
  // `/admin/keys/history/certificate` served while the console was drawn on
  // the server, for `GET /admin-api/keys/history/certificate` now. A
  // certificate is a public document — the half of a retired key worth
  // keeping — so this is a read.
  /**
   * Returns one signing key's certificate chain, leaf first, as PEM.
   *
   * @param unit - the signing unit (`jose:RS256`)
   * @param kid - the key's identifier
   * @returns the chain, or null when this realm holds none for that key
   */
  signingHistoryCertificate(unit, kid) {
    const { log, realms, signingHistory: history } = this.deps;
    log.debug("Entering AdminViews.signingHistoryCertificate().");
    const id = realms.currentId();
    let row = null;
    try {
      history.observe(id, { reason: 'observed' });
      row = history.rowsOf(id, String(unit || '')).filter(function (one) {
        return String(one.kid) === String(kid || '');
      })[0] || null;
    } catch (e) {
      log.debug("Caught in AdminViews.signingHistoryCertificate(): " +
                ((e && e.message) || e));
      row = null;
    }
    const one = row && row.certificate ? row.certificate : null;
    log.debug("Leaving AdminViews.signingHistoryCertificate(). " +
              (one && one.certificatePem ? "Held." : "None."));
    return one && one.certificatePem
      ? [one.certificatePem].concat(one.chainPem || []).join('\n') : null;
  }

  // The slice, with the paging that produced it. Written once because seven
  // lists across the two drill-downs do exactly this and a hand-written eighth
  // would be the one that forgets to slice.
  // ---------------------------------------------------------------------------
  // THE SIGNING-KEY HISTORY, FOR BOTH DOORS (2026-09-22, #42's follow-up).
  //
  // `/admin/keys/history` and `GET /admin-api/keys/history` answer out of
  // this one function, for `schedulerView()`'s reason: the console's table
  // and a caller's JSON reporting different generations of the same key would
  // be two answers to a question with one.
  //
  // **IT OBSERVES BEFORE IT READS, so a READ may write.** The history is a
  // projection of the realm's key set (`common/signing_history.ts`), so a
  // node that has just restarted, or a development-mode service whose keys
  // are new this start and whose rotation jobs are off, holds keys no row
  // describes yet — and a door that read the store alone would report a realm
  // as having NO history when what it has is no observation. `observe()` sets
  // a row only where one is missing or has changed, so in the steady state
  // neither door writes anything.
  // ---------------------------------------------------------------------------
  /**
   * Builds the signing key history of a realm, filtered by unit.
   *
   * @param query - the query, whose `unit` filters
   * @param realmId - the realm's id, or the ambient realm's
   * @returns the history
   */
  signingHistoryView(query, realmId?) {
    const { log, realms, signingHistory: history } = this.deps;
    log.debug("Entering AdminViews.signingHistoryView().");
    const q = query || {};
    const id = String(realmId || realms.currentId());
    const raw = q.unit;
    const unit = String((Array.isArray(raw) ? raw[0] : raw) || '').trim();
    let view: any = { realm: id, unit: unit, units: [], rows: [], total: 0,
                      found: false, observed: false, paging: null };
    try {
      history.observe(id, { reason: 'observed' });
      view = Object.assign(view, history.historyView(id, { unit: unit }),
                           { observed: true });
    } catch (e) {
      // No history in this process: both doors say so rather than drawing an
      // empty table, which reads as a realm that has never held a key.
      log.debug("Caught in AdminViews.signingHistoryView(): " +
                ((e && e.message) || e));
    }
    // ONE PAGER, over the named unit's generations. The index has a row per
    // UNIT and a realm has tens of those at most — it is bounded by the key
    // set — so what is paged is the list that is not.
    const paged = this.pagedRows(q, view.rows, { noun: 'generations' });
    view.rows = paged.shown;
    view.paging = this.pagingJson(paged.paging);
    log.debug("Leaving AdminViews.signingHistoryView(). " + view.rows.length +
              " of " + view.total + ".");
    return view;
  }

  // ---------------------------------------------------------------------------
  // PAGE, THEN DECORATE (#352, 2026-09-29).
  //
  // Every list here was built WHOLE and then sliced, and where a row's cells
  // cost something — a directory read, an unseal, a certificate parse — the
  // whole population paid for one page of it: `/admin/users` asked the
  // credential store about everybody in the realm to draw fifty rows.
  // `options.decorate(row)` is the other order: the list is filtered and
  // sorted on what is cheap, paged, and only the rows SHOWN are handed to the
  // decorator, whose answer replaces the row in `shown`. A caller that
  // passes none gets exactly the slice it always got.
  //
  // The rule it serves: a filter that needs the decoration (the users page's
  // `?factor=`) cannot be applied after it, so such a filter is the caller's
  // to answer from a one-pass census before paging — never by decorating
  // everybody.
  // ---------------------------------------------------------------------------
  /**
   * Pages a list of rows, decorating only the rows shown.
   *
   * @param query - the query
   * @param rows - the rows
   * @param options - as `pagingOf()` takes them, and `decorate(row)`, applied
   *   to each shown row and returning the row to show
   * @returns the paging and the rows shown
   */
  pagedRows(query, rows, options?) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.pagedRows().");
    const pg = this.pagingOf(query, rows.length, options);
    const slice = rows.slice(pg.offset, pg.offset + pg.perPage);
    const decorate = options && typeof options.decorate === 'function'
      ? options.decorate : null;
    const shown = decorate
      ? slice.map(function (row) { return decorate(row); })
      : slice;
    log.debug("Leaving AdminViews.pagedRows().");
    return { paging: pg, shown: shown };
  }

  // The filtered, paged token list and the reply built from it. The WHOLE view
  // rather than only its JSON, because the console's markup needs every
  // intermediate step of it — and a second walk of the same list a few lines
  // later is how a table and the JSON beside it come to disagree about a
  // revocation that happened in between.
  /**
   * Builds `/admin/tokens`: the issued tokens and sets, filtered and paged.
   *
   * @param query - the request's query
   * @returns the view
   */
  tokensView(query) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.tokensView().");
    const wantedFamily = String(query.family || '');
    const wantedKind = String(query.kind || '');
    const wantedState = String(query.state || '');
    // WHICH SESSION A CREDENTIAL WAS ISSUED ON (2026-09-04). Every row of
    // /admin/sessions links here with it set, because "what came out of this
    // session" was a question this table held the answer to and could not be
    // asked. It is an EXACT match on the session id and not a search: the id is
    // what a token records, and a substring of one is not a session.
    //
    // A credential with NO session behind it — the two direct grants, a
    // pre-authorized code, a token exchange, every assertion and every ticket —
    // is therefore filtered out rather than shown, which is right: it was not
    // issued on that session, and the empty answer is the honest one for a
    // session nothing was issued on.
    const wantedSession = String(query.session || '');
    // Not tokenList(), and since 2026-09-05 not issuedList() either: this page
    // lists what came back in ONE REPLY. Every JWT, every SAML assertion
    // (whether WS-Trust or WS-Federation issued it), every Kerberos ticket and
    // every SVID is still here — grouped where the protocol grouped them, which
    // is OAuth 2.0 and OIDC and nowhere else. See issuedSetRow() in
    // admin-ui/admin.ts for the argument, and stats.issuedSets() for the
    // grouping, which is decided by a set id the ISSUER stated rather than by
    // anything this file could infer from these rows.
    const all = stats.issuedSets();
    // EVERY FILTER MATCHES A SET WHEN ANY MEMBER MATCHES, and that is the one
    // thing about this page a reader has to be told rather than left to work
    // out. Asking for `kind=id_token` answers with the SETS that contain an ID
    // Token — showing the access token and the refresh token beside it, which
    // is the reply that ID Token arrived in and the thing somebody filtering
    // for it is looking at. A filter that hid the neighbours would be the old
    // per-credential table wearing this one's clothes, and the note under the
    // form says so on the page.
    //
    // `family` and `session` are per-set facts in practice — every member of a
    // set shares them — but they are asked of the members for the same reason,
    // so that one rule covers all four and a family that starts grouping later
    // needs no second one.
    const matches = function (set, test) {
      log.debug("Entering matches().");
      log.debug("Leaving matches().");
      return set.members.some(test);
    };
    const filtered = all.filter(function (set) {
      if (wantedFamily &&
          !matches(set,
                   function (r) {
                     return r.family === wantedFamily;
                   })) return false;
      if (wantedKind &&
          !matches(set,
                   function (r) { return r.kind ===
                                         wantedKind; })) return false;
      if (wantedState &&
          !matches(set,
                   function (r) {
                     return r.state === wantedState;
                   })) return false;
      if (wantedSession &&
          !matches(set,
                   function (r) {
                     return String(r.sessionId || '') === wantedSession;
                   })) return false;
      return true;
    });
    // Filter first, then page: paging a list and then filtering it would give a
    // page 2 whose length depends on what page 1 happened to contain.
    //
    // PAGED BY SET AND NOT BY CREDENTIAL, which is what makes a page of this
    // table a whole number of replies. Twenty rows is now twenty issuances and
    // somewhere between twenty and sixty credentials, and the line under the
    // table says both — paging by credential would put the access token of one
    // reply at the bottom of page 1 and its refresh token at the top of page 2,
    // which is precisely the reassembly-by-eye this change exists to remove.
    const paging = this.pagingOf(query, filtered.length);
    const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
    // How much of each family is held, for the line under the table. Counted in
    // CREDENTIALS rather than sets, because "612 JWTs" is the figure the
    // metrics page prints and two pages of one console disagreeing about how
    // much has been issued is worse than this line being in different units
    // from the one above it — which it says. Counted from this list rather than
    // taken from the snapshot, because the snapshot's artifact count includes
    // the OID4VCI credentials this page does not list.
    const heldByFamily: Record<string, any> = {};
    let heldCredentials = 0;
    all.forEach(function (set) {
      set.members.forEach(function (record) {
        heldByFamily[record.family] = (heldByFamily[record.family] || 0) + 1;
        heldCredentials += 1;
      });
    });
    const countMembers = function (sets) {
      log.debug("Entering countMembers().");
      log.debug("Leaving countMembers().");
      return sets.reduce(function (n, set) { return n + set.size; }, 0);
    };
    const matchedCredentials = countMembers(filtered);
    const shownCredentials = countMembers(shown);
    // The flatten of what this page holds, in the order the table draws it:
    // each set's members in issuance order, sets newest first. It is DERIVED
    // from `shown` rather than filtered again out of issuedList(), which is the
    // whole reason the two can be published side by side — a second walk of the
    // register is how a table and the JSON beside it come to disagree about a
    // revocation that happened in between.
    const shownRecords = shown.reduce(function (out, set) {
      return out.concat(set.members);
    }, []);
    log.debug("Leaving AdminViews.tokensView(). " + shown.length +
              " set(s) of " +
              filtered.length + ", holding " + shownCredentials + " " +
                  "credential(s).");
    return {
      wantedFamily: wantedFamily, wantedKind: wantedKind,
      wantedState: wantedState, wantedSession: wantedSession,
      all: all, filtered: filtered, paging: paging, shown: shown,
      heldByFamily: heldByFamily, heldCredentials: heldCredentials,
      matchedCredentials: matchedCredentials,
      shownCredentials: shownCredentials,
      json: {
        // IN CREDENTIALS. `held` has meant this since the day the page had a
        // total on it, and a resource that quietly changed its unit under a
        // name nobody had to re-read would be the worst kind of breaking change
        // — so the SET counts are new members beside it rather than a new
        // meaning for an old one.
        held: heldCredentials,
        heldSets: all.length,
        // IN SETS, both of them, because sets are what this resource now lists
        // and what its paging counts. The credential figures are beside them.
        matched: filtered.length, matchedCredentials: matchedCredentials,
        shown: shown.length, shownCredentials: shownCredentials,
        heldByFamily: stats.ISSUED_FAMILIES.reduce(function (out, entry) {
          out[entry.family] = heldByFamily[entry.family] || 0;
          return out;
        }, {}),
        filter: { family: wantedFamily || null, kind: wantedKind || null,
                  state: wantedState || null, session: wantedSession || null },
        // The clamped values, not what was asked for: `?page=999` on a two-page
        // list reports page 2, which is the page whose rows are in the reply.
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        families: stats.ISSUED_FAMILIES,
        revocableKinds: stats.REVOCABLE_KINDS,
        revokedCount: stats.revokedCount(),
        // WHAT THIS RESOURCE LISTS SINCE 2026-09-05: one entry per issuance,
        // each carrying its members. A caller that wants the credentials
        // ungrouped has `issued` below and need not walk two levels.
        sets: shown,
        // `issued` rather than `tokens`, because the array is no longer only
        // tokens and a key that says otherwise is the kind of thing a test
        // asserts against once and then trusts. Nothing outside this repository
        // read the old name.
        //
        // IT IS THE FLATTEN OF `sets` AND NOT A SECOND LIST. Same rows, same
        // order, ungrouped — so every caller written against the per-credential
        // shape still reads what it read, and the two cannot come to disagree
        // because one is built out of the other. What DID change under it is
        // the paging: a page is now a whole number of sets, so this array is
        // between `perPage` and three times it rather than exactly `perPage`.
        issued: shownRecords,
        // The paging the page draws its pager from (#446).
        paging: this.pagingJson(paging)
      }
    };
  }

  // The protocols this list can hold, for the filter. Built from the rows
  // themselves rather than written down, because the set depends on what people
  // have signed in THROUGH — `session.via` is a federation relationship's name
  // on a federated sign-in — and a hand-written list would be a select with
  // entries that match nothing beside sign-ins it cannot name.
  /**
   * Returns the protocols the sign-on sessions came through, for the filter.
   *
   * @param rows - the session rows
   * @returns the protocols
   */
  sessionProtocolsIn(rows) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.sessionProtocolsIn().");
    const out = [];
    rows.forEach(function (row) {
      if (row.protocol && out.indexOf(row.protocol) < 0) {
        out.push(row.protocol);
      }
    });
    out.sort();
    log.debug("Leaving AdminViews.sessionProtocolsIn(). " + out.length +
              " protocol(s).");
    return out;
  }

  // One route, two answers, and the choice is here rather than in the route so
  // that GET /admin-api/sessions makes the same one — the rule every view in
  // this file follows, and the reason the management API cannot come to
  // disagree with the page about who is signed in.
  /**
   * Builds `/admin/sessions`: every sign-on session, filtered and paged.
   *
   * @param req - the request
   * @returns the view
   */
  sessionsView(req) {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.sessionsView().");
    const query = req.query || {};
    if (!logoutReader) {
      log.debug("Leaving AdminViews.sessionsView(). No logout reader.");
      return { installed: false, all: [], protocols: [], shown: [],
               paging: null,
               wantedText: '', wantedProtocol: '',
               json: { installed: false, held: 0, matched: 0, shown: 0,
                       sessions: [],
                       note: 'logout/logout.ts is not loaded in this ' +
                             'process, so there is no reader for what is ' +
                             'live.' } };
    }
    const all = logoutReader.liveSessions();
    const wantedText = this.queryOne(query, 'q').trim();
    const wantedProtocol = this.queryOne(query, 'protocol').trim();
    // Filter first, then page — pagingOf()'s rule, and for its reason.
    const filtered = all.filter(function (row) {
      if (wantedProtocol && row.protocol !== wantedProtocol) return false;
      return self.chooserMatches([row.username, row.sub, row.handle, row.key,
                                  row.kind, row.protocol], wantedText);
    });
    const paging = this.pagingOf(query, filtered.length, { noun: 'sessions' });
    const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
    const byKind: Record<string, any> = {};
    all.forEach(function (row) {
      byKind[row.family] = (byKind[row.family] || 0) + 1;
    });
    // THE UNAUTHENTICATED ONES, AS A LIST OF THEIR OWN (2026-09-05).
    //
    // NOT FILTERED AND NOT PAGED, deliberately, where the table above it is
    // both. The two lists answer different questions: the main one is *what is
    // live*, which is long and needs narrowing, and this one is *is anybody in
    // here without having signed in*, which is a question about the whole
    // service and would be answered wrongly by a filter somebody had left set.
    // A search box that could hide one of these rows would make the section
    // worse than not having it.
    //
    // It is a SECTION rather than a column on the table above because the
    // answer is almost always "none", and a column that is the same on every
    // row for weeks at a time stops being read. A section that is empty says so
    // in one line and a section with rows in it is the thing somebody notices.
    const unauthenticated = all.filter(function (row) {
      return row.authenticated === false;
    });
    log.debug("Leaving AdminViews.sessionsView(). " + shown.length +
              " row(s) of " +
              filtered.length + " (" + all.length + " live).");
    return {
      installed: true, all: all, filtered: filtered, shown: shown,
      paging: paging, byKind: byKind, unauthenticated: unauthenticated,
      protocols: this.sessionProtocolsIn(all),
      wantedText: wantedText, wantedProtocol: wantedProtocol,
      json: {
        installed: true,
        held: all.length, matched: filtered.length, shown: shown.length,
        heldByKind: byKind,
        // Rule 7: the page grew a section, so the API grew the same answer. The
        // COUNT and the ROWS both, because "are there any" and "which ones" are
        // the two things a caller asks and deriving the first from the second
        // would make an empty list and an absent field look alike.
        unauthenticatedHeld: unauthenticated.length,
        unauthenticatedSessions: unauthenticated.map(function (row) {
          return { id: row.id, family: row.family, username: row.username,
                   sub: row.sub, protocol: row.protocol,
                   sessionId: row.sessionId,
                   startedAt: row.startedAt, expiresAt: row.expiresAt,
                   carries: row.carries, key: row.key,
                   // What the page's row draws too (#446).
                   kind: row.kind, handle: row.handle, acr: row.acr,
                   amr: row.amr, detail: row.detail,
                   terminable: row.terminable, why: row.why,
                   expiryRule: row.expiryRule };
        }),
        filter: { q: wantedText || null, protocol: wantedProtocol || null },
        // The clamped values, not what was asked for: `?page=999` on a two-page
        // list reports page 2, which is the page whose rows are in the reply.
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        at: Date.now(),
        // The rules, once, beside the rows rather than repeated on each of
        // them: a caller reading `expiresAt` needs to know which of the three
        // arithmetics produced it, and every row already says which family it
        // is.
        expiryRules: logoutReader.SESSION_EXPIRY_RULES || {},
        sessions: shown,
        // What the page draws from beside the rows (#446): the protocol
        // filter's choices and the paging.
        protocols: this.sessionProtocolsIn(all),
        // Whether sessions that authenticated nobody are kept, which the
        // page says beside them.
        unauthenticatedKept: !!config.value('authn.unauthenticatedSessions'),
        paging: this.pagingJson(paging)
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE USED-ASSERTION HISTORY — every RFC 7523 JWT and RFC 7522 SAML assertion
  // this realm has accepted and that has not yet expired (2026-09-13).
  //
  // **A PROMISE, WHICH ALMOST NO VIEW HERE IS**, because on a postgres store
  // the history is not in this process at all: the database IS the history, so
  // that every process against it agrees, and reading it is a query. The page
  // and the operation both await this one function, so they cannot disagree
  // about a row.
  //
  // **IT IS READ-ONLY AND MUST STAY SO.** Forgetting a row would make that
  // assertion acceptable again while it is still valid, which is the one thing
  // the history exists to prevent; the only thing that removes a row is the
  // assertion expiring. `common/used_assertions.js` argues the rest.
  //
  // The page is clamped the way `pagingOf()` clamps every list here, and a page
  // asked for beyond the end is re-read at the last page rather than drawn
  // empty under a line saying rows matched.
  // ---------------------------------------------------------------------------
  /**
   * Builds the used-assertion history, paged.
   *
   * @param query - the request's query
   * @returns the view
   */
  usedAssertionsView(query) {
    const { log, usedAssertions } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.usedAssertionsView().");
    const q = query || {};
    const filter = { q: String(q.q || '').trim(), format: String(q.format ||
                                                                 ''),
                     use: String(q.use || ''), state: String(q.state || '') };
    const asked = this.pagingOf(q, Number.MAX_SAFE_INTEGER);
    log.debug("Leaving AdminViews.usedAssertionsView().");
    return usedAssertions.list(Object.assign({}, filter, {
      limit: asked.perPage, offset: asked.offset
    })).then(function (first) {
      const paging = self.pagingOf(q, first.matched);
      if (paging.offset === asked.offset) {
        return { page: first, paging: paging };
      }
      return usedAssertions.list(Object.assign({}, filter, {
        limit: paging.perPage, offset: paging.offset
      })).then(function (again) {
        return { page: again, paging: paging };
      });
    }).then(function (read) {
      const summary = usedAssertions.summary();
      const page = read.page;
      const json = Object.assign({
        store: summary.store,
        persistent: summary.persistent,
        atomicAcrossProcesses: summary.atomicAcrossProcesses,
        storeNote: summary.why,
        cap: summary.cap,
        live: page.live,
        matched: page.matched,
        shown: page.rows.length,
        // A TEXT SEARCH READS THE NEWEST ROWS ONLY (#222): the columns it
        // reads are sealed in a database, so it is done in memory over a
        // bounded window, and says so when the window did not hold them all.
        searchNote: page.searched !== undefined && !page.searchedAll
          ? 'The text search read the newest ' + page.searched + ' rows ' +
            'matching the other filters, not all of them: in a database ' +
            'the searched columns are sealed and are searched here, in ' +
            'memory. Narrow it with the format, use or state filter.'
          : '',
        filter: page.filter,
        formats: usedAssertions.FORMATS,
        uses: usedAssertions.USES,
        states: usedAssertions.STATES,
        rows: page.rows,
        // The paging control's own object as well as its members spread
        // below, as every other answer carries it (#446).
        paging: self.pagingJson(read.paging)
      }, self.pagingJson(read.paging));
      return { json: json, rows: page.rows, paging: read.paging,
               filter: page.filter, summary: summary, live: page.live };
    });
  }

  // ---------------------------------------------------------------------------
  // THE ERROR CODES, AS /admin/error-codes AND GET /admin-api/error-codes DRAW
  // THEM (2026-09-12).
  //
  // The table is `common/error_codes.js`'s and nothing here restates it: this
  // is the table FILTERED and PAGED, with one column the documentation page
  // cannot have — how many rows in this realm's audit log carry each code right
  // now. That column is what makes the page worth having beside
  // `docs/error-codes.md`: the page answers *what does STS-FED-0012 mean* and
  // *which failures has this service actually been producing*, and only a
  // running service can answer the second.
  //
  // **THE COUNT IS OF THE HELD AUDIT LOG IN THIS REALM**, the same rows
  // `/admin/audit` lists, so it drops as that ring's cap discards the oldest
  // and it is zero for a code logged only as a line (`tag()`) — a startup
  // refusal, or anything the remote PEP container records. The page says so
  // rather than letting a zero read as "never happens".
  //
  // **A CODE ON A ROW THAT THE TABLE DOES NOT HOLD IS REPORTED**, not dropped:
  // `mark()` and `audit()` both record an unregistered code as given, precisely
  // so that the one row saying the table is incomplete survives, and this is
  // the page somebody would look for it on.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/error-codes`: the error-code table and the codes recorded.
   *
   * @param query - the request's query
   * @returns the view
   */
  errorCodesView(query) {
    const { log, auditLog, errorCodes } = this.deps;
    log.debug("Entering AdminViews.errorCodesView().");
    const wantedSubsystem = String(query.subsystem || '').trim().toUpperCase();
    const wantedText = String(query.q || '').trim();
    const wantedSeen = ['1', 'true', 'on', 'yes'].indexOf(
      String(query.seen || '').toLowerCase()) >= 0;
    const needle = wantedText.toLowerCase();

    // One pass over the held rows. `lastSeenAt` is the newest because list() is
    // newest first, so the first sighting of a code is its latest.
    const seen: Record<string, any> = {};
    auditLog.list().forEach(function (row) {
      const code = row && row.errorCode;
      if (!code) return;
      if (!seen[code]) {
        seen[code] = { count: 0, lastSeenAt: row.at || 0 };
      }
      seen[code].count++;
    });

    const subsystems = errorCodes.SUBSYSTEMS.map(function (s) {
      const rows = errorCodes.CODES.filter(function (r) {
        return errorCodes.subsystemOf(r.code) === s.id;
      });
      let seenRows = 0;
      rows.forEach(function (r) {
        if (seen[r.code]) seenRows += seen[r.code].count;
      });
      return { id: s.id, prefix: 'STS-' + s.id, label: s.label, where: s.where,
               what: s.what, codes: rows.length, seen: seenRows };
    });

    const all = errorCodes.CODES.map(function (r) {
      const sighting = seen[r.code];
      return { code: r.code, subsystem: errorCodes.subsystemOf(r.code),
               summary: r.summary, spec: r.spec || '', retired: !!r.retired,
               seen: sighting ? sighting.count : 0,
               lastSeenAt: sighting ? sighting.lastSeenAt : 0 };
    });

    const filtered = all.filter(function (r) {
      if (wantedSubsystem && r.subsystem !== wantedSubsystem) return false;
      if (wantedSeen && !r.seen) return false;
      // One box over the three columns a reader would search: a code pasted out
      // of a log line, a word from what failed, or a protocol's own error name.
      if (needle && (r.code + ' ' + r.summary + ' ' + r.spec).toLowerCase()
                      .indexOf(needle) < 0) return false;
      return true;
    });

    const unregisteredSeen = Object.keys(seen).filter(function (code) {
      return !errorCodes.isKnown(code);
    }).sort().map(function (code) {
      return { code: code, seen: seen[code].count,
               lastSeenAt: seen[code].lastSeenAt };
    });

    const paging = this.pagingOf(query, filtered.length);
    const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
    let heldWithCode = 0;
    Object.keys(seen)
          .forEach(function (code) { heldWithCode += seen[code].count; });
    log.debug("Leaving AdminViews.errorCodesView(). " + shown.length + " of " +
              filtered.length + " code(s).");
    return {
      wantedSubsystem: wantedSubsystem, wantedText: wantedText,
      wantedSeen: wantedSeen, paging: paging, shown: shown, filtered: filtered,
      subsystems: subsystems, unregisteredSeen: unregisteredSeen,
      json: {
        registered: all.length,
        retired: all.filter(function (r) { return r.retired; }).length,
        subsystemCount: subsystems.length,
        matched: filtered.length, shown: shown.length,
        // What the audit log held when this was drawn, so a zero can be read
        // against how much there was to find it in.
        auditRowsHeld: auditLog.summary().held,
        auditRowsWithCode: heldWithCode,
        distinctCodesSeen: Object.keys(seen).length,
        filter: { subsystem: wantedSubsystem || null, q: wantedText || null,
                  seen: wantedSeen || null },
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        documentation: 'docs/error-codes.md',
        neverSentToClients: true,
        subsystems: subsystems,
        unregisteredSeen: unregisteredSeen,
        codes: shown,
        // The paging a page draws its pager from (#446), as every paged
        // answer carries it.
        paging: this.pagingJson(paging)
      }
    };
  }

  // Everything the page and the API both need out of one query string. Written
  // as a view function for the reason the comment above consoleJson() in
  // admin-ui/admin.ts gives: this console and /admin-api are two callers, and
  // two hand-built copies of the same filtering would be two answers that each
  // look right alone.
  /**
   * Builds `/admin/audit`: the audit log, filtered and paged.
   *
   * @param query - the request's query
   * @returns the view
   */
  auditView(query) {
    const { log, auditLog } = this.deps;
    log.debug("Entering AdminViews.auditView().");
    const wantedCategory = String(query.category || '');
    const wantedAction = String(query.action || '');
    const wantedOutcome = String(query.outcome || '');
    const wantedActor = String(query.actor || '');
    const wantedText = String(query.q || '');
    // An error code, or the front of one: a whole code is one condition and
    // `STS-OAUTH` is a whole subsystem. A PREFIX rather than a substring, so
    // `STS-OAUTH` cannot match inside `STS-XOAUTH-…` if such a subsystem is
    // ever added — the codes are a hierarchy and the match reads them as one.
    const wantedCode = String(query.code || '').trim().toUpperCase();
    // The client's address (2026-09-18), or the FRONT of one: `10.0.` is a
    // range an operator can name without CIDR, and a whole address is one
    // client. A prefix for `code`'s reason — `10.0.0.1` must not match
    // inside `110.0.0.12`.
    const wantedAddress = String(query.address || '').trim().toLowerCase();
    const all = auditLog.list();
    const needle = wantedText.toLowerCase();
    const actorNeedle = wantedActor.toLowerCase();
    const filtered = all.filter(function (row) {
      if (wantedCategory && row.category !== wantedCategory) return false;
      if (wantedAction && row.action !== wantedAction) return false;
      if (wantedOutcome && row.outcome !== wantedOutcome) return false;
      if (wantedCode && String(row.errorCode || '').indexOf(wantedCode) !== 0) {
        return false;
      }
      if (wantedAddress && String(row.address || '').toLowerCase()
                             .indexOf(wantedAddress) !== 0) {
        return false;
      }
      // Substring rather than equality, and case-insensitively, because the
      // actor on a directory row may be the console key (`alice`) while the one
      // on a Kerberos row arrived as `alice@STS.MOCK` — the collapse to one key
      // is done where an identity is normalised and cannot be done for a row
      // whose actor is a bind DN. A substring finds the person either way.
      if (actorNeedle && (row.actor + ' ' + row.actorForm).toLowerCase()
                           .indexOf(actorNeedle) < 0) return false;
      // One free-text box over the three columns somebody would look in. The
      // summary alone would miss a DN that only appears in `target`, and a box
      // that silently searched one column while the reader assumed three is
      // worse than no box.
      if (needle && (row.summary + ' ' + row.target + ' ' + row.action)
                      .toLowerCase().indexOf(needle) < 0) return false;
      return true;
    });
    // Filter first, then page — the same order the tokens page uses and for the
    // same reason: paging a list and then filtering it gives a page 2 whose
    // length depends on what page 1 happened to hold.
    const paging = this.pagingOf(query, filtered.length);
    const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
    const summary = auditLog.summary();
    log.debug("Leaving AdminViews.auditView(). " + shown.length +
              " row(s) of " +
              filtered.length + ".");
    const known = this.knownUserKeys();
    const knownActors: Record<string, boolean> = {};
    shown.forEach(function (row) {
      if (row.actor && known[row.actor]) {
        knownActors[row.actor] = true;
      }
    });
    return {
      wantedCategory: wantedCategory, wantedAction: wantedAction,
      wantedOutcome: wantedOutcome, wantedActor: wantedActor,
      wantedText: wantedText, wantedCode: wantedCode,
      wantedAddress: wantedAddress,
      all: all, filtered: filtered, paging: paging, shown: shown,
      summary: summary,
      json: {
        held: summary.held,
        // Everything ever recorded and everything dropped, both, because `held`
        // alone reads as "this is all there was" the moment the cap has bitten.
        recorded: summary.recorded, dropped: summary.dropped,
        maxEvents: summary.maxEvents, protocolCalls: summary.protocolCalls,
        matched: filtered.length, shown: shown.length,
        // The lowest and highest sequence numbers still held. A caller polling
        // this endpoint uses them rather than a timestamp: `seq` is monotonic
        // and never reused, so "everything after 4,102" is exact, and a gap
        // between the last seq you saw and `oldestSeq` is precisely how many
        // events you missed.
        oldestSeq: summary.oldestSeq, newestSeq: summary.newestSeq,
        byCategory: summary.byCategory, byOutcome: summary.byOutcome,
        byAction: summary.byAction,
        filter: { category: wantedCategory || null, action: wantedAction ||
                                                            null,
                  outcome: wantedOutcome || null, actor: wantedActor || null,
                  q: wantedText || null, code: wantedCode || null,
                  address: wantedAddress || null },
        // The clamped values, not what was asked for: `?page=999` on a two-page
        // list reports page 2, which is the page whose rows are in the reply.
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        // The vocabulary, off the data rather than out of a list in a test:
        // what the `category`, `action` and `outcome` filters take.
        categories: auditLog.CATEGORIES, actions: auditLog.ACTIONS,
        outcomes: auditLog.OUTCOMES,
        events: shown,
        // What the page draws from beside the rows (#446): the paging, which
        // actors on this page have a user page to link to, and the page's
        // settings.
        paging: this.pagingJson(paging),
        knownActors: knownActors,
        settings: configSettingsJson ? configSettingsJson('/admin/audit')
          : null
      }
    };
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
    log.debug("Entering AdminViews.firstAttributeValue().");
    if (!entry || !entry.attributes) {
      log.debug("Leaving AdminViews.firstAttributeValue().");
      return '';
    }
    const wanted = String(name).toLowerCase();
    const key = Object.keys(entry.attributes).filter(function (one) {
      return String(one).toLowerCase() === wanted;
    })[0];
    const values = key ? entry.attributes[key] : null;
    log.debug("Leaving AdminViews.firstAttributeValue().");
    return (values && values.length) ? String(values[0]) : '';
  }

  // WHAT A BOX IS, WHICH IS THE ONE QUESTION `delegation_map.js` DELIBERATELY
  // CANNOT ANSWER. It is handed this function and asks it once per node.
  //
  // The three states are `delegationPartyCell()`'s three states, and they are
  // the same three on purpose: a name this console can resolve, a name it could
  // file somebody under and never has, and a name for something the registry
  // has never seen. What the picture does with them is what a picture can do
  // and a table cannot — the first two get a SHAPE and the third gets a DASHED
  // one — and the row under the diagram still draws the cell, so nothing that
  // was linkable in the table stops being linkable here.
  //
  // **THE LABEL IS THE CN WHERE THERE IS ONE.** A directory entry's `cn` and an
  // application entry's `appName` are what somebody CALLED this thing, and the
  // identifier is what a protocol spelled it as; on a diagram the first is
  // worth more than the second, and the second is one line below it and in the
  // tooltip. Where there is no entry there is no cn, and the identifier is all
  // there is.
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
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.delegationNodeLook().");
    if (node.kind === 'sts') {
      log.debug("Leaving AdminViews.delegationNodeLook().");
      // The one box that is not a party. It carries the REALM because a realm
      // is a whole logical copy of this service — two realms' pictures are two
      // different services' pictures — and it says `default` rather than
      // nothing in the realm that has no prefix, since a hexagon labelled only
      // `IYA STS` would be silent about the one thing this box is here to say.
      return {
        shape: 'sts',
        label: 'IYA STS',
        sublabel: 'realm: ' + (node.realm ? node.realm.name : 'Default') +
                  (node.realm && !node.realm.isDefault ?
                   ' (' + node.realm.id + ')' : ''),
        title: 'THIS SERVICE, in the trust realm ' +
          (node.realm ? node.realm.name + ' (' + node.realm.id + ')' :
           'default') +
          '.\nIssuer: ' + (node.issuer || '(unset)') +
          '\nEvery line in this picture exists because this service issued ' +
          'or refused a credential: ' + node.issued + ' issued, ' +
          node.refused +
          ' refused.\nThe dashed lines leaving it go to whoever ASKED — the ' +
          'intermediary where a chain has one, the initial identity where it ' +
          'does not.',
        href: '/admin/realms',
        dashed: false
      };
    }

    // The directory's own answer about a PERSON. `directoryReader` is a slot
    // and is empty in a build with no `ldap_server.js`, which is a state this
    // console reports everywhere else rather than guessing through — so with no
    // directory every party falls back to the role's shape, dashed, and the
    // page says why.
    let entry = null;
    if (directoryReader && node.key) {
      const info = directoryReader(node.key);
      entry = info && info.found ? info.entry : null;
    }
    // The registry's answer about an APPLICATION. Looked up by the identifier
    // the ACT carried rather than by the node's id: the id is normalised (see
    // `nodeIdOf()` in delegation.js) and `ou=applications` is keyed by what a
    // caller actually presented.
    const application = node.application ? applications.get(node.application) :
                        null;

    const isPerson = !!entry;
    const isApplication = !!application;
    const shape = isPerson && isApplication ? 'both'
                : isApplication ? 'application'
                : isPerson ? 'person'
                // Nothing is known. The ROLE decides, which is the ROLES table
                // read as a drawing: an initial identity is a person, a target
                // is an application, and an intermediary is drawn as an
                // application because that is what a front-end service is.
                : node.chiefRole === 'initial' ? 'person' : 'application';

    const cn = entry ? this.firstAttributeValue(entry, 'cn') : '';
    const appName = application ? (application.name || application.dnLabel) :
                    '';
    const label = cn || appName || node.id;

    // WHAT A PROTOCOL WOULD HAVE TO PRESENT TO REACH THIS BOX. Added
    // 2026-08-27, and it exists because of the paragraph above it: the label is
    // the CN where there is one, so a rectangle reading `Acme Web` said nothing
    // anywhere on the diagram about the string a request would have to carry.
    // That is the fact somebody opens a delegation picture to get — the
    // `client_id` they are about to put in a token request, the `AppliesTo` in
    // the RequestSecurityToken they are about to send — and it was in the
    // tooltip, which is not a place a diagram pasted into a ticket keeps.
    //
    // The list comes from `applications.identifiersOf()` rather than from a
    // walk of the entry here: which attribute is a family's identifier and what
    // the specification calls it are that module's statements, and a picture
    // holding a second opinion about either is drift nothing can see.
    //
    // **THE SPELLING IS OF THE NAME THE ACT ACTUALLY CARRIED**, not of the
    // first identifier the entry happens to hold. An application answering to a
    // client_id AND an entityID is one box, and which of the two is on the line
    // is what the act says; naming the other one would put a string on the
    // picture that nothing in this picture ever presented. The rest are in the
    // tooltip, where "it also answers to" belongs.
    const identifiers = application ? applications.identifiersOf(application) :
                        [];
    const presented = node.application ? String(node.application) : '';
    // GROUPED BY VALUE AND NOT BY ATTRIBUTE, because one string is commonly two
    // families' identifier and the box has room for one line: an application
    // declared for WS-Trust and SAML 2.0 carries `https://esb.example.com` on
    // `wstrustAppliesTo` AND on `samlEntityId`, and drawing the first of those
    // would pick one of two true answers. `AppliesTo / entityID:
    // https://esb.example.com` is the whole fact and is one line.
    //
    // Exact equality throughout, because `applications.js` does not case-fold
    // an identifier anywhere else either — an audience that differs by a
    // character is a different audience, and matching loosely here would be
    // this page deciding a comparison rule on that module's behalf.
    const byValue = [];
    identifiers.forEach(function (row) {
      row.values.forEach(function (value) {
        const already =
            byValue.filter(function (one) { return one.value === value; })[0];
        if (already) {
          if (already.names.indexOf(row.name) < 0) already.names.push(row.name);
          return;
        }
        byValue.push({ value: value, names: [row.name] });
      });
    });
    // WHICH ONE GOES ON THE BOX. The name the ACT carried wins, because that is
    // the string on the line the reader is following; where the act's name is
    // not an identifier attribute at all — the registry key of an entry made by
    // hand, or an application reached through an audience it registered — the
    // first declared identifier is drawn instead, since a box that named only
    // the key would be silent about the one thing somebody opened the picture
    // to get. Everything not drawn is in the tooltip.
    const chosen =
        byValue.filter(function (one) { return one.value === presented; })[0] ||
                   byValue[0] || null;
    // Nothing at all where the drawn name IS the identifier and no family
    // claims it: the string is already on the box, and a second line repeating
    // it is the same fact drawn twice. Where a family DOES claim it, the word
    // alone is drawn — `client_id` under `acme-web` says what kind of name that
    // is, which the box could not otherwise say.
    const identifierLine = chosen
      ? chosen.names.join(' / ') +
        (chosen.value === label ? '' : ': ' + chosen.value)
      : (presented && presented !== label ? presented : '');

    const parts = [];
    if (isPerson) parts.push('person');
    if (isApplication) parts.push('application');
    // WHICH STORE HAS NOT HEARD OF IT, and the two are different sentences. A
    // target drawn as a rectangle is missing from `ou=applications` — the
    // REGISTRY — and an initial identity drawn as a figure is missing from
    // `ou=users` — the DIRECTORY. One word for both would send half the readers
    // to the wrong page to look for it, which is the mistake
    // `delegationPartyCell()` avoids by drawing up to two links rather than
    // one.
    const missing = shape === 'person' ? 'not in the directory' : 'not in ' +
        'the registry';
    const sublabel = parts.length ? parts.join(' + ')
                   : (node.chiefRole ? node.chiefRole + ', ' + missing :
                      missing);

    // Where the box goes when it is clicked. ONE link, where the table draws up
    // to two — an SVG shape can be inside one anchor and the party table under
    // the picture carries both, which is where a reader who wants the other one
    // looks. The person's page wins when this console has SEEN them
    // authenticate, because that page answers the question a delegation raises
    // (what else was issued in their name); the application page otherwise.
    let href = '';
    if (node.key && known[node.key]) {
      href = '/admin/users' + self.queryWith({ user: node.key }, {});
    } else if (isApplication) {
      href = '/admin/applications' +
             self.queryWith({ application: node.application }, {});
    }

    const title = [
      label === node.id ? node.id : label + ' — ' + node.id,
      node.presented && node.presented !== node.id
        ? 'presented as ' + node.presented : '',
      node.application && node.application !== node.id
        ? 'named as an application: ' + node.application : '',
      entry ? 'In the directory at ' + entry.dn + '.'
            : (node.key ? 'No entry under ou=users names this.' : ''),
      application ? 'In the applications registry' +
        (application.dn ? ' at ' + application.dn : '') + '.'
        : (node.application ? 'NOT in the applications registry — the ' +
           'registry holds what this service has been ASKED ABOUT, and a ' +
           'delegation naming something nobody has otherwise mentioned is ' +
           'ordinary for an RFC 8693 audience.' : ''),
      // EVERY name it answers to, family by family, because the box has room
      // for one. This is where an application that is a client_id in one
      // protocol and an entityID in another says so.
      identifiers.length
        ? 'It answers to: ' + identifiers.map(function (row) {
            return row.name + ' ' + row.values.join(', ') +
                   ' (' + row.families.join(', ') + ')';
          }).join('; ') + '.'
        : '',
      (presented && chosen && chosen.value !== presented)
        ? 'THE NAME ON THE BOX IS NOT THE NAME THIS ACT PRESENTED. It ' +
          'presented "' +
          presented + '", which none of the identifier attributes above ' +
          'carries — so which family spells it that way cannot be said, and ' +
          'the first declared identifier is drawn instead. An entry created ' +
          'by a protocol sighting carries that family\'s attribute; one made ' +
          'by hand, or reached through an audience it registered, need not.'
        : '',
      'Roles: initial ' + node.roles.initial + ', intermediary ' +
        node.roles.intermediary + ', target ' + node.roles.target + '.',
      node.selfTarget
        ? 'Some act named this party as BOTH the intermediary and the target ' +
          '— a ticket to ITSELF, which is what S4U2Self is. There is no line ' +
          'for it because an arrow leaving a box and coming back is a ' +
          'drawing of nothing.'
        : '',
      node.protocols.length ? 'Seen over: ' + node.protocols.join(', ') + '.' :
      '',
      node.what || ''
    ].filter(Boolean).join('\n');

    log.debug("Leaving AdminViews.delegationNodeLook().");
    return { shape: shape, label: label, sublabel: sublabel,
             identifier: identifierLine, title: title,
             href: href, dashed: !isPerson && !isApplication };
  }

  // What every box is called and how it is drawn, worked out once per page.
  // `labelOf` is separate because a `reaches` line names a party that is
  // NEITHER of its ends — see the map route's call — and the renderer has no
  // `resolve()` answer for it.
  /**
   * Works out every box's look (label, shape, identifier) once for a
   * picture page.
   *
   * @param graph - the graph from delegation.graph()
   * @param known - the identities and applications the console knows
   * @returns an object of looks (by node id), resolve (for the renderer)
   *   and labelOf (an id's label)
   */
  delegationLooks(graph, known) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.delegationLooks().");
    const looks = {};
    graph.nodes.forEach(function (node) {
      looks[node.id] = self.delegationNodeLook(node, known);
    });
    log.debug("Leaving AdminViews.delegationLooks(). " + graph.nodes.length +
              " box(es).");
    return {
      looks: looks,
      resolve: function (node) {
        log.debug("Entering resolve().");
        log.debug("Leaving resolve().");
        return looks[node.id];
      },
      labelOf: function (id) {
        log.debug("Entering labelOf().");
        log.debug("Leaving labelOf().");
        return looks[id] ? looks[id].label : id;
      }
    };
  }

  // What a ROLE is called on this console, off `delegation.ROLES` rather than
  // out of a list here — the same rule the mechanism filter follows. A role
  // that existed in the store and was unnamed on a page would be a blank cell.
  // Moved here from the console (#446): the key is markup drawn out of the
  // layout module's glyphs, which only this process holds, so an answer
  // carries it as it carries the drawing (`mapKey`).
  // THE KEY. Drawn out of `delegation_map.js`'s own glyph functions and its own
  // palette rather than out of a second set of shapes written for the legend,
  // because a legend that is drawn separately is a legend that will eventually
  // describe a picture this service no longer draws. `options.issuance` adds
  // the two lines only the person's picture has. It is a parameter rather than
  // two more rows for everybody, because a legend must describe the diagram
  // beside it: a reader of /admin/delegation/map looking for a dotted `signed
  // in` line would never find one, and a key that lists shapes a page does not
  // draw teaches a reader to stop trusting it.
  /**
   * Draws the key to the delegation pictures, one row per shape or line,
   * using delegation_map.js's own glyphs and palette.
   *
   * @param options - optional; `issuance` adds the lines only the person's
   *   picture draws (signed in, ordinary grant, addressed to)
   * @returns the key as an HTML table
   */
  delegationMapKey(options?) {
    const { log, delegationMap } = this.deps;
    log.debug("Entering AdminViews.delegationMapKey().");
    const swatch = function (inner, width) {
      log.debug("Entering swatch().");
      log.debug("Leaving swatch().");
      return '<svg width="' + width + '" height="40" viewBox="0 0 ' + width +
        ' 40" aria-hidden="true">' + inner + '</svg>';
    };
    const C = delegationMap.COLOURS;
    // Drawn by `delegation_map.js` rather than here, so that the round end and
    // the pointed end in the key are the ones the picture actually puts on a
    // line. The arrowhead used to be drawn on this side and the tail disc would
    // have made that two shapes to keep in step instead of one.
    const line = function (colour, dash) {
      log.debug("Entering line().");
      log.debug("Leaving line().");
      return delegationMap.edgeSample(colour, dash);
    };
    const items = [
      { art: swatch(delegationMap.personGlyph(9, 3, C.indigo, false, 1), 44),
        what: '<strong>A person.</strong> Something with an entry under ' +
              '<code>ou=users</code> — anybody this service has ' +
              'authenticated, in any of the sixteen families.' },
      { art: swatch('<rect x="3" y="9" width="56" height="22" rx="5" fill="' +
                    C.panel +
                    '" stroke="' + C.indigo + '" stroke-width="1.5"/>', 64),
        what: '<strong>An application.</strong> Something with an entry ' +
              'under <code>ou=applications</code> — an OAuth client, a ' +
              'service provider, a Kerberos service, a WS-Trust relying ' +
              'party.' },
      { art: swatch('<rect x="3" y="4" width="56" height="32" rx="5" fill="' +
                    C.panel +
                    '" stroke="' + C.indigo + '" stroke-width="1.5"/>' +
                    delegationMap.personGlyph(7, 3, C.indigo, false, 0.85), 64),
        what: '<strong>Both, which the middle tier usually is.</strong> ' +
              '<code>HTTP/frontend.example.com</code> authenticates (so the ' +
              'funnel files it with the people) AND has tickets issued FOR ' +
              'it (so the registry has it). Two entries, one party.' },
      { art: swatch('<path d="' + delegationMap.hexPath(3, 6, 58, 28) +
                    '" fill="' +
                    C.wash + '" stroke="' + C.indigo + '" stroke-width="1.8"/>',
                    64),
        what: '<strong>This service, in one trust realm.</strong> Every line ' +
              'here exists because it issued or refused a credential. The ' +
              'realm is on the box because a realm is a whole logical copy ' +
              'of this service.' },
      // Wider than every other swatch here, and it has to be: the whole point
      // of the row is the THIRD line, and an identifier is the one thing on a
      // box that is as long as a protocol allows. At 80 the sample ran out
      // through its own rectangle, which is precisely the mistake this row is
      // teaching a reader to look for.
      { art: swatch('<rect x="3" y="2" width="104" height="36" rx="5" fill="' +
                    C.panel +
                    '" stroke="' + C.indigo + '" stroke-width="1.5"/>' +
                    '<text x="55" y="15" text-anchor="middle" font-size="10" ' +
                    'font-weight="600" fill="' + C.ink + '">Acme ' +
                    'Web</text><text x="55" y="25" text-anchor="middle" ' +
                    'font-size="8" fill="' +
                    C.quiet + '">application</text><text x="55" y="34" ' +
                    'text-anchor="middle" font-size="8" fill="' +
                    C.quiet + '">client_id: acme-web</text>', 110),
        what: '<strong>The two small lines under a name are different ' +
              'sentences.</strong> The first is what the box IS &mdash; ' +
              'which of the two stores knows it, or the role its shape was ' +
              'guessed from. The second is <strong>the identifier a protocol ' +
              'would have to present to reach it, with that protocol\'s own ' +
              'word for it</strong>: a <code>client_id</code> for OAuth 2.0 ' +
              'and OpenID Connect, an <code>entityID</code> for either SAML ' +
              'profile, a <code>wtrealm</code> for WS-Federation, an ' +
              '<code>AppliesTo</code> for WS-Trust, an <code>SPN</code> for ' +
              'Kerberos. The NAME on the box is what somebody CALLED this ' +
              'thing &mdash; a <code>cn</code>, an <code>appName</code> ' +
              '&mdash; and is no use in a request you are about to build, ' +
              'which is why the identifier is on the picture and not only in ' +
              'the tooltip. Where the two are the same string only the word ' +
              'is drawn, because the value is already the label; where ONE ' +
              'string is two families\' identifier both words are drawn ' +
              '(<code>AppliesTo / entityID</code>); and where the ' +
              'application answers to several DIFFERENT names, the one drawn ' +
              'is the one this act actually carried &mdash; or, if the act ' +
              'carried something no identifier attribute holds, the first ' +
              'declared one, with the tooltip saying so. Every name it ' +
              'answers to is in that tooltip either way.' },
      { art: swatch(delegationMap.personGlyph(9, 3, C.grey, true, 1), 44),
        what: '<strong>A dashed outline is something neither store ' +
              'knows.</strong> It is drawn in the shape its ROLE implies and ' +
              'is not an error: an RFC 8693 <code>audience</code> nobody has ' +
              'otherwise mentioned is exactly this.' },
      { art: swatch(line(C.indigo, ''), 64),
        what: '<strong>Which way a line goes is at BOTH of its ' +
              'ends.</strong> It leaves the box with the round end and ' +
              'arrives at the box with the arrowhead &mdash; so the question ' +
              'a reader actually asks, standing at one box: <em>is this line ' +
              'mine, or somebody\'s on me?</em>, is answered where they are ' +
              'standing rather than at the far end of a curve that crosses ' +
              'three others on the way. Every line here has both marks, and ' +
              'no line here is two-way: two applications that reach each ' +
              'other are drawn as two lines.' },
      { art: swatch(line(C.amber, ''), 64),
        what: '<strong>acts for &mdash; an IMPERSONATION.</strong> What came ' +
              'out names the initial identity and nothing else, so nothing ' +
              'at the far end can tell an intermediary was involved. Amber ' +
              'because this picture is the only place that fact will ever ' +
              'exist.' },
      { art: swatch(line(C.green, ''), 64),
        what: '<strong>acts for &mdash; a DELEGATION.</strong> What came out ' +
              'CARRIES the chain: an <code>act</code> claim, a composite ' +
              '<code>ActAs</code>, <code>S4U_DELEGATION_INFO</code> in the ' +
              'PAC.' },
      { art: swatch(line(C.indigo, ''), 64),
        what: '<strong>reaches &mdash; the TRUST relationship.</strong> What ' +
              'the credential is FOR: the back-end service, the ' +
              '<code>AppliesTo</code>, the audience or resource. The label ' +
              'says whose name it carries.' },
      { art: swatch(line(C.indigo, '7 4'), 64),
        what: '<strong>A broken line jumps a party nobody named.</strong> A ' +
              'forwarded ticket-granting ticket has no intermediary and ' +
              'cannot have one — the client gives it to whichever service it ' +
              'chooses and this KDC is never told which.' },
      // #186: the configured pairs, beside the acts.
      { art: swatch(line(C.indigo, '6 4'), 64),
        what: '<strong>may delegate &mdash; a CONFIGURED relationship, ' +
              'DASHED until an act has used it.</strong> One line per pair ' +
              'an entry allows: <code>appAllowedToDelegateTo</code> on the ' +
              'source (constrained) or ' +
                '<code>appAllowedToActOnBehalfOf</code> ' +
              'on the target (resource-based) &mdash; the same controls for ' +
              'the OAuth 2.0 token exchange, WS-Trust and Kerberos. Solid ' +
              'once an act has crossed it. Drawn unless the acts are ' +
              'narrowed by outcome, type or text.' },
      { art: swatch(line(C.red, '5 3'), 64),
        what: '<strong>Red is a chain nothing was ever issued on.</strong> ' +
              'The tooltip carries the KDC\'s own words for why, which is ' +
              'the same sentence the client was sent.' },
      { art: swatch(line(C.grey, '4 3'), 64),
        what: '<strong>Grey and dashed, from the hexagon: this service ' +
              'ISSUED to that party.</strong> It goes to whoever ASKED — the ' +
              'intermediary where a chain has one, the initial identity ' +
              'where it does not.' }
    ];
    if (options && options.issuance) {
      items.push(
        { art: swatch(line(C.indigo, '2 3'), 64),
          what: '<strong>Dotted, into the hexagon: this person AUTHENTICATED ' +
                'here.</strong> The label is the protocol family and the ' +
                'tooltip is the method — the sign-in screen, an AS-REQ, a ' +
                'UsernameToken, a federated assertion. It is why everything ' +
                'else on the picture was allowed.' },
        { art: swatch(line(C.indigo, ''), 64),
          what: '<strong>Solid indigo: an ORDINARY GRANT, and the label is ' +
                'the exact one</strong> — <code>authorization_code</code>, ' +
                '<code>refresh_token</code>, ' +
                '<code>client_credentials</code>, with the specification ' +
                'section in the tooltip. Out of the PERSON it means a ' +
                'credential naming them went to that application; out of the ' +
                'HEXAGON it means nobody else holds it — a ' +
                '<code>client_credentials</code> token is about the client ' +
                'itself and an X509-SVID has no audience, so the subject and ' +
                'the holder are one box and there is one line rather than ' +
                'two. It takes no amber or green, because impersonation and ' +
                'delegation are properties of a delegation mechanism and a ' +
                'grant claims neither.' },
        { art: swatch(line(C.indigo, ''), 64),
          what: '<strong>Solid indigo out of an APPLICATION is that same ' +
                'relationship one step further on: what the credential it ' +
                'holds is ADDRESSED to.</strong> It is the <em>reaches</em> ' +
                'line above, said about an ordinary grant instead of about a ' +
                'delegation — an access token issued to a web front end and ' +
                'addressed to an API gateway is this service saying the ' +
                'first may reach the second in this person\'s name, with ' +
                'nothing exchanged to get there. The mechanism on the label ' +
                'is what tells the two apart: a grant, or <code>Token ' +
                'exchange</code>. The audience the token actually carries is ' +
                'in the tooltip, because the box is named after whichever ' +
                'application registered that audience. <strong>The line ' +
                'under it names the DELEGATED PERMISSIONS on that ' +
                'token</strong> — the values on its <code>scope</code> claim ' +
                'that the resource at the far end has DEFINED, which is what ' +
                'a client asks for by sending the whole permission ' +
                'identifier (the resource\'s base URI followed by the name) ' +
                'as a scope. <strong><code>default permissions</code> means ' +
                'the token named the resource and asked for none of ' +
                'them</strong>: that is what a scope naming the resource\'s ' +
                'own <code>client_id</code> produces, since that value ' +
                'becomes the audience and comes off the scope claim. It says ' +
                'what was ISSUED and not what was GRANTED — <a ' +
                'href="/admin/delegation/allowed">the configured ' +
                'register</a> is the other question, and ' +
                'in development <code>oauth2.delegatedPermissionsEnforced' +
                '</code> is off by default, so a token can carry a ' +
                'permission its client was never granted (product mode ' +
                'refuses one).' });
    }
    log.debug("Leaving AdminViews.delegationMapKey().");
    return '<table class="key"><tr><th>Shape</th><th>What it means</th></tr>' +
      items.map(function (one) {
        return '<tr><td class="art">' + one.art + '</td><td>' + one.what +
               '</td></tr>';
      }).join('') + '</table>';
  }
  // ---------------------------------------------------------------------------
  // THE WHOLE PICTURE AS ONE ANSWER, FOR THE MANAGEMENT API (#446, 2026-10-05).
  //
  // `/admin/delegation/map` had no operation, by rule 7 read exactly: it has
  // no form. A console that is a static client of `/admin-api` needs one all
  // the same, because three things on that page are known only to this
  // process: what each box IS (`delegationLooks()` asks the directory and the
  // application registry), where each box GOES (dagre, laid out on the
  // server), and the markup of the drawing. So the answer is the page's own
  // JSON — the graph, the filter, the counts — with `looks` and `svg` added.
  //
  // IT IS THE SAME FOUR CALLS THE PAGE'S ROUTE MAKES, in its order, and
  // deliberately not yet the route's own source of them: the route is left as
  // it is until its page is converted (#446 step 3), when both will be this.
  //
  // IT IS HERE AND NOT ON THE CONSOLE (`admin-ui/admin.ts`), where it was
  // written first: `tests/admin_actions_layer.js` holds the management API to
  // asking this layer, and what a box IS (`delegationNodeLook()`, moved with
  // it) is a view both surfaces answer.
  // ---------------------------------------------------------------------------
  /**
   * Builds the delegation picture as one answer: the graph, every box's look,
   * the counts and the drawing.
   *
   * @param query - the page's query: the delegation filter
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the page's JSON with `summary`, `looks`, `label` and `svg`
   */
  delegationMapModel(query, options?) {
    const { log, delegationMap } = this.deps;
    log.debug("Entering AdminViews.delegationMapModel().");
    const view = this.delegationView(query || {});
    const graph = view.graph;
    const look = this.delegationLooks(graph, this.knownUserKeys());
    const label = 'Delegation relationships in this service, as a diagram';
    const drawn = delegationMap.render(graph, {
      resolve: look.resolve, labelOf: look.labelOf,
      links: !(options && options.links === false), id: 'delmap', label: label
    });
    const model: any = Object.assign({}, graph, {
      filter: view.json.filter,
      matched: view.filtered.length,
      held: view.summary.held,
      summary: view.summary,
      drawing: { width: drawn.width, height: drawn.height,
                 failed: drawn.failed || null },
      looks: look.looks,
      label: label,
      svg: drawn.svg
    });
    if (!(options && options.links === false)) {
      // WHAT THE PAGE DRAWS AROUND THE PICTURE (#446): how many acts are
      // held at all, the filter's vocabulary, the two choosers' panes, the
      // key, whether a directory resolves the boxes, and the facts its
      // cells ask about the names in it.
      const carry = WebKit.listViewOf('/admin/delegation', query || {});
      model.all = view.all.length;
      model.types = view.json.types;
      model.modes = view.json.modes;
      model.outcomes = view.json.outcomes;
      model.applicationChooser = this.delegationChooser('application',
        query, view.applications, carry);
      model.userChooser = this.delegationChooser('user', query,
        this.deps.userGraph.userList(), carry);
      model.mapKey = this.delegationMapKey();
      model.directoryLoaded = !!directoryReader;
      model.facts = this.delegationFacts(model);
    }
    log.debug("Leaving AdminViews.delegationMapModel(). " + drawn.width +
              "x" + drawn.height + ".");
    return model;
  }

  // ---------------------------------------------------------------------------
  // ONE RELATIONSHIP, DRAWN ALONE, AS ONE ANSWER (#446).
  //
  // `/admin/delegation/chain?chain=` had no operation — it has no form —
  // and draws what only this process knows: what each box is, where it
  // goes, the drawing. The answer is the page's own JSON (the chain, its
  // acts, the graph) with the looks, the drawing, the key and the facts its
  // cells ask, as `delegationMapModel()` answers the whole picture. A key no
  // act is held under is `found: false`, which is not an error: the store is
  // capped and an old link coming back empty is the ordinary outcome.
  // ---------------------------------------------------------------------------
  /**
   * Builds one delegation relationship as one answer.
   *
   * @param query - the page's query: `chain`, the chain's key
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the chain, its acts and graph, and the drawing
   */
  delegationChainModel(query, options?) {
    const { log, delegation, delegationMap } = this.deps;
    log.debug("Entering AdminViews.delegationChainModel().");
    const wanted = String((query || {}).chain || '');
    const all = delegation.list();
    const acts = delegation.actsOfChain(all, wanted);
    // chainList() over the acts of ONE chain returns exactly one row, and it
    // is that function's answer rather than a shape built here.
    const chain = delegation.chainList(acts)[0] || null;
    const graph = delegation.graph(acts);
    const look = this.delegationLooks(graph, this.knownUserKeys());
    const label = chain
      ? 'One delegation relationship: ' + chain.typeLabel
      : 'A delegation relationship that is no longer held';
    const drawn = delegationMap.render(graph, {
      resolve: look.resolve, labelOf: look.labelOf,
      links: !(options && options.links === false), id: 'delmap', label: label
    });
    const summary = delegation.summary();
    const model: any = {
      chain: chain, chainKey: wanted, found: !!chain,
      acts: acts, graph: graph,
      held: summary.held, maxRecords: summary.maxRecords,
      drawing: { width: drawn.width, height: drawn.height,
                 failed: drawn.failed || null },
      looks: look.looks, label: label, svg: drawn.svg
    };
    if (!(options && options.links === false)) {
      model.mapKey = this.delegationMapKey();
      model.facts = this.delegationFacts(model);
    }
    log.debug("Leaving AdminViews.delegationChainModel(). " + acts.length +
              " act(s).");
    return model;
  }

  // ---------------------------------------------------------------------------
  // ONE APPLICATION'S DELEGATIONS, AS ONE ANSWER (#446).
  //
  // `/admin/delegation/application?application=`: every act an application
  // took part in, in either role, drawn — the page's own JSON with the
  // looks, the drawing, the key, the chooser's pane and the facts its cells
  // ask. An application no act names is `application: null`, with the
  // catalogue to choose from.
  // ---------------------------------------------------------------------------
  /**
   * Builds one application's delegations as one answer.
   *
   * @param query - the page's query: `application`, as presented or
   *   normalised
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the application, its acts and graph, and the drawing
   */
  delegationApplicationModel(query, options?) {
    const { log, delegation, delegationMap, applications } = this.deps;
    log.debug("Entering AdminViews.delegationApplicationModel().");
    const asked = String((query || {}).application || '').trim();
    // Normalised the same way the store normalises one, so a link carrying
    // the RAW identifier finds the same application the chooser's does.
    const key = delegation.applicationKeyOf(asked);
    const all = delegation.list();
    const catalogue = delegation.applicationList(all);
    const entry = catalogue.filter(function (one) {
      return one.key === key;
    })[0] || null;
    const acts = entry ? delegation.actsForApplication(all, key) : [];
    const graph = delegation.graph(acts);
    const look = this.delegationLooks(graph, this.knownUserKeys());
    const label = entry
      ? 'Everything delegated through or to ' + entry.identifier
      : 'Applications with delegated access';
    const drawn = delegationMap.render(graph, {
      resolve: look.resolve, labelOf: look.labelOf,
      links: !(options && options.links === false), id: 'delmap', label: label
    });
    // WHICH ROLES THIS APPLICATION PLAYED IN THE ACT EACH CREDENTIAL CAME
    // OUT OF, keyed on `seq` — the act's own identifier, monotonic and never
    // reused, so a role cannot attach to the wrong credential.
    const rolesBySeq = {};
    acts.forEach(function (row) {
      rolesBySeq[row.seq] = delegation.applicationRolesIn(row, key);
    });
    // The registry's answer, tried against every spelling: `ou=applications`
    // is keyed by what a caller presented, and this key is normalised.
    let registered = null;
    (entry ? entry.spellings : []).forEach(function (spelling) {
      if (!registered) {
        registered = applications.get(spelling) || null;
      }
    });
    const summary = delegation.summary();
    const model: any = {
      application: entry, asked: asked || null, key: key,
      registered: !!registered,
      registeredName: registered
        ? (registered.name || registered.dnLabel || '') : '',
      acts: acts, graph: graph,
      // The role played per act, keyed by the act's sequence number. It is
      // the one thing here a caller could not work out from `acts` without
      // reimplementing the normalisation.
      rolesBySeq: rolesBySeq,
      applications: catalogue,
      held: summary.held, maxRecords: summary.maxRecords,
      roles: delegation.ROLES,
      drawing: { width: drawn.width, height: drawn.height,
                 failed: drawn.failed || null },
      looks: look.looks, label: label, svg: drawn.svg
    };
    if (!(options && options.links === false)) {
      model.chooser = this.delegationChooser('application', query, catalogue,
        WebKit.listViewOf('/admin/delegation', query || {}));
      model.mapKey = this.delegationMapKey();
      model.facts = this.delegationFacts(model);
    }
    log.debug("Leaving AdminViews.delegationApplicationModel(). " +
              acts.length + " act(s).");
    return model;
  }

  // ---------------------------------------------------------------------------
  // EVERYTHING DONE IN ONE PERSON'S NAME, AS ONE ANSWER (#446).
  //
  // `/admin/delegation/user?user=`: the identity register and the
  // delegation register unioned for one person (`userGraph.activityFor()`)
  // — every credential with the grant that produced it, the sign-ins, the
  // acts naming them — drawn. The page's own JSON with the looks (the
  // issuance half appended to each tooltip), the drawing, the key with the
  // person picture's own three rows, the chooser's pane and the facts. A
  // name neither register holds is `user: null`, with the catalogue.
  // ---------------------------------------------------------------------------
  /**
   * Builds everything done in one person's name as one answer.
   *
   * @param query - the page's query: `user`, as presented or normalised
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the person, their credentials, flows, acts and graph, and the
   *   drawing
   */
  delegationUserModel(query, options?) {
    const { log, stats, delegation, delegationMap, userGraph } = this.deps;
    log.debug("Entering AdminViews.delegationUserModel().");
    const asked = String((query || {}).user || '').trim();
    // Normalised the way the identity register normalises one, so a link
    // carrying `alice@STS.MOCK` finds the same person the chooser's does.
    const key = stats.identityKeyOf(asked);
    const catalogue = userGraph.userList();
    const activity = key ? userGraph.activityFor(key) : null;
    // An empty graph rather than none when nobody is selected.
    const graph = activity ? activity.graph : delegation.graph([]);
    const look = this.delegationLooks(graph, this.knownUserKeys());

    // WHAT THE ISSUANCE HALF ADDS TO A TOOLTIP. `delegationNodeLook()` is the
    // one answer to "what is this box" and must stay that way — it is what
    // keeps this page, the map and the two other drill-downs drawing one
    // party one way — so the credentials are APPENDED to what it said rather
    // than folded into it.
    graph.nodes.forEach(function (node) {
      const entry = look.looks[node.id];
      if (!entry || node.kind === 'sts') {
        return;
      }
      // A CLIENT IS DRAWN AS AN APPLICATION, and only where neither store has
      // an opinion. `delegationNodeLook()`'s fallback is the shape the ROLE
      // implies and the subject of this page is an initial identity, so a
      // `client_credentials` client — which is a client BY ITS OWN SAYING, at
      // the one funnel that can know — was coming out as a stick figure.
      // Where the directory or the registry DOES know it, that answer stands:
      // the fallback is what is being corrected, not the stores.
      if (node.isClient && entry.dashed) {
        entry.shape = 'application';
        entry.sublabel = 'a client, not a person';
      }
      const extra = [];
      if (node.isSubject) {
        extra.push('THIS IS THE PERSON THIS PAGE IS ABOUT.');
      }
      if (node.isClient) {
        extra.push('It is a CLIENT rather than a person: something ' +
                   'authenticated under this name and said the client is ' +
                   'the identity, which the client_credentials grant is ' +
                   'the usual way of doing.');
      }
      if (node.credentials) {
        extra.push(node.credentials + ' credential(s) issued' +
                   (node.isSubject ? ' naming them' : ' to it') +
                   (node.kinds.length ? ': ' + node.kinds.join(', ') : '') +
                   '.');
      }
      if (node.flows.length) {
        extra.push('By: ' + node.flows.join(', ') + '.');
      }
      if (node.authentications) {
        extra.push(node.authentications + ' authentication(s) here.');
      }
      if (extra.length) {
        entry.title = entry.title + '\n' + extra.join('\n');
      }
    });

    const label = activity
      ? 'Everything issued in the name of ' + activity.key
      : 'People and the credentials issued in their name';
    const drawn = delegationMap.render(graph, {
      resolve: look.resolve, labelOf: look.labelOf,
      links: !(options && options.links === false), id: 'delmap', label: label
    });
    const model: any = {
      user: activity ? activity.entry : null,
      asked: asked || null, key: key,
      // The whole model, so a test can assert what the page draws without
      // parsing an SVG.
      credentials: activity ? activity.credentials : [],
      flows: activity ? activity.flows : [],
      onDelegationLines: activity ? activity.onDelegationLines : 0,
      acts: activity ? activity.acts : [],
      graph: graph,
      counts: activity ? activity.counts : null,
      users: catalogue,
      drawing: { width: drawn.width, height: drawn.height,
                 failed: drawn.failed || null },
      looks: look.looks, label: label, svg: drawn.svg
    };
    if (!(options && options.links === false)) {
      model.chooser = this.delegationChooser('user', query, catalogue,
        WebKit.listViewOf('/admin/delegation', query || {}));
      model.mapKey = this.delegationMapKey({ issuance: true });
      model.facts = this.delegationFacts(model);
    }
    log.debug("Leaving AdminViews.delegationUserModel(). " +
              model.credentials.length + " credential(s).");
    return model;
  }

  // ---------------------------------------------------------------------------
  // ONE CREDENTIAL AND EVERY GENERATION BEHIND IT, AS ONE ANSWER (#446).
  //
  // `/admin/tokens/credential?id=`: the lineage `credentialGraph.lineageOf()`
  // walks, drawn — the page's own JSON with the looks (the box the
  // credential ended up at marked in its tooltip), the drawing, and what the
  // page asked the registers for while it drew: each generation's holder and
  // the label of the grant or flow at its origin (`holder`, `originLabel`
  // on each generation), the key the credential's person is filed under
  // (`subjectKey`), the cap on the walk, and the facts.
  // ---------------------------------------------------------------------------
  /**
   * Builds one credential's lineage as one answer.
   *
   * @param query - the page's query: `id`, the credential's identifier
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the lineage, the graph and the drawing
   */
  credentialLineageModel(query, options?) {
    const { log, stats, delegation, delegationMap, userGraph,
            credentialGraph } = this.deps;
    log.debug("Entering AdminViews.credentialLineageModel().");
    const asked = String((query || {}).id || '').trim();
    const lineage = asked ? credentialGraph.lineageOf(asked) : null;
    const graph = lineage ? lineage.graph : delegation.graph([]);
    const look = this.delegationLooks(graph, this.knownUserKeys());
    // WHICH BOX IS THE ONE THIS CREDENTIAL IS AT NOW, appended to what
    // `delegationNodeLook()` said, as the person's picture appends its own.
    const holder = lineage && lineage.credential
      ? stats.identityKeyOf(userGraph.holderOf(lineage.credential)) : '';
    if (holder && look.looks[holder]) {
      look.looks[holder].title = look.looks[holder].title +
        '\nTHIS IS WHERE THE CREDENTIAL THIS PAGE IS ABOUT ENDED UP: ' +
        (lineage.credential.kind || 'a credential') + ' ' + asked + '.';
    }
    const label = lineage
      ? 'How ' +
        (lineage.credential ? lineage.credential.kind : 'this credential') +
        ' ' + asked + ' came to exist'
      : 'One credential, and every generation behind it';
    const drawn = delegationMap.render(graph, {
      resolve: look.resolve, labelOf: look.labelOf,
      links: !(options && options.links === false), id: 'delmap', label: label
    });
    const model: any = {
      identifier: asked || null,
      held: lineage ? lineage.held : null,
      credential: lineage ? lineage.credential : null,
      counts: lineage ? lineage.counts : null,
      generations: lineage
        ? lineage.generations.map(function (row) {
          const one = row.credential;
          return Object.assign({}, row, {
            holder: one ? userGraph.holderOf(one) || '' : '',
            originLabel: row.act ? '' : (one && one.family === 'token'
              ? userGraph.flowRow(one.grant).label
              : (one ? userGraph.artifactFlowRow(one.kind).label
                     : 'nothing here produced it'))
          });
        })
        : [],
      origins: lineage ? lineage.origins : [],
      issuances: lineage ? lineage.issuances : [],
      walls: lineage ? lineage.walls : [],
      truncated: lineage ? lineage.truncated : false,
      acts: lineage ? lineage.acts : [],
      graph: graph,
      maxGenerations: credentialGraph.MAX_GENERATIONS,
      drawing: { width: drawn.width, height: drawn.height,
                 failed: drawn.failed || null },
      looks: look.looks, label: label, svg: drawn.svg
    };
    const credential = model.credential;
    model.subjectKey = credential && credential.family === 'token' &&
      (credential.username || credential.sub)
      ? stats.identityKeyOf(credential.username || credential.sub) : '';
    if (!(options && options.links === false)) {
      model.facts = this.delegationFacts(model);
    }
    log.debug("Leaving AdminViews.credentialLineageModel(). " +
              model.generations.length + " generation(s).");
    return model;
  }

  // ---------------------------------------------------------------------------
  // WHICH ROWS OF THE CONFIGURED PERMISSIONS REGISTER A PAGE SHOWS (#446).
  //
  // The console's `permissionsListState()`, here so that an answer carries
  // it: the two searches (`permq`, `grantq`) and the two pagings, worked out
  // in ONE function so the table and the reply cannot disagree. The pages
  // are `{ shown, paging }` with the paging as every answer carries one.
  // ---------------------------------------------------------------------------
  /**
   * Works out the searched and paged rows of the permissions register.
   *
   * @param query - the page's query
   * @param register - the configured permissions register
   * @returns `permWanted`, `grantWanted`, `permPage` and `grantPage`
   */
  permissionsListStateOf(query, register) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.permissionsListStateOf().");
    const permWanted = this.queryOne(query, 'permq').trim();
    const grantWanted = this.queryOne(query, 'grantq').trim();
    const permissionsMatched = register.permissions.filter(function (one) {
      return self.chooserMatches([one.resourceName, one.resource], permWanted);
    });
    // BOTH ENDS OF THE RELATIONSHIP: a dangling grant carries no resource,
    // so it matches on its client alone.
    const grantsMatched = register.grants.filter(function (one) {
      return self.chooserMatches([one.clientName, one.client,
                                  one.resourceName, one.resource],
                                 grantWanted);
    });
    const permPage = this.pagedRows(query, permissionsMatched,
      { name: 'permissions', noun: 'permissions',
        defaultPer: DELEGATION_PER_PAGE });
    const grantPage = this.pagedRows(query, grantsMatched,
      { name: 'grants', noun: 'grants', defaultPer: DELEGATION_PER_PAGE });
    log.debug("Leaving AdminViews.permissionsListStateOf().");
    return {
      permWanted: permWanted, grantWanted: grantWanted,
      permPage: { shown: permPage.shown,
                  paging: this.pagingJson(permPage.paging) },
      grantPage: { shown: grantPage.shown,
                   paging: this.pagingJson(grantPage.paging) }
    };
  }

  // ---------------------------------------------------------------------------
  // PROTOCOLS → DELEGATION, AS ONE ANSWER (#446).
  //
  // `/admin/delegation-settings`: the configured permissions register with
  // its searches and pagings, every application for the two selects, and
  // the page's settings block. `allowed` is what the page answered before.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/delegation-settings`'s answer.
   *
   * @param query - the page's query
   * @returns the register, its list state, the applications and settings
   */
  delegationSettingsModel(query) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.delegationSettingsModel().");
    const permissions = this.permissionsView();
    const register = permissions.register;
    const listState = this.permissionsListStateOf(query || {}, register);
    log.debug("Leaving AdminViews.delegationSettingsModel().");
    return {
      allowed: {
        resources: register.resources,
        permissions: register.permissions,
        grants: register.grants,
        counts: register.counts,
        filter: { permissions: listState.permWanted || null,
                  grants: listState.grantWanted || null },
        paging: { permissions: listState.permPage.paging,
                  grants: listState.grantPage.paging }
      },
      settings: this.settingsBlockOf('/admin/delegation-settings'),
      register: register,
      listState: listState,
      allApplications: applications.list().map(function (row) {
        return { identifier: row.identifier, name: row.name || '' };
      })
    };
  }

  // ---------------------------------------------------------------------------
  // THE ALLOWED MAPPINGS, AS ONE ANSWER (#446).
  //
  // `/admin/delegation/allowed`: every configured delegated permission
  // drawn, and the groups of applications the grants join, paged. The
  // page's own JSON with the looks, the drawing, the register and the
  // clusters its chooser searches, the groups on this page in full (the
  // table spells their members out), and `apps`: each member the registry
  // holds, with its name.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/delegation/allowed`'s answer.
   *
   * @param query - the page's query
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the graph, the groups, the register and the drawing
   */
  delegationAllowedModel(query, options?) {
    const { log, delegationMap } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.delegationAllowedModel().");
    const permissions = this.permissionsView();
    const graph = permissions.graph;
    const look = this.delegationLooks(graph, this.knownUserKeys());
    const label = 'Delegated permissions between applications, as a diagram';
    const drawn = delegationMap.render(graph, {
      resolve: look.resolve, labelOf: look.labelOf,
      links: !(options && options.links === false), id: 'delmap', label: label
    });
    const groups = permissions.clusters;
    // THE GROUPS, PAGED, on a parameter of their own (`groupsPage`).
    const groupPage = this.pagedRows(query || {}, groups.clusters,
                                     { name: 'groups', noun: 'groups' });
    const model: any = {
      graph: graph, counts: permissions.register.counts,
      grants: permissions.register.grants,
      // The groups on this page through the SAME `clusterSummary()` that
      // `GET /admin-api/permissions/groups` answers with: the counts, not
      // the rows.
      groups: groupPage.shown.map(function (group) {
        return self.clusterSummary(group);
      }),
      groupCounts: groups.counts,
      groupsPaging: this.pagingJson(groupPage.paging),
      drawing: { width: drawn.width, height: drawn.height,
                 failed: drawn.failed || null },
      looks: look.looks, label: label, svg: drawn.svg
    };
    if (!(options && options.links === false)) {
      // What the page draws beyond that: the register and the clusters the
      // chooser searches, and the shown groups whole.
      model.register = permissions.register;
      model.clusters = groups;
      model.shownGroups = groupPage.shown;
      model.facts = this.delegationFacts(model);
      model.apps = model.facts.apps;
    }
    log.debug("Leaving AdminViews.delegationAllowedModel().");
    return model;
  }

  // ---------------------------------------------------------------------------
  // ONE GROUP OF APPLICATIONS JOINED BY PERMISSIONS, AS ONE ANSWER (#446).
  //
  // `/admin/delegation/cluster?application=`: the group an application is
  // in (`appPermissions.clusterFor()`, exact equality on the identifier),
  // drawn. `permissionGroupsView()` — what the page answered before and
  // `GET /admin-api/permissions/groups` answers — with the group whole, its
  // grants and permissions paged, the looks and the drawing, the register
  // and clusters the chooser searches, the groups paged for the bare page,
  // and `apps`: each member the registry holds, with its name.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/delegation/cluster`'s answer.
   *
   * @param query - the page's query: `application`
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the group, its pages, the chooser's data and the drawing
   */
  delegationClusterModel(query, options?) {
    const { log, delegationMap, appPermissions } = this.deps;
    log.debug("Entering AdminViews.delegationClusterModel().");
    const asked = String((query || {}).application || '').trim();
    const permissions = this.permissionsView();
    const groups = permissions.clusters;
    const group = asked ? appPermissions.clusterFor(asked, groups) : null;
    const graph = appPermissions.graph(group ? group.grants : []);
    const look = this.delegationLooks(graph, this.knownUserKeys());
    const label = group
      ? 'Delegated permissions across the ' + group.counts.applications +
        ' application(s) joined to ' + asked
      : 'Applications joined by delegated permissions';
    const drawn = delegationMap.render(graph, {
      resolve: look.resolve, labelOf: look.labelOf,
      links: !(options && options.links === false), id: 'delmap', label: label
    });
    const model: any = Object.assign({},
      this.permissionGroupsView(query || {}, permissions), {
        asked: asked, graph: graph,
        drawing: { width: drawn.width, height: drawn.height,
                   failed: drawn.failed || null },
        looks: look.looks, label: label, svg: drawn.svg
      });
    if (!(options && options.links === false)) {
      const page = function (rows, name, noun) {
        const one = this.pagedRows(query || {}, rows,
                                   { name: name, noun: noun });
        return { shown: one.shown, paging: this.pagingJson(one.paging) };
      }.bind(this);
      model.cluster = group;
      model.register = permissions.register;
      model.clusters = groups;
      if (group) {
        model.grantPage = page(group.grants, 'groupGrants', 'grants');
        model.permissionPage = page(group.permissions, 'groupPermissions',
                                    'permissions');
      } else {
        model.groupPage = page(groups.clusters, 'groups', 'groups');
      }
      model.facts = this.delegationFacts(model);
      model.apps = model.facts.apps;
    }
    log.debug("Leaving AdminViews.delegationClusterModel().");
    return model;
  }

  // ---------------------------------------------------------------------------
  // MONITORING → DELEGATION, AS ONE ANSWER (#446).
  //
  // `/admin/delegation`: the acts, filtered and paged (`delegationView()`,
  // what `GET /admin-api/delegation` answered alone), the configured
  // permissions register as `allowed` and the WS-Trust and token-exchange
  // policy as `delegationPolicy` — the page's `?format=json` before — and
  // what the page draws beyond them: its other six lists paged, the two
  // choosers' panes, the two sections' views, and the facts.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/delegation`'s answer.
   *
   * @param query - the page's query: the delegation filter, the searches
   *   and every list's page
   * @returns the acts and everything the page draws beside them
   */
  delegationPageModel(query) {
    const { log, delegation, userGraph, applications } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.delegationPageModel().");
    const q = query || {};
    const view = this.delegationView(q);
    const permissions = this.permissionsView();
    const listState = this.permissionsListStateOf(q, permissions.register);
    const exchangePolicy = this.delegationPolicyView(q);
    const policy = view.policy;
    const page = function (rows, name, noun) {
      const one = self.pagedRows(q, rows, { name: name, noun: noun,
                                            defaultPer: DELEGATION_PER_PAGE });
      return { shown: one.shown, paging: self.pagingJson(one.paging) };
    };
    const carry = WebKit.listViewOf('/admin/delegation', q);
    const model: any = Object.assign({}, view.json, {
      // UNDER A MEMBER OF ITS OWN AND NOT MERGED INTO THE ACTS: different
      // registers, and `allowed` is the word the page uses.
      allowed: {
        resources: permissions.register.resources,
        permissions: permissions.register.permissions,
        grants: permissions.register.grants,
        counts: permissions.register.counts,
        graph: permissions.graph,
        // What the browser was shown, beside the whole lists.
        filter: { permissions: listState.permWanted || null,
                  grants: listState.grantWanted || null },
        paging: { permissions: listState.permPage.paging,
                  grants: listState.grantPage.paging }
      },
      // WS-Trust and token exchange (#108), paged as GET
      // /admin-api/delegation/policy pages it.
      delegationPolicy: exchangePolicy.json,
      all: view.all.length,
      paging: this.pagingJson(view.paging),
      // The size every list here starts at, which the page states.
      delegationPerPage: DELEGATION_PER_PAGE,
      // The page's other lists, each on a parameter of its own.
      chainPage: page(view.chains, 'chains', 'chains'),
      pairPage: page(policy.pairs, 'pairs', 'pairs'),
      flagPage: page(policy.accounts, 'flags', 'accounts'),
      mechanismPage: page(delegation.TYPES, 'mechanisms', 'mechanisms'),
      applicationChooser: this.delegationChooser('application', q,
                                                 view.applications, carry),
      userChooser: this.delegationChooser('user', q, userGraph.userList(),
                                          carry),
      // What `permissionsSection()` and `delegationPolicySection()` draw.
      permissionsView: {
        register: permissions.register, listState: listState,
        allApplications: applications.list().map(function (row) {
          return { identifier: row.identifier, name: row.name || '' };
        })
      },
      exchangePolicyView: {
        register: exchangePolicy.register,
        pairs: { shown: exchangePolicy.pairs.shown,
                 paging: this.pagingJson(exchangePolicy.pairs.paging) },
        intermediaries: {
          shown: exchangePolicy.intermediaries.shown,
          paging: this.pagingJson(exchangePolicy.intermediaries.paging) },
        people: { shown: exchangePolicy.people.shown,
                  paging: this.pagingJson(exchangePolicy.people.paging) }
      }
    });
    model.facts = this.delegationFacts({ acts: model.acts,
                                         chains: model.chainPage.shown });
    log.debug("Leaving AdminViews.delegationPageModel().");
    return model;
  }

  // Moved here from the console (#446), as `delegationMapKey()` was.
  // THE KEY, drawn by the same render() the picture is, so that a legend cannot
  // come to describe a diagram this service no longer draws. Every swatch is a
  // one-node, one-edge graph put through the real code path — which is the
  // delegation page's rule and is worth the few extra bytes: a legend
  // hand-drawn out of the same colour constants would still go stale the day a
  // shape changed.
  /**
   * Draws the federation picture's key, each swatch rendered by the same
   * code as the picture so the legend cannot drift from it.
   *
   * @returns the key's boxes and lines tables as HTML
   */
  federationMapKey() {
    const { log, federationDiagram } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.federationMapKey().");
    const shapes = [
      { kind: 'sts', label: 'This service',
        realm: 'default', realmName: 'this realm',
        what: 'The trust realm you are looking at. Every line on the picture ' +
              'starts or ends here, because every relationship is between ' +
              'this realm and somebody else.' },
      { kind: 'application', label: 'an application',
        what: 'An application registered HERE whose people are authenticated ' +
              'somewhere else. What points it at a partner is ' +
              '<code>appFederationRelationship</code> on its entry under ' +
              '<code>ou=applications</code>.' },
      { kind: 'partner-sp', label: 'a partner',
        what: 'A FOREIGN SERVICE PROVIDER. It asks this service to ' +
              'authenticate somebody. Dashed, because it is not this service ' +
              'and nothing here can see inside it.' },
      { kind: 'partner-idp', label: 'a partner',
        what: 'A FOREIGN IDENTITY PROVIDER. It authenticates the person and ' +
              'this service consumes what it issues. Dashed for the same ' +
              'reason — and a hexagon rather than a rectangle because it is ' +
              'an identity service, which is what this service is too.' }
    ];
    const shapeRows = shapes.map(function (one) {
      const drawn = federationDiagram.render(
        { nodes: [Object.assign({ id: 'k', relationships: [] }, one)],
          edges: [] },
        { links: false, id: 'key-' + one.kind, label: one.label });
      return '<tr><td>' + drawn.svg + '</td><td>' + one.what + '</td></tr>';
    }).join('');

    // THE LINES, AND THE FOUR STATES ARE THE LIST PAGE'S FOUR. Each is drawn by
    // handing render() a relationship in that state, so the colour in the key
    // is the colour edgeLook() will actually choose rather than a second
    // opinion about it.
    const states = [
      { what: '<strong>Ready</strong> — enabled and fully configured. It ' +
              'will work.',
        row: { id: 'ready', protocolLabel: 'SAML 2.0', enabled: true,
               ready: true,
               usable: true, missing: [], applicationCount: 0,
               authentications: 0,
               users: 0, releases: [], lastError: '', mechanismLabel: '' } },
      { what: '<strong>Disabled</strong> — which is how every relationship ' +
              'starts. This is the ordinary state of something somebody has ' +
              'not finished setting up, not a fault.',
        row: { id: 'disabled', protocolLabel: 'SAML 2.0', enabled: false,
               ready: true,
               usable: false, missing: [], applicationCount: 0, authentications:
                                                                  0,
               users: 0, releases: [], lastError: '', mechanismLabel: '' } },
      { what: '<strong>Enabled and NOT configured</strong> — the loud one, ' +
              'and it earns being the only red on this page: it will REFUSE ' +
              'at the moment somebody tries to use it, and it looks finished ' +
              'from every angle except this one.',
        row: { id: 'half', protocolLabel: 'SAML 2.0', enabled: true,
               ready: false,
               usable: false, missing: ['fedSigningCertificate'],
               applicationCount: 0, authentications: 0, users: 0, releases: [],
               lastError: '', mechanismLabel: '' } },
      { what: '<strong>A broker that cannot broker</strong> — the ' +
              'relationship is fine and the relationship it authenticates ' +
              'THROUGH is not, so the person meets the sign-in screen ' +
              'instead of the partner. That screen checks no password, which ' +
              'is why this is worth a colour of its own: it is the only ' +
              'failure here that produces a working sign-in.',
        row: { id: 'broker', protocolLabel: 'OpenID Connect', enabled: true,
               ready: true, usable: true, missing: [], applicationCount: 0,
               authentications: 0, users: 0, releases: [], lastError: '',
               mechanismLabel: 'Another federation relationship',
               brokersTo: 'somewhere', brokerUsable: false,
               brokerProblem: 'it is disabled' } }
    ];
    const stateRows = states.map(function (one, i) {
      const drawn = federationDiagram.render({
        nodes: [{ id: 'a', kind: 'application', label: 'from',
                  relationships: [] },
                { id: 'b', kind: 'sts', label: 'to', realm: '',
                  realmName: '' }],
        edges: [{ id: 'e', from: 'a', to: 'b',
                  relation: one.row.brokersTo ? 'asks' : 'signs-in',
                  relationship: one.row.id, row: one.row, use: null }]
      }, { links: false, id: 'key-state-' + i, label: 'a line' });
      // Only the line is wanted, not the two boxes it needs in order to exist,
      // so the swatch is the label panel's own words. It is drawn rather than
      // written because these four colours are the whole content of the key.
      return '<tr><td><svg xmlns="http://www.w3.org/2000/svg" width="120" ' +
        'height="26" viewBox="0 0 120 26" role="img"><title>' +
        WebKit.esc(WebKit.plainTextOf(one.what)) + '</title>' +
        drawn.svg.replace(/^[\s\S]*?<defs>/, '<defs>')
                 .replace(/<rect[\s\S]*$/, '') +
        '</svg></td><td>' + one.what + '</td></tr>';
    }).join('');

    log.debug("Leaving AdminViews.federationMapKey().");
    return '<h3>The boxes</h3>' +
      '<table><tr><th>Drawn as</th><th>What it is</th></tr>' + shapeRows +
      '</table><h3>The ' +
      'lines</h3>' +
      WebKit.note('<strong>An arrow is a REQUEST and not an ' +
      'assertion</strong>, which is the one thing about this picture that ' +
      'looks backwards until it is said. Everything on the left arrives ' +
      'wanting somebody signed in; everything on the right is asked to do ' +
      'the signing in. So an identity-provider-side relationship — where ' +
      'this service ASSERTS to the partner — points INWARD, because what the ' +
      'partner did was ask. Drawn the other way an identity broker is two ' +
      'arrows leaving the same box with nothing joining them; drawn this way ' +
      'it is one straight line through the middle, which is what a bridge ' +
      'is.') +
      '<table><tr><th>Colour</th><th>What it means</th></tr>' + stateRows +
      '</table>';
  }
  // What every box is called, where it links, and nothing about its shape — the
  // shape is `federation_diagram.js`'s and is decided from the node's kind,
  // which is the one thing a caller must not be able to override. See lookOf()
  // there.
  /**
   * Decides where each box of the federation picture links: an application
   * to the applications register, a partner to its first relationship.
   *
   * @param graph - the federation graph
   * @returns `looks`, keyed by node id, and `resolve`, a node's look
   */
  federationMapLooks(graph) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.federationMapLooks().");
    const looks = {};
    graph.nodes.forEach(function (node) {
      if (node.kind === 'sts') {
        looks[node.id] = {};
        return;
      }
      if (node.kind === 'application') {
        // An application box goes to the APPLICATIONS registry and not to the
        // relationship, because the thing somebody clicks it to change is
        // `appFederationRelationship`, which lives on that entry. The
        // relationship is one click away on the line's own label.
        looks[node.id] = {
          href: '/admin/applications' +
                WebKit.queryWith({}, { application: node.label })
        };
        return;
      }
      // BOTH PARTNER SHAPES GO TO THE RELATIONSHIP, and where a partner has
      // more than one they go to the FIRST — which is a real limitation rather
      // than a choice, and it is the delegation picture's own: an SVG anchor
      // wraps one shape and can have one href. The table under the picture
      // lists every relationship a partner has, which is where a reader with
      // two goes.
      looks[node.id] = {
        href: '/admin/federation' +
              WebKit.queryWith({},
                { relationship: node.relationships[0] || '' })
      };
    });
    log.debug("Leaving AdminViews.federationMapLooks(). " +
              graph.nodes.length +
              " box(es).");
    return {
      looks: looks,
      resolve: function (node) {
        log.debug("Entering resolve().");
        log.debug("Leaving resolve().");
        return looks[node.id];
      }
    };
  }
  // ---------------------------------------------------------------------------
  // THE FEDERATION PICTURE, AS ONE ANSWER (#446).
  //
  // `/admin/federation/map`: one trust realm's federation relationships,
  // filtered by role, protocol and text (`federationGraph.graph()`), drawn
  // on the server. The page's own JSON, with the vocabulary its filter
  // offers, the drawing, its size, and the key — markup drawn by the
  // diagram's own renderer, as `delegationMapKey()` is.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/federation/map`'s answer.
   *
   * @param query - the page's query: `role`, `protocol`, `q`
   * @param options - `links` (true by default): false draws the document
   *   with no links in it, as `?format=svg` answers
   * @returns the realm's relationships, the graph and the drawing
   */
  federationMapModel(query, options?) {
    const { log, federation, federationGraph, federationDiagram } = this.deps;
    log.debug("Entering AdminViews.federationMapModel().");
    const q = query || {};
    const wanted = {
      role: String(q.role || '').trim(),
      protocol: String(q.protocol || '').trim(),
      q: String(q.q || '').trim()
    };
    const graph = federationGraph.graph(wanted);
    const look = this.federationMapLooks(graph);
    const label = 'Federation relationships in the trust realm "' +
      graph.realm.id + '", as a diagram';
    const drawn = federationDiagram.render(graph, {
      resolve: look.resolve, links: !(options && options.links === false),
      id: 'fedmap', label: label
    });
    const model: any = {
      realm: graph.realm, counts: graph.counts, filter: wanted,
      empty: graph.empty, filtered: graph.filtered,
      relationships: graph.relationships,
      nodes: graph.nodes.map(function (node) {
        return { id: node.id, kind: node.kind, label: node.label,
                 relationships: node.relationships || [] };
      }),
      edges: graph.edges.map(function (edge) {
        return { id: edge.id, from: edge.from, to: edge.to,
                 relation: edge.relation,
                 relationship: edge.relationship,
                 brokeredTo: edge.brokeredTo || '',
                 use: edge.use || null };
      }),
      drawing: { width: drawn.width, height: drawn.height,
                 failed: drawn.failed || null },
      label: label, svg: drawn.svg
    };
    if (!(options && options.links === false)) {
      model.roles = federation.ROLES;
      model.protocols = federation.PROTOCOLS;
      model.mapKey = this.federationMapKey();
    }
    log.debug("Leaving AdminViews.federationMapModel(). " +
              graph.relationships.length + " relationship(s).");
    return model;
  }

  // ---------------------------------------------------------------------------
  // A DELEGATION CHOOSER'S PANE, SEARCHED AND PAGED HERE (#446).
  //
  // The console drew both choosers from the whole catalogue — every
  // application an act named, every identity either register knows — and
  // `WebKit.chooserPane()` searched and paged it while it drew. An answer
  // carries the page of results instead (`chooserPane()`'s `slice`), because
  // the person catalogue is everybody this service has seen. The entries
  // are the console's, link and all; `carry` is the delegation table's
  // filter, kept in every result's link.
  // ---------------------------------------------------------------------------
  /**
   * Searches and pages one of the two delegation choosers.
   *
   * @param kind - `application` (searched by `appq`, paged by `appfrom`) or
   *   `user` (`userq`, `userfrom`)
   * @param query - the page's query
   * @param catalogue - the delegation register's applications, or
   *   `userGraph.userList()`
   * @param carry - the delegation table's filter
   * @returns `total`, the pane's `entries` and its `slice`
   */
  delegationChooser(kind, query, catalogue, carry) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.delegationChooser(). kind=" + kind);
    const isApplication = kind === 'application';
    const entries = (catalogue || []).map(function (entry) {
      if (isApplication) {
        const roles = [];
        if (entry.roles.intermediary) {
          roles.push(entry.roles.intermediary + ' as the intermediary');
        }
        if (entry.roles.target) {
          roles.push(entry.roles.target + ' as the target');
        }
        if (entry.roles.initial) {
          roles.push(entry.roles.initial + ' as the initial identity');
        }
        return {
          key: entry.key,
          names: [entry.identifier].concat(entry.spellings || []),
          label: entry.identifier,
          detail: entry.acts + ' act(s): ' + roles.join(', '),
          href: '/admin/delegation/application' +
                WebKit.queryWith(carry || {},
                                 { application: entry.identifier })
        };
      }
      const facts = [];
      if (entry.authentications) {
        facts.push(entry.authentications + ' sign-in(s)');
      }
      if (entry.tokens.issued) {
        facts.push(entry.tokens.issued + ' token(s)');
      }
      if (entry.artifacts) {
        facts.push(entry.artifacts + ' artifact(s)');
      }
      if (entry.acts) {
        facts.push(entry.acts + ' delegation act(s)');
      }
      return {
        key: entry.key,
        names: [entry.key, entry.presented].concat(entry.forms || []),
        label: entry.key + (entry.isClient ? ' (a client)' : ''),
        detail: facts.length ? facts.join(', ') : 'nothing yet',
        href: '/admin/delegation/user' +
              WebKit.queryWith(carry || {}, { user: entry.key })
      };
    });
    const param = isApplication ? 'appq' : 'userq';
    const fromParam = isApplication ? 'appfrom' : 'userfrom';
    const wanted = WebKit.queryOne(query || {}, param).trim();
    const matched = entries.filter(function (entry) {
      return WebKit.chooserMatches(entry.names, wanted);
    });
    // The clamp `chooserPane()` applies, applied where the slice is cut.
    let from = parseInt(WebKit.queryOne(query || {}, fromParam), 10);
    if (!isFinite(from) || from < 0 || from >= matched.length) {
      from = 0;
    }
    log.debug("Leaving AdminViews.delegationChooser(). " + matched.length +
              " of " + entries.length + " matched.");
    return {
      total: entries.length,
      entries: matched.slice(from, from + WebKit.CHOOSER_HITS),
      slice: { matched: matched.length, from: from }
    };
  }

  // ---------------------------------------------------------------------------
  // WHAT A DELEGATION PAGE'S CELLS ASK ABOUT ITS NAMES (#446).
  //
  // A party is drawn linked to the users page when this console has seen
  // the person, and to the application page when the registry holds the
  // application. The console asked `knownUserKeys()` and
  // `applications.get()` while it drew; an answer carries the answers, for
  // the names in it only — every string in the answer that is a known user
  // key goes into `users`, every one the registry holds into `apps` with
  // its name. Read off the answer itself, so nothing the page draws is
  // missing and nothing it does not draw is sent.
  // ---------------------------------------------------------------------------
  /**
   * Works out which names in a delegation page's answer are known people
   * and registered applications.
   *
   * @param answer - the page's answer, before `facts` is added
   * @returns `users` (key → true) and `apps` (identifier → `name`,
   *   `dnLabel`)
   */
  delegationFacts(answer) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.delegationFacts().");
    const known = this.knownUserKeys();
    const users = {};
    const apps = {};
    const seen = {};
    const visit = function (value) {
      if (typeof value === 'string') {
        if (seen[value] || value.length > 512) {
          return;
        }
        seen[value] = true;
        if (known[value]) {
          users[value] = true;
        }
        const entry = applications.get(value);
        if (entry) {
          apps[value] = { name: entry.name || '',
                          dnLabel: entry.dnLabel || '' };
        }
      } else if (Array.isArray(value)) {
        value.forEach(visit);
      } else if (value && typeof value === 'object') {
        Object.keys(value).forEach(function (key) {
          visit(value[key]);
        });
      }
    };
    visit(answer);
    log.debug("Leaving AdminViews.delegationFacts(). " +
              Object.keys(users).length + " person(s), " +
              Object.keys(apps).length + " application(s).");
    return { users: users, apps: apps };
  }

  // The whole view, filtered and paged, for the page AND for
  // GET /admin-api/delegation. One function for the reason the block above
  // consoleJson() (admin-ui/admin.ts) gives: the filtering and the paging are
  // work both need, and two copies of it would be two answers that each looked
  // right alone.
  /**
   * Builds `/admin/delegation`: the delegation acts, filtered and paged.
   *
   * @param query - the request's query
   * @returns the view
   */
  delegationView(query) {
    const { log, delegation, krb5Principals, delegationPolicy } = this.deps;
    log.debug("Entering AdminViews.delegationView().");
    const wantedType = String(query.type || '');
    const wantedMode = String(query.mode || '');
    const wantedOutcome = String(query.outcome || '');
    const wantedProtocol = String(query.protocol || '');
    const wantedText = String(query.q || '');
    const all = delegation.list();
    const needle = wantedText.toLowerCase();
    const filtered = all.filter(function (row) {
      if (wantedType && row.type !== wantedType) return false;
      if (wantedMode && row.mode !== wantedMode) return false;
      if (wantedOutcome && row.outcome !== wantedOutcome) return false;
      if (wantedProtocol && row.protocol !== wantedProtocol) return false;
      // One free-text box over every party of the chain and both explanations,
      // because the question a reader arrives with names ONE of them — a
      // person, an SPN, an attribute — and does not know which column it will
      // be in. A box that silently searched one column while the reader assumed
      // six is worse than no box.
      if (needle) {
        const hay = [row.initial.key, row.initial.presented,
                     row.initial.application,
                     row.intermediary.key, row.intermediary.presented,
                     row.intermediary.application,
                     row.target.key, row.target.presented,
                     row.target.application,
                     row.authorizedBy, row.reason, row.note]
                      .join(' ').toLowerCase();
        if (hay.indexOf(needle) < 0) return false;
      }
      return true;
    });
    // Filter first, then page — the same order the tokens and audit pages use
    // and for the same reason: paging a list and then filtering it gives a page
    // 2 whose length depends on what page 1 happened to hold.
    // DELEGATION_PER_PAGE rather than the console-wide fifty, and it is passed
    // HERE rather than at the page, so that `GET /admin-api/delegation` and the
    // page it mirrors agree about what one page of acts is. A caller walking
    // the API with `?page=` and a reader clicking `next ›` must not be reading
    // two different pagings of one list.
    const paging = this.pagingOf(query, filtered.length,
                            { noun: 'acts', defaultPer: DELEGATION_PER_PAGE });
    const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
    const summary = delegation.summary();
    // The chains of what MATCHED rather than of everything held: a reader who
    // has filtered to one person wants that person's chains, and a count that
    // ignored the filter would disagree with the table under it.
    const chains = delegation.chainList(filtered);
    // THE PICTURE'S MODEL, BUILT HERE AND NOT IN THE ROUTE THAT DRAWS IT, for
    // the reason the whole of this function exists: /admin/delegation/map, this
    // page's ?format=json and GET /admin-api/delegation must all be describing
    // the same graph, and three calls to delegation.graph() with three ideas
    // about which acts to pass it would be three answers that each looked right
    // alone. Of the matched acts rather than the paged ones — a diagram of one
    // page of a list is a diagram of the pagination.
    // AND THE CONFIGURED RELATIONSHIPS (#186, rcbj's decision): every pair
    // an entry allows, drawn DASHED until an act has used it — for all three
    // protocols, whose controls are one set. Left out while the reader has
    // narrowed the acts by outcome, type or text, which say nothing about a
    // pair nobody has used; kept under a protocol filter, which they do not
    // contradict.
    let configured = [];
    if (!wantedOutcome && !wantedType && !wantedText) {
      try {
        configured = (delegationPolicy.list().pairs || [])
          .map(function (pair) {
            return { from: pair.intermediary,
                     to: pair.targetApplication || pair.target,
                     attribute: pair.attribute, mechanism: pair.mechanism,
                     setOn: pair.setOn };
          });
      } catch (e) {
        log.debug("Caught in AdminViews.delegationView(): " +
                  ((e && e.message) || e));
        // The picture of the acts stands without them.
        configured = [];
      }
    }
    const graph = delegation.graph(filtered, { configured: configured });
    // EVERY APPLICATION AMONG THE MATCHED ACTS, in whatever role it played. It
    // follows the filter for the same reason `chains` does — a reader who has
    // narrowed to one person wants that person's applications — and there is
    // one consequence worth stating rather than leaving to be met: the PAGE
    // this chooser opens is not filtered. `/admin/delegation/application` shows
    // everything that application has ever been part of, because "what exists
    // because of this thing" is not a question a half-answer is useful for. The
    // chooser says so.
    const applicationsInvolved = delegation.applicationList(filtered);
    const policy = krb5Principals.delegationPolicy();
    log.debug("Leaving AdminViews.delegationView(). " + shown.length +
              " act(s) of " +
              filtered.length + ", " + chains.length + " chain(s).");
    return {
      wantedType: wantedType, wantedMode: wantedMode,
      wantedOutcome: wantedOutcome,
      wantedProtocol: wantedProtocol, wantedText: wantedText,
      all: all, filtered: filtered, paging: paging, shown: shown,
      summary: summary, chains: chains, graph: graph, policy: policy,
      applications: applicationsInvolved,
      json: {
        held: summary.held,
        // AND HOW MANY PROCESSES THAT IS, beside how many of them are this
        // one's. `held` is a fan-in across every request worker since
        // 2026-09-11; a client that compared it with `recorded` below without
        // these two would have no way to see why the second is smaller.
        heldHere: summary.heldHere, processes: summary.processes,
        // Everything ever recorded and everything dropped, both, because `held`
        // alone reads as "this is all there was" the moment the cap has bitten.
        // BY THIS PROCESS — see the store's own comment: there is no counter
        // store to fan in and inventing one to make the numbers match would be
        // a store nothing else reads.
        recorded: summary.recorded, dropped: summary.dropped,
        maxRecords: summary.maxRecords,
        matched: filtered.length, shown: shown.length,
        // The lowest and highest sequence numbers still held. A caller polling
        // this endpoint uses them rather than a timestamp, for the reason
        // /admin-api/audit gives: `seq` is monotonic and never reused, so
        // "everything after 41" is exact.
        oldestSeq: summary.oldestSeq, newestSeq: summary.newestSeq,
        byType: summary.byType, byMode: summary.byMode,
        byOutcome: summary.byOutcome, byProtocol: summary.byProtocol,
        filter: { type: wantedType || null, mode: wantedMode || null,
                  outcome: wantedOutcome || null,
                  protocol: wantedProtocol || null,
                  q: wantedText || null },
        // The clamped values, not what was asked for: `?page=999` on a two-page
        // list reports page 2, which is the page whose rows are in the reply.
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        // The vocabulary, off the store rather than out of a list here: what
        // the `type`, `mode` and `outcome` filters take, and what each of them
        // means. A mechanism cannot be recordable and unfilterable, nor offered
        // and never occur.
        types: delegation.TYPES, modes: delegation.MODES,
        outcomes: delegation.OUTCOMES, roles: delegation.ROLES,
        acts: shown,
        // The DISTINCT chains among what matched — one entry per (type,
        // initial, intermediary, target) — which is what the visualisation will
        // be drawn from and is already the more useful answer for a caller
        // asking "what talks to what".
        chains: chains,
        // THE APPLICATIONS among what matched, in whatever role each played,
        // with the counts the chooser on the page is built from. It is a
        // strictly different question from `chains` and cannot be derived from
        // one: an application is keyed on its IDENTIFIER — see
        // applicationList() in delegation.js — and a chain names three parties,
        // one of which routinely carries an application identifier that is not
        // its identity.
        applications: applicationsInvolved,
        // THE PICTURE, as a graph. The nodes and edges /admin/delegation/map
        // draws, with the credentials folded onto each edge and the list of
        // what was issued — so a test can assert what that page shows without
        // parsing an SVG, which is the only way a drawing can be kept honest
        // from outside. It is a strictly different shape from `chains` and not
        // a second copy of it: a chain has three parties and therefore up to
        // TWO edges, and the boxes are SHARED between chains, which is the
        // whole reason to draw one.
        graph: graph,
        // The configured policy: who MAY delegate to whom, and the account
        // flags that decide what delegation can do to somebody. Kerberos only,
        // because it is the only family here that polices this at all.
        policy: policy
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE WS-TRUST AND TOKEN-EXCHANGE DELEGATION POLICY (#108, 2026-09-23), for
  // the section on /admin/delegation and GET /admin-api/delegation/policy —
  // one function for both doors, `delegationView()`'s reason. Three lists,
  // each PAGED on a parameter of its own at the page's ten rows
  // (`policyPairsPage`, `intermediariesPage`, `peoplePage`; `per` for all
  // three), because the people list is a walk of the directory and has no
  // natural bound. `common/delegation_policy.ts` builds the register; the
  // attributes are EDITED where every application attribute is — the
  // application's own page and POST /admin-api/applications/update — and
  // the two person flags on the person's page and POST
  // /admin-api/users/set-not-delegated and /set-may-act.
  // ---------------------------------------------------------------------------
  /**
   * Builds the delegation policy: who may act for whom.
   *
   * @param query - the request's query
   * @returns the view
   */
  delegationPolicyView(query) {
    const { log, delegationPolicy } = this.deps;
    log.debug("Entering AdminViews.delegationPolicyView().");
    const q = query || {};
    const register = delegationPolicy.list();
    const pairs = this.pagedRows(q, register.pairs,
      { name: 'policyPairs', noun: 'pairs', defaultPer: DELEGATION_PER_PAGE });
    const intermediaries = this.pagedRows(q, register.intermediaries,
      { name: 'intermediaries', noun: 'intermediaries',
        defaultPer: DELEGATION_PER_PAGE });
    const people = this.pagedRows(q, register.people,
      { name: 'people', noun: 'people', defaultPer: DELEGATION_PER_PAGE });
    log.debug("Leaving AdminViews.delegationPolicyView().");
    return {
      register: register, pairs: pairs, intermediaries: intermediaries,
      people: people,
      json: {
        enforced: register.enforced,
        attributes: register.attributes,
        protectedGroups: register.protectedGroups,
        pairs: pairs.shown,
        pairsPaging: this.pagingJson(pairs.paging),
        intermediaries: intermediaries.shown,
        intermediariesPaging: this.pagingJson(intermediaries.paging),
        people: people.shown,
        peoplePaging: this.pagingJson(people.paging)
      }
    };
  }

  // One group as a REPLY carries: what it is and how big, and not the rows.
  //
  // The rows are on the group's own page and in its own `?format=json`. A list
  // of groups that carried every grant would repeat the whole register once per
  // group in the worst case — a caller asking *what is joined to what* would be
  // handed the answer to a question they did not ask, and the reply would grow
  // with the square of the register on exactly the service where that matters.
  /**
   * Summarises one cluster of the permission picture: its key, members and
   * counts.
   *
   * @param group - the cluster
   * @returns the summary
   */
  clusterSummary(group) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.clusterSummary().");
    log.debug("Leaving AdminViews.clusterSummary().");
    return { key: group.key, members: group.members, counts: group.counts };
  }

  // THE GROUPINGS AS A REPLY, AND THE ONE FUNCTION BOTH DOORS ONTO THEM GO
  // THROUGH.
  //
  // `GET /admin-api/permissions/groups` calls it and so does
  // /admin/delegation/cluster's own `?format=json`, for the reason
  // `delegationView()` and `permissionsView()` both give: two hand-built copies
  // of one object is precisely the drift this console's own text keeps warning
  // about, and it is invisible — each looks right alone and neither ever sees
  // the other.
  //
  // `view` is an optional `permissionsView()` already in hand. The route has
  // one because it is drawing the page from it; the management API has not and
  // this function makes its own. Passing it is what keeps a page's markup and
  // its JSON describing ONE read of `ou=applications` rather than two taken a
  // few milliseconds apart — which on a register somebody is editing is the
  // difference between a table and a picture that agree and two that nearly do.
  //
  // **`application` DECIDES THE SHAPE and there is only one operation**,
  // because the two are the same question at two scales: without it, every
  // group with its counts and none of its rows; with it, the ONE group that
  // application is in, with its grants, its permissions and the graph the
  // picture is drawn from. An application this register has never heard of is
  // `group: null` and a 200 — having no permissions configured is the ordinary
  // state of most entries in the registry, and it is a fact rather than an
  // error.
  /**
   * Builds the permission register's clusters, or one application's cluster.
   *
   * @param query - the query
   * @param view - the register, when already built
   * @returns the clusters, or the one asked for
   */
  permissionGroupsView(query, view?) {
    const { log, appPermissions } = this.deps;
    log.debug("Entering AdminViews.permissionGroupsView().");
    const permissions = view || this.permissionsView();
    const groups = permissions.clusters;
    const asked = this.queryOne(query, 'application').trim();

    if (asked) {
      const group = appPermissions.clusterFor(asked, groups);
      // The SAME paging the page's own grants table uses, by the same name, so
      // that a caller reading `?format=json` off a page they are looking at
      // gets the rows they can see. `graph()` of an absent group is an empty
      // graph rather than a null, because every caller of this member hands it
      // to a renderer and a renderer takes a graph.
      const grantPage = this.pagedRows(query, group ? group.grants : [],
                                       { name: 'groupGrants', noun: 'grants' });
      const permissionPage = this.pagedRows(query, group ? group.permissions :
                                                   [],
                                            { name: 'groupPermissions',
                                              noun: 'permissions' });
      const answer = {
        application: asked,
        group: group ? this.clusterSummary(group) : null,
        grants: grantPage.shown,
        grantsPaging: this.pagingJson(grantPage.paging),
        permissions: permissionPage.shown,
        permissionsPaging: this.pagingJson(permissionPage.paging),
        graph: appPermissions.graph(group ? group.grants : []),
        counts: groups.counts
      };
      log.debug("Leaving AdminViews.permissionGroupsView(). " +
                (group ? group.counts.applications + " application(s) in the " +
                                                     "group."
                       : "Nothing configured names that."));
      return answer;
    }

    const groupPage = this.pagedRows(query, groups.clusters,
                                     { name: 'groups', noun: 'groups' });
    const answer = {
      application: null,
      groups: groupPage.shown.map(this.clusterSummary.bind(this)),
      counts: groups.counts,
      paging: this.pagingJson(groupPage.paging)
    };
    log.debug("Leaving AdminViews.permissionGroupsView(). " +
              groups.counts.clusters +
              " group(s), " + groupPage.shown.length + " on this page.");
    return answer;
  }

  // One query parameter, first-wins. Express hands back an array when a
  // parameter is repeated, and String() on one is "a,b" — a search nothing
  // matches, reached by a link somebody clicked twice. The same rule
  // pageParamsOf() applies.
  /**
   * Reads one query parameter, the first when it is repeated.
   *
   * @param query - the query
   * @param key - the parameter
   * @returns its value, or ''
   */
  queryOne(query, key) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.queryOne().");
    log.debug("Leaving AdminViews.queryOne().");
    return WebKit.queryOne(query, key);
  }


  // Does one catalogue entry match what was typed? Case-insensitive, and over
  // EVERY spelling the catalogue holds rather than the one it shows: an
  // application arrives as `HTTP/backend@EXAMPLE.COM` and as `HTTP/backend`, a
  // person as `alice`, as `alice@STS.MOCK` and as `urn:uuid:<entryUUID>`, and
  // each chooser draws one of them. A reader searching for a name they pasted
  // out of the acts table four inches up the page is pasting the OTHER one
  // about half the time, and a search that answers "nothing matches" to a
  // string printed on the same page is worse than no search at all.
  /**
   * Asks whether any of an identity's names contains a search, ignoring case.
   *
   * @param names - the names
   * @param wanted - the search
   * @returns whether one matches
   */
  chooserMatches(names, wanted) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.chooserMatches().");
    log.debug("Leaving AdminViews.chooserMatches().");
    // The kit's since #446: a chooser drawn in a browser matches the same way.
    return WebKit.chooserMatches(names, wanted);
  }


  // ---------------------------------------------------------------------------
  // WHAT A CLAIMS REQUEST WOULD RETURN, for the person being previewed.
  //
  // Built by oauth2.js's parseClaimsRequest() and requestedClaimsOf() — the two
  // functions the UserInfo endpoint itself calls — rather than by a second
  // reader of section 5.5 written for this page. The rule is
  // claim_attributes.js's and is not new here: a preview that agreed with the
  // page and disagreed with the endpoint would be worse than no preview at all,
  // and section 5.5 is exactly the kind of thing two implementations would come
  // to disagree about (is `{}` the same as `null`? does an unknown top-level
  // member refuse?).
  //
  // A MALFORMED REQUEST IS SHOWN AS AN ERROR AND IS NOT AN ERROR ON THE PAGE.
  // The endpoint answers `invalid_request` for the same string, so what this
  // shows is the refusal a client would get — which is the thing somebody is
  // here to see.
  // ---------------------------------------------------------------------------
  /**
   * Previews a `claims` request parameter for a person, or the refusal the
   * endpoint would give it.
   *
   * @param previewUser - the person to preview
   * @param raw - the parameter's JSON text
   * @returns the preview
   */
  claimsRequestPreview(previewUser, raw) {
    const { log, userFor, oauth2 } = this.deps;
    log.debug("Entering AdminViews.claimsRequestPreview(). user=" +
              previewUser);
    if (!raw) {
      log.debug("Leaving AdminViews.claimsRequestPreview(). Nothing was " +
                "asked for.");
      return { asked: false };
    }
    const parsed = oauth2.parseClaimsRequest(raw);
    if (parsed.error) {
      log.debug("Leaving AdminViews.claimsRequestPreview(). " + parsed.error);
      return { asked: true, ok: false, error: parsed.error, request: raw };
    }
    const answer = oauth2.requestedClaimsOf(parsed.claims, 'userinfo',
                                            previewUser,
                                            userFor(previewUser));
    log.debug("Leaving AdminViews.claimsRequestPreview(). " +
              answer.report.length + " " +
        "claim(s) resolved.");
    return { asked: true, ok: true, request: raw, parsed: parsed.claims,
             ignoredMembers: parsed.ignored || [],
             idTokenNames: oauth2.requestedClaimNames(parsed.claims,
                                                      'id_token'),
             claims: answer.claims, report: answer.report,
             unresolvable: answer.unknown,
             essentialAndAbsent: answer.missingEssential,
             valueMismatches: answer.mismatched,
             entryFound: answer.entryFound };
  }

  // The section 5.5 half of the page, and of the API's reply. It is one builder
  // for both, for the reason claimSetsJson() is: the vocabulary a client may
  // ask for is the thing a caller with no browser most needs, and a list
  // published by the page that the API answered differently would be two
  // answers to one question.
  /**
   * Builds the claims request half of the UserInfo page's JSON.
   *
   * @param previewUser - the person to preview
   * @param raw - the parameter's JSON text
   * @returns the JSON
   */
  claimsRequestJson(previewUser, raw) {
    const { log, claimAttributes, oauth2 } = this.deps;
    log.debug("Entering AdminViews.claimsRequestJson().");
    const json = {
      supported: true,
      members: oauth2.CLAIMS_REQUEST_MEMBERS.slice(0),
      maxClaims: oauth2.MAX_REQUESTED_CLAIMS,
      // Every name a request may use, in the two spellings the resolver
      // indexes: the flat claim name of each catalogue row, and the top-level
      // name of a nested one (`address`), which is the spelling section 5.5.1's
      // own example uses and which returns the whole Address Claim of OIDC Core
      // 5.1.1.
      requestable: claimAttributes.requestableClaims(),
      // The six this service invents from the username rather than reading off
      // an entry. They are answerable too, and they are listed separately
      // because the DIFFERENCE is the interesting part: an `ldapmodify` moves
      // everything in `requestable` and moves none of these.
      fromTheSignIn: oauth2.PERSONA_CLAIMS.slice(0),
      precedence: [
        'the configured UserInfo set on this page (typed claims, ticked ' +
          'directory attributes, the groups claim)',
        'OIDC Core 5.4\'s scope-driven claims (profile, email)',
        'OIDC Core 5.5\'s individually requested claims, read off ou=users',
        'sub, which no layer may displace (OIDC Core 5.3.2)'
      ],
      notEnforced: [
        '`essential` is carried and is a hint: section 5.5.1 says a server ' +
          'MUST NOT error because a requested claim is unavailable, so an ' +
          'essential claim this service cannot produce is simply absent and ' +
          'is logged.',
        '`value` and `values` are CHECKED and not honoured. This service ' +
          'could echo back whatever a client asked it to assert and ' +
          'deliberately does not — everything it says about a person comes ' +
          'from the directory or from the invented persona, and a mock that ' +
          'agreed with the request could not be used to test anything. A ' +
          'mismatch is reported in the log and in the response\'s artifact.',
        'A claims request IS filtered by the federation release policy, ' +
          'exactly as a custom claim set is. The list is about what an ' +
          'audience may see rather than about which mechanism produced the ' +
          'value, so a partner released `email` alone cannot ASK for ' +
          '`birthdate` and be given it — which is precisely the hole a ' +
          'release list exists to close.'
      ],
      // NON-SPEC, and labelled in the reply rather than only on the page: a
      // caller reading this document is exactly the caller who would otherwise
      // have to run a browser flow per variation.
      directParameter: {
        note: 'NON-SPEC. The UserInfo endpoint also accepts a claims request ' +
              'on the request itself, which section 5.3.1 does not define — ' +
              'it takes an access token and nothing else. It exists because ' +
              'exercising section 5.5 through the specified route means a ' +
              'whole authorization flow per variation. It is a UNION with ' +
              'what ' +
              'the access token carries and can never take a claim away from ' +
              'it.',
        spellings: ['GET ' +
                    '/oauth2/userinfo?claims={"userinfo":{"birthdate":null}}',
                    'GET /oauth2/userinfo?claim=birthdate&claim=address',
                    'POST /oauth2/userinfo with the same two, form-encoded'],
        malformedIsRefused: 'invalid_request, with the reason. Ignoring a ' +
                            'debugging parameter that was typed wrong would ' +
                            'produce the same response as one never sent.'
      },
      preview: this.claimsRequestPreview(previewUser, raw)
    };
    log.debug("Leaving AdminViews.claimsRequestJson().");
    return json;
  }

  // The one UserInfo set, the rules that are its own, and the section 5.5 half.
  // `reservedJwtClaims` IS here, unlike the SAML page's reply, and the reason
  // is in the page header: every name on that list is load-bearing in at least
  // one of this response's two shapes.
  /**
   * Builds `/admin/userinfo-claims`'s JSON.
   *
   * @param previewUser - the person to preview
   * @param raw - the `claims` parameter to preview
   * @returns the JSON
   */
  userinfoClaimsJson(previewUser, raw) {
    const { log, stats, userFor } = this.deps;
    log.debug("Entering AdminViews.userinfoClaimsJson(). previewUser=" +
              previewUser);
    const json = Object.assign(
      { reservedJwtClaims: stats.RESERVED_JWT_CLAIMS,
        claimsRequest: this.claimsRequestJson(previewUser, raw),
        // The request as it was typed, which the preview form echoes, and
        // the address the sign-in invents for this person, which a note
        // contrasts with the directory's (#446).
        request: raw || '',
        inventedEmail: userFor(previewUser || 'alice').email },
      this.claimSetsJson(stats.USERINFO_CLAIM_SET_IDS, previewUser));
    log.debug("Leaving AdminViews.userinfoClaimsJson(). " + json.sets.length +
              " set(s).");
    return json;
  }

  // ---------------------------------------------------------------------------
  // THE THIRD BATCH (2026-09-12): the Shared Signals reports, found last
  // because the console EXPORTS them under different names than it defines them
  // by.
  //
  // `/admin-api` calls `admin.ssfView()`, `admin.caepView()` and four more; the
  // functions behind those exports are `ssfJson()`, `caepJson()` and so on, and
  // an analysis keyed on the name the API says was looking at a function that
  // does not exist. Six pure reports sat behind that indirection for two
  // passes.
  // ---------------------------------------------------------------------------
  // The reply BOTH doors answer with — `/admin/signals?format=json` and
  // GET /admin-api/signals are the same document, rule 7 — built by the
  // receiver module so that the console, the management API and the portal
  // cannot come to three different opinions about what a delivered event is.
  /**
   * Builds `/admin/signals`'s JSON, through the receiver module.
   *
   * @param req - the request
   * @returns the JSON
   */
  signalsJson(req) {
    const { log, signals } = this.deps;
    log.debug("Entering AdminViews.signalsJson().");
    // THE CONSOLE SEES EVERYTHING IN THE REALM IT IS READING, which is the
    // `sees: 'all'` on its row over there. It is an administrative surface: the
    // question it answers is "what has this service been telling its
    // receivers", and a per-person filter here would be the portal's page drawn
    // in the wrong application.
    const view = signals.view(signals.ADMIN, {});
    const state = this.signalsState(req, view);
    log.debug("Leaving AdminViews.signalsJson(). " + view.received.length +
              " row(s).");
    return Object.assign({}, view, {
      filter: { received: state.wanted || null },
      received: state.page.shown,
      total: view.received.length,
      paging: { received: this.pagingJson(state.page.paging) }
    });
  }

  // Filter first, then page — `pagingOf()`'s rule, for its reason: paging a
  // list and then filtering it gives a page 2 whose length depends on what page
  // 1 happened to hold.
  //
  // THE SEARCH IS OVER WHAT A READER ARRIVES HOLDING: a username or an address
  // out of a complaint, an event name, a `jti` out of a transmitter's log, or a
  // stream id. They do not know which column it will be in, so it is one box
  // over all of them rather than four.
  /**
   * Filters and pages the delivered events for `/admin/signals`.
   *
   * @param req - the request
   * @param view - the receiver's report
   * @returns the rows shown and their paging
   */
  signalsState(req, view) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.signalsState().");
    const wanted = this.queryOne(req.query, 'sigq').trim().toLowerCase();
    const rows = wanted
      ? view.received.filter(function (row) {
          return [row.name, row.subject, row.jti, row.stream, row.vocabulary,
                  row.issuer, row.audience].concat(row.types)
            .some(function (value) {
              return String(value || '').toLowerCase().indexOf(wanted) >= 0;
            });
        })
      : view.received;
    const page = this.pagedRows(req.query, rows,
      { name: 'received', noun: 'events' });
    log.debug("Leaving AdminViews.signalsState(). " + rows.length +
              " match(es).");
    return { wanted: wanted, page: page };
  }

  // ---------------------------------------------------------------------------
  // THE CLIENT-CERTIFICATE TRUSTSTORE, AS `/admin/tls/trust` AND
  // `GET /admin-api/tls/trust` BOTH ANSWER IT (2026-09-12).
  //
  // One function for both, rule 7. It reads `req.query` for the paging and
  // nothing else off the request. The rows are `tls/tls_server.js`'s own
  // description of each anchor — this computes nothing about a certificate —
  // and they are the same in every realm, because the array is the PROCESS's:
  // the listeners are shared by every realm, so a realm-scoped view of them
  // would be a filter over something that has no realm in it.
  //
  // **NO PRIVATE KEY IS IN THIS REPLY, AND NOT BECAUSE ONE IS REMOVED**: the
  // truststore holds certificates and nothing else. Each row carries its PEM,
  // which is the half of a key pair meant to be handed around.
  // ---------------------------------------------------------------------------
  /**
   * Builds the client-certificate truststore's JSON; certificates only.
   *
   * @param req - the request
   * @returns the JSON
   */
  truststoreJson(req) {
    const { log, mode, realms, adminActions } = this.deps;
    log.debug("Entering AdminViews.truststoreJson().");
    const openToAnybody = realms.run(realms.get(realms.DEFAULT_ID),
                                     function () {
      return mode.opensTestControls();
    });
    const doors = {
      console: '/admin/tls/trust',
      api: '/admin-api/tls/trust',
      testControls: { add: '/tls/trust', clear: '/tls/trust/clear',
                      open: openToAnybody }
    };
    const notes = {
      persisted: 'A RUNTIME ANCHOR IS WRITTEN TO ou=trustAnchors in the ' +
        'directory as it is added, so it survives a restart wherever the ' +
        'directory is persisted (persistence.mode ldif or postgres) and ' +
        'reaches every other process against the same store; each row says ' +
        'whether it was. An anchor from tls.trustAnchorsFile is not stored ' +
        'there and comes back at the next start however it was removed.',
      scope: 'ONE TRUSTSTORE FOR THE PROCESS, not one per trust realm: the ' +
        'main port and LDAPS 636 are shared by every realm, so this ' +
        'answer is the same under every realm prefix.',
      effect: 'A change applies to the NEXT handshake. Connections already ' +
        'open keep the truststore they were made under.',
      revocation: 'Nothing checks revocation against these anchors — a ' +
        'certificate revoked by its issuer still verifies here.'
    };
    if (!truststore) {
      log.debug("Leaving AdminViews.truststoreJson(). Not installed.");
      return { installed: false, anchors: [], total: 0, fromFile: 0,
               atRuntime: 0, max: 0, anchorsFile: '', persisted: false,
               actions: [], doors: doors, notes: notes,
               note: 'tls/tls_server.js was not handed to the console in ' +
                     'this process, so there is no truststore to report on.' };
    }
    const listed = truststore.list();
    const rows = listed.anchors;
    const page = this.pagedRows(req.query || {}, rows, { noun: 'anchors' });
    const fromFile = rows.filter(function (one) {
      return one.source === 'file';
    }).length;
    log.debug("Leaving AdminViews.truststoreJson(). " + rows.length +
              " anchor(s).");
    return {
      installed: true,
      anchors: page.shown,
      total: rows.length,
      fromFile: fromFile,
      atRuntime: rows.length - fromFile,
      max: listed.max,
      anchorsFile: listed.file,
      loadedFromFile: listed.loadedFromFile,
      persisted: listed.stored === true,
      actions: adminActions.TRUSTSTORE_ACTIONS.slice(),
      doors: doors,
      notes: notes,
      page: page.paging.page, pages: page.paging.pages,
      perPage: page.paging.perPage, paging: this.pagingJson(page.paging)
    };
  }

  // ---------------------------------------------------------------------------
  // THE KERBEROS PRINCIPALS, AS `/admin/kerberos/principals` AND
  // `GET /admin-api/kerberos/principals` BOTH ANSWER IT (2026-09-12).
  //
  // Two lists, paged separately (`?peoplePage=`, `?servicesPage=`, one `per`):
  // the directory people who hold Kerberos keys, and the service principals an
  // operator stored a random key for. **NO KEY IS IN EITHER** — both lists are
  // built from the PUBLIC info attributes, and nothing is opened to draw them.
  // A person row says whether the keys match the password the entry holds NOW,
  // which is the question somebody arrives with after a KDC refused a person
  // with "sign in once".
  //
  // **IT ANSWERS FOR THE REALM IT IS READ IN SINCE 2026-09-15.** It read the
  // same under every realm prefix while the KDC was the process's; a trust
  // realm now has a Kerberos realm and a principal database of its own, so the
  // people and service principals here are that realm's — and a realm whose
  // `krb5.enabled` is off has none, which `kerberos` below says rather than
  // showing an empty table that looks like a service with nothing in it.
  // ---------------------------------------------------------------------------
  // The krbtgt block of `kerberosPrincipalsJson()` and of `/admin/kerberos`'s
  // status (#169). A process without the rotation module — a console loaded
  // without the composition root — answers the register's state alone.
  /**
   * Describes the realm's krbtgt key and its rotation (#169).
   *
   * @returns the state
   */
  krbtgtView() {
    const { log, krb5PersonKeys, krbtgtRotation } = this.deps;
    log.debug("Entering AdminViews.krbtgtView().");
    try {
      const view = krbtgtRotation().rotationView();
      log.debug("Leaving AdminViews.krbtgtView().");
      return view;
    } catch (e) {
      log.debug("Caught in AdminViews.krbtgtView(): " +
                ((e && e.message) || e));
      log.debug("Leaving AdminViews.krbtgtView(). The register's state.");
      return krb5PersonKeys.krbtgtState();
    }
  }

  /**
   * Builds `/admin/kerberos/principals`'s JSON.
   *
   * @param req - the request
   * @returns the JSON
   */
  kerberosPrincipalsJson(req) {
    const { log, config, realms, krb5Principals, krb5PersonKeys,
      adminActions } = this.deps;
    log.debug("Entering AdminViews.kerberosPrincipalsJson().");
    const query = (req && req.query) || {};
    // PAGED, THEN DESCRIBED (#352): the population is the undescribed rows,
    // sorted by username, and only the page is parsed, stamped and given
    // its retained versions.
    const people = krb5PersonKeys.listPeopleKeys();
    const services = krb5PersonKeys.listServices();
    // `name` and NOT `param`: pagingOf() builds the parameter as `<name>Page`
    // and reads no `param` option at all. This passed `param` until 2026-09-13,
    // so both lists read the bare `?page=` while the page's links wrote
    // `peoplePage` and `servicesPage` — every next and previous link on
    // /admin/kerberos/principals reloaded the same first page.
    const peopleKeyPage = this.pagedRows(query, people,
                                         { name: 'people', noun: 'people' });
    const peoplePage = Object.assign({}, peopleKeyPage, {
      shown: krb5PersonKeys.describePeople(peopleKeyPage.shown) });
    const servicesPage = this.pagedRows(query, services,
                                        { name: 'services', noun: 'service ' +
                                            'principals' });
    const account = krb5Principals.serviceAccount();
    log.debug("Leaving AdminViews.kerberosPrincipalsJson(). " + people.length +
              " " +
        "person(s), " +
              services.length + " service principal(s).");
    const kerberos = krb5Principals.kerberosRealmOf();
    return {
      installed: krb5PersonKeys.installed(),
      realm: krb5Principals.REALM,
      trustRealm: realms.currentId(),
      // WHETHER THIS REALM HAS A KDC AT ALL, and if not why (2026-09-15):
      // `enabled` is the realm's own `krb5.enabled`, `served` the Kerberos
      // realm names its KDC answers for, and `reason` the sentence behind an
      // off one.
      kerberos: kerberos,
      productKdc: krb5PersonKeys.productKdc(),
      personKeys: krb5PersonKeys.personKeysEnabled(),
      enctypes: krb5Principals.KDC_ETYPES.slice(),
      startingKvno: Number(config.value('krb5.kvno')),
      // THE PREVIOUS-VERSION WINDOW AS IT STANDS NOW: how many a key keeps and
      // for how long, in seconds, with zero in the setting already turned into
      // the ticket lifetime plus the clock skew it means. Each row's `retained`
      // lists the versions inside it — kvno, enctypes, expiry, and never a key.
      retention: { versions: krb5PersonKeys.retainedVersionsLimit(),
                   ttlSeconds: krb5PersonKeys.retainedTtlSeconds(),
                   ttlSetting: Number(config.value('krb5.retainedKeyTtlS')) },
      acceptor: { spn: account.spn, available: account.available,
                  storedKey: !!account.storedKey },
      // THE REALM'S KRBTGT (#169): where its key comes from, the kvno, when
      // it was made and last rotated, the versions kept, and the schedule —
      // never a key. `null` in a realm with no KDC.
      krbtgt: kerberos.enabled ? this.krbtgtView() : null,
      actions: adminActions.KERBEROS_PRINCIPAL_ACTIONS.slice(),
      people: peoplePage.shown,
      peopleTotal: people.length,
      peoplePaging: this.pagingJson(peoplePage.paging),
      services: servicesPage.shown,
      servicesTotal: services.length,
      servicesPaging: this.pagingJson(servicesPage.paging),
      notes: {
        keys: 'No key material is in this answer or on the page. A person\'s ' +
          'keys are derived from their password when it is set or verified ' +
          'and ' +
          'are never shown; a service principal\'s keytab is handed over ' +
          'ONCE, by the create or rotate that made it, and a person\'s ' +
          'keytab ONCE, derived from a password in hand — the one an ' +
          'administrator sets on the person\'s page, or their own on ' +
          '/portal/kerberos.',
        mode: krb5PersonKeys.productKdc()
          ?
          'This KDC is a PRODUCT one: a person authenticates with their own ' +
            'password through the keys stored on their directory entry, and ' +
            'a person with none is refused with "sign in once".'
          : 'This KDC is a DEVELOPMENT one: every user is keyed from ' +
            'krb5.userPassword and people are never given stored keys. ' +
            'Service principals created here are used in both modes.',
        realm: kerberos.enabled
          ? 'A KDC PER TRUST REALM: these are the people and applications of ' +
            'the trust realm this page is read in, as principals of its own ' +
            'Kerberos realm ' + (kerberos.kerberosRealm || '') + '.'
          : 'THIS TRUST REALM HAS NO KDC: ' + (kerberos.reason ||
            'krb5.enabled is off for it') + '. Set krb5.realm on the realm ' +
            'and turn ' +
            'krb5.enabled on to give it one; port 88 routes a request by the ' +
            'Kerberos realm name inside it.',
        window: 'Keys are derived AFTER a password is set or verified and ' +
                'take ' +
          'a few tens of milliseconds to land; until they do, the KDC ' +
          'refuses the person rather than accepting an older key.',
        previous: 'A password change or a rotation keeps the version it ' +
          'replaced — at most krb5.retainedKeyVersions of them, each for ' +
          'krb5.retainedKeyTtlS — so a ticket issued under it is still ' +
          'accepted until it could have expired. A previous version only ' +
          'ever ' +
          'OPENS such a ticket: nothing is issued under it and an old ' +
          'password never signs in. "Drop previous versions" ends the window ' +
          'at once, after a compromise.'
      }
    };
  }

  // The whole report, for this page and for `GET /admin-api/ssf`. One function,
  // so the page and the API cannot disagree about what this transmitter is
  // doing — which is rule 7's entire subject.
  /**
   * Builds `/admin/ssf`'s report.
   *
   * @param req - the request
   * @returns the report
   */
  ssfJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.ssfJson().");
    if (!signalsReporter) {
      log.debug("Leaving AdminViews.ssfJson(). Not installed.");
      return { installed: false, enabled: false, streamDetail: [],
               receivedDetail: [], settings: configSettingsJson('/admin/ssf'),
               statuses: [], eventTypes: [],
               note: 'ssf/ssf.ts is not loaded in this process, so nothing ' +
                     'here can report on the Shared Signals Framework.' };
    }
    const report = signalsReporter.report(req);
    report.installed = true;
    report.settings = configSettingsJson('/admin/ssf');
    // The two menus each stream's forms offer (#446): the statuses a stream
    // may be set to and the event types this transmitter can send.
    report.statuses = signalsReporter.statuses.slice();
    report.eventTypes = signalsReporter.eventTypes();
    log.debug("Leaving AdminViews.ssfJson(). " + report.streamDetail.length +
              " stream(s).");
    return report;
  }

  // ---------------------------------------------------------------------------
  // MONITORING -> SHARED SIGNALS -> DEAD LETTERS (2026-09-14).
  //
  // What every dead-letter queue in the realm holds, counted, and the letters
  // themselves searched and paged. `ssf/ssf_dead_letter_report.ts` computes the
  // report; this adds only the search and the slice, for both doors —
  // `/admin/ssf/dead-letters` and `GET /admin-api/ssf/dead-letters` — so the
  // two cannot disagree about what was filtered (rule 7).
  //
  // THREE NARROWINGS AND THEY COMBINE. `dlstream` and `dlcause` are EXACT: a
  // stream id and a cause id are what the page's own links carry, and a
  // substring of a stream id is not a stream. `dlq` is the box over everything
  // a reader arrives holding — a jti out of a receiver's log, an error code, an
  // event name, a status, a phrase from a reason. The counts above the list are
  // the WHOLE realm's whatever is narrowed, because "how many are there" and
  // "which ones am I looking at" are two questions, and `matched` answers the
  // second.
  // ---------------------------------------------------------------------------
  /**
   * Filters and pages the Shared Signals dead letters.
   *
   * @param req - the request
   * @param report - the transmitter's report
   * @returns the rows shown, the count matched and the paging
   */
  ssfDeadLettersState(req, report) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.ssfDeadLettersState().");
    const wanted = this.queryOne(req.query, 'dlq').trim().toLowerCase();
    const stream = this.queryOne(req.query, 'dlstream').trim();
    const cause = this.queryOne(req.query, 'dlcause').trim();
    const rows = (report.letters || []).filter(function (row) {
      if (stream && row.stream_id !== stream) {
        return false;
      }
      if (cause && row.cause !== cause) {
        return false;
      }
      if (!wanted) {
        return true;
      }
      const event = row.event || { name: '', types: [], subject: '' };
      return [row.jti, row.stream_id, row.reason, row.errorCode,
              String(row.status), event.name, event.subject]
        .concat(event.types)
        .some(function (value) {
          return String(value || '').toLowerCase().indexOf(wanted) >= 0;
        });
    });
    const page = this.pagedRows(req.query, rows,
      { name: 'letters', noun: 'dead letters' });
    log.debug("Leaving AdminViews.ssfDeadLettersState(). " + rows.length +
              " match(es).");
    return { wanted: wanted, stream: stream, cause: cause, rows: rows,
             page: page };
  }

  /**
   * Builds the Shared Signals dead-letter page's JSON.
   *
   * @param req - the request
   * @returns the JSON
   */
  ssfDeadLettersJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.ssfDeadLettersJson().");
    if (!signalsReporter || typeof signalsReporter.deadLetters !== 'function') {
      log.debug("Leaving AdminViews.ssfDeadLettersJson(). Not installed.");
      return { installed: false, enabled: false, letters: [], streams: [],
               causes: [], byCode: [], byStatus: [], byEventType: [],
               totals: { held: 0 }, matched: 0,
               filter: { q: null, stream: null, cause: null },
               paging: { letters: this.pagingJson(this.pagingOf(req.query, 0,
                 { name: 'letters', noun: 'dead letters' })) },
               note: 'ssf/ssf.ts is not loaded in this process, so nothing ' +
                     'here can report on the Shared Signals dead-letter ' +
                     'queues.' };
    }
    const report = signalsReporter.deadLetters();
    const state = this.ssfDeadLettersState(req, report);
    log.debug("Leaving AdminViews.ssfDeadLettersJson(). " +
              state.page.shown.length +
              " of " + state.rows.length + " shown.");
    return Object.assign({}, report, {
      installed: true,
      filter: { q: state.wanted || null, stream: state.stream || null,
                cause: state.cause || null },
      matched: state.rows.length,
      letters: state.page.shown,
      paging: { letters: this.pagingJson(state.page.paging) }
    });
  }

  // The whole report, for both pages and for `GET /admin-api/caep`. ONE
  // function, so the two pages and the API cannot come to disagree about what
  // this transmitter has said — rule 7's entire subject.
  /**
   * Builds the CAEP report.
   *
   * @param req - the request
   * @returns the report
   */
  caepJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.caepJson().");
    if (!caepReporter) {
      log.debug("Leaving AdminViews.caepJson(). Not installed.");
      return { installed: false, enabled: false, sessions: [], eventTypes: [],
               streams: [], totals: {}, tracked: 0,
               settings: configSettingsJson('/admin/caep'),
               note: 'ssf/ssf.ts is not loaded in this process, so nothing ' +
                     'here can report on the Continuous Access Evaluation ' +
                     'Profile.' };
    }
    const report = caepReporter.report(req);
    report.installed = true;
    report.catalogue = caepReporter.eventTypes();
    report.settings = configSettingsJson('/admin/caep');
    log.debug("Leaving AdminViews.caepJson(). " + report.tracked +
              " session(s).");
    return report;
  }

  // ---------------------------------------------------------------------------
  // MONITORING -> CAEP SESSIONS.
  //
  // **THE REGISTER OUTLIVES THE SESSION AND THAT IS THE POINT.** `authn.ts`
  // forgets a session the moment it is signed out; a row here whose state is
  // `revoked` is the only remaining evidence that the session existed and was
  // revoked, and "did anything go out when I signed that person out?" is the
  // question this page is for.
  //
  // It is under Monitoring rather than beside the settings for the reason
  // /admin/delegation is: that section's heading says *what this service has
  // done*, and this is an OBSERVATION. The settings are a configuration and
  // live at /admin/caep.
  // ---------------------------------------------------------------------------
  // THE SEARCH AND THE SLICE, as one pure function called twice — by the page
  // and by GET /admin-api/caep/sessions. Written once for the reason
  // `permissionsListState()` (admin-ui/admin.ts) is: the markup and the reply
  // have to agree about what was filtered and what was drawn, and two walks of
  // one list is how they come to disagree about a session that ended in
  // between.
  /**
   * Filters and pages the CAEP sessions.
   *
   * @param req - the request
   * @param report - the CAEP report
   * @returns the rows shown and their paging
   */
  caepSessionsState(req, report) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.caepSessionsState().");
    const wanted = this.queryOne(req.query, 'sessq').trim();
    const matched = (report.sessions || []).filter(function (row) {
      return self.chooserMatches([row.username, row.sub, row.sessionId,
                                  row.subject,
                                  row.protocol], wanted);
    });
    const page = this.pagedRows(req.query, matched,
      { name: 'sessions', noun: 'sessions' });
    log.debug("Leaving AdminViews.caepSessionsState(). " + page.shown.length +
              " of " +
              matched.length + ".");
    return { wanted: wanted, matched: matched, page: page };
  }

  // THE PER-RECEIVER SECTION'S SEARCH AND SLICE, the same shape
  // `caepSessionsState()` has and for the same reason: the markup and the reply
  // have to agree about what was filtered and what was drawn.
  //
  // The search is over the RECEIVER — its identifier, its name, and the `aud`
  // its SETs are addressed to — because those are the three strings a reader
  // arrives holding and they are routinely different. It is NOT over the event
  // types: a receiver that takes none of the eight is exactly the row somebody
  // is looking for when they ask why nothing arrived, and a search that hid it
  // would hide the answer.
  /**
   * Filters and pages the CAEP receivers.
   *
   * @param req - the request
   * @param report - the CAEP report
   * @returns the rows shown and their paging
   */
  caepApplicationsState(req, report) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.caepApplicationsState().");
    const wanted = this.queryOne(req.query, 'appq').trim();
    const matched = (report.applications || []).filter(function (row) {
      return self.chooserMatches([row.identifier, row.name,
                                  row.audiences.join(' ')],
                                 wanted);
    });
    const page = this.pagedRows(req.query, matched,
      { name: 'applications', noun: 'receivers' });
    log.debug("Leaving AdminViews.caepApplicationsState(). " +
              page.shown.length + " of " +
              matched.length + ".");
    return { wanted: wanted, matched: matched, page: page };
  }

  // The reply BOTH doors answer with. `/admin/caep-sessions?format=json` and
  // GET /admin-api/caep/sessions are the same document — rule 7 — and the
  // drill- down is `?session=`, which is one operation answering two shapes for
  // the reason /admin-api/permissions/groups gives: they are the same question
  // at two scales and the console draws them with one register.
  /**
   * Builds the CAEP sessions page's JSON, or one session's with `?session=`.
   *
   * @param req - the request
   * @returns the JSON
   */
  caepSessionsJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.caepSessionsJson().");
    const json = this.caepJson(req);
    const asked = String(req.query.session || '').trim();
    if (asked) {
      const row = (json.sessions || []).filter(function (one) {
        return String(one.sessionId) === asked;
      })[0] || null;
      const eventPage = this.pagedRows(req.query, (row && row.events) || [],
        { name: 'events', noun: 'events' });
      log.debug("Leaving AdminViews.caepSessionsJson(). One session.");
      return { installed: json.installed, id: asked, session: row,
               eventTypes: json.eventTypes || [],
               events: eventPage.shown,
               paging: { events: this.pagingJson(eventPage.paging) } };
    }
    const state = this.caepSessionsState(req, json);
    const appState = this.caepApplicationsState(req, json);
    log.debug("Leaving AdminViews.caepSessionsJson(). The list.");
    return Object.assign({}, json, {
      filter: { sessions: state.wanted || null,
                applications: appState.wanted || null },
      paging: { sessions: this.pagingJson(state.page.paging),
                applications: this.pagingJson(appState.page.paging) },
      // The rows each table's page shows and how many each filter matched
      // (#446): the page draws its two tables from this answer.
      shown: { sessions: state.page.shown,
               applications: appState.page.shown },
      matched: { sessions: state.matched.length,
                 applications: appState.matched.length }
    });
  }

  // The whole report, for both pages and for `GET /admin-api/risc`. ONE
  // function, so the two pages and the API cannot come to disagree about what
  // this transmitter has said — rule 7's entire subject.
  /**
   * Builds the RISC report.
   *
   * @param req - the request
   * @returns the report
   */
  riscJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.riscJson().");
    if (!riscReporter) {
      log.debug("Leaving AdminViews.riscJson(). Not installed.");
      return { installed: false, enabled: false, accounts: [], eventTypes: [],
               streams: [], totals: {}, tracked: 0,
               settings: configSettingsJson('/admin/risc'),
               note: 'ssf/ssf.ts is not loaded in this process, so nothing ' +
                     'here can report on the Risk Incident Sharing and ' +
                     'Coordination profile.' };
    }
    const report = riscReporter.report(req);
    report.installed = true;
    report.catalogue = riscReporter.eventTypes();
    report.settings = configSettingsJson('/admin/risc');
    log.debug("Leaving AdminViews.riscJson(). " + report.tracked +
              " account(s).");
    return report;
  }

  // ---------------------------------------------------------------------------
  // MONITORING -> RISC ACCOUNTS.
  //
  // **THE REGISTER OUTLIVES THE ACCOUNT, AND MORE STARKLY THAN THE CAEP ONE
  // OUTLIVES A SESSION.** That register keeps a row for a session the session
  // store has forgotten. This one keeps a row for an account that has been
  // DELETED FROM THE DIRECTORY ENTIRELY — the row whose lifecycle says `purged`
  // is the only remaining evidence anywhere that this service ever told anybody
  // the account was purged, and *"did anything go out when I deleted that
  // person?"* is the entire question this page answers.
  //
  // It is under Monitoring rather than beside the settings for the reason
  // /admin/caep-sessions is: that section's heading says *what this service has
  // done*, and this is an OBSERVATION.
  // ---------------------------------------------------------------------------
  // THE SEARCH AND THE SLICE, as one pure function called twice — by the page
  // and by the management API — for the reason caepSessionsState() is one.
  //
  // The search reaches `formerIdentifiers` as well as the current ones, and
  // that is not thoroughness: an `identifier-changed` is an event ABOUT the
  // key, so the address a reader arrives holding — out of a log, off an event
  // they are chasing — is routinely the one the account no longer has. A search
  // that matched only the current spelling would hide exactly the row somebody
  // came to find.
  /**
   * Filters and pages the RISC accounts.
   *
   * @param req - the request
   * @param report - the RISC report
   * @returns the rows shown and their paging
   */
  riscAccountsState(req, report) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.riscAccountsState().");
    const wanted = this.queryOne(req.query, 'acctq').trim();
    const matched = (report.accounts || []).filter(function (row) {
      return self.chooserMatches([row.accountId, row.username, row.sub,
                                  row.email,
                                  row.phone, row.subject, row.dn].concat(
                                  row.formerIdentifiers || []), wanted);
    });
    const page = this.pagedRows(req.query, matched,
      { name: 'accounts', noun: 'accounts' });
    log.debug("Leaving AdminViews.riscAccountsState(). " + page.shown.length +
              " of " +
              matched.length + ".");
    return { wanted: wanted, matched: matched, page: page };
  }

  /**
   * Filters and pages the RISC receivers.
   *
   * @param req - the request
   * @param report - the RISC report
   * @returns the rows shown and their paging
   */
  riscApplicationsState(req, report) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.riscApplicationsState().");
    const wanted = this.queryOne(req.query, 'rappq').trim();
    const matched = (report.applications || []).filter(function (row) {
      return self.chooserMatches([row.identifier, row.name,
                                  row.audiences.join(' ')],
                                 wanted);
    });
    const page = this.pagedRows(req.query, matched,
      { name: 'rapplications', noun: 'receivers' });
    log.debug("Leaving AdminViews.riscApplicationsState(). " +
              page.shown.length + " of " +
              matched.length + ".");
    return { wanted: wanted, matched: matched, page: page };
  }

  // The reply BOTH doors answer with. `/admin/risc-accounts?format=json` and
  // GET /admin-api/risc/accounts are the same document — rule 7 — and the
  // drill-down is `?account=`, one operation answering two shapes for the
  // reason the CAEP pair gives: they are the same question at two scales and
  // the console draws them from one register.
  /**
   * Builds the RISC accounts page's JSON, or one account's with `?account=`.
   *
   * @param req - the request
   * @returns the JSON
   */
  riscAccountsJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.riscAccountsJson().");
    const json = this.riscJson(req);
    const asked = String(req.query.account || '').trim();
    if (asked) {
      const row = (json.accounts || []).filter(function (one) {
        return String(one.accountId) === asked;
      })[0] || null;
      const eventPage = this.pagedRows(req.query, (row && row.events) || [],
        { name: 'events', noun: 'events' });
      log.debug("Leaving AdminViews.riscAccountsJson(). One account.");
      return { installed: json.installed, id: asked, account: row,
               eventTypes: json.eventTypes || [],
               events: eventPage.shown,
               paging: { events: this.pagingJson(eventPage.paging) } };
    }
    const state = this.riscAccountsState(req, json);
    const appState = this.riscApplicationsState(req, json);
    log.debug("Leaving AdminViews.riscAccountsJson(). The list.");
    return Object.assign({}, json, {
      filter: { accounts: state.wanted || null,
                applications: appState.wanted || null },
      paging: { accounts: this.pagingJson(state.page.paging),
                applications: this.pagingJson(appState.page.paging) },
      // The rows each table's page shows (#446): the page draws its two
      // tables from this answer.
      shown: { accounts: state.page.shown,
               applications: appState.page.shown }
    });
  }

  // ---------------------------------------------------------------------------
  // THE SPIFFE REPORTS (2026-09-12), and this family was already split.
  //
  // `spiffeAgentsListPage()` on the console opens with `const view =
  // spiffeAgentsJson(req)` and does nothing but render what comes back.
  // Somebody drew that line here long before there was anywhere to move the
  // computation TO — which is why these three came across whole while the other
  // twelve views still compute and render in one pass.
  // ---------------------------------------------------------------------------
  // Answered with empty listeners rather than null when the slot is unfilled,
  // so every caller renders the same "nothing bound" table instead of each
  // having to guard. The bundle path falls back to the configured value, which
  // is what that module reads too — one setting, two readers, no third opinion.
  /**
   * Returns the SPIFFE listeners and the bundle path; empty listeners when the
   * slot is unfilled.
   *
   * @returns the listeners
   */
  spiffeListeners() {
    const { log, config } = this.deps;
    log.debug("Entering AdminViews.spiffeListeners().");
    const read = spiffeReader ? spiffeReader() : null;
    log.debug("Leaving AdminViews.spiffeListeners().");
    return read || { workload: [], api: [], broker: [],
                     bundlePath: config.value('spiffe.bundlePath') };
  }

  // ---------------------------------------------------------------------------
  // THE TRUST DOMAIN PAGE.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/spiffe`'s JSON: the trust domain page.
   *
   * @param req - the request
   * @returns the JSON
   */
  spiffeJson(req) {
    const { log, config, spiffeRegistry, spiffeCa, spiffeAuth } = this.deps;
    log.debug("Entering AdminViews.spiffeJson().");
    const state = spiffeCa.state();
    const bindings = this.spiffeListeners();
    const json = {
      enabled: state.enabled,
      ready: state.ready,
      error: state.error,
      trustDomain: state.trustDomain,
      trustDomainId: state.trustDomainId,
      serverId: state.serverId,
      bundle: {
        path: bindings.bundlePath,
        sequence: state.sequence,
        refreshHint: state.refreshHint
      },
      authorities: { source: state.authoritySource,
                     realm: state.realm,
                     x509: state.x509Authorities, jwt: state.jwtAuthorities,
                     trustAnchors: state.trustAnchors,
                     chainSubjects: state.chainSubjects,
                     root: state.root,
                     maxRetained: spiffeCa.MAX_RETAINED_AUTHORITIES },
      listeners: { workloadApi: bindings.workload, serverApi: bindings.api,
                   // The SPIFFE Broker API's (#170).
                   brokerApi: (bindings as any).broker || [] },
      // What the Workload API's Unix socket attests (#40 phase four): the
      // native module, the attestors, and each open attested connection.
      workloadAttestation: (bindings as any).workloadAttestation || null,
      federated: state.federated,
      counts: { entries: spiffeRegistry.entryCount(),
                agents: spiffeRegistry.agentCount(),
                maxEntries: spiffeRegistry.maxEntries(),
                maxAgents: spiffeRegistry.maxAgents(),
                maxFederatedBundles:
                  config.value('spiffe.maxFederatedBundles') },
      keyTypes: state.keyTypes,
      // WHO MAY CALL, from the one table `GET /spiffe` and the management API
      // read too. Built there rather than here for the reason the two discovery
      // documents are built from one object: three surfaces describing what is
      // enforced three ways is two of them eventually wrong.
      authentication: spiffeAuth.state(),
      // Which settings shape this, so that a reader who wants to change
      // something knows where to go rather than hunting /admin/config. The same
      // courtesy /admin/scim pays.
      settings: ['spiffe.enabled', 'spiffe.trustDomain', 'spiffe.x509KeyType',
                 'spiffe.jwtKeyType', 'spiffe.caTtl', 'spiffe.svidTtl',
                 'spiffe.jwtSvidTtl', 'spiffe.refreshHint',
                 'spiffe.svidSubject',
                 'spiffe.autoCreateEntries', 'spiffe.requireSecurityHeader',
                 'spiffe.trustLocalSocket',
                 'spiffe.adminIds', 'spiffe.clockSkew',
                 'spiffe.attestWorkloads', 'spiffe.acceptAssertedSelectors',
                 'spiffe.maxEntries', 'spiffe.maxAgents',
                 'spiffe.maxFederatedBundles', 'spiffe.bundlePath',
                 'spiffe.workloadSocketEnabled', 'spiffe.workloadSocket',
                 'spiffe.workloadPort', 'spiffe.serverPort',
                 'spiffe.serverSocketEnabled', 'spiffe.serverSocket',
                 'spiffe.grpcHost', 'spiffe.workloadAttestors',
                 'spiffe.workloadProcRoot', 'spiffe.brokerPort',
                 'spiffe.brokers', 'spiffe.dockerSigstoreEnabled',
                 'spiffe.dockerUseRootlessPodman'].map(function (key) {
        return { key: key, value: config.text(key) };
      })
    };
    // WHAT THE PAGE DRAWS BESIDE (#446): the authorities and the federated
    // bundles as the CA holds them, whether the SPIRE Server API
    // authenticates, and the page's settings block — `settings` above is
    // this answer's own list of readings, and stays what it was.
    const extra: Record<string, any> = json;
    extra.authorityState = {
      x509Authorities: state.x509Authorities.map(function (one) {
        return { id: one.id, active: one.active, notAfter: one.notAfter,
                 subject: one.subject, createdAt: one.createdAt,
                 keyType: one.keyType };
      }),
      jwtAuthorities: state.jwtAuthorities.map(function (one) {
        return { id: one.id, active: one.active, notAfter: one.notAfter,
                 alg: one.alg, createdAt: one.createdAt };
      }),
      federated: state.federated.map(function (one) {
        return { trustDomain: one.trustDomain,
                 trustDomainId: one.trustDomainId, x509Keys: one.x509Keys,
                 jwtKeys: one.jwtKeys, sequence: one.sequence,
                 bundleEndpointProfile: one.bundleEndpointProfile,
                 bundleEndpointUrl: one.bundleEndpointUrl };
      })
    };
    extra.serverApiAuthenticated = spiffeAuth.authRequired();
    extra.settingsForms = configSettingsJson('/admin/spiffe');
    log.debug("Leaving AdminViews.spiffeJson(). ready=" + json.ready);
    return json;
  }

  // ---------------------------------------------------------------------------
  // THE REGISTRATION ENTRIES.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/spiffe/entries`'s JSON: the registration entries.
   *
   * @param req - the request
   * @returns the JSON
   */
  spiffeEntriesJson(req) {
    const { log, spiffeRegistry } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.spiffeEntriesJson().");
    const q = String(req.query.q || '').trim().toLowerCase();
    const origin = String(req.query.origin || '').trim();
    const all = spiffeRegistry.allEntries();
    const rows = all.filter(function (entry) {
      if (origin && entry.origin !== origin) return false;
      if (!q) return true;
      return (entry.spiffeId + ' ' + entry.parentId + ' ' + entry.id + ' ' +
              entry.hint + ' ' +
              entry.selectors.map(self.spiffeSelectorText.bind(self)).join(' '))
                .toLowerCase()
        .indexOf(q) >= 0;
    });
    const pg = this.pagingOf(req.query, rows.length, { unit: 'entry' });
    const json = {
      total: all.length,
      matched: rows.length,
      filter: { q: q, origin: origin },
      origins: all.map(function (entry) { return entry.origin; })
        .filter(function (value, index, list) {
          return list.indexOf(value) === index;
        })
        .sort(),
      paging: this.pagingJson(pg),
      max: spiffeRegistry.maxEntries(),
      container: 'ou=entries,ou=spiffe',
      // What the page states beside the rows (#446): whether the SPIRE
      // Server API authenticates, and the trust domain a new entry's
      // SPIFFE ID is written in.
      serverApiAuthenticated: spiffeAuth.authRequired(),
      trustDomain: spiffeCa.trustDomain(),
      // Each entry with its selectors as text, the column the page draws.
      entries: rows.slice(pg.offset, pg.offset + pg.perPage)
        .map(function (entry) {
          return Object.assign({}, entry, {
            selectorTexts: entry.selectors
              .map(self.spiffeSelectorText.bind(self))
          });
        })
    };
    log.debug("Leaving AdminViews.spiffeEntriesJson(). " + rows.length +
              " matched.");
    return { json: json, paging: pg };
  }

  // ---------------------------------------------------------------------------
  // THE SPIFFE BROKER API'S BROKERS (#170): `spiffe.brokers`, parsed by the
  // one parser the endpoint uses, filtered and paged, with the listeners the
  // realm bound and what each broker may reference. An entry that does not
  // parse is listed WITH its problem — it authorizes nothing, and a list
  // that hid it would leave an operator wondering why a broker is refused.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/spiffe/brokers`'s JSON: the brokers and what each may
   * reference, an unparsed entry listed with its problem.
   *
   * @param req - the request
   * @returns the JSON
   */
  spiffeBrokersJson(req) {
    const { log, config, spiffeAuth } = this.deps;
    log.debug("Entering AdminViews.spiffeBrokersJson().");
    const q = String(req.query.q || '').trim().toLowerCase();
    const all = spiffeAuth.brokers();
    const rows = all.filter(function (one) {
      return !q || (one.id + ' ' + one.types.join(' ') + ' ' + one.problem)
        .toLowerCase().indexOf(q) >= 0;
    });
    const pg = this.pagingOf(req.query, rows.length, { unit: 'broker' });
    const bindings = this.spiffeListeners();
    const json = {
      total: all.length,
      matched: rows.length,
      filter: { q: q },
      paging: this.pagingJson(pg),
      trustDomain: spiffeCa.trustDomain(),
      setting: 'spiffe.brokers',
      port: config.text('spiffe.brokerPort'),
      referenceTypes: ['pid', 'k8s', '*'],
      listeners: (bindings as any).broker || [],
      brokers: rows.slice(pg.offset, pg.offset + pg.perPage)
        .map(function (one) {
          return { id: one.id, referenceTypes: one.types,
                   problem: one.problem };
        })
    };
    log.debug("Leaving AdminViews.spiffeBrokersJson(). " + rows.length +
              " matched.");
    return { json: json, paging: pg };
  }

  // ---------------------------------------------------------------------------
  // THE AGENTS.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/spiffe/agents`'s JSON: the attested agents.
   *
   * @param req - the request
   * @returns the JSON
   */
  spiffeAgentsJson(req) {
    const { log, spiffeRegistry } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.spiffeAgentsJson().");
    const q = String(req.query.q || '').trim().toLowerCase();
    const all = spiffeRegistry.allAgents();
    const rows = all.filter(function (agent) {
      if (!q) return true;
      return (agent.id + ' ' + agent.attestationType + ' ' +
              agent.selectors.map(self.spiffeSelectorText.bind(self)).join(' '))
                .toLowerCase()
        .indexOf(q) >= 0;
    });
    const pg = this.pagingOf(req.query, rows.length, { unit: 'agent' });
    const json = {
      total: all.length,
      matched: rows.length,
      filter: { q: q },
      max: spiffeRegistry.maxAgents(),
      container: 'ou=agents,ou=spiffe',
      paging: this.pagingJson(pg),
      serverApiAuthenticated: spiffeAuth.authRequired(),
      agents: rows.slice(pg.offset, pg.offset + pg.perPage)
    };
    log.debug("Leaving AdminViews.spiffeAgentsJson(). " + rows.length +
              " matched.");
    return { json: json, paging: pg };
  }

  // ONE REGISTRATION ENTRY AND ONE AGENT (#446), for the two drill-downs and
  // for the `entry` and `agent` parameters `GET /admin-api/spiffe/entries`
  // and `/agents` have always documented and, until now, ignored — they
  // answered the list. Each carries its selectors as text and what its page
  // states beside it; one that is not there answers `found: false`.
  /**
   * Builds one registration entry's drill-down JSON.
   *
   * @param id - the entry's id
   * @returns the JSON
   */
  spiffeEntryJson(id) {
    const { log, spiffeRegistry } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.spiffeEntryJson(). id=" + id);
    const entry = spiffeRegistry.entryById(id);
    const serverApiAuthenticated = spiffeAuth.authRequired();
    if (!entry) {
      log.debug("Leaving AdminViews.spiffeEntryJson(). Not here.");
      return { found: false, id: id,
               error: 'No registration entry has the id ' + id,
               serverApiAuthenticated: serverApiAuthenticated };
    }
    log.debug("Leaving AdminViews.spiffeEntryJson().");
    return {
      found: true,
      entry: Object.assign({}, entry, {
        selectorTexts: entry.selectors.map(self.spiffeSelectorText.bind(self))
      }),
      editable: spiffeRegistry.EDITABLE,
      serverApiAuthenticated: serverApiAuthenticated,
      defaults: { x509SvidTtl: config.text('spiffe.svidTtl'),
                  jwtSvidTtl: config.text('spiffe.jwtSvidTtl') }
    };
  }

  /**
   * Builds one attested agent's drill-down JSON.
   *
   * @param id - the agent's SPIFFE ID
   * @returns the JSON
   */
  spiffeAgentJson(id) {
    const { log, spiffeRegistry } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.spiffeAgentJson(). id=" + id);
    const agent = spiffeRegistry.agentById(id);
    const serverApiAuthenticated = spiffeAuth.authRequired();
    if (!agent) {
      log.debug("Leaving AdminViews.spiffeAgentJson(). Not here.");
      return { found: false, id: id,
               error: 'No agent has attested here as ' + id,
               serverApiAuthenticated: serverApiAuthenticated };
    }
    log.debug("Leaving AdminViews.spiffeAgentJson().");
    return {
      found: true,
      agent: Object.assign({}, agent, {
        selectorTexts: agent.selectors.map(self.spiffeSelectorText.bind(self))
      }),
      serverApiAuthenticated: serverApiAuthenticated
    };
  }

  /**
   * Writes a selector as `type:value`.
   *
   * @param selector - the selector
   * @returns the text
   */
  spiffeSelectorText(selector) {
    const { log, spiffeRegistry } = this.deps;
    log.debug("Entering AdminViews.spiffeSelectorText().");
    log.debug("Leaving AdminViews.spiffeSelectorText().");
    return spiffeRegistry.selectorText(selector);
  }

  // A FIELD GRID ROW TYPED for the control it is drawn as (#446): a setting
  // override takes its setting's type and choices from config.js's
  // description, and a field with a closed set of its own is a choice. It
  // was the console's `gridFieldTyped()`, which still delegates here.
  /**
   * Types one field grid row for the control it is drawn as.
   *
   * @param row - the field, as `applications.applicationFields()` lists it
   * @returns the row, typed
   */
  typedField(row) {
    const { log, configSettingFor } = this.deps;
    log.debug("Entering AdminViews.typedField().");
    if (!row.overrides) {
      // A closed set of its own (applications.attributeChoices()): one value
      // is chosen from them, a list is ticked from them.
      if (row.choices && row.choices.length && row.type === 'string') {
        log.debug("Leaving AdminViews.typedField(). A closed set.");
        return Object.assign({}, row, { type: 'enum' });
      }
      log.debug("Leaving AdminViews.typedField(). Not an override.");
      return row;
    }
    const setting = configSettingFor(row.overrides);
    if (!setting) {
      log.debug("Leaving AdminViews.typedField(). Unknown setting.");
      return row;
    }
    const described = config.describe(setting);
    const typed = Object.assign({}, row, { described: described });
    if (described.type === 'bool') {
      typed.type = 'boolean';
    } else if (described.type === 'enum') {
      typed.type = 'enum';
      typed.choices = (described.enumValues || []).filter(function (one) {
        return one !== '';
      });
    } else if (described.type === 'int') {
      typed.type = 'int';
    }
    log.debug("Leaving AdminViews.typedField().");
    return typed;
  }

  // ---------------------------------------------------------------------------
  // THE NEW-APPLICATION FORM'S ANSWER (2026-09-12), and the first view whose
  // computation was SPLIT rather than moved.
  //
  // `newApplicationPage()` on the console computed four facts, decided whether
  // there was a directory to create anything in, and then built both a form and
  // the JSON that describes it. The form stays there; this is the rest.
  //
  // **THE PAGE NOW RENDERS FROM WHAT THIS RETURNS**, rather than from its own
  // copy of the same four values — so the vocabulary the form offers and the
  // vocabulary `/admin-api` publishes are one computation, which is the
  // property rule 7 asks for and the reason the json was next to the markup to
  // begin with.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/applications/new`'s JSON: the vocabulary the form draws.
   *
   * @param req - the request
   * @returns the JSON
   */
  newApplicationJson(req) {
    const { log, realms, applications, mode } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.newApplicationJson().");
    const container = applications.containerDn ? applications.containerDn() :
                      null;
    const max = applications.maxApplications ? applications.maxApplications() :
                null;
    const held = applications.count();
    const realm = realms.current();
    // NO DIRECTORY IN THIS PROCESS — the page draws no form at all in this
    // case, and this is the answer it publishes instead. See the page.
    if (!container) {
      log.debug("Leaving AdminViews.newApplicationJson(). There is no " +
                "directory.");
    return { directory: false, container: null, max: null,
             applicationCount: held,
            realm: { id: realms.currentId(), name: realm ? realm.name : '' },
            kinds: applications.KINDS, protocols: applications.PROTOCOLS,
            declarations: applications.declarationAttributes() };
    }
    log.debug("Leaving AdminViews.newApplicationJson().");
    return {
        directory: true,
        container: container,
        max: max,
        applicationCount: held,
        realm: { id: realms.currentId(), name: realm ? realm.name : '' },
        // The two vocabularies this form is built from, published rather than
        // described: a caller of POST /admin-api/applications/create reads
        // these to learn what it may send, which is what stops a document and a
        // form offering different sets. The `editable` list is what comes NEXT
        // — the attributes a create cannot take and `set`/`add` can.
        // `kinds` is still published and the form no longer offers it, which is
        // not a contradiction: `createApplication()` still TAKES a kind — the
        // two SAML register buttons pass one — so a caller of POST
        // /admin-api/applications/create may send one and needs the vocabulary
        // to send it from. What was removed is a person being asked to guess.
        kinds: applications.KINDS,
        protocols: applications.PROTOCOLS,
        // THE FIELDS THIS FORM DRAWS, in the order it draws them: the
        // identifier and redirect-URI attributes, deduped by attribute, each
        // carrying the families it serves and whether it holds a list. A caller
        // reads this to learn what may go in `fields` on a create, which is the
        // same walk of the PROTOCOLS table the page itself renders — so the
        // document cannot offer a field the form has never heard of, nor the
        // other way round.
        declarations: applications.declarationAttributes(),
        // WHAT THE FORM DRAWS (#446): every field its grid can draw, typed
        // as the grid types it and saying whether the simplified view offers
        // it, the groups they are drawn under, the protocol families' choices,
        // the attributes one box holds whole, and what the RFC 9728 import
        // section says about this mode.
        fields: applications.applicationFields().map(function (row) {
          return Object.assign({}, self.typedField(row), {
            inSimple: !!row.declaration || !!row.overrides ||
              SAML_KEY_SOURCE_FIELDS.some(function (one) {
                return one.attribute === row.attribute;
              })
          });
        }),
        fieldGroups: applications.FIELD_GROUPS,
        familyChoices: applications.FAMILY_CHOICES,
        longTextAttributes: applications.LONG_TEXT_ATTRIBUTES || [],
        persistence: { persistsDirectory:
                         !!persistence.status().persistsDirectory,
                       mode: persistence.status().mode },
        resourceMetadataImport: {
          wellKnown: resourceMetadata.WELL_KNOWN,
          acceptsNonconforming: mode.acceptsNonconformingResourceMetadata(),
          dialsInternalAddresses: mode.dialsInternalAddresses()
        },
        editable: applications.editableAttributes().map(function (row) {
          // `families` where the attribute has one, and ABSENT where it does
          // not, so that a caller reading this document to learn what it may
          // send is told about the one refusal it could otherwise only discover
          // by being refused. An empty array here would have said "applies to
          // no family", which is the opposite of what an absent member means.
          const published: Record<string, any> = { name: row.name,
                                                   mode: row.editable,
                              sensitive: !!row.sensitive };
          if (row.families && row.families.length) {
            published.families = row.families.slice(0);
          }
          return published;
        })
    };
  }

  // EVERY FIELD THE NEW-USER FORM CAN DRAW (#446), as the console's
  // `newUserFieldRows()` built them while drawing: the person editor's
  // attributes, then any credential-catalogue attribute it does not hold,
  // each with the sentence its tooltip says and whether the simplified view
  // offers it. The page filters by view; this is all of them.
  /**
   * Lists the fields the new-user form's grid can draw.
   *
   * @returns the rows, each with `simple`
   */
  newUserFieldRows() {
    const { log, vcClaims } = this.deps;
    log.debug("Entering AdminViews.newUserFieldRows().");
    const catalogue = vcClaims.personFields();
    const claimOf: Record<string, string> = {};
    catalogue.forEach(function (row) {
      claimOf[row.ldap.toLowerCase()] = row.claim.join('.');
    });
    const rows = personEditor.editableAttributes().map(function (row) {
      return { name: row.name, label: row.label, schema: row.schema,
               multi: row.multi, must: row.must, note: row.note,
               group: row.group, example: row.example, simple: row.simple };
    });
    catalogue.forEach(function (row) {
      const known = rows.some(function (one) {
        return one.name.toLowerCase() === row.ldap.toLowerCase();
      });
      if (!known) {
        rows.push({ name: row.ldap, label: row.label, schema: row.schema,
                    multi: false, must: false, note: '',
                    group: personEditor.groupOf(row.ldap) === 'other' &&
                      row.ldap.toLowerCase() === 'mail'
                      ? 'contact' : personEditor.groupOf(row.ldap),
                    example: personEditor.FIELD_EXAMPLES[
                      row.ldap.toLowerCase()] || '',
                    simple: row.ldap.toLowerCase() === 'mail' });
      }
    });
    const out = rows.map(function (row) {
      const claim = claimOf[row.name.toLowerCase()];
      return {
        attribute: row.name,
        type: row.multi ? 'array' : 'string',
        what: row.label + ' — ' + row.schema + '.' +
              (row.note ? ' It takes ' + row.note + '.' : '') +
              (row.multi ? '' : ' It holds one value.') +
              (claim ? ' It reaches a credential as ' + claim + '.' : ''),
        example: row.example,
        forText: row.label,
        families: [], everyFamily: true, group: row.group,
        simple: !!row.simple
      };
    });
    log.debug("Leaving AdminViews.newUserFieldRows(). " + out.length +
              " field(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE NEW-PERSON FORM'S ANSWER (2026-09-12). Split from newUserPage() the way
  // newApplicationJson() was split from its own page, and for the same reason:
  // the attribute catalogue this form draws its boxes from and the one
  // `/admin-api` publishes were the same computation written twice in one
  // function, with a form between them.
  // ---------------------------------------------------------------------------
  // THE INVENTED PERSON FOR A USERNAME, as Fill puts it into the new-user
  // form (moved here from the console with #446, so the API answers it):
  // `vcClaims.personaFor()` keyed by the attribute each field is stored in.
  /**
   * The attribute values this service would invent for a username.
   *
   * @param username - the username
   * @returns the values, by LDAP attribute name
   */
  inventedFieldValues(username) {
    const { log, vcClaims } = this.deps;
    log.debug("Entering AdminViews.inventedFieldValues().");
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
    log.debug("Leaving AdminViews.inventedFieldValues(). " +
              Object.keys(out).length + " value(s).");
    return out;
  }

  /**
   * Builds `/admin/users/new`'s JSON: the attribute catalogue and credential
   * choices.
   *
   * @param req - the request
   * @param prefill - values to fill the form with
   * @returns the JSON
   */
  newUserJson(req, prefill?) {
    const { log, credentials, mode, realms, vcClaims, applications } =
      this.deps;
    log.debug("Entering AdminViews.newUserJson().");
    const given = prefill || {};
    const values = given.fields || {};
    const username = String(given.username === undefined
      ? (req.query.user || '') : given.username).trim();
    const credential = String(given.credential || DEFAULT_CREDENTIAL);
    const realm = realms.current();
    const container = directoryReader ? this.newUserContainer() : null;
    const fields = vcClaims.personFields();
    const development = mode.isDevelopment();

    // NO DIRECTORY IN THIS PROCESS. The form is left OUT rather than drawn and
    // refused, which is `newApplicationPage()`'s shape and is right for the
    // same reason: `createUser()` would answer with exactly this sentence, and
    // a form whose only possible outcome is that message is a control that lies
    // about what it does.
    if (!directoryWriter || !container) {
      log.debug("Leaving AdminViews.newUserJson(). There is no directory to " +
                "write to.");
      return { directory: false, container: null,
          realm: { id: realms.currentId(), name: realm ? realm.name : '' },
          fields: [], credentials: CREDENTIAL_CHOICES.map(function (one) {
            return { id: one.id, label: one.label };
          }) }
    }
    log.debug("Leaving AdminViews.newUserJson().");
    return {
      directory: true,
      container: container,
      realm: { id: realms.currentId(), name: realm ? realm.name : '' },
      mode: mode.current(),
      // WHETHER THE BUTTON IS THERE, published rather than left to be inferred
      // from `mode`: a caller of GET /admin-api/users/new reading this document
      // to find out what the console offers should not have to know which
      // predicate in mode.js decides it.
      offersExampleData: development,
      // THE FIELDS THIS FORM DRAWS, in the order it draws them, each with the
      // attribute name a create takes and the claim it reaches. A caller reads
      // this to learn what may go in `attributes` on a create — the same
      // catalogue `createUser()` checks against, so the document cannot offer a
      // field the writer has never heard of, nor the other way round.
      fields: fields.map(function (row) {
        return { attribute: row.ldap, label: row.label, schema: row.schema,
                 claim: row.claim.slice(0), invented: !!row.from };
      }),
      // THE FIELD GRID THE FORM DRAWS (2026-10-01): every attribute a
      // person's Attributes tab edits, which a create takes too and holds to
      // the same rules, with the group it is drawn under, whether it is a
      // list, an example of a valid value and whether the simplified view
      // offers it. `fields` above is the credential catalogue, unchanged.
      fieldGroups: personEditor.FIELD_GROUPS.map(function (group) {
        return { id: group.id, label: group.label, what: group.what };
      }),
      gridFields: personEditor.editableAttributes().map(function (row) {
        return { attribute: row.name, label: row.label, group: row.group,
                 multi: row.multi, example: row.example,
                 simple: row.simple, takes: row.note || 'text' };
      }),
      credentials: CREDENTIAL_CHOICES.map(function (one) {
        return { id: one.id, label: one.label, what: one.what };
      }),
      // WHAT THE FORM DRAWS BESIDE (#446): the username it was asked with,
      // every field its grid can draw (each saying whether the simplified
      // view offers it), the attributes one box holds whole, whether a link
      // can be mailed, and whether a create survives a restart.
      username: username,
      fieldRows: this.newUserFieldRows(),
      longTextAttributes: applications.LONG_TEXT_ATTRIBUTES || [],
      mailAvailable: require('../common/mail').available(),
      persistence: { persistsDirectory:
                       !!persistence.status().persistsDirectory,
                     mode: persistence.status().mode },
      // WHAT A CREATE THAT NAMES NO CREDENTIAL GETS (2026-09-12), and the rules
      // a typed or generated password meets — published so that a caller learns
      // both from the document rather than from a refusal.
      defaultCredential: DEFAULT_CREDENTIAL,
      credential: credential,
      passwordPolicy: credentials.passwordRules(username)
    }
  }

  // WHERE A USER CREATED ON THIS PAGE LANDS, in the realm the page is being
  // read in. `directoryReader('')` is the same slot the drill-down uses, asked
  // with no name: it answers about the DIRECTORY rather than about a person,
  // which is what a note above an empty form has to do.
  /**
   * Returns the container a new user lands in, in the ambient realm.
   *
   * @returns the DN
   */
  newUserContainer() {
    const { log, realms } = this.deps;
    log.debug("Entering AdminViews.newUserContainer().");
    if (!directoryReader) {
      log.debug("Leaving AdminViews.newUserContainer(). No directory is " +
                "loaded.");
      return 'ou=users,' + realms.baseDnOf(realms.current());
    }
    const info = directoryReader('');
    log.debug("Leaving AdminViews.newUserContainer(). " + info.usersDn);
    return info.usersDn;
  }

  // ---------------------------------------------------------------------------
  // WHAT /admin/rbac ANSWERS (2026-09-12). The console page is a long one — two
  // tables, a status block, four forms — and all of it is drawn from the twelve
  // facts computed at the top of it, which are now computed here.
  //
  // `candidates` comes with them although the page declares it half way down,
  // among the markup: it is `rbac.candidates()` over the keys of a map, the
  // json publishes it, and a second call to work it out again for the document
  // would be the page and the API asking the register two different questions.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/rbac`'s JSON: who holds each console role.
   *
   * @param req - the request
   * @returns the JSON
   */
  rbacListJson(req) {
    const { log, realms, rbac } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.rbacListJson().");
    // The roster of the realm being read (2026-09-14, #32): the service roster
    // in the default realm, that realm's own anywhere else.
    const info = rbac.describe(realms.currentId());
    const state = this.gateStateFor(req);

    // One row per grant, flattened out of the two rosters. Sorted by name and
    // then by role so that somebody holding both is two adjacent rows rather
    // than two rows a page apart.
    const grants = [];
    info.roles.forEach(function (role) {
      role.members.forEach(function (member) {
        grants.push({
          username: member.username, role: role.role, roleLabel: role.label,
          cn: role.cn, dn: role.dn, value: member.value,
          attribute: member.attribute,
          holds: member.holds, memberDn: member.dn, present: member.present,
          kind: member.kind, userKey: member.userKey
        });
      });
    });
    grants.sort(function (a, b) {
      const an = String(a.username).toLowerCase();
      const bn = String(b.username).toLowerCase();
      if (an !== bn) {
        return an < bn ? -1 : 1;
      }
      return a.role < b.role ? -1 : 1;
    });

    const wantedText = String(req.query.q || '').trim();
    const needle = wantedText.toLowerCase();
    const wantedRole = String(req.query.role || '').trim().toLowerCase();
    const filtered = grants.filter(function (row) {
      if (wantedRole && row.role !== wantedRole) {
        return false;
      }
      if (!needle) {
        return true;
      }
      return String(row.username).toLowerCase().indexOf(needle) >= 0 ||
             String(row.value).toLowerCase().indexOf(needle) >= 0;
    });

    const paging = this.pagingOf(req.query, filtered.length,
                                 { noun: 'grants' });
    const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
    const filterParams: Record<string, any> = { q: wantedText || '',
                                                role: wantedRole || '',
                           per: req.query.per ? paging.perPage : '' };
    const knownKeys = this.knownUserKeys();
    const candidates = rbac.candidates(Object.keys(knownKeys),
                                      realms.currentId());

    // WHO CAN BE PICKED, SEARCHED AND PAGED (2026-09-13). This was a `<select>`
    // holding every candidate, and a realm bulk loaded with thousands of people
    // made it a control nobody could use — and made this reply thousands of
    // rows long for a caller that wanted the roster. It is /admin/delegation's
    // person chooser now: `personq` narrows, `personfrom` pages by
    // CHOOSER_HITS, a stale offset is clamped rather than obeyed, and `person`
    // is the one a result link picked. The page draws the pane from the same
    // list with the same rule (chooserPane() in admin-ui/admin.ts), so what the
    // page shows and what `candidates` answers are the same twenty.
    //
    // `person` is RESOLVED against the candidates rather than echoed. The grant
    // form it opens says "picked from the list", and a name typed into the URL
    // that the list does not hold belongs on the typed form, which says what a
    // dangling grant is.
    const personWanted = this.queryOne(req.query, 'personq').trim();
    const candidateMatched = candidates.filter(function (row) {
      return self.chooserMatches([row.username], personWanted);
    });
    // PAGED THE WAY EVERY SECOND LIST IN A REPLY IS PAGED HERE:
    // `candidatesPage` and a `candidatesPaging` object beside the array, with
    // `per` shared with the grants — detailPagingParameters()'s naming, so a
    // caller that can read the reply can write the request. Two things differ
    // from a drill-down's lists and both are for the console's pane:
    //
    //   * the default page size is CHOOSER_HITS rather than DEFAULT_PER_PAGE,
    //     because the pane shows twenty and a reply that defaulted to fifty
    //     would be a second answer to "which people are on this page";
    //   * `personfrom`, the pane's own OFFSET, is honoured when
    //     `candidatesPage` is absent, as the page that offset falls on.
    //     chooserPane() pages by offset for every chooser in this console, and
    //     the pane's links carry one; `candidatesPage` wins when both are sent.
    const candidateOptions = { name: 'candidates', defaultPer: CHOOSER_HITS,
                               noun: 'people' };
    let candidatePaging = this.pagingOf(req.query, candidateMatched.length,
                                        candidateOptions);
    const offsetAsked = parseInt(this.queryOne(req.query, 'personfrom'), 10);
    if (this.queryOne(req.query, 'candidatesPage') === '' &&
        isFinite(offsetAsked) &&
        offsetAsked > 0 && offsetAsked < candidateMatched.length) {
      const asPage = Object.assign({}, req.query, {
        candidatesPage: String(Math.floor(offsetAsked /
                                          candidatePaging.perPage) + 1)
      });
      candidatePaging = this.pagingOf(asPage, candidateMatched.length,
                                      candidateOptions);
    }
    const candidateShown = candidateMatched.slice(candidatePaging.offset,
        candidatePaging.offset + candidatePaging.perPage);
    const personAsked = this.queryOne(req.query, 'person').trim();
    const picked = personAsked
      ? (candidates.filter(function (row) {
          return row.username.toLowerCase() === personAsked.toLowerCase();
        })[0] || null)
      : null;
    // The grants table's own controls carry the search, so that paging or
    // filtering the table does not clear the pane the reader is still using.
    filterParams.personq = personWanted;
    filterParams.personfrom = this.queryOne(req.query, 'personfrom');
    filterParams.person = personAsked;
    // THE PANE'S OWN SLICE (#446), by the chooser's rule rather than the
    // reply's paging: `personfrom` clamped as `chooserPane()` clamps it and
    // CHOOSER_HITS at a time whatever `per` says, so a page drawn from this
    // answer shows what the pane drawn from the whole catalogue showed.
    let paneFrom = parseInt(this.queryOne(req.query, 'personfrom'), 10);
    if (!isFinite(paneFrom) || paneFrom < 0 ||
        paneFrom >= candidateMatched.length) {
      paneFrom = 0;
    }
    const candidatePane = {
      from: paneFrom, matched: candidateMatched.length,
      shown: candidateMatched.slice(paneFrom, paneFrom + CHOOSER_HITS)
    };
    // Who of the grants on this page has authenticated here, for the
    // member cell's link — the page's people only, as the group drill-down
    // carries them.
    const knownHere: Record<string, boolean> = {};
    shown.forEach(function (row) {
      if (row.userKey && knownKeys[row.userKey]) {
        knownHere[row.userKey] = true;
      }
    });
    const pagingJson = this.pagingJson(paging);
    log.debug("Leaving AdminViews.rbacListJson(). " + candidateMatched.length +
              " of " +
              candidates.length + " candidate(s) match.");
    return {
      // `an` and `bn` are NOT here: they are locals inside the sort comparator
      // above, and a first pass of this split lifted them as though they were
      // the page's, which is a ReferenceError the moment anything asks.
      info: info, state: state, grants: grants,
      wantedText: wantedText, needle: needle, wantedRole: wantedRole,
      filtered: filtered, paging: paging, shown: shown,
      filterParams: filterParams, knownKeys: knownKeys, candidates: candidates,
      personWanted: personWanted, personAsked: personAsked, picked: picked,
      candidateMatched: candidateMatched,
      json: (function () {
      return {
          enforced: info.enforced, openWhenEmpty: info.openWhenEmpty,
          openToAnyone: info.openToAnyone,
          closedToEveryone: info.closedToEveryone,
          // #103 (2026-09-22): whether the mode opens the window here at all
          // (false in product), and whether the bootstrap administrator's
          // roles are honoured from a password sign-in only, until it claims.
          windowOpens: info.windowOpens,
          bootstrapPasswordRequired: info.bootstrapPasswordRequired,
          // THE BOOTSTRAP ADMINISTRATOR (2026-09-13): who it is, whether it was
          // seeded, and when it first signed in to the console — the moment
          // `openToAnyone` stopped being true. See admin_rbac.js.
          bootstrap: info.bootstrap,
          available: info.available, groupsDn: info.groupsDn,
          usersDn: info.usersDn,
          grantCount: info.grantCount, matched: filtered.length,
          shown: shown.length,
          settings: configSettingsJson('/admin/rbac'),
          filter: { q: wantedText || null, role: wantedRole || null },
          page: paging.page, pages: paging.pages, perPage: paging.perPage,
          firstRow: paging.firstRow, lastRow: paging.lastRow,
          // WHO IS ASKING, which is on the reply rather than only in the banner
          // because a caller driving this over JSON has no banner and the
          // answer to "why did that 403" is here.
          you: { username: state.username, roles: state.roles,
                 read: state.read, write: state.write,
                 viaEmptyRoster: state.open },
          // THE ROLES WITHOUT THEIR MEMBER LISTS (2026-09-13). `members` and
          // `claimed` were every membership value of each role, unpaged, and
          // they are the same rows `grants` carries — paged, and narrowed to
          // one role by `?role=`. So a role here is what it is and how many
          // hold it; who holds it is `grants`.
          roles: info.roles.map(function (role) {
            const out = Object.assign({}, role);
            delete out.members;
            delete out.claimed;
            return out;
          }),
          grants: shown,
          // THE SLICE, NOT THE REGISTER — see the comment above. The paging
          // object beside it says how much there is, so a caller can tell
          // twenty of twenty from twenty of five thousand.
          candidates: candidateShown,
          candidatesPaging: self.pagingJson(candidatePaging),
          candidateSearch: {
            q: personWanted || null, total: candidates.length,
            matched: candidateMatched.length
          },
          picked: personAsked
            ? { asked: personAsked, candidate: picked }
            : null,
          // What the page draws beside (#446): its paging, the pane's slice,
          // the people on the page who have signed in here, and the two
          // roles a grant can name.
          paging: pagingJson, candidatePane: candidatePane, known: knownHere,
          roleChoices: rbac.ROLES
      };
      }())
    };
  }

  // THE TWO LISTS ARE DIFFERENT QUESTIONS, and this is where that shows.
  //
  // The directory holds an entry for anybody somebody wrote one for — the three
  // it seeds at startup in development mode, and whatever a client has added
  // since. The users page
  // holds everybody who has actually presented a credential to this service.
  // `alice` is in the directory from the moment the process starts and is on
  // the users page only once somebody signs in as her, so a member row that
  // always linked there would usually land on "nothing here has authenticated
  // as alice", which reads as a broken link rather than as the fact it is.
  //
  // So the console's own user registry is consulted, and a member it does not
  // know is named without a link and with the reason. Reading it once per page
  // rather than once per row is deliberate: userRows() walks the whole
  // registry.
  /**
   * Returns the keys of every identity the console's user registry knows.
   *
   * @returns a set of keys, as an object
   */
  knownUserKeys() {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.knownUserKeys().");
    const known: Record<string, any> = {};
    // THE KEYS AND NOT THE ROWS (#352): `stats.userKeys()` answers the key of
    // every row `userRows()` would build, without building one — nine pages
    // ask this and every one of them threw the rows away.
    stats.userKeys().forEach(function (key) {
      known[key] = true;
    });
    log.debug("Leaving AdminViews.knownUserKeys().");
    return known;
  }

  // ---------------------------------------------------------------------------
  // WHAT /admin/saml2 ANSWERS. The list, and the drill-down below it.
  //
  // The page keeps `nav`, `listView` and the row markup; everything those are
  // built FROM is here, and so is the json, so the table a person reads and the
  // document a client fetches are one pass over the registry.
  // ---------------------------------------------------------------------------
  /**
   * Builds `/admin/saml2`'s list of service providers.
   *
   * @param req - the request
   * @returns the JSON
   */
  saml2ListJson(req) {
    const { log, baseUrlOf, saml2, spMetadata } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.saml2ListJson().");
    const base = baseUrlOf(req);
    const all = this.saml2ServiceProviders();
    const needle = String(req.query.q || '').trim().toLowerCase();
    const filtered = needle
      ? all.filter(function (row) {
          return row.identifier.toLowerCase().indexOf(needle) >= 0 ||
                 String(row.name).toLowerCase().indexOf(needle) >= 0;
        })
      : all;
    const paged = this.pagedRows(req.query, filtered,
                                 { noun: 'service providers' });
    const paging = paged.paging;
    const filterParams = { q: String(req.query.q || '') || '',
                           per: req.query.per ? paging.perPage : '' };
    // THE ENTITYIDS A REQUEST-STARTED METADATA QUERY WAS REFUSED FOR (#112):
    // product mode's record of who asked to be registered by the responder
    // and was not. A list of its own with a pager of its own
    // (`mdqRefusedPage`), named after the array as the API's rule for a reply
    // holding several lists asks.
    const refused = this.pagedRows(req.query, spMetadata.mdqRefusalList(),
                                   { name: 'mdqRefused',
                                     noun: 'refused entityIDs' });

    log.debug("Leaving AdminViews.saml2ListJson(). " + filtered.length +
              " of " +
              all.length + ".");
    return {
      base: base, all: all, needle: needle, filtered: filtered,
      paged: paged, paging: paging, filterParams: filterParams,
      refused: refused,
      json: (function () {
      return {
          serviceProviders: paged.shown.map(function (row) {
            return Object.assign(self.saml2Facts(base, row.identifier), {
              name: row.name, authentications: row.authentications,
              sessions: row.sessions,
              users: row.users, firstSeen: row.firstSeen,
              lastSeen: row.lastSeen,
              assertionConsumerServices: self.valuesFor(
                  row.fields.samlAssertionConsumerService),
              singleLogoutServices:
                self.valuesFor(row.fields.samlSingleLogoutService),
              nameIdFormats: self.valuesFor(row.fields.samlNameIdFormat),
              responseBindings: self.valuesFor(row.fields.samlResponseBinding),
              lastRequestSigned: row.fields.samlAuthnRequestSigned === 'TRUE',
              lastRequestVerification:
                String(row.fields.samlAuthnRequestVerification || '')
                  .split(' ')[0]
            });
          }),
          paging: paging,
          unscopedMetadata: self.saml2Facts(base, '').metadataUrl,
          // The settings this page now EDITS, in the shape every page that owns
          // settings answers with: described rows carrying their source and
          // whether they can be changed while the service runs. It was a flat
          // key-to-value map while they were readings, which could say what a
          // value was and not where it came from — the question a person asking
          // about somebody else's deployment actually has.
          settings: configSettingsJson('/admin/saml2'),
          // Two numbers about the PROFILE rather than about any one service
          // provider, and both are the kind of thing that is invisible until it
          // is wrong: artifacts waiting to be resolved, and AuthnRequests held
          // while a browser is at the sign-in screen. A count that never falls
          // is a leak.
          artifactsAwaitingResolution: saml2.artifactCount(),
          requestsHeldForSignIn: saml2.pendingRequestCount(),
          mdqRefused: refused.shown,
          mdqRefusedPaging: refused.paging,
          // The kind the applications page files these entries under, for
          // the page's link to them (#446).
          kind: SAML2_SP_KIND
      };
      }())
    };
  }

  /**
   * Builds one SAML 2.0 service provider's drill-down.
   *
   * @param req - the request
   * @param identifier - the entityID
   * @returns the JSON
   */
  saml2DetailJson(req, identifier) {
    const { log, baseUrlOf, applications, requestSignature } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.saml2DetailJson(). identifier=" +
              identifier);
    const base = baseUrlOf(req);
    const facts = this.saml2Facts(base, identifier);
    const row = applications.get(identifier);
    const fields = (row && row.fields) || {};
    const acs = this.valuesFor(fields.samlAssertionConsumerService);
    const slo = this.valuesFor(fields.samlSingleLogoutService);
    log.debug("Leaving AdminViews.saml2DetailJson(). found=" + !!row);
    return {
      base: base, facts: facts, row: row, fields: fields, acs: acs, slo: slo,
      json: (function () {
      return Object.assign({ found: !!row }, facts, {
          name: (row && row.name) || '',
          authentications: (row && row.authentications) || 0,
          assertionConsumerServices: acs,
          singleLogoutServices: slo,
          nameIdFormats: self.valuesFor(fields.samlNameIdFormat),
          responseBindings: self.valuesFor(fields.samlResponseBinding),
          lastRequestSigned: fields.samlAuthnRequestSigned === 'TRUE',
          // THE SIGNATURE CHECK (#37). `signingCertificate` is kept, as the
          // first registered certificate, for the callers that read it when
          // the attribute held one value; `signingCertificates` is the list
          // requests are verified against.
          lastRequestVerification: self.verificationOf(
            fields.samlAuthnRequestVerification),
          signingCertificate:
            self.valuesFor(fields.samlSigningCertificate)[0] || '',
          signingCertificates: self.valuesFor(fields.samlSigningCertificate),
          observedSigningCertificate:
            String(fields.samlObservedSigningCertificate || ''),
          signedRequestsRequired: requestSignature.requiresSignedRequests(
            fields),
          metadata: self.consumedMetadataOf(fields, identifier),
          // Whether the identity provider names itself per service
          // provider, which the page's first row explains (#446).
          perApplicationEntityId:
            !!config.value('saml2.perApplicationEntityId')
      });
      }())
    };
  }

  // `<outcome> <binding> <sigAlg> [weak]`, as the SSO service records it, as
  // an object.
  /**
   * Parses a recorded request verification, `<outcome> <binding> <sigAlg>
   * [weak]`.
   *
   * @param value - the recorded text
   * @returns the outcome, binding, signature method and whether it was weak
   */
  verificationOf(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.verificationOf().");
    const parts = String(value || '').split(' ');
    log.debug("Leaving AdminViews.verificationOf().");
    return {
      outcome: parts[0] || '',
      binding: parts[1] && parts[1] !== '-' ? parts[1] : '',
      signatureMethod: parts[2] && parts[2] !== '-' ? parts[2] : '',
      weak: parts[3] === 'weak'
    };
  }

  // WHAT CONSUMING THE SERVICE PROVIDER'S METADATA WROTE (#37), as the page
  // and `GET /admin-api/saml2?sp=` show it. `consumed` is false for an entry
  // no document has been consumed onto. Since the #37 follow-up `state` is
  // `sp_metadata.ts`'s freshness — fresh, stale or expired, ENFORCED — and
  // `refresh` is what the background refresher last found.
  /**
   * Describes the SAML metadata consumed onto a service provider's entry, and
   * its freshness.
   *
   * @param fields - the entry's attributes
   * @param entityId - the entityID
   * @returns the description; `consumed` is false when none was
   */
  consumedMetadataOf(fields, entityId?) {
    const { log, spMetadata, config } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.consumedMetadataOf().");
    const consumedAt = String(fields.samlSpMetadataConsumedAt || '');
    const validUntil = String(fields.samlSpMetadataValidUntil || '');
    const fresh = spMetadata.freshness(fields);
    const identifier = entityId || self.valuesFor(fields.samlEntityId)[0] ||
                       '';
    log.debug("Leaving AdminViews.consumedMetadataOf().");
    return {
      state: fresh.state,
      stateWhy: fresh.why,
      expiresAt: fresh.expiresAt,
      staleAt: fresh.staleAt,
      refreshable: fresh.refreshable,
      refresh: identifier ? spMetadata.refreshStatus(identifier) : null,
      refresherEnabled: !!config.value('saml2.spMetadataRefresh'),
      refresherRunning: spMetadata.refresherRunning(),
      trustAnchors: spMetadata.trustAnchorsFor(fields).length,
      trustAnchorProblems: spMetadata.anchorProblems(),
      mdqUrl: identifier ? spMetadata.mdqUrlFor(identifier) : '',
      consumed: !!consumedAt,
      consumedAt: consumedAt.split(' ')[0] || '',
      how: consumedAt.split(' ')[1] || '',
      url: self.valuesFor(fields.samlSpMetadataUrl)[0] || '',
      signature: String(fields.samlSpMetadataSignature || ''),
      signingCertificateConfigured:
        !!String(fields.samlSpMetadataSigningCertificate || ''),
      validUntil: validUntil,
      expired: fresh.state === 'expired',
      cacheDuration: String(fields.samlSpMetadataCacheDuration || ''),
      authnRequestsSigned: fields.samlSpAuthnRequestsSigned === 'TRUE',
      wantAssertionsSigned: fields.samlSpWantAssertionsSigned === 'TRUE',
      wantAssertionsEncrypted:
        fields.samlSpWantAssertionsEncrypted === 'TRUE',
      nameIdFormats: self.valuesFor(fields.samlSpNameIdFormat),
      assertionConsumerServices: self.valuesFor(fields.samlAcsEndpoint)
        .map(function (value) {
          const parts = value.split(' ');
          return { index: parts[0] === '-' ? '' : parts[0],
                   isDefault: parts[1] === 'true' ? true
                     : (parts[1] === 'false' ? false : null),
                   binding: parts[2] || '',
                   location: parts.slice(3).join(' ') };
        }),
      singleLogoutServices: self.valuesFor(fields.samlSloEndpoint)
        .map(function (value) {
          const parts = value.split(' ');
          return { binding: parts[0] || '', location: parts[1] || '',
                   responseLocation: parts[2] || '' };
        }),
      encryptionCertificate:
        !!self.valuesFor(fields.samlEncryptionCertificate).length
    };
  }

  // WHICH OF THE TWO A REQUEST IS ASKING FOR, decided the way the page decides
  // it — `?sp=` means the drill-down. It is here rather than in the management
  // API so that the page and the document cannot disagree about what a query
  // string means.
  /**
   * Builds `/admin/saml2`'s JSON: the list, or the drill-down with `?sp=`.
   *
   * @param req - the request
   * @returns the JSON
   */
  saml2Json(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.saml2Json().");
    const wanted = String((req.query || {}).sp || '').trim();
    log.debug("Leaving AdminViews.saml2Json().");
    return wanted ? this.saml2DetailJson(req, wanted).json :
           this.saml2ListJson(req).json;
  }

  // Every application this profile has answered for. Read off the registry
  // rather than kept, so a service provider created by an `ldapadd` appears
  // here with no help from this file.
  /**
   * Lists every application the SAML 2.0 profile has answered for.
   *
   * @returns the applications
   */
  saml2ServiceProviders() {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.saml2ServiceProviders().");
    const rows = applications.list().filter(function (row) {
      return row.kinds.indexOf(SAML2_SP_KIND) >= 0;
    });
    log.debug("Leaving AdminViews.saml2ServiceProviders(). " + rows.length +
              " service " +
        "provider(s).");
    return rows;
  }

  // One service provider's four URLs and its entityID, from the profile's own
  // functions (`saml/saml2_sso.ts`). Never rebuilt here, so the page cannot
  // publish an address the profile does not answer on.
  /**
   * Returns one service provider's four URLs and its entityID, from the
   * profile's own functions.
   *
   * @param base - the base URL
   * @param identifier - the entityID
   * @returns the facts
   */
  saml2Facts(base, identifier) {
    const { log, saml2 } = this.deps;
    log.debug("Entering AdminViews.saml2Facts().");
    const where = saml2.endpointsFor(base, identifier);
    log.debug("Leaving AdminViews.saml2Facts().");
    return {
      identifier: identifier,
      slug: saml2.slugOf(identifier),
      idpEntityId: saml2.idpEntityIdFor(identifier),
      metadataUrl: where.metadata,
      ssoUrl: where.sso,
      sloUrl: where.slo,
      arsUrl: where.ars
    };
  }

  // An attribute's values as a plain array whatever the schema's `kind` is. The
  // registry hands back a string for a single-valued attribute and an array for
  // a multi-valued one, and a JSON reply that varied between the two shapes
  // would be one a caller has to test the type of.
  /**
   * Returns an attribute's values as an array, whatever its kind.
   *
   * @param value - the value or values
   * @returns the values
   */
  valuesFor(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.valuesFor().");
    if (value === undefined || value === null || value === '') {
      log.debug("Leaving AdminViews.valuesFor().");
      return [];
    }
    log.debug("Leaving AdminViews.valuesFor().");
    return Array.isArray(value) ? value.slice(0) : [String(value)];
  }

  // WHAT /admin/saml11 ANSWERS. Built the same way as the SAML 2.0 pair above
  // and kept separate from it for the reason saml/CLAUDE.md gives about the two
  // profiles: they share a framework and almost no spelling.
  /**
   * Builds `/admin/saml11`'s list of relying parties.
   *
   * @param req - the request
   * @returns the JSON
   */
  saml11ListJson(req) {
    const { log, baseUrlOf, saml11 } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.saml11ListJson().");
    const base = baseUrlOf(req);
    const all = this.saml11RelyingParties();
    const needle = String(req.query.q || '').trim().toLowerCase();
    const filtered = needle
      ? all.filter(function (row) {
          return row.identifier.toLowerCase().indexOf(needle) >= 0 ||
                 String(row.name).toLowerCase().indexOf(needle) >= 0;
        })
      : all;
    const paged = this.pagedRows(req.query, filtered,
                                 { noun: 'relying parties' });
    const paging = paged.paging;
    const filterParams = { q: String(req.query.q || '') || '',
                           per: req.query.per ? paging.perPage : '' };
    log.debug("Leaving AdminViews.saml11ListJson().");
    return {
      base: base, all: all, needle: needle, filtered: filtered,
      paged: paged, paging: paging, filterParams: filterParams,
      json: (function () {
      return {
          relyingParties: paged.shown.map(function (row) {
            return Object.assign(self.saml11Facts(base, row.identifier), {
              name: row.name, authentications: row.authentications,
              sessions: row.sessions,
              users: row.users, firstSeen: row.firstSeen,
              lastSeen: row.lastSeen,
              assertionConsumerServices: self.valuesFor(
                  row.fields.samlAssertionConsumerService),
              nameIdFormats: self.valuesFor(row.fields.samlNameIdFormat),
              profiles: self.valuesFor(row.fields.samlResponseBinding).filter(
                  function (v) {
                return v === saml11.PROFILE_POST || v ===
                       saml11.PROFILE_ARTIFACT;
              })
            });
          }),
          paging: paging,
          unscopedMetadata: self.saml11Facts(base, '').metadataUrl,
          // The shape every page that owns settings answers with. See the SAML
          // 2.0 page's equivalent for why it is no longer a flat map.
          settings: configSettingsJson('/admin/saml11'),
          // Three numbers about the PROFILE rather than about any one relying
          // party, and all three are the kind of thing that is invisible until
          // it is wrong: artifacts minted and not yet resolved, assertions held
          // for an AssertionIDReference, and flows held while a browser is at
          // the sign-in screen. A count that never falls is a leak; the middle
          // one is CAPPED rather than swept, so it is the one that should sit
          // at its ceiling.
          artifactsAwaitingResolution: saml11.artifactCount(),
          assertionsHeldByReference: saml11.cachedAssertionCount(),
          flowsHeldForSignIn: saml11.pendingFlowCount(),
          // The kind the applications page files these entries under, for
          // the page's link to them (#446).
          kind: SAML11_RP_KIND
      };
      }())
    };
  }

  /**
   * Builds one SAML 1.1 relying party's drill-down.
   *
   * @param req - the request
   * @param identifier - the providerID
   * @returns the JSON
   */
  saml11DetailJson(req, identifier) {
    const { log, baseUrlOf, applications, saml11 } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.saml11DetailJson(). identifier=" +
              identifier);
    const base = baseUrlOf(req);
    const facts = this.saml11Facts(base, identifier);
    const row = applications.get(identifier);
    const fields = (row && row.fields) || {};
    const acs = this.valuesFor(fields.samlAssertionConsumerService);
    const profiles = this.valuesFor(fields.samlResponseBinding)
      .filter(function (v) {
      return v === saml11.PROFILE_POST || v === saml11.PROFILE_ARTIFACT;
    });

    // WHETHER THE ENDPOINTS WERE GUESSED, which the page also decides for its
    // own warning line. It is one regex over the identifier; both halves say
    // the same thing about it because both compute it from the same input.
    const looksGuessed = /^https?:\/\/[^/]+$/i.test(identifier);
    log.debug("Leaving AdminViews.saml11DetailJson(). found=" + !!row);
    return {
      base: base, facts: facts, row: row, fields: fields,
      acs: acs, profiles: profiles,
      json: (function () {
      return Object.assign(facts, {
          registered: !!row,
          identifierLooksGuessed: looksGuessed,
          name: row ? row.name : '',
          authentications: row ? row.authentications : 0,
          assertionConsumerServices: acs,
          nameIdFormats: self.valuesFor(fields.samlNameIdFormat),
          profiles: profiles,
          // Whether the identity provider names itself per relying party,
          // which the page's first row explains (#446).
          perApplicationProviderId:
            !!config.value('saml11.perApplicationProviderId')
      });
      }())
    };
  }

  // `?rp=` means the drill-down here where SAML 2.0 uses `?sp=` — one of the
  // six spellings saml/CLAUDE.md tabulates.
  /**
   * Builds `/admin/saml11`'s JSON: the list, or the drill-down with `?rp=`.
   *
   * @param req - the request
   * @returns the JSON
   */
  saml11Json(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.saml11Json().");
    const wanted = String((req.query || {}).rp || '').trim();
    log.debug("Leaving AdminViews.saml11Json().");
    return wanted ? this.saml11DetailJson(req, wanted).json :
           this.saml11ListJson(req).json;
  }

  // Every application this profile has answered for. Read off the registry
  // rather than kept, so a relying party created by an `ldapadd` appears here
  // with no help from this file.
  //
  // **THE KIND IS SHARED WITH WS-FEDERATION AND THAT IS DELIBERATE.**
  // `saml11-relying-party` is what a WS-Federation relying party handed a 1.1
  // assertion has always been recorded as, and a relying party that takes the
  // same assertion through the passive requestor profile and through
  // Browser/POST is ONE application with one audience. Giving the browser
  // profiles a kind of their own would have split one entry into two, which is
  // the defect this repository calls two spellings of one DN. The consequence
  // to know when reading this list: a row here may have arrived through /wsfed
  // and never touched /saml11, which is why the profiles column says what it
  // has actually used.
  /**
   * Lists every application the SAML 1.1 profile has answered for.
   *
   * @returns the applications
   */
  saml11RelyingParties() {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.saml11RelyingParties().");
    const rows = applications.list().filter(function (row) {
      return row.kinds.indexOf(SAML11_RP_KIND) >= 0;
    });
    log.debug("Leaving AdminViews.saml11RelyingParties(). " + rows.length +
              " relying " +
        "party/parties.");
    return rows;
  }

  // One relying party's three URLs and its providerID, from the profile's own
  // functions (`saml/saml11_sso.ts`). Never rebuilt here, for saml2Facts()'s
  // reason.
  /**
   * Returns one relying party's three URLs and its providerID, from the
   * profile's own functions.
   *
   * @param base - the base URL
   * @param identifier - the providerID
   * @returns the facts
   */
  saml11Facts(base, identifier) {
    const { log, saml11 } = this.deps;
    log.debug("Entering AdminViews.saml11Facts().");
    const where = saml11.endpointsFor(base, identifier);
    log.debug("Leaving AdminViews.saml11Facts().");
    return {
      identifier: identifier,
      slug: saml11.slugOf(identifier),
      idpProviderId: saml11.providerIdFor(identifier),
      metadataUrl: where.metadata,
      ssoUrl: where.sso,
      responderUrl: where.responder
    };
  }

  // WHAT /admin/authorization-servers ANSWERS: the profiles, and one of them.
  /**
   * Builds `/admin/authorization-servers`'s list of profiles.
   *
   * @param req - the request
   * @returns the JSON
   */
  asListJson(req) {
    const { log, authorizationServers } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.asListJson().");
    const all = authorizationServers.list();
    const paged = this.pagedRows(req.query, all,
                                 { noun: 'authorization servers' });
    const paging = paged.paging;
    const pagingJson = this.pagingJson(paging);
    // The page's three tiles count every profile, not the page shown (#446).
    const overrideTotal = all.reduce(function (n, r) {
      return n + Object.keys(r.overrides).length;
    }, 0);
    const driftTotal = all.reduce(function (n, r) {
      return n + self.asDriftRows(r.id).length;
    }, 0);
    log.debug("Leaving AdminViews.asListJson().");
    return {
      all: all, paged: paged, paging: paging,
      json: (function () {
      return {
          profileCount: all.length, shown: paged.shown.length,
          page: paging.page, pages: paging.pages, perPage: paging.perPage,
          firstRow: paging.firstRow, lastRow: paging.lastRow,
          members: authorizationServers.MEMBERS,
          paging: pagingJson, overrideTotal: overrideTotal,
          driftTotal: driftTotal,
          authorizationServers: paged.shown.map(function (row) {
            return Object.assign({}, row, { drift: self.asDriftRows(row.id) });
          })
      };
      }())
    };
  }

  // The drill-down. `capabilities` is the document the authorization server
  // publishes and `drift` is where its members disagree with this service's own
  // — both are what the page draws AND what the resource answers.
  /**
   * Builds one authorization server's drill-down: its published capabilities
   * and where they drift from this service's own.
   *
   * @param req - the request
   * @param id - the profile's id
   * @returns the JSON
   */
  asDetailJson(req, id) {
    const { log, oauth2, authorizationServers } = this.deps;
    log.debug("Entering AdminViews.asDetailJson(). id=" + id);
    const profile = authorizationServers.get(id);
    if (!profile) {
      log.debug("Leaving AdminViews.asDetailJson(). No such profile.");
      return { profile: null, json: { found: false, id: id } };
    }
    const drift = this.asDriftRows(id);
    // The document this authorization server publishes, which is the same
    // object its endpoints read their capabilities out of.
    const capabilities = authorizationServers.capabilitiesOf(id,
      oauth2.asMetadata(this.asTruthRequest(), true));
    log.debug("Leaving AdminViews.asDetailJson(). " + drift.length +
              " drifting member(s).");
    return {
      profile: profile, drift: drift, capabilities: capabilities,
      // What the page draws beside the profile (#446): the effective
      // capabilities, and the member catalogue its two menus are built from.
      json: Object.assign({ found: true }, profile, {
        drift: drift, capabilities: capabilities,
        members: authorizationServers.MEMBERS,
        memberGroups: authorizationServers.GROUPS
      })
    };
  }

  // `?profile=` means the drill-down.
  /**
   * Builds `/admin/authorization-servers`'s JSON: the list, or the drill-down
   * with `?profile=`.
   *
   * @param req - the request
   * @returns the JSON
   */
  authorizationServersJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.authorizationServersJson().");
    const wanted = String((req.query || {}).profile || '').trim();
    log.debug("Leaving AdminViews.authorizationServersJson().");
    return wanted ? this.asDetailJson(req, wanted).json :
           this.asListJson(req).json;
  }

  /**
   * Lists where a named authorization server's metadata differs from this
   * service's own.
   *
   * @param id - the profile's id
   * @returns the drift rows
   */
  asDriftRows(id) {
    const { log, oauth2, authorizationServers } = this.deps;
    log.debug("Entering AdminViews.asDriftRows().");
    log.debug("Leaving AdminViews.asDriftRows().");
    // The document this service would publish for THIS profile if the profile
    // said nothing — built from the same function the endpoints serve, so the
    // comparison cannot go stale as that document grows members.
    // `asTruthRequest()` gives it a request-shaped object because asMetadata()
    // derives every URL in it from the one the request arrived on.
    return authorizationServers.driftOf(id, oauth2.asMetadata(
        this.asTruthRequest()));
  }

  // A request-shaped stand-in, so the document can be built outside a request.
  // The host is this service's own default, which is what /admin/config and
  // /admin/sts-metadata already assume when they name a URL: the console is
  // being read by somebody who reached this process, and the comparison is
  // about MEMBERS rather than about hostnames.
  /**
   * Builds the request this service's own metadata is computed for, at its
   * default host.
   *
   * @returns the request
   */
  asTruthRequest() {
    const { log, config } = this.deps;
    log.debug("Entering AdminViews.asTruthRequest().");
    log.debug("Leaving AdminViews.asTruthRequest().");
    return {
      protocol: config.value('global.https') ? 'https' : 'http',
      get: function (name) {
        log.debug("Entering get().");
        log.debug("Leaving get().");
        return String(name).toLowerCase() === 'host'
          ? 'localhost:' + config.value('global.port') : '';
      },
      query: {}
    };
  }

  // WHAT /admin/groups ANSWERS. The two totals come with the computation
  // although the page declares them among its markup: they are one reduce each
  // over the same list, and the tiles a person reads are the numbers the
  // resource publishes.
  /**
   * Builds `/admin/groups`'s list, with its totals.
   *
   * @param req - the request
   * @returns the JSON
   */
  groupsListJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.groupsListJson().");
    const info = groupReader('');
    const wantedText = String(req.query.q || '').trim();
    const needle = wantedText.toLowerCase();
    // DNs LEFT OUT OF THE MATCH (#459), before the paging, for the
    // application page's search for `appDelegationSubjectGroup`: the groups
    // its list already holds. A DN is compared as LDAP compares one — case
    // and the spaces after a comma do not matter.
    const dnKey = function (dn) {
      return String(dn).trim().toLowerCase().replace(/\s*,\s*/g, ',');
    };
    const excluded = [].concat(req.query.exclude === undefined
                                 ? [] : req.query.exclude)
      .map(dnKey)
      .filter(function (one) { return one !== ''; });
    const filtered = info.groups.filter(function (group) {
      if (excluded.indexOf(dnKey(group.dn)) >= 0) {
        return false;
      }
      if (!needle) {
        return true;
      }
      // The DN and the cn both, because a person looking for a group has one or
      // the other in mind and which one depends on whether they came from an
      // LDAP client or from this console.
      return group.dn.toLowerCase().indexOf(needle) >= 0 ||
             String(group.cn).toLowerCase().indexOf(needle) >= 0;
    });
    const paging = this.pagingOf(req.query, filtered.length);
    const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
    const filterParams = { q: wantedText || '',
                           per: req.query.per ? paging.perPage : '' };
    const totalMembers = info.groups.reduce(function (n, g) {
      return n + g.memberCount;
    }, 0);
    const totalDangling = info.groups.reduce(function (n, g) {
      return n + g.danglingCount;
    }, 0);
    const pagingJson = this.pagingJson(paging);
    log.debug("Leaving AdminViews.groupsListJson().");
    return {
      info: info, wantedText: wantedText, needle: needle, filtered: filtered,
      paging: paging, shown: shown, filterParams: filterParams,
      totalMembers: totalMembers, totalDangling: totalDangling,
      json: (function () {
      return {
          groupCount: info.groupCount, matched: filtered.length,
          shown: shown.length,
          // WHETHER THE TWO CONTROLS ARE THERE, on the JSON as well as on the
          // page. A caller of /admin-api/groups that got a 400 saying "no
          // directory is loaded" from the create beside it would otherwise have
          // no way to tell that from a create it had got wrong.
          canWrite: !!groupWriter,
          membershipValues: totalMembers, dangling: totalDangling,
          settings: configSettingsJson('/admin/groups'),
          filter: { q: wantedText || null,
                    exclude: excluded.length ? excluded : null },
          page: paging.page, pages: paging.pages, perPage: paging.perPage,
          firstRow: paging.firstRow, lastRow: paging.lastRow,
          baseDn: info.baseDn, groupsDn: info.groupsDn, usersDn: info.usersDn,
          port: info.port, listening: info.listening, listenError:
                                                        info.listenError,
          ldapsPort: info.ldapsPort, ldapsListening: info.ldapsListening,
          // WHAT THE PAGE DRAWS AND THIS ANSWER DID NOT CARRY (#446): the
          // paging control's own object, the directory's size for the fourth
          // tile, and the two console groups the caveat names.
          paging: pagingJson, entryCount: info.entryCount,
          adminGroups: { read: config.value('admin.readGroup'),
                         write: config.value('admin.writeGroup') },
          groups: shown
      };
      }())
    };
  }

  // The group drill-down. Two paged lists on one page, so the answer carries
  // both pagings; the page draws the navs from them.
  /**
   * Builds one group's drill-down, with its two paged lists.
   *
   * @param req - the request
   * @param wantedDn - the group's DN
   * @returns the JSON
   */
  groupDetailJson(req, wantedDn) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.groupDetailJson(). dn=" + wantedDn);
    const info = groupReader(wantedDn);
    if (!info.found) {
      log.debug("Leaving AdminViews.groupDetailJson(). Not a group.");
      return { info: info, json: Object.assign({ found: false }, info, {
        wanted: wantedDn,
        adminGroups: { read: config.value('admin.readGroup'),
                       write: config.value('admin.writeGroup') }
      }) };
    }
    const group = info.group;
    const known = this.knownUserKeys();

    // Two lists on this page and a page parameter each, sharing `per` — the
    // same arrangement the users drill-down has, and for the same reason: one
    // `page` would move both, and the two disagreements this page exists to
    // show are read against each other, so advancing the members while the
    // claimants jumped with them would be the one navigation that makes the
    // page harder to read than no navigation.
    //
    // The counts above the tables — memberCount, presentCount, danglingCount —
    // stay counts of the WHOLE list and are read off the directory rather than
    // off the slice, because "seven members, five resolve" is the fact the page
    // is for and "five members on this page" is not an answer to it.
    const params = this.pageParamsOf(req.query);
    const memberPage = this.pagedRows(req.query, group.members,
                                      { name: 'members', noun: 'members' });
    const claimedPage = this.pagedRows(req.query, group.claimed,
                                       { name: 'claimed', noun: 'entries' });

    // THE GROUP AS THIS PAGE OF IT, which the page used to build after its own
    // row markup — so the first pass of this split returned a name nothing
    // here declared. Recovered from the committed file rather than retyped.
    const pagedGroup = Object.assign({}, group, {
      members: memberPage.shown, claimed: claimedPage.shown
    });
    // WHO OF THIS PAGE HAS AUTHENTICATED HERE (#446): the users-page links
    // are drawn only for them, and the page is drawn from this answer. Only
    // the names on this page, because the register is every person who ever
    // signed in and the page needs a dozen of them.
    const knownHere: Record<string, boolean> = {};
    memberPage.shown.concat(claimedPage.shown).forEach(function (one) {
      if (one.userKey && known[one.userKey]) {
        knownHere[one.userKey] = true;
      }
    });
    log.debug("Leaving AdminViews.groupDetailJson().");
    return {
      info: info, group: group, known: known, params: params,
      memberPage: memberPage, claimedPage: claimedPage, pagedGroup: pagedGroup,
      json: Object.assign({ found: true }, info, {
        canWrite: !!groupWriter,
        group: pagedGroup,
        membersPaging: this.pagingJson(memberPage.paging),
        claimedPaging: this.pagingJson(claimedPage.paging),
        known: knownHere,
        adminGroups: { read: config.value('admin.readGroup'),
                       write: config.value('admin.writeGroup') }
      })
    };
  }

  // `?group=` means the drill-down — and the NO-DIRECTORY branch comes first,
  // exactly as it does on the page. Without it a build with no ldap_server.js
  // reaches `groupReader(...)` and throws, where the page answers "the page
  // exists, the directory does not", which are different facts about a process.
  /**
   * Builds `/admin/groups`'s JSON: the list, the drill-down with `?group=`, or
   * the no-directory answer.
   *
   * @param req - the request
   * @returns the JSON
   */
  groupsJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.groupsJson().");
    if (!groupReader) {
      log.debug("groupsJson(): no directory is loaded.");
      log.debug("Leaving AdminViews.groupsJson().");
      return { directory: false, groups: [] };
    }
    const wanted = String((req.query || {}).group || '').trim();
    log.debug("Leaving AdminViews.groupsJson().");
    return wanted ? this.groupDetailJson(req, wanted).json :
           this.groupsListJson(req).json;
  }

  /**
   * Returns a query's view parameters, first value each, without `format`,
   * `notice` and `error`.
   *
   * @param query - the query
   * @returns the parameters
   */
  pageParamsOf(query) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.pageParamsOf().");
    // The kit's since #446, with its reasoning: a renderer in a browser
    // names the same view parameters this does.
    const out = WebKit.pageParamsOf(query);
    log.debug("Leaving AdminViews.pageParamsOf(). " +
              Object.keys(out).length + " parameter(s).");
    return out;
  }

  // THE LIST'S EXPIRING-SECRET MARK (#49 P5): a client secret that has
  // expired, or expires within oauth2.clientSecretExpiryWarningDays — the
  // same two the daily job oauth2.client-secret-expiry warns about. Judged
  // here since #446, against the clock and
  // `oauth2.clientSecretExpiryWarningDays`, so the answer says it and a page
  // drawn from the answer needs neither.
  /**
   * Judges an application's client secret against its expiry.
   *
   * @param row - the application, as the register lists it
   * @returns `{ state, at }` — `expired`, `soon` or `''`, and the expiry as
   *   an ISO 8601 instant ('' when the secret does not expire)
   */
  secretExpiryOf(row) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.secretExpiryOf().");
    const record = applications.get(row.identifier);
    const fields = (record && record.fields) || {};
    const expiresAt = fields.oauthClientSecret
      ? applications.secretExpiryOf(fields) : 0;
    if (!expiresAt) {
      log.debug("Leaving AdminViews.secretExpiryOf(). None.");
      return { state: '', at: '' };
    }
    const nowS = Math.floor(Date.now() / 1000);
    const warnS = Number(config.value('oauth2.clientSecretExpiryWarningDays')) *
                  86400;
    log.debug("Leaving AdminViews.secretExpiryOf().");
    return {
      state: expiresAt <= nowS ? 'expired'
                               : (expiresAt - nowS <= warnS ? 'soon' : ''),
      at: new Date(expiresAt * 1000).toISOString()
    };
  }

  // WHAT /admin/applications ANSWERS. `registeredCount` comes with the
  // computation although the page declares it among the markup: the tile a
  // person reads and the number the resource publishes are one count.
  /**
   * Builds `/admin/applications`'s list, with its registered count.
   *
   * @param req - the request
   * @returns the JSON
   */
  applicationsListJson(req) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.applicationsListJson().");
    const all = applications.list();
    const wantedText = String(req.query.q || '').trim();
    const wantedKind = String(req.query.kind || '').trim();
    const needle = wantedText.toLowerCase();
    // IDENTIFIERS LEFT OUT OF THE MATCH (#459), exactly as spelled, BEFORE
    // the paging — so a page still holds `per` rows. The application page's
    // search for the two delegation lists sends the application itself and
    // what its list already holds, neither of which it could add.
    const excluded = [].concat(req.query.exclude === undefined
                                 ? [] : req.query.exclude)
      .map(function (one) { return String(one).trim(); })
      .filter(function (one) { return one !== ''; });
    const filtered = all.filter(function (row) {
      if (excluded.indexOf(row.identifier) >= 0) {
        return false;
      }
      // Recorded OR declared, the union the Kind column shows — a filter
      // that dropped a row showing the kind asked for would be lying.
      if (wantedKind && row.kinds.indexOf(wantedKind) < 0 &&
          (row.declaredKinds || []).indexOf(wantedKind) < 0) {
        return false;
      }
      if (!needle) {
        return true;
      }
      // The identifier and the name both, because somebody looking for an
      // application has one or the other in mind and which one depends on
      // whether they came from a client's configuration or from this console.
      return row.identifier.toLowerCase().indexOf(needle) >= 0 ||
             String(row.name).toLowerCase().indexOf(needle) >= 0;
    });
    const paged = this.pagedRows(req.query, filtered, { noun: 'applications' });
    const paging = paged.paging;
    const filterParams = { q: wantedText || '', kind: wantedKind || '',
                           per: req.query.per ? paging.perPage : '' };
    // Every registration, not only RFC 7591's: the Registered column counts
    // an application an administrator created, and so does this.
    const registeredCount =
        all.filter(function (row) {
          return row.registered || !!row.registeredBy;
        }).length;
    // WHAT THE PAGE COUNTS AND MARKS (#446): the kind menu counts over every
    // application, the tile sums every authentication, and a row's client
    // secret is judged against the clock and the warning setting here,
    // where both are, rather than in a page that has neither.
    const self = this;
    const kindCounts: Record<string, number> = {};
    applications.KINDS.forEach(function (one) {
      kindCounts[one.kind] = all.filter(function (row) {
        return row.kinds.indexOf(one.kind) >= 0 ||
               (row.declaredKinds || []).indexOf(one.kind) >= 0;
      }).length;
    });
    const authenticationTotal = all.reduce(function (n, r) {
      return n + r.authentications;
    }, 0);
    // Each row with its credentials masked (#446): no GET carries one.
    const shownRows = paged.shown.map(function (row) {
      return Object.assign(self.maskedApplicationRow(row),
                           { secretExpiry: self.secretExpiryOf(row) });
    });
    const pagingJson = this.pagingJson(paging);
    log.debug("Leaving AdminViews.applicationsListJson().");
    return {
      all: all, wantedText: wantedText, wantedKind: wantedKind, needle: needle,
      filtered: filtered, paged: paged, paging: paging,
      filterParams: filterParams, registeredCount: registeredCount,
      json: (function () {
      return {
          applicationCount: all.length, matched: filtered.length,
          shown: paged.shown.length,
          registered: registeredCount,
          filter: { q: wantedText || null, kind: wantedKind || null,
                    exclude: excluded.length ? excluded : null },
          page: paging.page, pages: paging.pages, perPage: paging.perPage,
          firstRow: paging.firstRow, lastRow: paging.lastRow,
          container: applications.containerDn ? applications.containerDn() :
                     null,
          max: applications.maxApplications ? applications.maxApplications() :
               null,
          kinds: applications.KINDS,
          settings: configSettingsJson('/admin/applications'),
          paging: pagingJson, kindCounts: kindCounts,
          authentications: authenticationTotal,
          protocols: applications.PROTOCOLS || [],
          applications: shownRows
      };
      }())
    };
  }

  // THE ATTRIBUTES THAT ARE CREDENTIALS (#446): the application schema's
  // `sensitive` rows. Every one is masked in a GET answer.
  /**
   * Lists the application attributes that hold a credential.
   *
   * @returns the attribute names
   */
  sensitiveApplicationAttributes() {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.sensitiveApplicationAttributes().");
    log.debug("Leaving AdminViews.sensitiveApplicationAttributes().");
    return applications.SCHEMA.attributes.filter(function (one) {
      return !!one.sensitive;
    }).map(function (one) {
      return one.name;
    });
  }

  /**
   * Masks a credential's values: each held value becomes the same sentence.
   *
   * @param value - the attribute's value or values
   * @returns the masked value, the same shape
   */
  maskedCredential(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.maskedCredential().");
    const mask = '(set — not returned)';
    log.debug("Leaving AdminViews.maskedCredential().");
    if (Array.isArray(value)) {
      return value.map(function () {
        return mask;
      });
    }
    return value === undefined || value === null || value === '' ? value
                                                                  : mask;
  }

  /**
   * Copies an application's registry row with every credential masked in
   * its `fields` and `attributes`.
   *
   * @param row - the registry row
   * @returns the masked copy
   */
  maskedApplicationRow(row) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.maskedApplicationRow().");
    const names = this.sensitiveApplicationAttributes();
    const out = Object.assign({}, row);
    ['fields', 'attributes'].forEach(function (member) {
      if (!row[member]) {
        return;
      }
      const copy = Object.assign({}, row[member]);
      Object.keys(copy).forEach(function (name) {
        if (names.indexOf(name) >= 0) {
          copy[name] = self.maskedCredential(copy[name]);
        }
      });
      out[member] = copy;
    });
    log.debug("Leaving AdminViews.maskedApplicationRow().");
    return out;
  }

  /**
   * Copies an application's attribute rows with every credential's values
   * masked.
   *
   * @param rows - the rows, `{ name, values, ... }`
   * @returns the masked copies
   */
  maskedAttributeRows(rows) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.maskedAttributeRows().");
    const names = this.sensitiveApplicationAttributes();
    log.debug("Leaving AdminViews.maskedAttributeRows().");
    return rows.map(function (one) {
      return names.indexOf(one.name) >= 0
        ? Object.assign({}, one, { values: self.maskedCredential(one.values) })
        : one;
    });
  }

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
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.applicationAttributeNote().");
    const lower = String(name).toLowerCase();
    const spec = applications.SCHEMA.attributes.filter(function (one) {
      return one.name.toLowerCase() === lower;
    })[0];
    if (spec) {
      log.debug("Leaving AdminViews.applicationAttributeNote().");
      return { text: spec.what, sensitive: !!spec.sensitive };
    }
    if (lower === 'entrydn') {
      log.debug("Leaving AdminViews.applicationAttributeNote().");
      return { text: 'WHERE THE ENTRY IS. RFC 5020, and the directory ' +
                     'synthesises it rather than storing it: the DN is the ' +
                     'key the entry is held under, so a stored copy would be ' +
                     'a second definition of the same fact and the one that ' +
                     'goes stale the moment the entry is renamed. It is the ' +
                     'name an ldapsearch filter matches this by, which is ' +
                     'why the dump calls it the same thing.' };
    }
    if (lower === 'createtimestamp' || lower === 'modifytimestamp') {
      log.debug("Leaving AdminViews.applicationAttributeNote().");
      return { text: 'The directory\'s own, not the registry\'s: when this ' +
                     'ENTRY was ' +
                     (lower === 'createtimestamp' ? 'created' :
                      'last written') +
                     '. Different from appFirstSeen and appLastSeen one row ' +
                     'up, which are when the APPLICATION was seen — an ' +
                     'ldapmodify moves this one and not those.' };
    }
    if (lower === 'objectclass') {
      log.debug("Leaving AdminViews.applicationAttributeNote().");
      return { text: 'The classes this entry claims, from the registry\'s ' +
                     'vocabulary: ' +
                     applications.SCHEMA.objectClasses.map(function (one) {
                       return one.name;
                     }).join(', ') + '. A VOCABULARY and not a constraint — ' +
                     'node-ldapjs has no schema subsystem and this directory ' +
                     'is schemaless on purpose, so nothing rejects an entry ' +
                     'for disobeying it.' };
    }
    if (operational) {
      log.debug("Leaving AdminViews.applicationAttributeNote().");
      // An operational attribute this function has no sentence for, which means
      // ldap_server.js's OPERATIONAL list grew and this one did not. Saying so
      // is better than the "written by hand" answer below, which would be
      // flatly wrong about an attribute the directory sets itself.
      return { text: 'An operational attribute the directory sets. A search ' +
                     'returns it only when it is asked for by name (RFC 4511 ' +
                     'section 4.5.1.8); this dump is not a search, so it is ' +
                     'here. This page has nothing more specific to say about ' +
                     'it.' };
    }
    log.debug("Leaving AdminViews.applicationAttributeNote().");
    return { text: 'Not in the published schema and not one the directory ' +
                   'sets — written by hand into this entry, which nothing ' +
                   'here prevents and which is what a schemaless directory ' +
                   'means. The registry\'s own writes REPLACE the entry, so ' +
                   'a value here survives only until the next time this ' +
                   'application is seen.' };
  }
  // ---------------------------------------------------------------------------
  // WHAT AN APPLICATION'S PAGE IS DRAWN FROM (#446). The page's tabs read the
  // registry, the mode and the section states while they drew; a page drawn
  // in a browser has none of those, so this collects what they read, once,
  // from the same functions. It carries NO CREDENTIAL: a client secret's
  // value, the registration access token and every private key stay behind
  // `reveal-secret` (rcbj, 2026-10-05), and a section that showed one draws a
  // control that asks for it instead.
  // ---------------------------------------------------------------------------
  /**
   * Collects what an application's page draws its tabs from.
   *
   * @param req - the request
   * @param row - the application's registry row
   * @param states - the section states `applicationDetailJson()` built
   * @returns the page data
   */
  applicationPageData(req, row, states) {
    const { log, applications, mode, baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.applicationPageData().");
    const fields = row.fields || {};
    const listOf = function (name) {
      return [].concat(fields[name] || []).map(String)
        .filter(function (one) { return one !== ''; });
    };
    // The configuration tab's fields: every field but the credentials and
    // those a tab of their own edits (#392: the CORS origins are the
    // Browser origins tab's; #458: the required roles are the Roles tab's),
    // typed as the grid types them, with the entry's values.
    const ownTab = applications.PAGE_TAB_ATTRIBUTES || [];
    const configFields = applications.applicationFields()
      .filter(function (one) {
        return !one.sensitive && ownTab.indexOf(one.attribute) < 0;
      }).map(function (one) { return self.typedField(one); });
    const configValues: Record<string, string[]> = {};
    configFields.forEach(function (one) {
      const value = fields[one.attribute];
      configValues[one.attribute] = [].concat(value === undefined ||
        value === null ? [] : value).map(String);
    });
    // The DID panel: the document advertised for it, and which keys this
    // service keeps the private half of — by kid, never the key.
    const vcDid = require('../oid4vc/vc_did');
    const base = baseUrlOf(req);
    const did = vcDid.applicationDid(base, row.identifier);
    const document = vcDid.applicationDidDocument(base, row.identifier);
    let keptKids = [];
    try {
      keptKids = JSON.parse(String(fields.didPrivateKeys || '[]'))
        .map(function (one) { return String(one && one.kid || ''); });
    } catch (e) {
      log.debug("Caught in AdminViews.applicationPageData(): " +
                ((e && e.message) || e));
      keptKids = [];
    }
    // The credentials state, less every value: the page asks reveal-secret.
    const credentials = Object.assign({}, states.credentials);
    delete credentials.json;
    credentials.clientSecret = Object.assign({},
                                             states.credentials.clientSecret);
    delete credentials.clientSecret.values;
    delete credentials.clientSecret.registrationAccessToken;
    const declared = applications.declaredFamiliesOf(row);
    const editable = function (kind, filtered) {
      return applications.editableAttributes(kind).filter(function (one) {
        return !filtered ||
          !applications.familyRefusal(one.name, declared, row.identifier);
      }).map(function (one) {
        return { name: one.name, sensitive: !!one.sensitive };
      });
    };
    const permissions = states.permissions;
    const out = {
      notes: {},
      config: {
        fields: configFields, values: configValues,
        groups: applications.FIELD_GROUPS,
        familyChoices: applications.FAMILY_CHOICES,
        protocols: applications.PROTOCOLS,
        longTextAttributes: applications.LONG_TEXT_ATTRIBUTES || [],
        // The lists the grid offers a search on, and what each searches
        // (#459): `applications` or `groups`.
        fieldSearches: applications.FIELD_SEARCHES || {}
      },
      cors: listOf('appCorsOrigin').map(function (stored) {
        return { stored: stored,
                 canonical: applications.corsOriginsOf(
                   { appCorsOrigin: [stored] })[0] || '' };
      }),
      accessTypes: listOf('oauthAuthorizationDetailsType').map(
        function (stored) {
          return Object.assign({ stored: stored },
                               applications.authorizationDetailsTypeOf(stored));
        }),
      grantsUncataloguedAccess: mode.grantsUncataloguedAccess(),
      acceptsUnregisteredAddresses: mode.acceptsUnregisteredAddresses(),
      protocolRows: applications.PROTOCOL_IDS.map(function (id) {
        const meta = applications.protocolRow(id) ||
                     { label: id, kinds: [], kind: '' };
        return { id: id, label: meta.label, kinds: meta.kinds || [],
                 kind: meta.kind || '' };
      }),
      editable: { set: editable('set', true), multi: editable('multi', true),
                  multiAll: editable('multi', false) },
      did: {
        did: did,
        url: base + '/applications/' + encodeURIComponent(row.identifier) +
             '/did.json',
        ok: !!document.ok, why: document.why || '',
        methods: document.ok ? document.document.verificationMethod
          .map(function (m) {
            const jwk = m.publicKeyJwk || {};
            const kid = m.id.slice(did.length + 1);
            return { kid: kid, kty: String(jwk.kty || ''),
                     crv: String(jwk.crv || ''), alg: String(jwk.alg || ''),
                     kept: keptKids.indexOf(kid) >= 0 };
          }) : [],
        origins: document.ok ? (document.document.service || [])
          .filter(function (one) { return one.type === 'LinkedDomains'; })
          .map(function (one) { return String(one.serviceEndpoint); }) : []
      },
      credentials: credentials,
      signals: states.signals,
      softwareStatement: states.softwareStatement,
      roles: states.roles,
      permissions: {
        held: permissions.held, exposes: permissions.exposes,
        offerable: permissions.offerable, clients: permissions.clients,
        heldPage: { paging: permissions.heldPage.paging,
                    shown: permissions.heldPage.shown },
        exposedPage: { paging: permissions.exposedPage.paging,
                       shown: permissions.exposedPage.shown },
        grantedOutPage: { paging: permissions.grantedOutPage.paging,
                          shown: permissions.grantedOutPage.shown },
        registerPermissions: permissions.register.permissions.length
      },
      lifetimes: { rows: states.lifetimes.rows, skew: states.lifetimes.skew },
      claims: states.claims.sets,
      enrollment: {
        credentials: this.applicationEnrollmentState(req, row, 'enrolled'),
        config: this.applicationEnrollmentState(req, row, 'enrolledConfig')
      },
      observed: { shown: states.observed.shown,
                  paging: states.observed.paging }
    };
    // The note beside every attribute row, by its name.
    Object.keys(row.attributes || {}).forEach(function (name) {
      out.notes[name] = self.applicationAttributeNote(name,
        (row.operational || []).indexOf(name) >= 0);
    });
    log.debug("Leaving AdminViews.applicationPageData().");
    return out;
  }

  // The application drill-down: the entry, its attributes as a paged list, and
  // the delegated permissions it holds and exposes.
  /**
   * Builds one application's drill-down: the entry, its attributes paged, and
   * the delegated permissions it holds and exposes.
   *
   * @param req - the request
   * @param identifier - the application
   * @returns the JSON
   */
  applicationDetailJson(req, identifier) {
    const { log, applications } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.applicationDetailJson(). identifier=" +
              identifier);
    const row = applications.get(identifier);
    if (!row) {
      log.debug("Leaving AdminViews.applicationDetailJson(). No such " +
                "application.");
      return { row: null, json: { found: false, identifier: identifier } };
    }
    const attributeRows = Object.keys(row.attributes).sort()
      .map(function (name) {
      const value = row.attributes[name];
      // ---------------------------------------------------------------------
      // THE ONE ATTRIBUTE THIS TABLE DOES NOT SHOW AS THE ENTRY HOLDS IT.
      //
      // `oauthAssertionPrivateKey` is sealed at rest in product mode — see
      // `common/applications.js`'s SEALED_FIELDS — so what the ENTRY carries is
      // `$aesgcm$…` and what `row.fields` carries is the PEM, because that
      // module opened it on the way out. This page shows the opened value and
      // says the store holds it encrypted.
      //
      // **THAT IS A DECISION AND `/admin/ldap/applications` MAKES THE OPPOSITE
      // ONE**, which is why it is argued here rather than done quietly: the
      // seal protects the STORE — an ldapsearch on 389, where no read is
      // authorized in either mode, an ldif file, a postgres row, a backup of
      // either — and not this console, which is behind a session and a role and
      // is where an operator goes to collect a credential this service issued
      // them. The directory page is headed "the registry as the directory sees
      // it" and shows the ciphertext, because an opened value there would be a
      // page lying about its subject.
      // ---------------------------------------------------------------------
      const opened = applications.isSealed(value) && row.fields
        ? row.fields[name] : null;
      const shown = opened && !applications.isSealed(opened) ? opened : value;
      return { name: name, values: Array.isArray(shown) ? shown :
                                   [String(shown)],
               sealedAtRest: shown !== value,
               operational: (row.operational || []).indexOf(name) >= 0 };
    });
    const paged = this.pagedRows(req.query, attributeRows,
                                 { name: 'attributes', noun: 'attributes' });
    const paging = paged.paging;
    // THE RETURN ADDRESSES AWAITING CONFIRMATION (2026-09-12), the second list
    // on this page and paged under a name of its own for pagingOf()'s reason.
    // The rows are `row.returnAddressesObserved`, which `applications.view()`
    // built from the one function that decides whether an address counts —
    // so the page, this reply and the check at the protocol door cannot
    // disagree about which addresses product mode withholds.
    const observedPaged = this.pagedRows(req.query,
                                         row.returnAddressesObserved || [],
                                         { name: 'observed',
                                           noun: 'observed addresses' });
    const permissionState = this.applicationPermissionsState(req.query,
                                                             row.identifier);
    const credentialsState = this.applicationCredentialsState(row);
    const softwareStatementState = this.applicationSoftwareStatementState(row);
    const rolesState = this.applicationRolesState(row.identifier, row);
    const signalsState = this.applicationSignalsState(req, row);
    const enrollmentState = this.applicationEnrollmentState(req, row);
    const claimsState = this.applicationClaimsState(row);
    const lifetimesState = this.applicationTokenLifetimesState(row);
    log.debug("Leaving AdminViews.applicationDetailJson().");
    return {
      row: row, attributeRows: attributeRows, paged: paged, paging: paging,
      observedPaged: observedPaged,
      permissionState: permissionState,
      rolesState: rolesState,
      credentialsState: credentialsState,
      softwareStatementState: softwareStatementState,
      signalsState: signalsState,
      enrollmentState: enrollmentState,
      claimsState: claimsState,
      lifetimesState: lifetimesState,
      json: (function () {
      // NO CREDENTIAL IN A GET (#446, rcbj 2026-10-05). The entry's sensitive
      // attributes — client secrets, the registration access token, private
      // keys, GNAP keys — are masked in every copy this answer carries of
      // them: `fields`, `attributes` and the attribute rows. A value is read
      // with `POST /admin-api/applications/reveal-secret`, which needs the
      // write role and is audited. Until then this answer handed every one
      // of them out, opened.
      const masked = self.maskedApplicationRow(row);
      return Object.assign({ found: true }, masked, {
          // WHAT THE PAGE DRAWS ITS TABS FROM (#446), in one member because
          // this answer is the entry spread out and a name of its own could
          // never collide with an attribute: see applicationPageData().
          page: self.applicationPageData(req, row, {
            credentials: credentialsState, signals: signalsState,
            softwareStatement: softwareStatementState, roles: rolesState,
            permissions: permissionState, lifetimes: lifetimesState,
            claims: claimsState, observed: observedPaged }),
          attributesShown: self.maskedAttributeRows(paged.shown),
          attributesPaging: self.pagingJson(paging),
          // `returnAddressesObserved` itself is WHOLE, on the row, beside the
          // slice the page draws — the same arrangement `delegatedPermissions`
          // makes below, because the slicing is this page's layout and not a
          // fact about the entry.
          returnAddressesObservedShown: observedPaged.shown,
          returnAddressesObservedPaging: self.pagingJson(observedPaged.paging),
          // THE CREDENTIALS SECTION, AS DATA (2026-09-13) — which key pair is
          // managed per profile, where it came from, the chain, and the keys
          // the party registered itself. No secret and no private key: see
          // applicationCredentialsState().
          credentials: credentialsState.json,
          // THE SHARED SIGNALS SECTION, AS DATA (2026-10-01): the streams this
          // application owns and every per-receiver setting in force for
          // them. See applicationSignalsState().
          sharedSignals: signalsState.json,
          // THE CERTIFICATE ENROLLMENT SECTION, AS DATA (2026-10-01): the
          // ACME, EST and SCEP rules in force for it, the certificates it
          // was issued (paged), its EAB keys and SCEP challenges (no secret)
          // and its host names. See applicationEnrollmentState().
          certificateEnrollment: enrollmentState.json,
          // AN APPLICATION'S OWN CUSTOM CLAIMS AND SAML ATTRIBUTES, AND THE
          // TOKEN LIFETIMES IN FORCE FOR IT (2026-10-01): its configuration
          // tabs' sections, as data. See applicationClaimsState() and
          // applicationTokenLifetimesState().
          customClaims: claimsState.json,
          tokenLifetimes: lifetimesState.json,
          // THE SOFTWARE STATEMENTS SECTION, AS DATA (2026-09-13): the issuers
          // this application vouches for as a publisher, the statement this
          // realm issued it, and how it registered if a statement let it in. A
          // statement is not a secret, so the issued one is here whole.
          softwareStatements: softwareStatementState.json,
          // THE RESOLVED DELEGATED PERMISSIONS, because the page draws a
          // section of them and a reply that carried only the raw attribute
          // would leave a caller to compose `baseUri + name` for itself — which
          // is the one string in this feature that must not be worked out in
          // two places. WHOLE, with the paging beside it rather than applied to
          // it, for the reason /admin/delegation's own `allowed` member gives:
          // the slicing is this page's layout and not a fact about the entry,
          // and `GET /admin-api/permissions` answers with the same register
          // under its own name.
          // THE ROLES IT HOLDS AS ITSELF (#93), the page's Application
          // permissions section as data: what a client_credentials token of
          // its carries, and the roles it could be granted. Granting and
          // removing are `POST /admin-api/roles/add-member` and
          // `remove-member` with `kind: application`, the console's own act.
          // AND THE ROLES IT REQUIRES (#458), the Roles tab's other section:
          // `required` and `requirable`, written through
          // `POST /admin-api/applications/add` and `remove` with
          // `attribute: appRequiredRole`.
          applicationRoles: rolesState,
          delegatedPermissions: {
            held: permissionState.held,
            exposes: permissionState.exposes,
            offerable: permissionState.offerable.map(function (one) {
              return one.id;
            }),
            // The grants of its OWN permissions to other applications
            // (2026-10-01), the Permissions tab's third table.
            grantedOut: permissionState.grantedOut,
            paging: { held: self.pagingJson(permissionState.heldPage.paging),
                      exposes:
                        self.pagingJson(permissionState.exposedPage.paging),
                      grantedOut: self.pagingJson(
                        permissionState.grantedOutPage.paging) }
          }
      });
      }())
    };
  }

  // ---------------------------------------------------------------------------
  // THE ROLES AN APPLICATION HOLDS AS ITSELF (#93): application permissions.
  //
  // An application is granted a role — a realm-wide one, or another
  // application's own (#310) — as a member (`roleMemberApplication`), and a
  // client_credentials token of its carries it: a realm-wide role in every
  // token, an application's role only in a token for that application, under
  // its short name. ONE STORE: the role entry. This is that store read from
  // the application's side, which is the question an administrator asks
  // here — "what may this client do as itself?" — and granting from here is
  // the same act as adding the member on /admin/roles, audited the same.
  //
  // `offerable` is every role it does not hold that admits applications: a
  // role restricted to people is not offered, and would be refused.
  //
  // AND THE OTHER RELATION, ON THE SAME TAB (#458): `required` is the
  // entry's `appRequiredRole` — the roles somebody must hold before anything
  // is issued for this application — read as STORED, not through
  // `requiredRolesFrom()`, because that reader answers EVERYBODY for an empty
  // list and the page has to show (and offer to remove) exactly what is on
  // the entry. Each value says what it resolves to, by the rule the issuance
  // PEP holds a requirement to (#310): a built-in role, a realm-wide role of
  // that name, or THIS application's own role of that name — never another
  // application's. One that resolves to nothing is a requirement nobody can
  // satisfy, which refuses everybody and looks exactly like a broken
  // application, so it is marked rather than drawn like the others.
  //
  // `requirable` is what the add control offers: the built-in roles but
  // EVERYBODY (an empty list already means everybody, and EVERYBODY beside a
  // narrower role would quietly undo it), the realm-wide roles and this
  // application's own roles by their name inside it, less those already
  // required. Membership types do not narrow it — a role restricted to
  // applications is still a role a client_credentials subject can meet.
  // ---------------------------------------------------------------------------
  /**
   * The roles an application holds as itself, those it could be granted, the
   * roles it requires of whoever uses it and those it could require.
   *
   * @param identifier - the application
   * @param row - the application's registry view, when the caller has it;
   *   read by identifier otherwise
   * @returns `{ held, offerable, required, requirable }`: `held` rows carry
   *   `name`, `id`, `displayName`, `application` (whose role it is, or empty
   *   for a realm-wide one), `carriedAs` and `permissions`; `offerable` is
   *   role names; `required` rows carry `name` (as stored), `resolves`
   *   (`built-in`, `realm`, `application` or `none`), `displayName` and
   *   `role` (the register's name for it, or empty); `requirable` is the
   *   names a requirement may be given
   */
  applicationRolesState(identifier, row?) {
    const { log, roles, applications } = this.deps;
    log.debug("Entering AdminViews.applicationRolesState(). identifier=" +
              identifier);
    const key = String(identifier || '').toLowerCase();
    const all = roles.all();
    const holds = function (role) {
      return (role.applications || []).some(function (one) {
        return String(one).toLowerCase() === key;
      });
    };
    const held = all.filter(holds).map(function (role) {
      return { name: role.name, id: role.id || '',
               displayName: role.displayName || '',
               application: role.application || '',
               carriedAs: role.localName || role.name,
               permissions: role.permissions || [] };
    });
    const offerable = all.filter(function (role) {
      return !holds(role) &&
             (!(role.memberTypes || []).length ||
              role.memberTypes.indexOf('application') >= 0);
    }).map(function (role) {
      return role.name;
    });
    // The requirement's two lists (#458), against this application's own
    // roles by their name inside it.
    const view = row || applications.get(identifier);
    const fields = (view && view.fields) || {};
    const stored = [].concat(fields.appRequiredRole === undefined ||
      fields.appRequiredRole === null ? [] : fields.appRequiredRole)
      .map(function (one) { return String(one).trim(); })
      .filter(function (one) { return one.length > 0; });
    const ownOf = function (role) {
      return !!role.application &&
             String(role.application).toLowerCase() === key;
    };
    const required = stored.map(function (name) {
      if (roles.isBuiltIn(name)) {
        return { name: name, resolves: 'built-in', displayName: '',
                 role: name };
      }
      const own = all.filter(function (role) {
        return ownOf(role) && role.localName === name;
      })[0];
      if (own) {
        return { name: name, resolves: 'application',
                 displayName: own.displayName || '', role: own.name };
      }
      const wide = all.filter(function (role) {
        return !role.application && role.name === name;
      })[0];
      if (wide) {
        return { name: name, resolves: 'realm',
                 displayName: wide.displayName || '', role: wide.name };
      }
      return { name: name, resolves: 'none', displayName: '', role: '' };
    });
    const candidates = roles.BUILT_IN_NAMES.filter(function (name) {
      return name !== roles.DEFAULT_REQUIRED_ROLE;
    }).concat(all.filter(function (role) {
      return !role.application;
    }).map(function (role) {
      return role.name;
    })).concat(all.filter(ownOf).map(function (role) {
      return role.localName || role.name;
    }));
    const requirable = candidates.filter(function (name, at) {
      return candidates.indexOf(name) === at && stored.indexOf(name) < 0;
    });
    log.debug("Leaving AdminViews.applicationRolesState(). " + held.length +
              " held, " + offerable.length + " offerable, " +
              required.length + " required, " + requirable.length +
              " requirable.");
    return { held: held, offerable: offerable, required: required,
             requirable: requirable };
  }

  // ---------------------------------------------------------------------------
  // AN APPLICATION'S CREDENTIALS, IN ONE PLACE (2026-09-13).
  //
  // The client secret, and for each assertion profile the key pair this service
  // manages — issued here or a certificate uploaded in its place — beside the
  // keys the party registered itself. Every fact was already on the entry and
  // in the attribute table under it; what was missing is the READING: which
  // certificate, issued by whom, through what chain, expiring when, and whether
  // this service holds the private half. So this parses the certificates and
  // names the attributes from `applications.KEY_PAIR_ATTRIBUTES`, the one table
  // the writer (`admin-ui/pki_admin.ts`) reads too.
  //
  // **THE JSON CARRIES NO SECRET AND NO PRIVATE KEY.** Both are already in the
  // reply's `fields`, opened, for a caller holding `admin:read` — that is the
  // registry's decision and this does not repeat it; a second copy of a
  // credential in one reply is one more place a log line or a screenshot picks
  // it up. The page reads the values from the state, which never leaves this
  // process as JSON.
  // ---------------------------------------------------------------------------
  private certificateSummary(pem) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering AdminViews.certificateSummary().");
    try {
      const cert = new nodeCrypto.X509Certificate(String(pem));
      const notAfter = new Date(cert.validTo);
      const summary = {
        subject: String(cert.subject || '').split('\n').filter(Boolean)
          .join(', '),
        issuer: String(cert.issuer || '').split('\n').filter(Boolean)
          .join(', '),
        serialHex: String(cert.serialNumber || '').toLowerCase(),
        notBefore: new Date(cert.validFrom).toISOString(),
        notAfter: notAfter.toISOString(),
        expired: notAfter.getTime() < Date.now(),
        selfSigned: cert.subject === cert.issuer,
        keyType: cert.publicKey.asymmetricKeyType,
        thumbprint: nodeCrypto.createHash('sha256').update(cert.raw)
          .digest('base64url')
      };
      log.debug("Leaving AdminViews.certificateSummary().");
      return summary;
    } catch (e) {
      log.debug("Caught in AdminViews.certificateSummary(): " + ((e &&
          e.message) || e));
      // An attribute an `ldapmodify` reaches: reported as unreadable rather
      // than dropped, so the section says what the entry holds.
      log.debug("Leaving AdminViews.certificateSummary(). Unreadable.");
      return { unreadable: String((e && e.message) || e) };
    }
  }

  private pemCertificatesIn(value) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.pemCertificatesIn().");
    const text = Array.isArray(value) ? value.join('\n') : String(value || '');
    const blocks = text.match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    log.debug("Leaving AdminViews.pemCertificatesIn(). " + blocks.length +
              " block(s).");
    return blocks;
  }

  private registeredJwksKeys(value) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.registeredJwksKeys().");
    if (!value) {
      log.debug("Leaving AdminViews.registeredJwksKeys(). None.");
      return { keys: [], problem: '' };
    }
    try {
      const doc = typeof value === 'string' ? JSON.parse(value) : value;
      const keys = (doc && Array.isArray(doc.keys) ? doc.keys : []).map(
          function (jwk) {
        return { kid: jwk.kid ? String(jwk.kid) : '', kty: String(jwk.kty ||
                                                                  ''),
                 alg: jwk.alg ? String(jwk.alg) : '',
                 use: jwk.use ? String(jwk.use) : '',
                 certificate: Array.isArray(jwk.x5c) && jwk.x5c.length
                   ? self.certificateSummary('-----BEGIN CERTIFICATE-----\n' +
                                             String(jwk.x5c[0]) +
                                             '\n-----END CERTIFICATE-----')
                   : null };
      });
      log.debug("Leaving AdminViews.registeredJwksKeys(). " + keys.length +
                " key(s).");
      return { keys: keys, problem: '' };
    } catch (e) {
      log.debug("Caught in AdminViews.registeredJwksKeys(): " + ((e &&
          e.message) || e));
      // The verifier reports the same thing when it reads it; the page says it
      // before anybody has to find out that way.
      log.debug("Leaving AdminViews.registeredJwksKeys(). Not JSON.");
      return { keys: [], problem: 'not valid JSON: ' + e.message };
    }
  }

  // ---------------------------------------------------------------------------
  // THE SHARED SIGNALS STREAMS AN APPLICATION OWNS (2026-10-01), and the
  // per-receiver settings in force for them. A stream is this application's
  // when the principal that created it resolves to this entry — its
  // identifier, or one of its ssfReceiverId values — which is the same match
  // `ssf_streams.ts` narrows events and applies settings by, so the page and
  // the transmitter cannot disagree about whose a stream is. This service's
  // own two streams are nobody's. The stream's members are shown as the
  // receiver set them (SSF 1.0 section 8.1.1); only its status is an
  // administrator's to change, through the existing `status` action.
  // ---------------------------------------------------------------------------
  /**
   * Builds the Shared Signals state of one application's page.
   *
   * @param req - the request
   * @param row - the application's view
   * @returns `{ installed, streams, settings, json }`
   */
  applicationSignalsState(req, row) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.applicationSignalsState(). identifier=" +
              row.identifier);
    const settings = applications.ssfOverrideRows().map(function (one) {
      const answer = applications.ssfSettingFor(row.identifier, one.setting);
      return { setting: one.setting, attribute: one.attribute,
               value: answer.value, source: answer.source };
    });
    if (!signalsReporter) {
      log.debug("Leaving AdminViews.applicationSignalsState(). Not loaded.");
      return { installed: false, streams: [], settings: settings,
               json: { installed: false, streams: [], settings: settings } };
    }
    let detail = [];
    try {
      detail = signalsReporter.report(req).streamDetail || [];
    } catch (e) {
      log.debug("Caught in AdminViews.applicationSignalsState(): " +
                ((e && e.message) || e));
      // A report that could not be built shows no streams rather than
      // costing the application's page.
      detail = [];
    }
    const owned = detail.filter(function (stream) {
      if (stream.internal || !stream.createdBy) {
        return false;
      }
      const owner = applications.ssfAllowedEventsFor(stream.createdBy);
      return !!owner && owner.identifier === row.identifier;
    }).map(function (stream) {
      return { stream_id: stream.stream_id, status: stream.status,
               statusReason: stream.statusReason, aud: stream.aud,
               delivery: stream.delivery,
               events_requested: stream.events_requested || [],
               events_delivered: stream.events_delivered || [],
               format: stream.format || '',
               description: stream.description || '',
               createdBy: stream.createdBy, createdAt: stream.createdAt,
               updatedAt: stream.updatedAt,
               lastPushAt: stream.lastPushAt || '',
               lastPushError: stream.lastPushError || '' };
    });
    log.debug("Leaving AdminViews.applicationSignalsState(). " +
              owned.length + " stream(s).");
    return { installed: true, streams: owned, settings: settings,
             json: { installed: true, streams: owned, settings: settings } };
  }

  // AN APPLICATION'S CERTIFICATE ENROLLMENT, AS ONE MODEL (rcbj,
  // 2026-10-01): what its Credentials tab and its Certificate enrollment
  // configuration tab draw, and what `GET /admin-api/applications?application=`
  // answers as `certificateEnrollment`. Drawn for an application declared for
  // ACME, EST or SCEP. Everything is read from `common/cert_enrollment.ts`, so
  // the rules shown are the rules applied: the profile list, default,
  // lifetime and cap IN FORCE for it (its own override, else the realm's),
  // EST's three switches through `estSwitch()`, the certificates on its entry
  // newest first (PAGED on `enrolledPage`: revoked and expired ones stay on
  // the entry and the list grows), its EAB keys and SCEP challenges (bounded
  // per entry, and with no key material — the core's own listings carry
  // none), and its registered host names. Generating and revoking are the
  // three protocols' own console actions, posted from the application's page.
  /**
   * Answers an application's certificate enrollment: the rules in force for
   * it, its certificates, EAB keys, SCEP challenges and host names.
   *
   * @param req - the request, for the paging of its certificates
   * @param row - the application's view
   * @param listName - the paging name of its certificate list, `enrolled`
   *   unless the caller draws the list a second time on one page
   * @returns `{ families, rules, certificates, paged, eabKeys, challenges,
   *   hostNames, keyAlgorithms, json }`
   */
  applicationEnrollmentState(req, row, listName?) {
    const { log, config } = this.deps;
    log.debug("Entering AdminViews.applicationEnrollmentState(). " +
              "identifier=" + (row && row.identifier));
    const core = require('../common/cert_enrollment');
    const id = String((row && row.identifier) || '');
    const entry = { kind: 'application', id: id };
    const fields = (row && row.fields) || {};
    const declared = [].concat((row && row.allowedProtocols) || []);
    const families = ['acme', 'est', 'scep'].filter(function (one) {
      return declared.indexOf(one) >= 0;
    });
    const own = function (attribute) {
      log.debug("Entering own().");
      const value = Number(String(fields[attribute] || '').trim());
      log.debug("Leaving own().");
      return Number.isFinite(value) && value > 0 ? value : null;
    };
    const rules = families.map(function (family) {
      const days = own(family + 'CertificateLifetimeDays');
      const ownList = [].concat(fields[family + 'AllowedProfiles'] || [])
        .map(String).filter(Boolean);
      return {
        family: family,
        label: core.FAMILY_LABELS[family],
        allowedProfiles: core.allowedProfiles(family, entry),
        allowedProfilesSource: ownList.length ? 'application' : 'realm',
        defaultProfile: core.defaultProfile(family, entry),
        defaultProfileSource: String(fields[family + 'DefaultProfile'] || '')
          .trim() ? 'application' : 'realm',
        certificateLifetimeDays: days !== null ? days
          : Number(config.value(family + '.certificateLifetimeDays')),
        certificateLifetimeSource: days !== null ? 'application' : 'realm'
      };
    });
    const capOwn = own('enrollMaxCertificates');
    const cap = {
      value: capOwn !== null ? capOwn
        : Number(config.value('pki.enrollmentMaxCertificatesPerEntry')),
      source: capOwn !== null ? 'application' : 'realm'
    };
    const switchOf = function (name, attribute) {
      log.debug("Entering switchOf().");
      const raw = String(fields[attribute] || '').trim().toUpperCase();
      log.debug("Leaving switchOf().");
      return { on: core.estSwitch(name, entry),
               source: raw === 'TRUE' || raw === 'FALSE' ? 'application'
                                                         : 'realm' };
    };
    const est = families.indexOf('est') >= 0 ? {
      basicAuthentication: switchOf('basicAuthentication',
                                    'estBasicAuthentication'),
      certificateAuthentication: switchOf('certificateAuthentication',
                                          'estCertificateAuthentication'),
      serverKeyGeneration: switchOf('serverKeyGeneration',
                                    'estServerKeyGeneration')
    } : null;
    let certificates = [];
    let eabKeys = [];
    let challenges = [];
    let hostNames = [];
    if (families.length && core.hasDirectory()) {
      certificates = core.enrolledOf(entry).map(function (one) {
        return Object.assign({}, one, { entry: undefined });
      });
      eabKeys = families.indexOf('acme') >= 0 ? core.eabsOf(entry) : [];
      challenges = families.indexOf('scep') >= 0
        ? core.scepChallengesOf(entry) : [];
      hostNames = core.hostNamesOf(entry);
    }
    // The list's paging name is also its pager's id (`list-<name>Page`), so
    // a page that draws the list twice names each copy apart — or both
    // pagers' links land on whichever copy comes first in the document.
    const paged = this.pagedRows((req && req.query) || {}, certificates,
                                 { name: listName || 'enrolled',
                                   noun: 'certificates' });
    let keyAlgorithms = [];
    try {
      keyAlgorithms = require('../common/vendored/key_material').keyAlgIds();
    } catch (e) {
      log.debug("Caught in AdminViews.applicationEnrollmentState(): " +
                ((e && e.message) || e));
      keyAlgorithms = ['ec-p256'];
    }
    const json = {
      families: families, rules: rules, certificateCap: cap,
      est: est,
      certificates: paged.shown, certificatesPaging: this.pagingJson(
        paged.paging),
      certificatesTotal: certificates.length,
      eabKeys: eabKeys, scepChallenges: challenges, hostNames: hostNames
    };
    log.debug("Leaving AdminViews.applicationEnrollmentState(). " +
              certificates.length + " certificate(s).");
    return { families: families, rules: rules, cap: cap, est: est,
             certificates: certificates, paged: paged, eabKeys: eabKeys,
             challenges: challenges, hostNames: hostNames,
             keyAlgorithms: keyAlgorithms, json: json };
  }

  // AN APPLICATION'S OWN CLAIM SETS, BESIDE THE REALM'S (rcbj, 2026-10-01):
  // what its OAuth / OpenID Connect tab's Custom claims section and its SAML
  // tab's Custom SAML attributes section draw. Per set, for the families the
  // application is declared for: the realm's rows, its own rows, and the
  // rows IN FORCE for it (`stats.effectiveClaimSet()`: the realm's, with its
  // own added and winning by name), each marked with where it came from.
  /**
   * Answers an application's own claim sets beside the realm's.
   *
   * @param row - the application's view
   * @returns `{ sets, json }`, one member per set it is declared for
   */
  applicationClaimsState(row) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.applicationClaimsState(). identifier=" +
              (row && row.identifier));
    const declared = [].concat((row && row.allowedProtocols) || []);
    const families = {
      access_token: ['oauth2', 'oidc', 'oid4vci'],
      id_token: ['oidc', 'oauth2'],
      userinfo: ['oidc', 'oauth2'],
      saml2: ['saml2'],
      saml11: ['saml11']
    };
    const labels = {
      access_token: 'Access token', id_token: 'ID Token',
      userinfo: 'UserInfo response', saml2: 'SAML 2.0 attributes',
      saml11: 'SAML 1.1 attributes'
    };
    const sets = Object.keys(families).filter(function (id) {
      return families[id].some(function (one) {
        return declared.indexOf(one) >= 0;
      });
    }).map(function (id) {
      const realmRows = stats.claimSet(id);
      const own = stats.applicationClaimSet(id, row);
      const ownNames = own.map(function (one) { return one.name; });
      const effective = realmRows.filter(function (one) {
        return ownNames.indexOf(one.name) < 0;
      }).map(function (one) {
        return Object.assign({ source: 'realm' }, one);
      }).concat(own.map(function (one) {
        const replaced = realmRows.some(function (r) {
          return r.name === one.name;
        });
        return Object.assign({ source: 'application', replacesRealm: replaced },
                             one);
      }));
      return { id: id, label: labels[id],
               attribute: stats.APP_CLAIM_ATTRIBUTES[id],
               realm: realmRows, own: own, effective: effective };
    });
    log.debug("Leaving AdminViews.applicationClaimsState(). " + sets.length +
              " set(s).");
    return { sets: sets, json: sets };
  }

  // THE TOKEN LIFETIMES IN FORCE FOR AN APPLICATION (2026-10-01): its OAuth
  // tab's Token lifetimes section. The four settings it may override, each
  // with the value in force (`applications.settingFor()`, which is what the
  // token endpoint reads), the realm's value, and where the value came from;
  // and the realm's clock skew, which stays realm-wide.
  /**
   * Answers the token lifetimes in force for an application.
   *
   * @param row - the application's view
   * @returns `{ rows, skew, json }`
   */
  applicationTokenLifetimesState(row) {
    const { log, applications, config } = this.deps;
    log.debug("Entering AdminViews.applicationTokenLifetimesState().");
    const id = String((row && row.identifier) || '');
    const fields = (row && row.fields) || {};
    const keys = [
      { key: 'oauth2.accessTokenTtlS', attribute: 'oauthAccessTokenTtlS',
        label: 'Access token' },
      { key: 'oauth2.idTokenTtlS', attribute: 'oauthIdTokenTtlS',
        label: 'ID Token' },
      { key: 'oauth2.refreshTokenTtlS', attribute: 'oauthRefreshTokenTtlS',
        label: 'Refresh token' },
      { key: 'oauth2.refreshIdleSeconds',
        attribute: 'oauthRefreshIdleSeconds',
        label: 'Refresh chain idle limit (RFC 9700 mode)' }
    ];
    const rows = keys.map(function (one) {
      const own = String([].concat(fields[one.attribute] || [])[0] || '')
        .trim();
      return {
        setting: one.key, attribute: one.attribute, label: one.label,
        value: Number(applications.settingFor(id, one.key, config)),
        realmValue: Number(config.value(one.key)),
        source: own ? 'application' : 'realm'
      };
    });
    const skew = Number(config.value('oauth2.clockSkewS'));
    log.debug("Leaving AdminViews.applicationTokenLifetimesState().");
    return { rows: rows, skew: skew,
             json: { lifetimes: rows, clockSkewS: skew } };
  }

  private applicationCredentialsState(row) {
    const { log, applications, pki, config } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.applicationCredentialsState(). identifier=" +
              (row && row.identifier));
    const fields = (row && row.fields) || {};
    const one = function (name) {
      log.debug("Entering one().");
      const value = name ? fields[name] : undefined;
      log.debug("Leaving one().");
      return Array.isArray(value) ? value.join('\n') : String(value || '');
    };
    const chainAvailable = pki.hasChain();
    const described = chainAvailable ? pki.describe() : null;
    const purposes = pki.PURPOSES.map(function (purpose) {
      const names = applications.KEY_PAIR_ATTRIBUTES[purpose.id];
      const certificatePem = one(names.certificate);
      const privateKeyPem = one(names.privateKey);
      const recorded = one(names.source);
      const source = recorded ||
        (privateKeyPem ? 'issued' : (certificatePem ? 'unrecorded' : ''));
      const registeredText = one(names.registered);
      return {
        id: purpose.id,
        label: purpose.label,
        attributes: names,
        held: !!(certificatePem || privateKeyPem),
        source: source,
        privateKeyHeld: !!privateKeyPem,
        sealedAtRest: applications.isSealed((row.attributes || {})[
          names.privateKey]),
        certificate: certificatePem ? self.certificateSummary(certificatePem) :
                     null,
        certificatePem: certificatePem,
        chain: self.pemCertificatesIn(one(names.chain))
          .map(self.certificateSummary.bind(self)),
        handle: one(names.handle),
        handleLabel: names.handleLabel,
        issuers: [].concat(fields[names.issuer] || []).map(String),
        registered: purpose.id === 'jwt'
          ? Object.assign({ attribute: names.registered },
                          self.registeredJwksKeys(registeredText))
          : { attribute: names.registered,
              certificates: self.pemCertificatesIn(registeredText)
                .map(self.certificateSummary.bind(self)),
              problem: registeredText &&
                       !self.pemCertificatesIn(registeredText).length
                ? 'it holds no PEM certificate block' : '' }
      };
    });
    // WHETHER THE TWO ASSERTION PROFILES ARE DRAWN AT ALL (2026-09-13). RFC
    // 7523 and RFC 7522 are both used at the TOKEN ENDPOINT, so an application
    // that has not been declared an OAuth 2.0 client or an OpenID Connect
    // relying party — the two families whose identifier is a client_id — has no
    // use for either section, and the page leaves them out. It is the
    // DECLARATION (`appAllowedProtocol`) and not the recorded kinds, because
    // that is the checkbox an operator ticks to say what the application is
    // for. Hiding a section grants and removes nothing: a key pair already on
    // the entry still verifies, and the page says so when one is there.
    const declared = [].concat(row.allowedProtocols || []);
    const oauthDeclared = declared.indexOf('oauth2') >= 0 ||
                          declared.indexOf('oidc') >= 0;
    // SEVERAL SECRETS (2026-10-01): each record with its expiry, newest
    // first, the primary marked. The VALUES go to the page (it shows each
    // behind a fold, as it showed the one) and never into the reply's JSON.
    const summaries = applications.clientSecretSummariesOf(row.fields || {});
    const secretValues: Record<string, string> = {};
    applications.clientSecretRecordsOf(row.fields || {}).forEach(
      function (rec) { secretValues[rec.id] = rec.secret; });
    const state: Record<string, any> = {
      oauthDeclared: oauthDeclared,
      clientSecret: {
        held: summaries.length > 0,
        secrets: summaries,
        values: secretValues,
        max: Number(config.value('oauth2.clientSecretsMax')) || 1,
        defaultLifetimeDays:
          Number(config.value('oauth2.clientSecretLifetimeDays')) || 0,
        overlapS: Number(config.value('oauth2.clientSecretOverlapS')) || 0,
        // Every declared method (2026-10-01), as one line.
        authMethod: one('oauthTokenEndpointAuthMethod').split('\n')
          .filter(function (m) { return m !== ''; }).join(', '),
        registered: !!row.registered,
        registrationAccessTokenHeld: !!one('appRegistrationAccessToken'),
        registrationAccessToken: one('appRegistrationAccessToken'),
        // When the PRIMARY expires (seconds, 0 never).
        expiresAt: applications.secretExpiryOf(row.fields || {})
      },
      purposes: purposes,
      ca: {
        available: chainAvailable,
        keyAlg: described && described.keyAlg ? String(described.keyAlg) : '',
        keyAlgorithms: pki.keyAlgorithms(),
        leafLifetimeDays: pki.leafLifetimeDays()
      },
      sources: applications.KEY_SOURCES.slice(),
      mtls: this.applicationMtlsState(row, one, chainAvailable)
    };
    state.json = {
      clientSecret: { held: state.clientSecret.held,
                      authMethod: state.clientSecret.authMethod,
                      registered: state.clientSecret.registered,
                      registrationAccessTokenHeld:
                        state.clientSecret.registrationAccessTokenHeld,
                      expiresAt: state.clientSecret.expiresAt,
                      // Every secret's id and expiry, never its value.
                      secrets: state.clientSecret.secrets,
                      max: state.clientSecret.max },
      keyPairs: purposes.map(function (p) {
        return { purpose: p.id, label: p.label, held: p.held, source: p.source,
                 privateKeyHeld: p.privateKeyHeld, certificate: p.certificate,
                 chain: p.chain, handle: p.handle, handleLabel: p.handleLabel,
                 issuers: p.issuers, attributes: p.attributes,
                 registered: p.registered };
      }),
      caAvailable: chainAvailable,
      oauthDeclared: oauthDeclared,
      sources: state.sources,
      mtls: state.mtls
    };
    log.debug("Leaving AdminViews.applicationCredentialsState().");
    return state;
  }

  // ---------------------------------------------------------------------------
  // RFC 8705 ON AN APPLICATION'S PAGE (2026-09-13).
  //
  // What the token endpoint will accept from this application and do with its
  // tokens, read from the same places it reads them: the declared method, the
  // TLS client certificates this realm issued to it (the IMPLICIT mapping,
  // whose record `tls_client_certificates.stillHeld()` asks), the one subject
  // parameter it may register instead (the EXPLICIT one), the section 2.2
  // thumbprint, and the section 3.4 flag. Certificates it enrolled over ACME,
  // EST or SCEP authenticate it too and are listed on those protocols' pages,
  // not here — this section issues and lists its own.
  // ---------------------------------------------------------------------------
  private applicationMtlsState(row, one, caAvailable) {
    const { log, applications, tlsClientCertificates, certificateSubject,
      mtls } = this.deps;
    log.debug("Entering AdminViews.applicationMtlsState().");
    const identifier = String((row && row.identifier) || '');
    let held = [];
    try {
      held = tlsClientCertificates.listFor(undefined, identifier, 'application')
        .map(function (cert) {
          return { serialHex: cert.serialHex, label: cert.label,
                   subject: cert.subject, keyAlg: cert.keyAlg,
                   notBefore: cert.notBefore, notAfter: cert.notAfter,
                   thumbprint: cert.thumbprint, state: cert.state,
                   reason: cert.reason, revokedAt: cert.revokedAt,
                   certificatePem: cert.certificatePem };
        });
    } catch (e) {
      // No certificate authority in this process: nothing issued, nothing held.
      log.debug("Caught in AdminViews.applicationMtlsState(): " + ((e &&
          e.message) || e));
      held = [];
    }
    const subjects = certificateSubject.MEMBER_NAMES.map(function (member) {
      const described = certificateSubject.MEMBERS[member];
      return { member: member, attribute: described.attribute,
               label: described.label, value: one(described.attribute) };
    });
    // Several since 2026-10-01: a certificate method among them is what the
    // page reports.
    const methods = String(one('oauthTokenEndpointAuthMethod') || '')
      .split('\n').filter(function (m) { return m !== ''; });
    const certificate = methods.filter(function (m) {
      return mtls.CERTIFICATE_METHODS.indexOf(m) >= 0;
    })[0] || '';
    log.debug("Leaving AdminViews.applicationMtlsState(). " + held.length +
              " held.");
    return {
      authMethod: certificate || methods.join(', '),
      certificateMethod: !!certificate,
      implicitName: tlsClientCertificates.APPLICATION_URN + identifier,
      certificates: held,
      active: held.filter(function (cert) {
        return cert.state === 'valid';
      }).length,
      max: tlsClientCertificates.maxPerHolder('application'),
      subjects: subjects,
      registeredSubject: subjects.filter(function (s) {
        return !!s.value;
      }).map(function (s) {
        return s.member;
      }),
      boundTokensAttribute: applications.TLS_BOUND_TOKENS_ATTRIBUTE,
      boundTokens: one(applications.TLS_BOUND_TOKENS_ATTRIBUTE)
        .toUpperCase() ===
                   'TRUE',
      selfSignedThumbprint: one('oauthTlsClientCertificateThumbprint'),
      bindingAvailable: mtls.available(),
      caAvailable: !!caAvailable,
      keyAlgorithms: tlsClientCertificates.KEY_ALGS.slice(),
      defaultKeyAlg: tlsClientCertificates.DEFAULT_KEY_ALG,
      revocationReasons: tlsClientCertificates.REVOCATION_REASONS.slice(),
      passwordMin: tlsClientCertificates.PKCS12_PASSWORD_MIN
    };
  }

  // ---------------------------------------------------------------------------
  // SOFTWARE STATEMENTS ON AN APPLICATION'S PAGE (RFC 7591 section 2.3,
  // 2026-09-13).
  //
  // Three facts from three places, read here so the page and
  // `GET /admin-api/applications?application=` cannot disagree about them:
  // `oauthSoftwareStatementIssuer` and whether the entry holds a key a
  // statement could verify under (the publisher half);
  // `oauthIssuedSoftwareStatement`, decoded and checked against the realm's key
  // NOW (the issued half); and the three `appSoftwareStatement*` facts a
  // registration wrote (the client half).
  // ---------------------------------------------------------------------------
  private applicationSoftwareStatementState(row) {
    const { log, applications, softwareStatement, assertionGrant } = this.deps;
    log.debug("Entering AdminViews.applicationSoftwareStatementState().");
    const fields = (row && row.fields) || {};
    const issuers = [].concat(fields.oauthSoftwareStatementIssuer || [])
      .map(String);
    const keys = assertionGrant.keysForParty(fields, 'application');
    const issuedToken = String([].concat(
      fields.oauthIssuedSoftwareStatement || [])[0] || '');
    const issued = issuedToken ? softwareStatement.describe(issuedToken) : null;
    const registeredWith = row
      ? applications.softwareStatementFactsOf(row.identifier) : null;
    const settings = {
      requireTrustedIssuer: softwareStatement.requiresTrustedIssuer(),
      opensRegistration: softwareStatement.opensRegistration(),
      required: softwareStatement.required(),
      lifetimeSeconds: softwareStatement.issuedLifetimeSeconds()
    };
    const state: Record<string, any> = {
      issuers: issuers,
      usableKeys: keys.keys.length,
      keyProblems: keys.problems,
      issuedToken: issuedToken,
      issued: issued,
      registeredWith: registeredWith,
      settings: settings
    };
    state.json = {
      declaredIssuers: issuers,
      usableKeys: keys.keys.length,
      issued: issued ? Object.assign({ statement: issuedToken }, issued) : null,
      registeredWith: registeredWith,
      settings: settings
    };
    log.debug("Leaving AdminViews.applicationSoftwareStatementState().");
    return state;
  }

  // ---------------------------------------------------------------------------
  // A PERSON'S KEY PAIRS, ON THEIR OWN PAGE (2026-09-13).
  //
  // The application's section above, for the other kind of holder: for each
  // assertion profile, the key pair on the person's own entry — issued here or
  // a certificate uploaded in its place — read into which certificate, issued
  // by whom, through what chain, and whether this service holds the private
  // half. `person_assertions.KEY_PAIR_ATTRIBUTES` names the attributes, which
  // is the table the writer uses.
  //
  // **THERE IS NO PRIVATE KEY IN THE STATE, EITHER HALF**, and that is a
  // difference from the application's which is the point rather than an
  // omission. An application's private key is readable through
  // `applications.view()`; a person's has no read door — it is handed over
  // once, by the issue — so this reports whether one is HELD and never what it
  // is. `recordFor()` opens the seal to answer that, and nothing opened leaves
  // this function.
  // ---------------------------------------------------------------------------
  /**
   * Reports which of a person's RFC 7523 and RFC 7522 credentials are held;
   * never what they are.
   *
   * @param key - the person
   * @returns the state
   */
  personCredentialsState(key) {
    const { log, config, applications, personAssertions, keystore,
      pki } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.personCredentialsState(). key=" + key);
    const storable = personAssertions.storable();
    const record = storable ? personAssertions.recordFor(key) : null;
    const chainAvailable = pki.hasChain();
    const described = chainAvailable ? pki.describe() : null;
    const labels: Record<string, any> = {};
    pki.PURPOSES.forEach(function (purpose) {
      labels[purpose.id] = purpose.label;
    });
    const purposes = personAssertions.PURPOSE_IDS.map(function (id) {
      const names = personAssertions.KEY_PAIR_ATTRIBUTES[id];
      const value = function (name) {
        log.debug("Entering value().");
        log.debug("Leaving value().");
        return record && name ? String(record[name] || '') : '';
      };
      const certificatePem = value(names.certificate);
      const privateKeyHeld = !!value(names.privateKey);
      const held = !!(record && (id === 'saml' ? record.hasSamlKeyPair
                                               : record.hasKeyPair));
      const declared = record
        ? (id === 'saml' ? record.samlIssuers : record.issuers) : [];
      return {
        id: id,
        label: labels[id] || id,
        attributes: { issuer: names.issuer, certificate: names.certificate,
                      chain: names.chain, privateKey: names.privateKey,
                      handle: names.handle, source: names.source,
                      expiresAt: names.expiresAt, jwks: names.jwks },
        held: held,
        source: value(names.source) ||
          (privateKeyHeld ? 'issued' : (certificatePem ? 'unrecorded' : '')),
        privateKeyHeld: privateKeyHeld,
        certificate: certificatePem ? self.certificateSummary(certificatePem) :
                     null,
        chain: self.pemCertificatesIn(value(names.chain))
          .map(self.certificateSummary.bind(self)),
        handle: value(names.handle),
        handleLabel: names.handleLabel,
        expiresAt: value(names.expiresAt),
        issuers: declared.slice(),
        effectiveIssuers: record
          ? (id === 'saml' ? record.samlEffectiveIssuers
                           : record.effectiveIssuers).slice() : []
      };
    });
    const state: Record<string, any> = {
      storable: storable,
      found: !!record,
      username: record ? record.username : String(key || ''),
      purposes: purposes,
      ca: {
        available: chainAvailable,
        keyAlg: described && described.keyAlg ? String(described.keyAlg) : '',
        keyAlgorithms: pki.keyAlgorithms(),
        leafLifetimeDays: pki.leafLifetimeDays()
      },
      sealsAtRest: storable && keystore.persists(),
      selfService: !!config.value('pki.personSelfService'),
      sources: applications.KEY_SOURCES.slice()
    };
    state.json = {
      storable: storable,
      found: state.found,
      keyPairs: purposes.map(function (p) {
        return { purpose: p.id, label: p.label, held: p.held, source: p.source,
                 privateKeyHeld: p.privateKeyHeld, certificate: p.certificate,
                 chain: p.chain, handle: p.handle, handleLabel: p.handleLabel,
                 expiresAt: p.expiresAt, issuers: p.issuers,
                 effectiveIssuers: p.effectiveIssuers,
                 attributes: p.attributes };
      }),
      caAvailable: chainAvailable,
      sealsAtRest: state.sealsAtRest,
      selfService: state.selfService,
      sources: state.sources
    };
    log.debug("Leaving AdminViews.personCredentialsState(). found=" +
              state.found);
    return state;
  }

  // `?application=` means the drill-down.
  /**
   * Builds `/admin/applications`'s JSON: the list, or the drill-down with
   * `?application=`.
   *
   * @param req - the request
   * @returns the JSON
   */
  applicationsJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.applicationsJson().");
    const wanted = String((req.query || {}).application || '').trim();
    log.debug("Leaving AdminViews.applicationsJson().");
    return wanted ? this.applicationDetailJson(req, wanted).json :
           this.applicationsListJson(req).json;
  }

  // ---------------------------------------------------------------------------
  // DELEGATED PERMISSIONS, ON THE APPLICATION'S OWN PAGE (2026-09-01).
  //
  // THE GRANT FORM LIVED ON /admin/delegation AND IT IS HERE NOW, and the
  // reason is the shape of the control rather than the length of that page.
  //
  // There it was two `<select>`s: every application in the registry beside
  // every permission anybody exposes, with the reader asked to get BOTH right.
  // That is the one write in this whole register where choosing the wrong
  // option still SUCCEEDS and stays plausible — a grant is a value on the
  // CLIENT's entry, so writing it to the resource instead produces a row that
  // resolves in both directions, reads correctly on the delegation page's own
  // grants table, and is wrong only at the token endpoint, later, to somebody
  // else. `tests/vendored/sts_delegated_permissions_example.js` asserts exactly
  // that pair of halves landing on the right entries, which is how much care
  // the distinction is worth.
  //
  // Here the first select does not exist: the client is the entry the reader is
  // standing on, and this page cannot be reached without having named it. A
  // control that could be half wrong became one that cannot be.
  //
  // **IT POSTS TO /admin/delegation AND THAT IS DELIBERATE.** A
  // `grant-permission` action on this page's own handler would mean a sixth
  // entry in APPLICATION_ACTIONS, and rule 7's parity check reads that list off
  // the handler's refusal sentence — so it would then want a `POST
  // /admin-api/applications/grant-permission` beside the `POST
  // /admin-api/permissions/grant-permission` that already exists, which is two
  // API operations for one write. Moving a FORM is not moving an ACTION. The
  // settings forms on the protocol pages already do this: they are drawn where
  // the setting belongs (`SETTING_HOMES`) and post to /admin/config, which
  // sends the reader back to the page the form was on. `from` is that field
  // here, and permissionsReturnTo() (admin-ui/admin.ts) rebuilds the
  // destination rather than echoing it, for configReturnTo()'s reason.
  //
  // WHAT IS NOT OFFERED, and each for its own reason:
  //   * this application's OWN permissions — the token would be audienced to
  //     itself, which is what an ID Token already is, and app_permissions.js
  //     refuses it anyway. Offering an option whose only outcome is a refusal
  //     is a control that can only fail.
  //   * permissions it ALREADY holds — the second grant is a no-op and the
  //     sentence it comes back with says nothing the table above it does not.
  //   * permissions with no identifier — nothing can ever ask for one, so a
  //     grant of it is a value no request will match. The delegation page says
  //     which ones those are and why.
  //
  // The table above the form is the read-back and it is what makes this a
  // section rather than a stray button: a write whose result you cannot see on
  // the page that took it is a write you have to go somewhere else to trust.
  // ---------------------------------------------------------------------------
  // The two halves of ONE application's delegated permissions, and what may
  // still be granted to it — in a pure function for permissionsListState()'s
  // reason: the drill-down's `?format=json` has to report the same answer, and
  // there is no reading it back out of a string of markup.
  /**
   * Builds one application's delegated permissions, both halves, and what may
   * still be granted to it.
   *
   * @param query - the request's query
   * @param identifier - the application
   * @returns the state
   */
  applicationPermissionsState(query, identifier) {
    const { log, appPermissions, applications } = this.deps;
    log.debug("Entering AdminViews.applicationPermissionsState(). identifier=" +
              identifier);
    const register = appPermissions.register();
    // WHAT THIS APPLICATION HOLDS, off the same register the delegation page
    // draws rather than off the entry's attribute — the attribute is the raw
    // identifier and nothing else, and everything a reader needs beside it
    // (which application exposes it, what the token will say, whether it has
    // ever been asked for) is the resolution that module does.
    const held = register.grants.filter(function (one) {
      return one.client === identifier;
    });
    // AND WHAT IT EXPOSES, the other half of the same question — configured
    // on that page since 2026-10-01 (rcbj): its base URI, its permissions,
    // and which OTHER applications hold them, each for this application only.
    const exposes = register.permissions.filter(function (one) {
      return one.resource === identifier;
    });
    // THE GRANTS OF ITS OWN PERMISSIONS: the relationships in which it is the
    // RESOURCE, one row per (client, permission) as on the register.
    const grantedOut = register.grants.filter(function (one) {
      return one.resource === identifier;
    });
    // WHO THEY MAY STILL GO TO: every other application in the registry. Not
    // itself — app_permissions.js refuses that grant however it arrives, for
    // the reason the `offerable` exclusions below give.
    const clients = applications.list().filter(function (row) {
      return row.identifier !== identifier;
    }).map(function (row) {
      return { identifier: row.identifier, name: row.name || row.identifier };
    });
    const heldIds = held.map(function (one) { return one.permissionId; });
    log.debug("Leaving AdminViews.applicationPermissionsState(). " +
              held.length +
              " held, " + exposes.length + " exposed.");
    return {
      register: register,
      held: held,
      exposes: exposes,
      grantedOut: grantedOut,
      clients: clients,
      // WHAT MAY STILL BE GRANTED. See the section's header for why each of the
      // three exclusions is an exclusion rather than an option that refuses.
      offerable: register.permissions.filter(function (one) {
        return !!one.id && one.resource !== identifier &&
               heldIds.indexOf(one.id) < 0;
      }),
      // BOTH TABLES ARE PAGED, at the same ten rows /admin/delegation uses and
      // for the same reason: neither is bounded by anything — one client can be
      // granted every permission in the registry, and one resource can expose
      // any number — and that drill-down already carries the attribute table
      // above them. They take page parameters of their own (`heldPage`,
      // `exposedPage`) so that moving one moves neither the other nor the
      // attributes, and they share the page's single `per` with the attribute
      // table, which is the arrangement perPageForm()'s header describes.
      //
      // NEITHER IS IN LIST_PARAMS AND THAT IS DELIBERATE — `attributesPage` is
      // not either. Those names are a DRILL-DOWN's own leaves; what LIST_PARAMS
      // carries is the state of the LIST the page hangs under, and a page
      // number from in here would be spent by /admin/applications, which has no
      // such table.
      heldPage: this.pagedRows(query, held,
        { name: 'held', noun: 'permissions', defaultPer: DELEGATION_PER_PAGE }),
      exposedPage: this.pagedRows(query, exposes,
        { name: 'exposed', noun: 'permissions',
          defaultPer: DELEGATION_PER_PAGE }),
      grantedOutPage: this.pagedRows(query, grantedOut,
        { name: 'grantedOut', noun: 'grants',
          defaultPer: DELEGATION_PER_PAGE })
    };
  }

  // WHAT /admin/federation ANSWERS: the relationships, and one of them.
  /**
   * Builds `/admin/federation`'s list of relationships.
   *
   * @param req - the request
   * @returns the JSON
   */
  federationListJson(req) {
    const { log, federation } = this.deps;
    log.debug("Entering AdminViews.federationListJson().");
    const all = federation.list().map(this.federationRow.bind(this));
    const wantedText = String(req.query.q || '').trim().toLowerCase();
    const wantedRole = String(req.query.role || '').trim();
    const filtered = all.filter(function (row) {
      if (wantedRole && row.role !== wantedRole) return false;
      if (!wantedText) return true;
      return (row.id + ' ' + row.name + ' ' + row.peer + ' ' + row.application)
        .toLowerCase().indexOf(wantedText) >= 0;
    });
    const paging = this.pagingOf(req.query, filtered.length, {});
    const paged = this.pagedRows(req.query, filtered, {});
    const pagingJson = this.pagingJson(paging);
    // WHAT THE TILES AND THE ROLE MENU COUNT, over every relationship and not
    // the page shown (#446).
    const roleCounts: Record<string, number> = {};
    all.forEach(function (r) {
      roleCounts[r.role] = (roleCounts[r.role] || 0) + 1;
    });
    const notConfigured = all.filter(function (r) {
      return r.enabled && !r.ready;
    }).length;
    const authenticationTotal = all.reduce(function (n, r) {
      return n + r.authentications;
    }, 0);
    log.debug("Leaving AdminViews.federationListJson().");
    return {
      all: all, wantedText: wantedText, wantedRole: wantedRole,
      filtered: filtered, paging: paging, paged: paged,
      json: (function () {
      return {
          relationshipCount: all.length, matched: filtered.length,
          shown: paged.shown.length,
          ready: all.filter(function (r) { return r.usable; }).length,
          filter: { q: String(req.query.q || '') || null,
                    role: wantedRole || null },
          page: paging.page, pages: paging.pages, perPage: paging.perPage,
          firstRow: paging.firstRow, lastRow: paging.lastRow,
          container: federation.containerDn(),
          max: federation.maxRelationships(),
          settings: configSettingsJson('/admin/federation'),
          roles: federation.ROLES, protocols: federation.PROTOCOLS,
          paths: federation.PATHS,
          paging: pagingJson, roleCounts: roleCounts,
          enabledNotConfigured: notConfigured,
          authentications: authenticationTotal,
          relationships: paged.shown
      };
      }())
    };
  }

  // The relationship drill-down. The three URLs are the ones the page prints
  // AND the ones the resource publishes — computed once so a partner reading
  // the document and an operator reading the page are told the same endpoint.
  /**
   * Builds one federation relationship's drill-down, with the three URLs a
   * partner uses.
   *
   * @param req - the request
   * @param id - the relationship's id
   * @returns the JSON
   */
  federationDetailJson(req, id) {
    const { log, baseUrlOf, realms, federation, fedLinks, fedEncryption } =
      this.deps;
    const self = this;
    log.debug("Entering AdminViews.federationDetailJson(). id=" + id);
    const record = federation.get(id);
    if (!record) {
      log.debug("Leaving AdminViews.federationDetailJson(). No such " +
                "relationship.");
      return { record: null, row: null,
               json: { found: false, id: id, paths: federation.PATHS } };
    }
    const row = this.federationRow(record);
    // ---------------------------------------------------------------------
    // THE ADDRESSES TO GIVE THE PARTNER, and they are the whole point of this
    // page: an operator copies them into somebody else's identity service,
    // where being wrong is a federation that fails at the far end with nothing
    // here to point at.
    //
    // `baseUrlOf(req)` is the ONLY way to build one. This was
    // `'http://' + req.get('host')` until 2026-08-26 — the one place in this
    // file that did not go through that helper — and it was wrong three ways at
    // once, each of them invisible on a default deployment:
    //
    //   * NO REALM PREFIX. A relationship is an entry in one realm's own
    //     register and its assertion consumer service answers only under that
    //     realm's prefix, so the URL printed here named a path that 404s —
    //     while the AuthnRequest this service actually sends carries the right
    //     one, because federation_sp.ts does use baseUrlOf(). The page and the
    //     wire disagreed, and the page is the half a person reads.
    //   * ALWAYS `http://`, on a service that binds TLS whenever `global.https`
    //     is set — which every launcher in the parent project's suite does.
    //   * NO FORWARDED HEADERS, so a deployment behind a proxy with
    //     `global.trustProxy` on was told its own internal address.
    // ---------------------------------------------------------------------
    const base = baseUrlOf(req);
    const acs = base + federation.PATHS.acs + '/' + encodeURIComponent(row.id);
    const login = federation.PATHS.login + '/' + encodeURIComponent(row.id);
    const metadata = base + federation.PATHS.metadata + '/' +
                     encodeURIComponent(row.id);
    // AND THE SAME PATH AGAIN, PREFIXED, FOR THE JSON — which is not a
    // duplicate. `login` above is used in an `href` on this page and must stay
    // ROOT-RELATIVE, because app.js's realm middleware rewrites root-relative
    // hrefs in an HTML response on the way out and its regex has no idempotence
    // guard: a path prefixed here would leave the page carrying
    // /realm/acme/realm/acme/federation/login/x. That rewrite runs on
    // `text/html` ONLY, so the JSON reply is never touched and has to carry the
    // prefix itself. `realms.href()` is the guarded version and is safe either
    // way.
    const loginPath = realms.href(login);
    // A PARTNER'S SIGN-OUT (#167): the addresses to register at the partner,
    // per protocol — the SAML SingleLogoutService and WS-Federation cleanup
    // URL (one path), and OpenID Connect's three registration members. None
    // for SAML 1.1 and OAuth 2.0, which define no sign-out.
    const slo = base + federation.PATHS.slo + '/' + encodeURIComponent(row.id);
    const signOut = row.protocol === 'saml2'
      ? { singleLogout: slo }
      : row.protocol === 'wsfed'
        ? { signOutCleanup: slo }
        : row.protocol === 'oidc'
          ? { backchannelLogout: base + federation.PATHS.backchannelLogout +
                '/' + encodeURIComponent(row.id),
              frontchannelLogout: base + federation.PATHS.frontchannelLogout +
                '/' + encodeURIComponent(row.id),
              postLogoutRedirect: slo }
          : {};

    // WHAT A PARTNER ENCRYPTS TO (#168): the policy, the public key table,
    // and the two places it is published.
    const encryption = fedEncryption.viewOf(record);
    const jwks = row.protocol === 'oidc' && row.role === 'service-provider'
      ? base + federation.PATHS.jwks + '/' + encodeURIComponent(row.id)
      : null;
    // THE PARTNER'S SHARED SIGNALS (#373, #374) are drawn in a section of
    // their own, so their fields leave the general lists below; and an `ssf`
    // relationship's fields are its signals alone (fieldsForRole() narrows
    // by protocol).
    const signalFields = federation.SIGNAL_FIELDS;
    const setFields = federation.fieldsForRole(row.role, 'set', row.protocol)
                                .filter(function (field) {
      if (signalFields.indexOf(field.name) >= 0) {
        return false;
      }
      // The four booleans get their own two-button control below, because a
      // text box a person types TRUE into is a text box a person types "true",
      // "yes" and "1" into — and one of those is how a relationship stays
      // disabled while the page says it is on.
      return ['fedEnabled', 'fedAutocreateUsers', 'fedUpdateUserAttributes',
              'fedMayAssertAdministrators', 'fedSignRequest',
              'fedAllowUnsolicited', 'fedAcceptSignout',
              'fedRequireSignedLogout', 'fedAllowUnencrypted']
        .indexOf(field.name) === -1 &&
        // A Trust Anchor to discover the OP through (#134) is OpenID
        // Connect's alone.
        (field.name !== 'fedTrustAnchor' || row.protocol === 'oidc') &&
        // The four encryption fields mean nothing to SAML 1.1 and OAuth 2.0.
        (federation.encrypts(record) ||
         ['fedEncryptionKeyType', 'fedKeyManagementAlgorithm',
          'fedContentEncryptionAlgorithm'].indexOf(field.name) === -1);
    });
    const multiFields = federation.fieldsForRole(row.role, 'multi',
                                                 row.protocol)
      .filter(function (field) {
        return signalFields.indexOf(field.name) < 0;
      });
    // The signals section's own fields — settings, the two switches, and the
    // event list — and what the receiver holds for this relationship.
    const signalSetFields = row.role === 'service-provider'
      ? federation.fieldsForRole(row.role, 'set', row.protocol)
          .filter(function (field) {
            return signalFields.indexOf(field.name) >= 0 &&
                   ['fedSignalsEnabled', 'fedSignalEmailMatch']
                     .indexOf(field.name) < 0;
          })
      : [];
    let signals = null;
    let arrivals = [];
    let outbound = null;
    try {
      const receiver = this.deps.loadSignals();
      if (row.role === 'service-provider') {
        signals = receiver.view(record);
        arrivals = receiver.arrivals(record.fedId, 10);
      } else {
        outbound = receiver.outboundFor(record);
      }
    } catch (e) {
      log.debug("Caught in AdminViews.federationDetailJson(): " +
                ((e && e.message) || e));
      signals = null;
    }
    // THE PEOPLE THIS PARTNER'S SUBJECTS ARE LINKED TO (#109), paged — a
    // relationship with ten thousand linked people is an ordinary one, and a
    // page drawing all of them is not. Service-provider side only: an
    // identity-provider-side relationship asserts, and nobody is linked to it.
    //
    // PAGED BEFORE IT IS PARSED (#352): the links are paged as the directory
    // hands them over, and only the page's are taken apart into issuer and
    // subject.
    const linkKeyPage = this.pagedRows(req.query,
      row.role === 'service-provider'
        ? federation.linkedThrough(record.fedId) : [],
      { name: 'links', noun: 'links' });
    const linkPage = Object.assign({}, linkKeyPage, {
      shown: linkKeyPage.shown.map(function (one) {
        const parts = fedLinks.parse(one.value) || {};
        return { username: one.username, dn: one.dn, link: one.value,
                 issuer: parts.issuer, subject: parts.subject };
      })
    });
    // WHAT THE PARTNER SENT AND NOTHING WROTE (#94): names no mapping names,
    // and names mapped onto an attribute no partner may write, newest
    // first. Service-provider side only, where attributes arrive.
    const unmapped = row.role === 'service-provider'
      ? federation.unmappedOf(record.fedId) : [];
    // The label of every value a select on the page offers: a sign-in
    // mechanism's or a subject policy's.
    const enumLabels: Record<string, string> = {};
    setFields.forEach(function (field) {
      (Array.isArray(field.enum) ? field.enum : []).forEach(function (one) {
        const known = federation.mechanismRow(one) ||
                      federation.subjectPolicyRow(one);
        if (known) {
          enumLabels[one] = known.label;
        }
      });
    });

    log.debug("Leaving AdminViews.federationDetailJson().");
    return {
      record: record, row: row, base: base, acs: acs, login: login,
      metadata: metadata, loginPath: loginPath, jwks: jwks,
      encryption: encryption,
      signOut: row.role === 'service-provider' ? signOut : {},
      setFields: setFields, multiFields: multiFields, linkPage: linkPage,
      unmapped: unmapped, signalSetFields: signalSetFields,
      signals: signals, arrivals: arrivals, outbound: outbound,
      json: (function () {
      return Object.assign({ found: true }, row, {
          endpoints: Object.assign({
                       assertionConsumerService: acs, login: loginPath,
                       metadata: (row.protocol === 'saml2' ||
                                  row.protocol === 'saml11' ||
                                  row.protocol === 'wsfed')
                         ? metadata : null,
                       jwks: jwks },
                       row.role === 'service-provider' ? signOut : {}),
          // The whole record, MINUS the one sensitive field. `fedClientSecret`
          // is replaced by a boolean saying whether one is set — which is the
          // fact a caller actually needs ("is this configured?") without the
          // API being a second way to read a credential out of this process. An
          // ldapsearch is still that way, deliberately and loudly.
          fields: (function () {
            const out: Record<string, any> = {};
            federation.SCHEMA.attributes.forEach(function (field) {
              if (field.sensitive) {
                out[field.name] = record[field.name] ? '(set — not returned)' :
                                  '';
                return;
              }
              out[field.name] = record[field.name];
            });
            return out;
          })(),
          editable: federation.fieldsForRole(row.role, '', row.protocol),
          unmappedAttributes: unmapped,
          // A partner's Shared Signals (#373): the stream's state and the
          // latest arrivals; for an identity-provider-side relationship,
          // what this service sends that partner instead.
          signals: signals,
          signalArrivals: arrivals,
          outboundSignals: outbound,
          encryption: encryption,
          // Who this partner's subjects are linked to (#109): the page, and
          // the paging a caller walks it with.
          links: linkPage.shown,
          linksPaging: self.pagingJson(linkPage.paging),
          // WHAT THE PAGE IS DRAWN FROM BESIDES THE RECORD (#446): the
          // field rows each list and form is built from, the schema the
          // switches are described by, the labels of the values a select
          // offers, the policy and encryption answers the register gives
          // about this record, and the addresses the page prints or links.
          setFields: setFields, multiFields: multiFields,
          signalSetFields: signalSetFields,
          schema: federation.SCHEMA.attributes,
          enumLabels: enumLabels,
          defaultSubjectPolicy: federation.DEFAULT_SUBJECT_POLICY,
          subjectPolicy: federation.subjectPolicyOf(record),
          encrypts: federation.encrypts(record),
          paths: federation.PATHS, base: base, loginHref: login,
          metadataUrl: metadata,
          signOut: row.role === 'service-provider' ? signOut : {}
      });
      }())
    };
  }

  // `?relationship=` means the drill-down — NOT `?id=`, which is what a first
  // pass of this assumed from the detail function's parameter name. The
  // dispatch has to read the same query key the page reads, or the resource
  // answers the LIST for every drill-down and a caller asking about one
  // relationship is told about all of them.
  /**
   * Builds `/admin/federation`'s JSON: the list, or one relationship.
   *
   * @param req - the request
   * @returns the JSON
   */
  federationJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.federationJson().");
    const wanted = String((req.query || {}).relationship || '').trim();
    log.debug("Leaving AdminViews.federationJson().");
    return wanted ? this.federationDetailJson(req, wanted).json :
           this.federationListJson(req).json;
  }

  // One row's summary, shared by the list and the JSON. It is a function rather
  // than being built inline twice because the READINESS is computed here — the
  // page prints it and the API answers it, and two computations of "is this
  // partner usable" would be two answers to the question the whole page is
  // about.
  /**
   * Describes one relationship as a row, with its readiness.
   *
   * @param record - the relationship
   * @returns the row
   */
  federationRow(record) {
    const { log, federation } = this.deps;
    log.debug("Entering AdminViews.federationRow().");
    const readiness = federation.readinessOf(record);
    log.debug("Leaving AdminViews.federationRow().");
    return {
      id: record.fedId,
      name: record.fedName || record.fedId,
      role: record.fedRole,
      roleLabel: (federation.roleRow(record.fedRole) ||
                  {}).short || record.fedRole,
      protocol: record.fedProtocol,
      protocolLabel: (federation.protocolRow(record.fedProtocol) ||
                      {}).label || record.fedProtocol,
      peer: record.fedPeer || '',
      application: record.fedApplication || '',
      enabled: federation.isEnabled(record),
      ready: readiness.ready,
      missing: readiness.missing,
      usable: federation.isEnabled(record) && readiness.ready,
      // Whether it signs anybody in, and whether its partner's Shared
      // Signals are received (#373, #374).
      signsIn: federation.signsIn(record),
      signalsEnabled: federation.signalsEnabled(record),
      releases: (record.fedRelease || []).slice(0),
      mappings: (record.fedAttributeMap || []).slice(0),
      authentications: parseInt(record.fedAuthentications, 10) || 0,
      users: parseInt(record.fedUsers, 10) || 0,
      lastUser: record.fedLastUser || '',
      lastSeen: record.fedLastSeen || '',
      lastError: record.fedLastError || '',
      lastErrorAt: record.fedLastErrorAt || '',
      dn: record.dn || ''
    };
  }

  // WHAT /admin/users ANSWERS: the population, and one person.
  //
  // `authenticatedHere` and `factorCounts` come with the computation although
  // the page declares them among its markup — they are filters over the same
  // list, and the tiles a person reads must be the numbers the resource
  // publishes. The second-factor roster is exactly that: one tally, two
  // renderings.
  /**
   * Builds `/admin/users`'s list of people, with its tiles and the
   * second-factor roster.
   *
   * @param req - the request
   * @returns the JSON
   */
  usersListJson(req) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.usersListJson().");
    const wantedText = String(req.query.q || '').trim();
    const wantedProtocol = String(req.query.protocol || '');
    // THE UNION, not `stats.userRows()` — see peopleRows(). The registry is
    // capped at two thousand and the directory is not, so on a realm that has
    // been bulk loaded this is the difference between a page that answers *who
    // holds no second factor* and one that answers it for the first two
    // thousand people it happens to remember.
    const population = this.peopleRows();
    const all = population.rows;
    const self = this;
    // The second-factor filter, which arrived with the roster on 2026-09-10. It
    // is `factor` rather than `mfa` because that is the name `/admin/mfa` used
    // and a link somebody bookmarked should keep working against the page that
    // absorbed it — the same courtesy `listViewFromBack()` extends to a filter
    // carried across a form.
    const wantedFactor = String(req.query.factor || '');
    // A SERVICE ACCOUNT IS A PERSON (#221), so it is on this list — TAGGED,
    // and filterable by `kind`: `service` for service accounts only, `person`
    // for everybody else. One read of the flag's holders, not one per row.
    const wantedKind = ['service', 'person'].indexOf(
      String(req.query.kind || '')) >= 0 ? String(req.query.kind) : '';
    const serviceNames = new Set(this.deps.serviceAccounts.names()
      .map(function (name) {
        return String(name).toLowerCase();
      }));
    all.forEach(function (row) {
      row.serviceAccount = serviceNames.has(String(row.key).toLowerCase());
    });
    // Every protocol any known user authenticated through, for the filter. Read
    // off the data rather than written down, so a protocol that starts
    // recording authentications appears in the dropdown by itself and one that
    // never has cannot offer a filter that matches nothing.
    const protocolsSeen: Record<string, any> = {};
    all.forEach(function (row) {
      row.protocols.forEach(function (family) {
        protocolsSeen[family.protocol] = true;
      });
    });
    // -----------------------------------------------------------------------
    // WHAT EVERYBODY HOLDS, COUNTED ONCE (#352, 2026-09-29).
    //
    // The tiles below and the `?factor=` filter are the two things on this
    // page that need every row's factors, and they used to get them by
    // decorating every row — `mechanismsFor()` per person, which is what made
    // this page ten seconds long on a realm of thirty thousand. They get them
    // from `peopleCensus()` now: seven facts per person from ONE pass over
    // the directory, each sealed TOTP secret opened at most once per process.
    // The census gives the same facts `mechanismsFor()` would, folded across
    // spellings by the same `mergeFactors()`, so the numbers do not move.
    // -----------------------------------------------------------------------
    const census = this.peopleCensus(population, all);
    const factorsOf = function (row) {
      return census.get(row.key) || null;
    };
    const filtered = all.filter(function (row) {
      if (wantedText &&
          row.key.toLowerCase()
                 .indexOf(wantedText.toLowerCase()) < 0) return false;
      if (wantedProtocol &&
          !row.protocols.some(function (f) {
            return f.protocol === wantedProtocol;
          })) {
        return false;
      }
      // `factors` is null where no credential store answered at all. Such a row
      // matches NO factor filter rather than matching `none`, because "this
      // service cannot tell" and "this person holds none" are different answers
      // and the second one is the dangerous one to guess.
      const factors = factorsOf(row);
      if (wantedFactor === 'totp' && !(factors && factors.totp)) return false;
      if (wantedFactor === 'key' &&
          !(factors && factors.mfaKeys > 0)) return false;
      if (wantedFactor === 'any' &&
          !(factors && factors.mfaRequired)) return false;
      if (wantedFactor === 'none' &&
          !(factors && !factors.mfaRequired)) return false;
      if (wantedFactor === 'unreadable' &&
          !(factors && factors.totp && !factors.totpUsable)) return false;
      if (wantedKind === 'service' && !row.serviceAccount) {
        return false;
      }
      if (wantedKind === 'person' && row.serviceAccount) {
        return false;
      }
      return true;
    });
    // PAGE, THEN DECORATE: the full factor row — keys, the authenticator's
    // detail, the recovery codes, what the columns draw — is built for the
    // rows on this page and for nobody else (`pagedRows()`).
    const page = this.pagedRows(req.query, filtered, {
      decorate: function (row) {
        return self.decoratePerson(population, row);
      }
    });
    const paging = page.paging;
    const shown = page.shown;
    const filterParams = { q: wantedText, protocol: wantedProtocol,
                           factor: wantedFactor, kind: wantedKind,
                           per: req.query.per ? paging.perPage : '' };
    const authenticatedHere = all.filter(function (
        row) { return row.authenticated; }).length;
    // Over everybody, from the census — never from `shown`, whose rows are
    // the only ones decorated. A row the census has nothing for (no
    // credential store answered) counts in no tile, as it always did.
    const counted = function (test) {
      return all.filter(function (r) {
        const f = factorsOf(r);
        return !!f && test(f, r);
      }).length;
    };
    const factorCounts = {
      withSecond: counted(function (f) { return f.mfaRequired; }),
      withTotp: counted(function (f) { return f.totp; }),
      withKeys: counted(function (f) { return f.mfaKeys > 0; }),
      primaryKeys: counted(function (f) { return f.primaryKeys > 0; }),
      passwordOnly: counted(function (f) {
        return f.password && !f.mfaRequired;
      }),
      unreadable: counted(function (f) { return f.totp && !f.totpUsable; }),
      // NOBODY CAN SIGN IN AS THEM. A person with an entry and no password and
      // no primary key — the ordinary state of somebody provisioned and not yet
      // activated, and the state an activation link exists to end. It is
      // counted beside the second-factor tiles because it is the OTHER question
      // an operator brings to a roster of people.
      noCredential: counted(function (f, r) {
        return !f.usable && !r.isClient;
      })
    };
    // WHO HOLDS A LIVE SIGN-ON SESSION, counted for the page's tile (#446):
    // one person with three browsers is one, by the same identity key the
    // rows are filed under.
    const liveByUser: Record<string, number> = {};
    this.signOnSessionRows().forEach(function (session) {
      if (session.expired) {
        return;
      }
      const key = stats.identityKeyOf(session.username || session.sub);
      liveByUser[key] = (liveByUser[key] || 0) + 1;
    });
    const pagingJson = this.pagingJson(paging);
    log.debug("Leaving AdminViews.usersListJson().");
    return {
      wantedText: wantedText, wantedProtocol: wantedProtocol,
      population: population,
      all: all, wantedFactor: wantedFactor, protocolsSeen: protocolsSeen,
      filtered: filtered, paging: paging, shown: shown, filterParams:
                                                          filterParams,
      authenticatedHere: authenticatedHere, factorCounts: factorCounts,
      json: (function () {
      return {
          known: all.length, matched: filtered.length, shown: shown.length,
          authenticatedHere: authenticatedHere,
          // THE SECOND-FACTOR ROSTER, HERE RATHER THAN ON A RESOURCE OF ITS OWN
          // (2026-09-10). `GET /admin-api/mfa` answers out of this same view,
          // so there is one tally and the console and the API cannot disagree
          // about how many people hold a second factor. Each row carries its
          // own `factors` object; these are the counts over the whole
          // population.
          factors: factorCounts,
          // WHICH POPULATION THIS IS, so a caller reading `known` knows what it
          // counted. `capped` is the one to check on a bulk-loaded realm: past
          // it the credential columns are absent rather than false.
          store: population.store, scanned: population.scanned,
          capped: population.capped, scanLimit: population.limit,
          registryCap: population.registryCap,
          filter: { q: wantedText || null, protocol: wantedProtocol || null,
                    factor: wantedFactor || null, kind: wantedKind || null },
          // #221: how many of the people are service accounts.
          serviceAccounts: all.filter(function (row) {
            return row.serviceAccount;
          }).length,
          protocols: Object.keys(protocolsSeen).sort(),
          page: paging.page, pages: paging.pages, perPage: paging.perPage,
          firstRow: paging.firstRow, lastRow: paging.lastRow,
          // What the page draws beside the rows (#446): the paging control,
          // the active-session tile, and three facts its notes state — how
          // many person fields a new entry may carry, where it goes, and how
          // many identities the registry keeps.
          paging: pagingJson,
          withActiveSession: Object.keys(liveByUser).length,
          personFieldCount: vcClaims.personFields().length,
          newUserContainer: self.newUserContainer(),
          registryKeeps: stats.MAX_USERS,
          // Each row with its live sign-on sessions, the column beside it.
          users: shown.map(function (row) {
            return Object.assign({}, row,
                                 { liveSessions: liveByUser[row.key] || 0 });
          })
      };
      }())
    };
  }

  // ===========================================================================
  // EVERYBODY THIS REALM KNOWS ABOUT, AND WHAT EACH OF THEM CAN SIGN IN WITH
  // (2026-09-10).
  //
  // **THIS PAGE'S POPULATION WIDENED ON THE DAY `/admin/mfa` WAS TAKEN AWAY.**
  // It was `stats.userRows()` — identities this service has SEEN — and its own
  // lead paragraph said so. `/admin/mfa` drew a different population: the union
  // of that with this realm's DIRECTORY people, because the question it
  // answered was *who holds no second factor* and the people most likely to
  // hold none are exactly the ones who have never signed in.
  //
  // Folding that roster into this page without widening the population would
  // have answered that question wrongly and quietly. So this function is the
  // union, and the page says which side of it each row came from.
  //
  // ---------------------------------------------------------------------------
  // THE GAP IS SMALLER THAN IT LOOKS AND IT IS NOT ZERO, WHICH IS WHY THIS IS
  // NOT A ONE-LINE CHANGE.
  //
  // Most directory people are ALREADY on `stats.userRows()`: every door that
  // creates one — the console, `POST /admin-api/users/create`, a SCIM create,
  // an LDAP add, a restore from the persistence store — calls
  // `stats.noteKnownIdentity()`, which is what put `knownBy` on a row. So on a
  // small service the union adds nothing at all.
  //
  // **THE REGISTRY IS CAPPED AT `stats.MAX_USERS` AND THE DIRECTORY IS NOT.**
  // Two thousand against `ldap.maxEntries`, so a realm with five thousand
  // people has at most two thousand of them here — and the three thousand
  // missing are invisible on every console page that asks a question about
  // people. That is the case this union exists for, and it is the case a bulk
  // load produces.
  //
  // ---------------------------------------------------------------------------
  // KEYED BY THE IDENTITY KEY AND NOT BY THE NAME.
  //
  // `credentials.secondFactorHolders()` dedupes case-insensitively on the raw
  // name; this page's whole premise is that ONE ROW IS ONE LOCAL NAME ACROSS
  // EVERY PROTOCOL, which is `stats.identityKeyOf()`. Two spellings that reach
  // the same identity key have to fold into one row here or the warning at the
  // top of the table stops being true. Where they do fold, the factor facts are
  // UNIONED rather than one of them winning: holding a key under one spelling
  // and an app under another is holding both.
  // ===========================================================================
  //
  // ---------------------------------------------------------------------------
  // AND IT READS NOTHING PER PERSON (#352, 2026-09-29).
  //
  // This function used to unite the FACTORS as it folded — every spelling
  // asked `mechanismsFor()` through `credentials.secondFactorHolders()` — so
  // building the population cost a credential lookup per person, and every
  // request to `/admin/users`, `/admin-api/users` and `/admin-api/mfa` paid it
  // for the whole realm to show one page. The fold is the same and the rows
  // are the same; what a row no longer carries is its factors (`factors` is
  // null on every row this returns). What it carries instead, beside the
  // rows, is `spellings` — which population names folded into which row, in
  // the order the fold met them — so that:
  //
  //   * `decoratePerson()` unites the full factor rows of ONE row's spellings,
  //     for the rows a page shows, in the order this used to; and
  //   * `peopleCensus()` unites the census facts of every row's spellings, for
  //     the tiles and the `?factor=` filter, in one pass.
  //
  // `isApplication` is the directory's one-listing answer to the third test
  // of `isApplicationRow()` (see there).
  // ---------------------------------------------------------------------------
  /**
   * Lists the people, one row per person, folding their spellings; the
   * factors are united later, for the rows shown (`decoratePerson()`) and in
   * one pass for the counts (`peopleCensus()`).
   *
   * @returns the rows, the population's reporting, and `spellings`
   */
  peopleRows() {
    const { log, credentials, stats } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.peopleRows().");
    const seen = stats.userRows();
    const byKey = new Map();
    seen.forEach(function (row) {
      // `factors` is filled below. Declared here so that every row has the
      // member whether or not the credential store answered — a page that read
      // `row.factors.totp` off a row that had none would throw on the one
      // deployment with no directory, which is the deployment least able to
      // report it.
      row.factors = null;
      row.inDirectory = false;
      byKey.set(row.key, row);
    });

    const holders = credentials.secondFactorPopulation(
      seen.map(function (row) {
        return row.key;
      }));
    // Row key -> the population rows (spellings) folded into it, in the order
    // the fold meets them, which is the order `mergeFactors()` used to be
    // applied in — so decorating later unites them exactly as this did.
    const spellings = new Map();

    holders.rows.forEach(function (holder) {
      const key = stats.identityKeyOf(holder.username);
      if (!key) return;
      let row = byKey.get(key);
      if (!row) {
        // A DIRECTORY PERSON THIS SERVICE HAS NEVER SEEN. Synthesised with the
        // same shape `blankUserRow()` produces, because every cell of this
        // table and every member of the JSON reply reads it — a row missing
        // `tokens` would be a column that throws rather than a column that says
        // nothing.
        // **THE SHAPE `userRows()` RETURNS AND NOT THE ONE `blankUserRow()`
        // BUILDS.** Those differ: the registry counts forms, realms, protocols
        // and artifact kinds in OBJECTS and converts every one of them to an
        // ARRAY on the way out. A row synthesised from the blank shape reaches
        // this page with `row.realms.map is not a function` — which is what the
        // first version of this did, on the one row type nothing else produces.
        row = { key: key, name: holder.username, forms: [], realms: [],
                protocols: [], authentications: 0, firstAt: 0, lastAt: 0,
                isClient: false, authenticated: false, knownBy: 'directory',
                events: [], eventsForgotten: 0,
                tokens: { issued: 0, valid: 0, expired: 0, revoked: 0,
                          other: 0 },
                artifactKinds: [], artifacts: 0, lastActivityAt: 0,
                factors: null, inDirectory: false };
        byKey.set(key, row);
      }
      row.inDirectory = row.inDirectory || !!holder.inDirectory;
      if (!spellings.has(key)) {
        spellings.set(key, []);
      }
      spellings.get(key).push(holder);
    });

    const isApplication = holders.isApplication;
    const rows = Array.from(byKey.values()).filter(function (row) {
      return !self.isApplicationRow(row, isApplication);
    });
    rows.sort(function (a, b) {
      return String(a.name).toLowerCase() < String(b.name).toLowerCase() ? -1 :
             1;
    });
    log.debug("Leaving AdminViews.peopleRows(). " + rows.length +
              " person/people, " +
              holders.scanned + " scanned in the directory.");
    return { rows: rows, store: holders.store, scanned: holders.scanned,
             capped: holders.capped, limit: holders.limit,
             registryCap: stats.MAX_USERS, spellings: spellings };
  }

  // ---------------------------------------------------------------------------
  // ONE SHOWN ROW'S FACTORS (#352): what `peopleRows()` used to compute for
  // everybody, for one row — each spelling's full roster row from
  // `credentials.factorHolderRow()`, united by `mergeFactors()` in the fold's
  // order. A row nothing folded into keeps `factors: null`, which is what it
  // had when no credential store answered for it.
  // ---------------------------------------------------------------------------
  /**
   * Fills in one people row's factors, for a row a page shows.
   *
   * @param population - what `peopleRows()` returned
   * @param row - one of its rows
   * @returns the row, with `factors`
   */
  decoratePerson(population, row) {
    const { log, credentials } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.decoratePerson(). key=" + row.key);
    let factors = null;
    ((population.spellings && population.spellings.get(row.key)) || [])
      .forEach(function (holder) {
        factors = self.mergeFactors(factors,
                                    credentials.factorHolderRow(holder));
      });
    row.factors = factors;
    log.debug("Leaving AdminViews.decoratePerson().");
    return row;
  }

  // ---------------------------------------------------------------------------
  // EVERY ROW'S FACTORS, IN ONE PASS, FOR WHAT COUNTS OR FILTERS (#352).
  //
  // `credentials.factorCensus()` answers the seven facts the tiles and the
  // `?factor=` filter read, for every spelling, from one call into the
  // directory; this unites them per row with the same `mergeFactors()` the
  // shown rows are united with, so a count and a row cannot disagree. Only
  // the rows passed in are asked about — the population after the
  // application filter, which is what the tiles have always counted.
  // ---------------------------------------------------------------------------
  /**
   * Answers each people row's census facts, united across its spellings.
   *
   * @param population - what `peopleRows()` returned
   * @param rows - the rows to answer for
   * @returns a Map from row key to its facts, or to null where nothing folded
   *   into it
   */
  peopleCensus(population, rows) {
    const { log, credentials } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.peopleCensus(). " + rows.length +
              " row(s).");
    const spellings = population.spellings || new Map();
    const names = [];
    rows.forEach(function (row) {
      (spellings.get(row.key) || []).forEach(function (holder) {
        names.push(holder.username);
      });
    });
    const facts = credentials.factorCensus(names);
    const out = new Map();
    rows.forEach(function (row) {
      let merged = null;
      (spellings.get(row.key) || []).forEach(function (holder) {
        merged = self.mergeFactors(merged,
          facts.get(String(holder.username).trim()) || {});
      });
      out.set(row.key, merged);
    });
    log.debug("Leaving AdminViews.peopleCensus().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // AN APPLICATION IS NOT A PERSON, AND THIS LIST IS A LIST OF PEOPLE
  // (2026-09-19).
  //
  // `stats.userRows()` is every IDENTITY this service has seen, and a
  // client_credentials client is one: it authenticated, it holds tokens, it
  // has a row. So the population above carried every such client, drawn with
  // `client` in a Kind column and counted in a "clients, not people" tile.
  // The 2026-09-19 fan-in fix (`everyUserRecord()`) made that FLAG right
  // across a cluster; it did not stop the row being on a page whose question
  // is who the PEOPLE are, and on testidp the "Management API operations
  // test" realm listed `app-stsapi-client-…` among its users. The rule is now
  // the directory's own: a person is somebody under `ou=users`, and an
  // application under `ou=applications` is never on this page.
  //
  // THREE TESTS, because each catches rows the others miss:
  //   * `isClient` — the register or a client_credentials token said so;
  //   * a `urn:sts:client:` subject among the row's forms — RFC 9700 mode's
  //     namespace for a client acting as itself (oauth2.ts);
  //   * the key is an application REGISTERED in this realm and the row has no
  //     person entry — which catches an application that reached the register
  //     by a door that sets no flag (an artifact's subject, a delegation).
  // The third one asks `inDirectory` first so a person who shares a name with
  // an application stays listed: the person entry is the stronger claim.
  // The rows are still on `stats.userRows()` for every page that is about
  // IDENTITIES rather than people — the delegation map, the token holders.
  //
  // **THE THIRD TEST WAS A REGISTRY READ PER ROW (#352)**: `applications.get()`
  // for every register row with no person entry — a directory lookup and, on
  // a miss, a walk of `ou=applications`, thousands of times on a cluster that
  // has seen many clients and whose directory is past the scan cap.
  // `isApplication` is the same question answered from ONE listing of that
  // container (`ldap_server.js`'s `applicationMatcher()`, handed over with
  // the population); where no directory offered one, the registry is asked
  // per row as before.
  // ---------------------------------------------------------------------------
  /**
   * Asks whether a user-registry row is an application rather than a person.
   *
   * @param row - the row
   * @param isApplication - the directory's one-listing matcher, when there
   *   is one; `applications.get()` is asked otherwise
   * @returns whether it is
   */
  isApplicationRow(row, isApplication?) {
    const { log, applications } = this.deps;
    log.debug("Entering AdminViews.isApplicationRow().");
    if (row.isClient) {
      log.debug("Leaving AdminViews.isApplicationRow(). Flagged a client.");
      return true;
    }
    const clientForm = (row.forms || []).some(function (one) {
      return /^urn:sts:client:/.test(String((one && one.form) || one));
    });
    if (clientForm) {
      log.debug("Leaving AdminViews.isApplicationRow(). A client subject.");
      return true;
    }
    if (!row.inDirectory &&
        (typeof isApplication === 'function' ? isApplication(row.key)
                                             : applications.get(row.key))) {
      log.debug("Leaving AdminViews.isApplicationRow(). A registered " +
                "application.");
      return true;
    }
    log.debug("Leaving AdminViews.isApplicationRow(). A person.");
    return false;
  }

  // TWO SPELLINGS THAT FOLD INTO ONE ROW HOLD THE UNION OF WHAT EACH HELD.
  // Taking the first would answer "no second factor" for somebody who has one
  // under their other name, which is the wrong answer in the direction that
  // matters: this table is read to find people who are NOT protected.
  /**
   * Folds one spelling's second factors into a person's, as a union.
   *
   * @param into - the factors held so far, or nothing for the first spelling
   * @param holder - the other spelling's facts
   * @returns the united factors
   */
  mergeFactors(into, holder) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.mergeFactors().");
    if (!into) {
      log.debug("Leaving AdminViews.mergeFactors().");
      return {
        password: !!holder.password,
        primaryKeys: holder.primaryKeys || 0,
        mfaKeys: holder.mfaKeys || 0,
        totp: !!holder.totp,
        totpUsable: !!holder.totpUsable,
        totpDetail: holder.totpDetail || null,
        mfaRequired: !!holder.mfaRequired,
        secondFactor: holder.secondFactor || '',
        usable: !!holder.usable,
        // **THE RECOVERY CODES (2026-09-11), AND THIS FUNCTION IS WHERE THEY
        // WERE BEING LOST.** `credentials.secondFactorHolders()` has always put
        // a `backupCodes` member on every row, and this merge built an explicit
        // shape without it — so the counts reached neither `/admin/users` nor
        // `GET /admin-api/mfa`, and an operator could see that somebody held an
        // authenticator and not that they had used nine of their ten ways back.
        //
        // Counts and never codes: `backupCodeStatus()` is what the member is
        // built from and it carries none.
        backupCodes: holder.backupCodes || null,
        recoveryAdvised: !!holder.recoveryAdvised
      };
    }
    into.password = into.password || !!holder.password;
    into.primaryKeys += (holder.primaryKeys || 0);
    into.mfaKeys += (holder.mfaKeys || 0);
    // `totpUsable` is only meaningful where `totp` is, so the two move together
    // — an enrolment this process cannot read must not be reported as absent,
    // which would sign somebody in on one factor.
    if (holder.totp && !into.totp) {
      into.totp = true;
      into.totpUsable = !!holder.totpUsable;
      into.totpDetail = holder.totpDetail || null;
    }
    into.mfaRequired = into.mfaRequired || !!holder.mfaRequired;
    into.usable = into.usable || !!holder.usable;
    // **A SET FOUND UNDER EITHER SPELLING WINS, WHICH IS `totp`'s RULE ABOVE
    // AND FOR ITS REASON.** This table is read to find people who are NOT
    // protected, so taking the first row's answer would report "no recovery
    // codes" for somebody who holds a set under their other name — the wrong
    // answer in the direction that matters.
    if (holder.backupCodes && holder.backupCodes.present &&
        !(into.backupCodes &&
        into.backupCodes.present)) {
      into.backupCodes = holder.backupCodes;
    } else if (!into.backupCodes) {
      into.backupCodes = holder.backupCodes || null;
    }
    // **AND THE ADVICE IS THE OTHER WAY ROUND: ALL OF THEM MUST WANT IT.** It
    // is true of somebody with a second factor and no set, so a spelling that
    // holds the set makes it false for the person — the union of two rows must
    // not tell an operator to chase somebody who is already covered.
    into.recoveryAdvised = (into.recoveryAdvised || !!holder.recoveryAdvised) &&
                           !(into.backupCodes && into.backupCodes.present);
    into.secondFactor = into.mfaKeys > 0 ? 'webauthn'
                      : (into.totp ? 'totp' : '');
    log.debug("Leaving AdminViews.mergeFactors().");
    return into;
  }

  // One person: their sessions, what was issued on each, and the credentials
  // they hold. The four paged lists come with the computation although the page
  // declares them among its markup — the resource publishes each one's paging.
  // One person's federation links as rows, paged (#109). Shared by the
  // console's panel and the JSON beside it, so the two cannot disagree.
  /**
   * Lists one person's federation links as rows, paged (#109).
   *
   * @param query - the request's query
   * @param key - the person
   * @returns the rows and their paging
   */
  federationLinksOf(query, key) {
    const { log, federation, fedLinks } = this.deps;
    log.debug("Entering AdminViews.federationLinksOf().");
    const person = federation.federatedPerson(key);
    const rows = (person ? person.links : []).map(function (value) {
      const parts = fedLinks.parse(value) || {};
      const record = parts.relationship ? federation.get(parts.relationship)
                                        : null;
      return { link: value, relationship: String(parts.relationship || ''),
               issuer: String(parts.issuer || ''),
               subject: String(parts.subject || ''),
               relationshipExists: !!record &&
                                   record.fedRole === 'service-provider' };
    });
    log.debug("Leaving AdminViews.federationLinksOf(). " + rows.length);
    return this.pagedRows(query || {}, rows,
                          { name: 'federationLinks', noun: 'links' });
  }

  // A person's GNAP grants (#432 phase 7), or an empty page where GNAP's view
  // layer cannot be loaded in this process.
  /**
   * Returns the GNAP grants a person is the resource owner of, as
   * `gnap/gnap_console.ts`'s `personGrantsView()` draws them.
   *
   * @param query - the request's query
   * @param key - the person
   * @returns `{ rows, paging, cells }`
   */
  gnapGrantsOf(query, key) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.gnapGrantsOf().");
    const loader = this.deps.loadGnapConsole;
    if (!loader) {
      log.debug("Leaving AdminViews.gnapGrantsOf(). No GNAP here.");
      return { rows: [], paging: null, cells: null };
    }
    const view = loader().personGrantsView(key, query || {});
    log.debug("Leaving AdminViews.gnapGrantsOf(). " + view.total + ".");
    return { rows: view.rows, paging: view.paging, cells: view.cells };
  }

  // `risk` is the person's current standing (#62), read by `riskFor()`
  // before this synchronous view runs and handed in, because a view reads
  // nothing off the request but its query.
  /**
   * Builds one person's drill-down on `/admin/users`.
   *
   * @param req - the request
   * @param key - the person
   * @param risk - the person's current risk standing, read by `riskFor()`
   * @returns the JSON
   */
  /**
   * Builds Monitoring → Service accounts (#221): every service account in the
   * realm with its push destination and the state of its rotation — when it
   * last rotated, when it is next due, and how many rotations in a row have
   * failed — paged, with the realm's rotation settings and the totals.
   *
   * @param query - the request's query (`page`, `per`, `failing`)
   * @returns the page's JSON
   */
  serviceAccountsMonitorJson(query) {
    const { log, serviceAccounts, serviceAccountPolicy } = this.deps;
    log.debug("Entering AdminViews.serviceAccountsMonitorJson().");
    const q = query || {};
    const profile = serviceAccountPolicy.read();
    const rotation = serviceAccountPolicy.rotation(profile);
    const self = this;
    const all = serviceAccounts.names().slice().sort().map(function (name) {
      const one = self.serviceAccountJson(name);
      return one ? Object.assign({ username: name }, one) : null;
    }).filter(function (row) {
      return !!row;
    });
    const failingOnly = String(q.failing || '') === 'true';
    const rows = failingOnly ? all.filter(function (row) {
      return row.rotation.failures > 0;
    }) : all;
    const listed = this.pagedRows(q, rows);
    const out = {
      policy: {
        rotationEnabled: rotation.enabled,
        intervalDays: profile.rotationIntervalDays,
        overlapMinutes: profile.rotationOverlapMinutes,
        alarmFailures: rotation.alarmFailures,
        from: profile.from
      },
      totals: {
        accounts: all.length,
        withDestination: all.filter(function (row) {
          return !!row.destination;
        }).length,
        rotating: all.filter(function (row) {
          return row.rotation.rotates;
        }).length,
        failing: all.filter(function (row) {
          return row.rotation.failures > 0;
        }).length,
        alarms: all.filter(function (row) {
          return row.rotation.alarm;
        }).length
      },
      filter: { failing: failingOnly },
      accounts: listed.shown,
      paging: this.pagingJson(listed.paging)
    };
    log.debug("Leaving AdminViews.serviceAccountsMonitorJson(). " +
              all.length + " account(s).");
    return out;
  }

  /**
   * Describes a service account for its person page: its owner, destination
   * and rotation state, and what the realm's policy lets it do.
   *
   * @param key - the person
   * @returns the description, or null for an ordinary person
   */
  serviceAccountJson(key) {
    const { log, serviceAccounts, serviceAccountPolicy } = this.deps;
    log.debug("Entering AdminViews.serviceAccountJson().");
    const facts = serviceAccounts.of(key);
    if (!facts) {
      log.debug("Leaving AdminViews.serviceAccountJson(). A person.");
      return null;
    }
    const profile = serviceAccountPolicy.read();
    const rotation = serviceAccountPolicy.rotation(profile);
    const rotatedMs = facts.rotatedAt
      ? Date.parse(facts.rotatedAt.replace(
          /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2}).*$/,
          '$1-$2-$3T$4:$5:$6Z'))
      : NaN;
    log.debug("Leaving AdminViews.serviceAccountJson().");
    return {
      owner: facts.owner || null, ownerKind: facts.ownerKind || null,
      ownerName: facts.ownerName || null,
      destination: facts.destination || null,
      secretName: facts.secretName || null,
      rotatedAt: facts.rotatedAt || null,
      // The overlap: until when the previous password is still accepted.
      previousPasswordUntil: facts.previousPasswordExpires > Date.now()
        ? new Date(facts.previousPasswordExpires).toISOString() : null,
      rotation: {
        enabled: rotation.enabled,
        rotates: rotation.enabled && !!facts.destination,
        nextDueAt: rotation.enabled && facts.destination && !isNaN(rotatedMs)
          ? new Date(rotatedMs + rotation.intervalMs).toISOString() : null,
        failures: facts.rotation.failures,
        lastError: facts.rotation.lastError || null,
        lastAttemptAt: facts.rotation.lastAttempt
          ? new Date(facts.rotation.lastAttempt).toISOString() : null,
        alarm: facts.rotation.failures >= rotation.alarmFailures
      },
      policy: {
        exemptFromSecondFactor: profile.exemptFromSecondFactor === true,
        allowBrowserSignIn: profile.allowBrowserSignIn === true,
        doors: serviceAccountPolicy.allowedDoors(profile),
        from: profile.from
      }
    };
  }

  userDetailJson(req, key, risk?: any) {
    const { log, subjectForName, stats } = this.deps;
    const self = this;
    log.debug("Entering AdminViews.userDetailJson(). key=" + key);
    log.debug("Entering userDetailPage(). key=" + key);
    let detail = stats.userDetail(key);
    if (!detail) {
      // ---------------------------------------------------------------------
      // A PERSON THE DIRECTORY HOLDS AND THE REGISTRY DOES NOT (2026-09-10).
      //
      // **THE LIST ABOVE STARTED LISTING THEM ON THIS DAY** — see peopleRows()
      // — and until this branch existed, clicking one landed on *nothing here
      // has authenticated as alice*. That is a true sentence and a useless
      // page: it is exactly the person whose second factor an operator has come
      // to look at, and both Clear buttons are on this page.
      //
      // So the registry's absence is filled with a blank record rather than
      // treated as a missing person. Every section below reads `detail.tokens`,
      // `detail.artifacts` and the row's counted arrays, and every one of them
      // is legitimately empty here: this identity has never signed in, so it
      // holds no session and nothing has been issued to it. The DIRECTORY and
      // SECOND FACTOR sections are the two that have something to say, and they
      // are the two that were unreachable.
      // ---------------------------------------------------------------------
      const inDirectory = !!(directoryReader && directoryReader(key).found);
      if (!inDirectory) {
        log.debug("Leaving userDetailPage(). No such user, and no entry " +
                  "either.");
        return null;
      }
      detail = {
        user: { key: key, name: key, forms: [], realms: [], protocols: [],
                authentications: 0, firstAt: 0, lastAt: 0, isClient: false,
                authenticated: false, knownBy: 'directory', events: [],
                eventsForgotten: 0,
                tokens: { issued: 0, valid: 0, expired: 0, revoked: 0,
                          other: 0 },
                artifactKinds: [], artifacts: 0, lastActivityAt: 0 },
        tokens: [], artifacts: []
      };
      log.debug("userDetailPage(). Directory-only: a blank registry record.");
    }
    const row = detail.user;
    const sessionRows = this.sessionRowsFor(key);
    const live = sessionRows.filter(function (s) { return !s.expired; });
    const split = this.tokensBySession(detail.tokens, sessionRows);
    // Where a revoke button on this page returns to: this user's page, which is
    // the only sensible answer — the reader is looking at one person and wants
    // to see the effect on that person. It carries the whole query and not just
    // the name, so the answer is the page of the table the button was on rather
    // than the first page of all five; backTo() picks the page parameters back
    // out by shape.
    //
    // `params` is the whole current query carried through, and every control on
    // this page rides on it, so moving one of the five lists leaves the other
    // four where they are. See pageParamsOf() for why it is carried rather than
    // listed.
    const params = this.pageParamsOf(req.query);
    const back = this.queryWith(params, {});
    const valid =
        detail.tokens.filter(function (t) { return t.state ===
                                                   'valid'; }).length;
    // Counted beside `valid` because "issued" minus "valid" is not "expired" —
    // a revoked token, one not yet valid and one with no expiry stated all sit
    // in that difference, and a reader doing the subtraction gets the wrong
    // answer silently. It is its own tile for the same reason the users table
    // grew its own column: a token running out of time is the ordinary end of a
    // token and the first thing to check when a client starts being refused.
    const expired = detail.tokens.filter(function (
        t) { return t.state === 'expired'; }).length;
    // Read before the markup is assembled rather than inside it, because it is
    // also one of the keys of the JSON view below and reading it twice could
    // show a page and a JSON body that disagree about a directory another
    // request just changed. The two panels' answers, from the functions above
    // rather than from the console sections that draw them.
    const directory = { json: this.ldapObjectJson(key) };
    // The second factors, on the same terms and for the same reason
    // (2026-09-10). `gateStateFor()` decides whether the two removals are drawn
    // at all; it is read HERE rather than inside the section because the
    // section is also called for `?format=json`, where there is no button to
    // draw and the answer is still needed for the write half of
    // `/admin-api/users`.
    const mfa = { json: this.mfaJson(key) };
    // The assertion key pairs (2026-09-13), read once for the reason the two
    // panels above are: the page and the reply must not disagree about one
    // read.
    const credentialsState = this.personCredentialsState(key);

    // Five lists on one page, each with its own page parameter and all of them
    // sharing `per` — see pagingOf() for why it is that way round.
    //
    // What is deliberately NOT paged here: the names this identity has been
    // seen under, the protocols it authenticated through, and the
    // authentication events. The first two are bounded by how many spellings
    // and protocols exist, and the third is capped at stats.MAX_EVENTS_PER_USER
    // — fifty — by the registry itself, which is the note authenticationTable()
    // already prints. Paging a list that cannot exceed fifty would buy a
    // control nobody will see, and it would cost something real: all three live
    // on `row`, which goes out whole as this reply's `user`, so slicing them
    // for the table would either corrupt that object or duplicate it, and
    // leaving the JSON whole while the table paged is the console-and-API
    // disagreement this file keeps warning about.
    const sessionPage = this.pagedRows(req.query, sessionRows,
      { name: 'sessions', noun: 'sessions',
        defaultPer: DEFAULT_BLOCKS_PER_PAGE });
    const sessionTokenPages = sessionPage.shown.map(function (session) {
      return self.pagedRows(req.query, split.held[session.id] || [],
                            { name: 'session-' + session.id, noun: 'tokens' });
    });
    const endedPage = this.pagedRows(req.query, split.ended,
                                     { name: 'tokensOnEndedSessions',
                                       noun: 'tokens' });
    const sessionlessPage = this.pagedRows(req.query, split.sessionless,
                                           { name: 'tokensWithNoSession',
                                             noun: 'tokens' });
    const artifactPage = this.pagedRows(req.query, detail.artifacts,
                                   { name: 'artifacts', noun: 'artifacts' });
    // THE PARTNERS' SUBJECTS THIS PERSON IS LINKED TO (#109), paged like the
    // five lists above. Read off the entry, one row per federationLink value,
    // with whether the relationship it names is still registered here — a
    // link through a deleted relationship matches nothing, and saying so is
    // cheaper than leaving a reader to wonder why it does nothing.
    const federationLinkPage = this.federationLinksOf(req.query, key);
    // THEIR KERBEROS ACCOUNT (#59): the principal, this realm's KDC, and the
    // PUBLIC half of their keys — never a key. Read once, for the page's
    // Kerberos section and this reply's `kerberos`.
    const kerberos = this.deps.krb5PersonKeys.personKerberosState(key);
    // WHAT AN ADMINISTRATOR MAY CHANGE ON THEIR ENTRY (#228): every editable
    // attribute with the values it holds, and the schema's attributes that are
    // withheld with the door to use instead. Null where there is no entry.
    const attributeEditor = this.deps.personEditor.editorFor(key);
    // THEIR GNAP GRANTS (#432 phase 7): every grant they are the resource
    // owner of, with its rights, tokens and why it ended — the view
    // `gnap/gnap_console.ts` draws for this page, the API and their own
    // `/portal/gnap`. Revoked with POST /admin-api/gnap/revoke-grant naming
    // the grant and this person.
    const gnapGrants = this.gnapGrantsOf(req.query, key);
    log.debug("Leaving AdminViews.userDetailJson().");
    const answer = {
      detail: detail, row: row, sessionRows: sessionRows, live: live,
      split: split,
      // `back` is handed over with the rest: the page's sign-out and revoke
      // forms carry it, and a first pass of the split left it out, so both
      // forms posted `back=undefined`.
      params: params, back: back, valid: valid, expired: expired, directory:
                                                                    directory,
      mfa: mfa, credentialsState: credentialsState,
      sessionPage: sessionPage, sessionTokenPages: sessionTokenPages,
      endedPage: endedPage, sessionlessPage: sessionlessPage, artifactPage:
                                                                artifactPage,
      federationLinkPage: federationLinkPage, kerberos: kerberos,
      attributeEditor: attributeEditor, gnapGrants: gnapGrants,
      json: (function (): any {
      return {
          user: row,
          // THE PERSON'S SUBJECT (2026-09-14): `urn:uuid:<entryUUID>`, the
          // `sub` every token issued to them carries — '' where the directory
          // holds no entry for them. Said here because it is no longer
          // derivable from the name, and "which sub is this person" is the
          // first thing somebody matching a relying party's records to this
          // page needs.
          subject: subjectForName(key),
          // WHETHER THEY ARE A SERVICE ACCOUNT (#221): its owner, push
          // destination and rotation state, and what this realm's
          // service-account policy lets it do — null for an ordinary person.
          serviceAccount: self.serviceAccountJson(key),
          // THE PERSON'S CURRENT RISK (#62) — null for a person never
          // assessed.
          risk: risk || null,
          // WHAT THEY CAN SIGN IN WITH, and what they are asked for as a second
          // factor (2026-09-10). It is `factors` here and on every row of the
          // list, so a caller reads one member name whichever view it fetched.
          factors: mfa.json,
          // Every array here is THE PAGE, not the whole list, exactly as
          // `users` is on the list view — and every one of them is answered by
          // a `*Paging` object carrying the same member names one level down,
          // so a caller walks a drill-down's five lists the way it already
          // walks the three flat ones. A session's own tokens are paged too and
          // its paging travels with it, because there is one such list per
          // session and no top-level place to put five of them that would still
          // say which was which.
          sessions: sessionPage.shown.map(function (session, index) {
            return Object.assign({}, session, {
              tokens: sessionTokenPages[index].shown,
              tokensPaging: self.pagingJson(sessionTokenPages[index].paging)
            });
          }),
          sessionsPaging: self.pagingJson(sessionPage.paging),
          tokensOnEndedSessions: endedPage.shown,
          tokensOnEndedSessionsPaging: self.pagingJson(endedPage.paging),
          tokensWithNoSession: sessionlessPage.shown,
          tokensWithNoSessionPaging: self.pagingJson(sessionlessPage.paging),
          artifacts: artifactPage.shown,
          artifactsPaging: self.pagingJson(artifactPage.paging),
          // null when no directory is loaded in this process, which is a
          // different answer from an entry that is not there — that one is an
          // object whose `found` is false and which says where it would have
          // been.
          ldap: directory.json,
          // THE ASSERTION KEY PAIRS (2026-09-13) — `credentials`, the member
          // name an application's drill-down uses for its own. No private key,
          // for the reason personCredentialsState() gives.
          credentials: credentialsState.json,
          // Which partners' subjects sign this person in (#109). Set and
          // removed with POST /admin-api/users/federation-link and
          // /federation-unlink.
          federationLinks: federationLinkPage.shown,
          federationLinksPaging: self.pagingJson(federationLinkPage.paging),
          // Their Kerberos principal and the public half of their keys
          // (#59). A keytab is made with POST
          // /admin-api/kerberos/principals/reset-person-keytab.
          kerberos: kerberos,
          // What POST /admin-api/users/set-attribute, /add-attribute and
          // /remove-attribute may change on their entry (#228), and what
          // they hold now; null where the directory holds no entry for them.
          attributeEditor: attributeEditor,
          // The GNAP grants they are the resource owner of (#432 phase 7),
          // paged as `gnapGrantsPage`; `cells` says what a multi-cell
          // service's list leaves out. Revoked with POST
          // /admin-api/gnap/revoke-grant { grant, user }.
          gnapGrants: gnapGrants.rows,
          gnapGrantsPaging: gnapGrants.paging,
          gnapGrantsCells: gnapGrants.cells
      };
      }())
    };
    answer.json.page = this.userPageData(key, answer, risk);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // WHAT THE PERSON'S PAGE READS BEYOND THE RECORD (#446).
  //
  // The page's thirteen sections read the credential store, three mechanisms'
  // settings, the federation register, the mode and the registry's caps while
  // they draw. A page drawn from the answer alone, which is what the static
  // console draws, reads them here instead. The answer carries them as `page`,
  // the member name the application drill-down uses for the same purpose.
  // **None of it is a credential**: the keys are the public half, the app
  // passwords are their views (no hash), and the key-pair state is the
  // `personCredentialsState()` that already leaves the private keys out.
  // ---------------------------------------------------------------------------
  /**
   * Builds what `/admin/users?user=` draws beyond the person's record.
   *
   * @param key - the person's name
   * @param view - what `userDetailJson()` built
   * @param risk - the person's standing as `riskFor()` read it; undefined
   *   when it was not asked, which draws no badge
   * @returns the page's data
   */
  userPageData(key, view, risk?: any) {
    const { log, stats, credentials, totp, webauthnPolicy, backupCodes, mode,
            federation } = this.deps;
    log.debug("Entering AdminViews.userPageData(). key=" + key);
    const storable = credentials.storable();
    let mfa: any = { storable: storable };
    if (storable) {
      const mech = credentials.mechanismsFor(key);
      mfa = {
        storable: true,
        mech: Object.assign({}, mech, {
          keys: (mech.keys || []).map(function (one) {
            return Object.assign({}, one,
                                 { algorithm: credentials.keyAlgorithm(one) });
          })
        }),
        totp: totp.settings(),
        webauthn: webauthnPolicy.settings(),
        recovery: backupCodes.settings(),
        appPasswords: credentials.appPasswordsOf(key),
        doors: this.passwordOnlyDoorsFor(key),
        verifications: this.verificationsJson({ user: key, per: 100 }),
        inventsClaimValues: mode.inventsClaimValues(),
        devices: this.devicesJson({ user: key }),
        selfIssued: this.selfIssuedSubjectsJson({ user: key }),
        // The address and the emailed second factor (#64), and the account
        // ids clients know them by (#148).
        mail: {
          status: require('../common/mail_factor').status(key),
          usable: require('../common/authn_policy').mailUsable(),
          audSubs: credentials.audSubsOf(key)
        }
      };
    }
    const keyPairs = Object.assign({}, view.credentialsState);
    delete keyPairs.json;
    const page = {
      // The name the page was asked for, which every form on it posts back.
      key: key,
      // Whether the risk standing was read: `risk: null` then means never
      // assessed, and the page says so; unread, it draws no badge.
      riskAsked: risk !== undefined,
      counts: {
        live: view.live.length,
        tokens: view.detail.tokens.length,
        valid: view.valid,
        expired: view.expired,
        artifacts: view.detail.artifacts.length,
        ended: view.split.ended.length,
        sessionless: view.split.sessionless.length
      },
      back: view.back,
      params: view.params,
      blocksPerPage: DEFAULT_BLOCKS_PER_PAGE,
      perPage: DEFAULT_PER_PAGE,
      maxEventsPerUser: stats.MAX_EVENTS_PER_USER,
      directoryLoaded: !!directoryReader,
      mfa: mfa,
      // The Attributes tab's sub-tabs, in order (`person_editor.ts`).
      fieldGroups: this.deps.personEditor.FIELD_GROUPS,
      // Who may act for them (#108): `stsNotDelegated` and `stsMayAct`.
      delegation: credentials.delegationFactsFor(key) || {},
      keyPairs: keyPairs,
      serviceProviders: (federation.inRole('service-provider') || [])
        .map(function (one) {
          return { fedId: one.fedId, fedPeer: one.fedPeer || '' };
        })
    };
    log.debug("Leaving AdminViews.userPageData().");
    return page;
  }

  // One route, three answers, and the choice between them is here rather than
  // in the route so that /admin-api/users makes the same one. `?user=` means
  // the drill-down; `known: false` is the third answer and it is not a 404 —
  // see the comment inside the console's usersView().
  //
  // **`known: true` IS ADDED HERE AND THAT IS NOT DECORATION.** The console's
  // `usersView()` wrapped the detail as `Object.assign({ known: true },
  // detail.json)`, and a first pass of this returned the bare json — so
  // `/admin-api/users?user=…` answered a complete record with no `known` in it,
  // and the one job that asks about a DIRECTORY-ONLY person read that as "this
  // person does not exist". The page was right and the resource was wrong,
  // which is the exact shape of disagreement this whole directory exists to
  // prevent.
  // -------------------------------------------------------------------------
  // THE PERSON'S CURRENT RISK, READ FIRST (#62). The user views are
  // synchronous and a person's standing is a row in the risk store, which is
  // not; so the console's route and the management API's both await this,
  // from the same query the view is drawn from, and hand the answer in.
  // Undefined when no person is named; null when never assessed or the store
  // could not say. Never rejects.
  // -------------------------------------------------------------------------
  /**
   * Reads the risk standing of the person the query names (#62), for the view
   * to be handed.
   *
   * @param query - the query
   * @returns the standing; undefined when no person is named, null when never
   *   assessed or the store could not say; never rejects
   */
  async riskFor(query: any): Promise<any> {
    const { log, subjectForName } = this.deps;
    log.debug("Entering AdminViews.riskFor().");
    const wanted = String((query || {}).user || '').trim();
    if (!wanted) {
      log.debug("Leaving AdminViews.riskFor(). No person named.");
      return undefined;
    }
    try {
      const standing = await require('../risk/risk_engine').standingFor(
        realms.currentId(), String(subjectForName(wanted) || ''));
      log.debug("Leaving AdminViews.riskFor().");
      return standing;
    } catch (e) {
      log.debug("Caught in AdminViews.riskFor(): " +
                ((e && e.message) || e));
      // No risk engine in this process: the page says the risk is unknown.
      log.debug("Leaving AdminViews.riskFor(). Unknown.");
      return null;
    }
  }

  /**
   * Builds `/admin/users`'s JSON: the list, or one person.
   *
   * @param req - the request
   * @param risk - the person's risk standing, for the drill-down
   * @returns the JSON
   */
  usersJson(req, risk?: any) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.usersJson().");
    const wanted = String((req.query || {}).user || '').trim();
    if (!wanted) {
      log.debug("Leaving AdminViews.usersJson().");
      return this.usersListJson(req).json;
    }
    const detail = this.userDetailJson(req, wanted, risk);
    if (!detail) {
      log.debug("Leaving AdminViews.usersJson().");
      // `registryKeeps` is what the page says about forgetting (#446).
      return { user: wanted, known: false, registryKeeps: stats.MAX_USERS };
    }
    log.debug("Leaving AdminViews.usersJson().");
    return Object.assign({ known: true }, detail.json);
  }

  // THE SECOND-FACTOR ANSWER FOR ONE PERSON. `mfaSection()` on the console
  // draws the panel and takes its json from here, so the card a person reads
  // and the resource a machine fetches describe one set of credentials.
  //
  // IT CARRIES NO CODES AND NO PUBLIC KEYS — see the comments inside. A caller
  // holding admin:read is never handed a working second factor.
  /**
   * Describes a person's second factors; no codes and no public keys.
   *
   * @param key - the person
   * @returns the description
   */
  mfaJson(key) {
    const { log, credentials, totp, webauthnPolicy, backupCodes } = this.deps;
    log.debug("Entering AdminViews.mfaJson(). key=" + key);
    const mech = credentials.mechanismsFor(key);
    if (!mech) {
      log.debug("Leaving AdminViews.mfaJson(). No credential store.");
      return null;
    }
    const totpLive = totp.settings();
    const keyLive = webauthnPolicy.settings();
    const recoveryLive = backupCodes.settings();
    log.debug("Leaving AdminViews.mfaJson().");
    return {
      // The mechanisms as the credential store answers them, minus the public
      // keys — a JWK per credential is several hundred bytes of no use to a
      // caller asking who holds what, and this reply is already the largest on
      // the console.
      password: mech.password,
      // WHAT AN ADMINISTRATOR HAS DECIDED ABOUT THEM (2026-09-13): whether the
      // password must be changed at their next sign-in, a password reset link
      // outstanding (an expiry, never a token), and whether a second factor is
      // REQUIRED of them — by their own entry or by the realm — which is a
      // different question from `mfaRequired` below, what they HOLD.
      passwordChangeRequired: credentials.passwordResetRequired(key),
      passwordResetLink: mech.passwordResetLink || null,
      // A DISABLED ACCOUNT (2026-09-17): `pwdAccountLockedTime` on the entry,
      // which every door refuses; `POST /admin-api/users/enable` clears it.
      disabled: !!mech.disabled,
      mfaRequirement: mech.mfaRequirement ||
        { required: false, byUser: false, byRealm: false },
      usable: mech.usable,
      activated: mech.activated,
      mfaRequired: mech.mfaRequired,
      secondFactor: mech.secondFactor || null,
      totp: mech.totp,
      totpUsable: mech.totpUsable,
      totpDetail: mech.totpDetail,
      // THE RECOVERY CODES AS A STATUS AND NEVER AS CODES — see the block
      // above. `credentials.backupCodeStatus()` is what fills it and it
      // carries none, so there is no shape of this reply in which a caller
      // holding `admin:read` is handed a working second factor.
      backupCodes: mech.backupCodes,
      keys: (mech.keys || []).map(function (one) {
        return { credentialId: one.credentialId, role: one.role,
                 label: one.label || null, signCount: one.signCount || 0,
                 enrolledAt: one.enrolledAt || 0,
                 // WHAT THE ATTESTATION PROVED (#105), the record
                 // `authn/webauthn_attestation.ts` wrote: format, type,
                 // verified, trusted, anchor, the model the FIDO metadata
                 // names and its certification. null for a key written by
                 // a door that verified nothing; the AAGUID is then only the
                 // authenticator's claim, which is why it is beside it.
                 aaguid: one.aaguid || null,
                 // ITS SIGNATURE ALGORITHM (2026-10-01): name, COSE id,
                 // and whether it is post-quantum or insecure.
                 algorithm: credentials.keyAlgorithm(one),
                 attestation: one.attestation || null };
      }),
      primaryKeys: mech.primaryKeys,
      mfaKeys: mech.mfaKeys,
      // WHAT THE REALM ALLOWS, beside what the person holds, because the two
      // together are the answer to "why can they not enrol one" — and a caller
      // that had to fetch /admin-api/webauthn as well would be reading a
      // second request's answer against this one's.
      // APP PASSWORDS (#101): name, scope, when made and last used — never
      // a hash — bounded by appPasswords.maxPerPerson (at most fifty), so not
      // paged here; `GET /admin-api/users/app-passwords` is the paged list.
      appPasswords: credentials.appPasswordsOf(key).passwords,
      // WHICH PASSWORD-ONLY DOORS REFUSE THIS PERSON'S OWN PASSWORD (#101),
      // the one sentence the page and the API both say.
      passwordOnlyDoors: this.passwordOnlyDoorsFor(key),
      policy: { totpEnabled: totpLive.enabled,
                backupCodesEnabled: recoveryLive.enabled,
                backupCodesCount: recoveryLive.count,
                webauthnEnabled: keyLive.enabled,
                primaryAllowed: keyLive.primaryAllowed,
                mfaAllowed: keyLive.mfaAllowed,
                maxKeysPerPerson: keyLive.maxKeysPerPerson }
    };
  }

  // ---------------------------------------------------------------------------
  // THE PASSWORD-ONLY DOORS FOR ONE PERSON (#101, 2026-09-22): which of the
  // five refuse their own password — every one not listed in
  // `authn.passwordAloneDoors`, in product mode, while they hold or must hold
  // a second factor — and which accept it, from
  // `credentials.passwordOnlyDoors()`, with the sentence the page and the API
  // both carry.
  // ---------------------------------------------------------------------------
  /**
   * Lists the password-only doors and whether each accepts this person's
   * password.
   *
   * @param key - the person
   * @returns the doors and the sentence both surfaces carry
   */
  passwordOnlyDoorsFor(key) {
    const { log, credentials, appPasswords } = this.deps;
    log.debug("Entering AdminViews.passwordOnlyDoorsFor().");
    const doors = credentials.passwordOnlyDoors(key);
    const label = function (door) {
      return appPasswords.doorLabel(door);
    };
    log.debug("Leaving AdminViews.passwordOnlyDoorsFor().");
    return {
      secondFactor: doors.secondFactor,
      refused: doors.refused,
      accepted: doors.accepted,
      passwordAloneDoors: doors.alone,
      sentence: !doors.secondFactor
        ? 'They hold no second factor and none is required of them, so ' +
          'their password is accepted at every password-only door.'
        : !doors.applies
          ? 'This service is in development mode, which checks no password ' +
            'at the password-only doors; in product mode their own password ' +
            'would be refused there while they hold or must hold a second ' +
            'factor.'
          : (doors.refused.length
              ? 'Their own password is REFUSED at ' +
                doors.refused.map(label).join(', ') + ', which cannot ask ' +
                'for a second factor; an app password scoped to the door is ' +
                'what they use there.'
              : 'Their own password is still accepted at every ' +
                'password-only door.') +
            (doors.alone.length
              ? ' authn.passwordAloneDoors lets it through at ' +
                doors.alone.map(label).join(', ') + ' — ONE factor there.'
              : '')
    };
  }

  // ---------------------------------------------------------------------------
  // ONE PERSON'S APP PASSWORDS, PAGED (#101) — `GET
  // /admin-api/users/app-passwords`, the list the person's /admin/users page
  // draws and `/portal/app-passwords` draws for themselves. Never a hash.
  // ---------------------------------------------------------------------------
  /**
   * Lists one person's app passwords, paged (#101); never a hash.
   *
   * @param query - the request's query
   * @returns the JSON
   */
  appPasswordsJson(query) {
    const { log, credentials, appPasswords } = this.deps;
    log.debug("Entering AdminViews.appPasswordsJson().");
    const who = String((query && (query.user || query.username)) || '').trim();
    const live = appPasswords.settings();
    const held = who ? credentials.appPasswordsOf(who)
      : { ok: true, unreadable: false, passwords: [] };
    // A FLAT list, so `page` and `per` — the parameters every list here
    // pages on — rather than a drill-down's `<name>Page`.
    const page = this.pagedRows(query || {}, held.passwords,
                                { noun: 'app passwords' });
    log.debug("Leaving AdminViews.appPasswordsJson(). " +
              held.passwords.length + " held.");
    return {
      user: who,
      enabled: live.enabled,
      maxPerPerson: live.maxPerPerson,
      unreadable: !!held.unreadable,
      doors: appPasswords.DOORS.map(function (one) {
        return { id: one.id, label: one.label, what: one.what };
      }),
      passwordOnlyDoors: this.passwordOnlyDoorsFor(who),
      passwords: page.shown,
      page: page.paging.page, pages: page.paging.pages,
      perPage: page.paging.perPage, total: page.paging.total,
      paging: this.pagingJson(page.paging)
    };
  }

  // ---------------------------------------------------------------------------
  // ONE PERSON'S IDENTITY VERIFICATIONS, PAGED (#127) — `GET
  // /admin-api/users/verifications`, the list the Identity verifications block
  // on their /admin/users page draws. The whole record, evidence included:
  // this is the administrator who recorded it reading it back, and the
  // directory withholds the attribute from every LDAP read for exactly that
  // reason. Beside it, the vocabularies a record is made from.
  // ---------------------------------------------------------------------------
  /**
   * Lists one person's identity assurance verifications and the vocabularies a
   * record is made from.
   *
   * @param query - the request's query
   * @returns the JSON
   */
  verificationsJson(query) {
    const { log, identityAssurance } = this.deps;
    log.debug("Entering AdminViews.verificationsJson().");
    const who = String((query && (query.user || query.username)) || '').trim();
    const held = who ? identityAssurance.list(who) : [];
    const page = this.pagedRows(query || {}, held,
                                { noun: 'identity verifications' });
    log.debug("Leaving AdminViews.verificationsJson(). " + held.length +
              " held.");
    return {
      user: who,
      trustFrameworks: identityAssurance.trustFrameworks(),
      evidenceTypes: identityAssurance.EVIDENCE_TYPES.slice(0),
      documentTypes: identityAssurance.DOCUMENT_TYPES.slice(0),
      checkMethods: identityAssurance.CHECK_METHODS.slice(0),
      electronicRecordTypes:
        identityAssurance.ELECTRONIC_RECORD_TYPES.slice(0),
      attestationTypes: identityAssurance.ATTESTATION_TYPES.slice(0),
      verifiableClaims: identityAssurance.VERIFIABLE_CLAIMS.slice(0),
      verifications: page.shown,
      page: page.paging.page, pages: page.paging.pages,
      perPage: page.paging.perPage, total: page.paging.total,
      paging: this.pagingJson(page.paging)
    };
  }

  // ---------------------------------------------------------------------------
  // ONE PERSON'S ENROLLED SELF-ISSUED SUBJECTS (#129) — `GET
  // /admin-api/users/self-issued-subjects`, the list the Self-issued IDs block
  // on their /admin/users page draws. At most `siop.MAX_SUBJECTS`, so not
  // paged.
  // ---------------------------------------------------------------------------
  /**
   * Lists one person's enrolled self-issued subjects.
   *
   * @param query - the request's query
   * @returns the JSON
   */
  selfIssuedSubjectsJson(query) {
    const { log, siop, config } = this.deps;
    log.debug("Entering AdminViews.selfIssuedSubjectsJson().");
    const who = String((query && (query.user || query.username)) || '').trim();
    const held = who ? siop.list(who) : null;
    log.debug("Leaving AdminViews.selfIssuedSubjectsJson().");
    return {
      user: who,
      entryFound: Array.isArray(held),
      signInEnabled: !!config.value('oid4vp.signInSelfIssued'),
      maxPerPerson: siop.MAX_SUBJECTS,
      subjectSyntaxTypes: siop.SUBJECT_SYNTAX_TYPES.slice(0),
      subjects: held || []
    };
  }

  // ---------------------------------------------------------------------------
  // ONE PERSON'S DEVICES (#130) — `GET /admin-api/users/devices`, the list
  // the Devices block on their /admin/users page draws: each device entry in
  // ou=devices they own, the applications that used it, and whether its
  // Native SSO secret is live. Never the secret or its hash. Bounded by
  // `devices.maxPerPerson`, so not paged. The whole register, paged and
  // filtered, is `admin-ui/devices_admin.ts`'s (#218).
  // ---------------------------------------------------------------------------
  /**
   * Lists one person's registered devices; never a secret or its hash.
   *
   * @param query - the request's query
   * @returns the JSON
   */
  devicesJson(query) {
    const { log, devices, oauth2, config } = this.deps;
    log.debug("Entering AdminViews.devicesJson().");
    const who = String((query && (query.user || query.username)) || '').trim();
    const held = who ? devices.listFor(who) : [];
    log.debug("Leaving AdminViews.devicesJson(). " + held.length + ".");
    return {
      user: who,
      maxPerPerson: Number(config.value('devices.maxPerPerson')),
      devices: held.map(function (one) {
        return devices.view(one, function (sid) {
          return oauth2.sessionIsLive(sid, who);
        });
      })
    };
  }

  // THIS PERSON'S DIRECTORY ENTRY, which is the whole json half of the panel
  // `ldapObjectSection()` draws: `directoryReader(key)`, or null where no
  // directory is loaded in this process. The section keeps the markup and takes
  // this for its answer.
  /**
   * Returns a person's directory entry.
   *
   * @param key - the person
   * @returns the entry, or null when no directory is loaded
   */
  ldapObjectJson(key) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.ldapObjectJson(). key=" + key);
    if (!directoryReader) {
      log.debug("Leaving AdminViews.ldapObjectJson(). No directory is loaded.");
      return null;
    }
    log.debug("Leaving AdminViews.ldapObjectJson().");
    return directoryReader(key);
  }

  // A query string built from what the caller is already looking at plus an
  // override. Every paging link goes through this, because a "next" that
  // dropped `?kind=` would be page 2 of a different list — the bug this exists
  // to make impossible rather than merely avoidable. Empty values are omitted
  // so the URL of the unfiltered first page is the bare path.
  /**
   * Builds a query string from parameters and overrides, omitting empty values.
   *
   * @param params - the current parameters
   * @param overrides - the parameters to change
   * @returns the query string with its `?`, or '' when nothing is left
   */
  queryWith(params, overrides) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.queryWith().");
    const merged = Object.assign({}, params, overrides);
    const parts = [];
    Object.keys(merged).forEach(function (key) {
      const value = merged[key];
      if (value === '' || value === null || value === undefined) {
        return;
      }
      parts.push(encodeURIComponent(key) + '=' +
                 encodeURIComponent(String(value)));
    });
    log.debug("Leaving AdminViews.queryWith().");
    return parts.length ? '?' + parts.join('&') : '';
  }

  // The live sign-on sessions belonging to one user. Sessions are keyed by an
  // opaque id and hold a user object, so the match is on the identity rather
  // than the string: the session says `alice` and the tokens say
  // `urn:uuid:<entryUUID>`, and these have to end up on the same page.
  /**
   * Lists the live sign-on sessions of one person, matched by identity.
   *
   * @param key - the person
   * @returns the rows
   */
  sessionRowsFor(key) {
    const { log, stats } = this.deps;
    log.debug("Entering AdminViews.sessionRowsFor(). key=" + key);
    const rows = this.signOnSessionRows().filter(function (session) {
      return stats.holderKeyOf(session.username, session.sub) === key;
    });
    log.debug("Leaving AdminViews.sessionRowsFor(). " + rows.length +
              " session(s).");
    return rows;
  }

  // The tokens of one user, split by the session they were issued on.
  //
  // Three buckets, and the third is the one worth explaining. A token whose
  // record names a session that is no longer held is not an error: sessions
  // expire and are swept, and the token outlives the sign-on it came from —
  // that is exactly the state an OIDC client is in when its ID Token still
  // verifies and the browser would be asked to sign in again. Showing those
  // under "no session" would say something false about how they were issued.
  /**
   * Groups a person's tokens under the sessions they came from.
   *
   * @param tokens - the tokens
   * @param sessionRows - the sessions
   * @returns the groups
   */
  tokensBySession(tokens, sessionRows) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.tokensBySession(). " + tokens.length +
              " token(s).");
    const held: Record<string, any> = {};
    sessionRows.forEach(function (session) { held[session.id] = []; });
    const ended = [];
    const sessionless = [];
    tokens.forEach(function (record) {
      if (!record.sessionId) {
        sessionless.push(record);
        return;
      }
      if (held[record.sessionId]) {
        held[record.sessionId].push(record);
        return;
      }
      ended.push(record);
    });
    log.debug("Leaving AdminViews.tokensBySession(). " +
              Object.keys(held).length + " " +
        "session(s), " +
              ended.length + " on an ended session, " + sessionless.length +
              " " +
                  "with none.");
    return { held: held, ended: ended, sessionless: sessionless };
  }

  // ---------------------------------------------------------------------------
  // WHAT `GET /admin-api/mfa` AND `POST /admin-api/mfa/:action` CALL NOW.
  //
  // **THE RESOURCE IS KEPT AND ITS PAGE IS GONE**, which is rule 7 read the way
  // round it is usually not. The rule says a console control owes an API
  // operation; it says nothing about an operation whose page moved, and
  // deleting a working one to tidy a table would be a regression dressed as
  // consistency — the same argument `mgmt-api/admin_api.ts` makes about `GET
  // /admin-api/users/new`.
  //
  // **BOTH ANSWER OUT OF THE USERS VIEW**, so there is ONE tally. A second scan
  // of the credential store would be a second answer to how many people hold a
  // second factor, and the two would agree until the day they did not.
  //
  // The reply keeps its own SHAPE — a flat `people` array, one object per
  // person, exactly the members it always carried — because a caller that reads
  // `people[].mfaRequired` is not a caller that should have to learn this page
  // moved. `GET /admin-api/users` is where the rows carry `factors` instead.
  // ---------------------------------------------------------------------------
  /**
   * Builds the second-factor roster, in the shape `/admin/mfa` always had.
   *
   * @param req - the request
   * @returns the JSON
   */
  mfaRosterJson(req) {
    const { log, totp, webauthnPolicy } = this.deps;
    log.debug("Entering AdminViews.mfaRosterJson().");
    const list = this.usersListJson(req);
    const people = (list.json.users || []).map(function (row) {
      const f = row.factors || {};
      return {
        username: row.name,
        inDirectory: !!row.inDirectory,
        known: !!row.authenticated || row.knownBy !== 'directory',
        // FALSE AND NOT NULL where no credential store answered, because every
        // one of these was a boolean before this moved and a caller comparing
        // with `=== false` must not start seeing `null`. `store` on the reply
        // is where "this service could not tell" is said, and it always was.
        password: !!f.password,
        primaryKeys: f.primaryKeys || 0,
        mfaKeys: f.mfaKeys || 0,
        totp: !!f.totp,
        totpUsable: !!f.totpUsable,
        totpDetail: f.totpDetail || null,
        mfaRequired: !!f.mfaRequired,
        secondFactor: f.secondFactor || '',
        usable: !!f.usable,
        // **THE RECOVERY CODES, AS COUNTS AND NEVER AS CODES (2026-09-11).**
        // `secondFactorHolders()` has always built this member and this mapping
        // dropped it, so `/admin/users` drew "7 of 10 unused" for an operator
        // and `GET /admin-api/mfa` answered about the same person without it —
        // which is rule 7's drift in the direction that check cannot see, since
        // the console side was never missing.
        //
        // `backupCodeStatus()` is what the whole member is built from and it
        // carries no codes, which is what makes it safe to publish here: an
        // operator reading this roster must never be handed a working second
        // factor. `hashed` and `legacy` are on it so that a set written by an
        // older build is visible as one rather than looking identical to a
        // hashed set that simply has not been used.
        backupCodes: f.backupCodes || null,
        // And whether this person should be TOLD to generate a set, which is
        // what replaced the automatic issue on 2026-09-11 and is therefore the
        // number an operator now has to be able to see across a population.
        recoveryAdvised: !!f.recoveryAdvised
      };
    });
    const json = {
      offered: totp.offered(),
      totp: totp.report(),
      webauthn: webauthnPolicy.report(),
      counts: Object.assign({ people: list.json.known }, list.json.factors),
      store: list.json.store, scanned: list.json.scanned,
      capped: list.json.capped, scanLimit: list.json.scanLimit,
      filter: list.json.filter,
      page: list.json.page, pages: list.json.pages, perPage: list.json.perPage,
      firstRow: list.json.firstRow, lastRow: list.json.lastRow,
      matched: list.json.matched, shown: list.json.shown,
      people: people
    };
    log.debug("Leaving AdminViews.mfaRosterJson(). " + people.length +
              " person/people.");
    // THE ROSTER ITSELF. The console page this belonged to split into
    // /admin/totp and /admin/webauthn on 2026-09-10 and the columns moved onto
    // /admin/users, so nothing here draws from this any more — it is the
    // resource, and only the resource.
    return json;
  }

  // WHAT /admin/logout ANSWERS for one identity: what is live across every
  // family, and what a sign-out would reach. `canWrite` is the gate's, because
  // the page draws a button and the resource says whether it would be honoured.
  // EVERY BRANCH RETURNS THE SAME SHAPE — a model with a `json` in it. The
  // first version answered the json directly on its two early paths and a model
  // on the third, which left the management API calling it twice to find out
  // which it had been given.
  //
  // `backchannelDeliveries` (2026-09-17, #36) is on EVERY branch: the
  // back-channel Logout Token deliveries in this realm, newest first, with the
  // state each reached — a sign-out answers before its deliveries are made,
  // so this is where `pending` turns into `sent` or `dead`. SINCE THE
  // FOLLOW-UP THE LIST IS THE CLUSTER'S: the deliveries are rows of a
  // persisted, replicated store, so every node lists every node's. It is
  // FILTERED (`deliveryState`, `deliveryq`) and PAGED
  // (`backchannelDeliveriesPage`, `per` shared), with `backchannelCounts`
  // beside it — the dead letters an operator retries are
  // `deliveryState=dead`.
  /**
   * Builds `/admin/logout`'s JSON: an identity's live inventory, or the
   * families, with the back-channel deliveries filtered and paged.
   *
   * @param req - the request
   * @returns the JSON
   */
  logoutJson(req): any {
    const { log, stats, backchannel } = this.deps;
    log.debug("Entering AdminViews.logoutJson().");
    const wantedUser = String((req.query || {}).user || '').trim();
    const gate = this.gateStateFor(req);
    const params = this.pageParamsOf(req.query);
    const families = this.logoutFamilies();
    const q = req.query || {};
    const deliveryState = backchannel.STATES.indexOf(
      String(q.deliveryState || '')) >= 0 ? String(q.deliveryState) : '';
    const deliveryQ = String(q.deliveryq || '').trim().slice(0, 256);
    const allDeliveries = backchannel.list({ state: deliveryState,
                                             q: deliveryQ });
    const deliveriesPg = this.pagedRows(q, allDeliveries,
      { name: 'backchannelDeliveries', noun: 'deliveries' });
    const backchannelDeliveries = deliveriesPg.shown;
    const backchannelBlock = {
      backchannelDeliveries: backchannelDeliveries,
      backchannelDeliveriesPaging: this.pagingJson(deliveriesPg.paging),
      backchannelCounts: backchannel.counts(),
      deliveryState: deliveryState,
      deliveryq: deliveryQ,
      // WHAT THE PAGE STATES IN EVERY STATE OF IT (#446): its settings,
      // whether this process can read what is live at all, the Kerberos
      // realm an identity's principal is spelt in, and whether the
      // development-only undo is offered.
      settings: configSettingsJson('/admin/logout'),
      hasReader: !!logoutReader,
      kerberosRealm: krb5Principals.REALM,
      opensTestControls: mode.opensTestControls()
    };
    if (!wantedUser) {
      log.debug("Leaving AdminViews.logoutJson(). Nobody was named.");
      return Object.assign({ families: families,
                             deliveriesPg: deliveriesPg },
                           backchannelBlock,
                           { json: Object.assign({ user: '', known: false,
                                                   families: families },
                                                 backchannelBlock) });
    }
    const key = stats.identityKeyOf(wantedUser);
    const inventory = this.logoutInventoryFor(key);
    // NO LOGOUT READER IN THIS PROCESS. The page draws a note and the trail;
    // this is only the answer half of that branch.
    if (!inventory) {
      log.debug("Leaving AdminViews.logoutJson(). No logout reader.");
      return Object.assign({ inventory: null, deliveriesPg: deliveriesPg },
                           backchannelBlock,
                           { json: Object.assign({ user: wantedUser,
                                                   known: false,
                                                   error: 'no logout reader ' +
                                                          'is installed' },
                                                 backchannelBlock) });
    }

    // Flattened, because this table filters and pages ACROSS families — see the
    // console page's header in admin-ui/admin.ts. The family's own prose stays
    // on the summary above it.
    const all = [];
    inventory.families.forEach(function (family) {
      family.rows.forEach(function (r) {
        all.push(Object.assign({ user: wantedUser, familyLabel: family.label },
                               r));
      });
    });
    const wantedFamily = String(req.query.family || '').trim();
    const filtered = wantedFamily
      ? all.filter(function (r) { return r.family === wantedFamily; }) : all;
    // `page` itself (2026-09-17): this passed `name: 'page'`, which pagingOf()
    // turns into `pagePage`, so the documented `?page=` moved nothing.
    const pg = this.pagedRows(req.query, filtered, { noun: 'live items' });

    const canWrite = gate.write;
    log.debug("Leaving AdminViews.logoutJson(). " + inventory.total +
              " live item(s).");
    return {
      wantedUser: wantedUser, gate: gate, params: params, families: families,
      key: key, inventory: inventory, all: all, wantedFamily: wantedFamily,
      filtered: filtered, pg: pg, canWrite: canWrite,
      deliveriesPg: deliveriesPg,
      backchannelDeliveries: backchannelDeliveries,
      backchannelDeliveriesPaging: backchannelBlock.backchannelDeliveriesPaging,
      backchannelCounts: backchannelBlock.backchannelCounts,
      deliveryState: deliveryState,
      deliveryq: deliveryQ,
      json: Object.assign({ user: wantedUser, known: true, canWrite: canWrite },
                          inventory,
                          { rows: pg.shown,
                            paging: this.pagingJson(pg.paging),
                            family: wantedFamily, key: key },
                          backchannelBlock)
    };
  }

  // NULL when the slot is unfilled — not an empty inventory, which would read
  // as "nothing is live". logoutJson() turns the null into its own no-reader
  // answer, and the page renders its own explanation from that.
  /**
   * Returns what is live for one identity, from the logout model.
   *
   * @param key - the identity
   * @returns the inventory, or null when the slot is unfilled
   */
  logoutInventoryFor(key) {
    const { log } = this.deps;
    log.debug("Entering AdminViews.logoutInventoryFor(). key=" + key);
    if (!logoutReader) {
      log.debug("Leaving AdminViews.logoutInventoryFor(). No logout reader " +
                "is installed.");
      return null;
    }
    const inventory = logoutReader.inventoryFor(key, '');
    log.debug("Leaving AdminViews.logoutInventoryFor(). " + inventory.total +
              " row(s).");
    return inventory;
  }

  // The families, for the summary table and for the filter. Read off the slot
  // so that a family added to logout.ts appears here with no edit — the reason
  // the prose lives over there and not in this file.
  /**
   * Returns the logout families, read from the logout model.
   *
   * @returns the families
   */
  logoutFamilies() {
    const { log } = this.deps;
    log.debug("Entering AdminViews.logoutFamilies().");
    log.debug("Leaving AdminViews.logoutFamilies().");
    return logoutReader ? logoutReader.FAMILIES : [];
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AdminViews>(
  'admin-core/admin_views',
  () => new AdminViews(AdminViews.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * What the two admin surfaces both read: the pure JSON views behind the console
 * and `/admin-api` (rule 7).
 * @namespace
 */
export = {
  AdminViews: AdminViews,
  installInstance: (instance: AdminViews): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  logoutInventoryFor: slot.forward('logoutInventoryFor'),
  logoutFamilies: slot.forward('logoutFamilies'),
  logoutJson: slot.forward('logoutJson'),
  mfaRosterJson: slot.forward('mfaRosterJson'),
  DEFAULT_BLOCKS_PER_PAGE: DEFAULT_BLOCKS_PER_PAGE,
  queryWith: slot.forward('queryWith'),
  sessionRowsFor: slot.forward('sessionRowsFor'),
  tokensBySession: slot.forward('tokensBySession'),
  ldapObjectJson: slot.forward('ldapObjectJson'),
  // The person's `sub` for the console's drill-down (2026-09-14): the same
  // answer the JSON half's `subject` member carries.
  userDetailSubject: helpers.subjectForName,
  mfaJson: slot.forward('mfaJson'),
  appPasswordsJson: slot.forward('appPasswordsJson'),
  verificationsJson: slot.forward('verificationsJson'),
  selfIssuedSubjectsJson: slot.forward('selfIssuedSubjectsJson'),
  devicesJson: slot.forward('devicesJson'),
  passwordOnlyDoorsFor: slot.forward('passwordOnlyDoorsFor'),
  userDetailJson: slot.forward('userDetailJson'),
  serviceAccountJson: slot.forward('serviceAccountJson'),
  serviceAccountsMonitorJson: slot.forward('serviceAccountsMonitorJson'),
  riskFor: slot.forward('riskFor'),
  personCredentialsState: slot.forward('personCredentialsState'),
  usersJson: slot.forward('usersJson'),
  peopleRows: slot.forward('peopleRows'),
  mergeFactors: slot.forward('mergeFactors'),
  usersListJson: slot.forward('usersListJson'),
  federationRow: slot.forward('federationRow'),
  federationDetailJson: slot.forward('federationDetailJson'),
  federationJson: slot.forward('federationJson'),
  federationListJson: slot.forward('federationListJson'),
  applicationPermissionsState: slot.forward('applicationPermissionsState'),
  applicationRolesState: slot.forward('applicationRolesState'),
  applicationEnrollmentState: slot.forward('applicationEnrollmentState'),
  applicationClaimsState: slot.forward('applicationClaimsState'),
  applicationTokenLifetimesState: slot.forward('applicationTokenLifetimesState'),
  attributeClaimChoices: slot.forward('attributeClaimChoices'),
  attributeClaimPreview: slot.forward('attributeClaimPreview'),
  releaseWithholding: slot.forward('releaseWithholding'),
  withheldFor: slot.forward('withheldFor'),
  applicationDetailJson: slot.forward('applicationDetailJson'),
  applicationAttributeNote: slot.forward('applicationAttributeNote'),
  applicationsJson: slot.forward('applicationsJson'),
  applicationsListJson: slot.forward('applicationsListJson'),
  secretExpiryOf: slot.forward('secretExpiryOf'),
  NOT_A_VIEW: NOT_A_VIEW,
  pageParamsOf: slot.forward('pageParamsOf'),
  groupDetailJson: slot.forward('groupDetailJson'),
  groupsJson: slot.forward('groupsJson'),
  setGroupReader: slot.forward('setGroupReader'),
  setGroupWriter: slot.forward('setGroupWriter'),
  groupsListJson: slot.forward('groupsListJson'),
  asDriftRows: slot.forward('asDriftRows'),
  asTruthRequest: slot.forward('asTruthRequest'),
  asDetailJson: slot.forward('asDetailJson'),
  authorizationServersJson: slot.forward('authorizationServersJson'),
  asListJson: slot.forward('asListJson'),
  saml11RelyingParties: slot.forward('saml11RelyingParties'),
  saml11Facts: slot.forward('saml11Facts'),
  saml11DetailJson: slot.forward('saml11DetailJson'),
  saml11Json: slot.forward('saml11Json'),
  saml11ListJson: slot.forward('saml11ListJson'),
  saml2ServiceProviders: slot.forward('saml2ServiceProviders'),
  saml2Facts: slot.forward('saml2Facts'),
  valuesFor: slot.forward('valuesFor'),
  saml2DetailJson: slot.forward('saml2DetailJson'),
  saml2Json: slot.forward('saml2Json'),
  saml2ListJson: slot.forward('saml2ListJson'),
  knownUserKeys: slot.forward('knownUserKeys'),
  rbacListJson: slot.forward('rbacListJson'),
  setDirectoryWriter: slot.forward('setDirectoryWriter'),
  setDirectoryReader: slot.forward('setDirectoryReader'),
  CREDENTIAL_CHOICES: CREDENTIAL_CHOICES,
  newUserContainer: slot.forward('newUserContainer'),
  newUserJson: slot.forward('newUserJson'),
  inventedFieldValues: slot.forward('inventedFieldValues'),
  typedField: slot.forward('typedField'),
  newApplicationJson: slot.forward('newApplicationJson'),
  spiffeSelectorText: slot.forward('spiffeSelectorText'),
  setSpiffeReader: slot.forward('setSpiffeReader'),
  spiffeListeners: slot.forward('spiffeListeners'),
  spiffeJson: slot.forward('spiffeJson'),
  spiffeEntriesJson: slot.forward('spiffeEntriesJson'),
  spiffeEntryJson: slot.forward('spiffeEntryJson'),
  spiffeAgentJson: slot.forward('spiffeAgentJson'),
  spiffeAgentsJson: slot.forward('spiffeAgentsJson'),
  spiffeBrokersJson: slot.forward('spiffeBrokersJson'),
  setSignalsReporter: slot.forward('setSignalsReporter'),
  setCaepReporter: slot.forward('setCaepReporter'),
  setRiscReporter: slot.forward('setRiscReporter'),
  signalsJson: slot.forward('signalsJson'),
  signalsState: slot.forward('signalsState'),
  ssfDeadLettersJson: slot.forward('ssfDeadLettersJson'),
  ssfDeadLettersState: slot.forward('ssfDeadLettersState'),
  ssfJson: slot.forward('ssfJson'),
  caepJson: slot.forward('caepJson'),
  caepSessionsState: slot.forward('caepSessionsState'),
  caepApplicationsState: slot.forward('caepApplicationsState'),
  caepSessionsJson: slot.forward('caepSessionsJson'),
  riscJson: slot.forward('riscJson'),
  riscAccountsState: slot.forward('riscAccountsState'),
  riscApplicationsState: slot.forward('riscApplicationsState'),
  riscAccountsJson: slot.forward('riscAccountsJson'),
  setLogoutReader: slot.forward('setLogoutReader'),
  DEFAULT_PER_PAGE: DEFAULT_PER_PAGE,
  DELEGATION_PER_PAGE: DELEGATION_PER_PAGE,
  MAX_ROWS: MAX_ROWS,
  pagingOf: slot.forward('pagingOf'),
  pagingJson: slot.forward('pagingJson'),
  pagedRows: slot.forward('pagedRows'),
  tokensView: slot.forward('tokensView'),
  sessionProtocolsIn: slot.forward('sessionProtocolsIn'),
  sessionsView: slot.forward('sessionsView'),
  auditView: slot.forward('auditView'),
  errorCodesView: slot.forward('errorCodesView'),
  usedAssertionsView: slot.forward('usedAssertionsView'),
  delegationView: slot.forward('delegationView'),
  delegationNodeLook: slot.forward('delegationNodeLook'),
  delegationLooks: slot.forward('delegationLooks'),
  delegationMapModel: slot.forward('delegationMapModel'),
  delegationMapKey: slot.forward('delegationMapKey'),
  apiGateStateOf: slot.forward('apiGateStateOf'),
  signingHistoryCertificate: slot.forward('signingHistoryCertificate'),
  federationMapModel: slot.forward('federationMapModel'),
  federationMapKey: slot.forward('federationMapKey'),
  federationMapLooks: slot.forward('federationMapLooks'),
  delegationPageModel: slot.forward('delegationPageModel'),
  delegationClusterModel: slot.forward('delegationClusterModel'),
  delegationAllowedModel: slot.forward('delegationAllowedModel'),
  permissionsListStateOf: slot.forward('permissionsListStateOf'),
  delegationSettingsModel: slot.forward('delegationSettingsModel'),
  credentialLineageModel: slot.forward('credentialLineageModel'),
  delegationUserModel: slot.forward('delegationUserModel'),
  delegationApplicationModel: slot.forward('delegationApplicationModel'),
  delegationChainModel: slot.forward('delegationChainModel'),
  delegationChooser: slot.forward('delegationChooser'),
  delegationFacts: slot.forward('delegationFacts'),
  delegationPolicyView: slot.forward('delegationPolicyView'),
  clusterSummary: slot.forward('clusterSummary'),
  permissionGroupsView: slot.forward('permissionGroupsView'),
  queryOne: slot.forward('queryOne'),
  chooserMatches: slot.forward('chooserMatches'),
  CHOOSER_HITS: CHOOSER_HITS,
  claimsRequestPreview: slot.forward('claimsRequestPreview'),
  claimsRequestJson: slot.forward('claimsRequestJson'),
  userinfoClaimsJson: slot.forward('userinfoClaimsJson'),
  setCryptoReporter: slot.forward('setCryptoReporter'),
  setXacmlPages: slot.forward('setXacmlPages'),
  setDirectoryPages: slot.forward('setDirectoryPages'),
  setScimReader: slot.forward('setScimReader'),
  setRolePreviewer: slot.forward('setRolePreviewer'),
  setConfigSettingsJson: slot.forward('setConfigSettingsJson'),
  settingsBlockOf: slot.forward('settingsBlockOf'),
  setTruststore: slot.forward('setTruststore'),
  truststoreJson: slot.forward('truststoreJson'),
  kerberosPrincipalsJson: slot.forward('kerberosPrincipalsJson'),
  krbtgtView: slot.forward('krbtgtView'),
  consoleRpSession: slot.forward('consoleRpSession'),
  gateStateFor: slot.forward('gateStateFor'),
  signOnSessionRows: slot.forward('signOnSessionRows'),
  metricsJson: slot.forward('metricsJson'),
  tokenSetView: slot.forward('tokenSetView'),
  permissionsView: slot.forward('permissionsView'),
  cryptoView: slot.forward('cryptoView'),
  keysView: slot.forward('keysView'),
  signingHistoryView: slot.forward('signingHistoryView'),
  keysExport: slot.forward('keysExport'),
  xacmlView: slot.forward('xacmlView'),
  xacmlPoliciesView: slot.forward('xacmlPoliciesView'),
  xacmlEditorView: slot.forward('xacmlEditorView'),
  xacmlPepsView: slot.forward('xacmlPepsView'),
  xacmlDecideView: slot.forward('xacmlDecideView'),
  xacmlMonitorView: slot.forward('xacmlMonitorView'),
  directoryPageJson: slot.forward('directoryPageJson'),
  consentView: slot.forward('consentView'),
  consentPageView: slot.forward('consentPageView'),
  rolesRegister: slot.forward('rolesRegister'),
  rolesView: slot.forward('rolesView'),
  policiesView: slot.forward('policiesView'),
  DEFAULT_CREDENTIAL: DEFAULT_CREDENTIAL,
  rolesPreview: slot.forward('rolesPreview'),
  claimsPreviewUser: slot.forward('claimsPreviewUser'),
  claimSetsJson: slot.forward('claimSetsJson'),
  claimsJson: slot.forward('claimsJson'),
  samlAttributesJson: slot.forward('samlAttributesJson'),
  claimsRequestParameter: slot.forward('claimsRequestParameter'),
  vcPreviewUser: slot.forward('vcPreviewUser'),
  vcJson: slot.forward('vcJson'),
  vpConfigJson: slot.forward('vpConfigJson'),
  realmRootUrl: slot.forward('realmRootUrl'),
  realmSettingRows: slot.forward('realmSettingRows'),
  realmJson: slot.forward('realmJson'),
  realmsJson: slot.forward('realmsJson'),
  tokenLifetimesJson: slot.forward('tokenLifetimesJson'),
  samlAssertionSeconds: slot.forward('samlAssertionSeconds'),
  samlAssertionsJson: slot.forward('samlAssertionsJson'),
  scimJson: slot.forward('scimJson'),
  scimMappingRow: slot.forward('scimMappingRow'),
  scimMonitorJson: slot.forward('scimMonitorJson')
};
