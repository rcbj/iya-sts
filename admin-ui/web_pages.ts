// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pages.ts
//
// ---------------------------------------------------------------------------
// THE PAGES OF THE STATIC CONSOLE, AND THE ENTRY OF ITS BROWSER BUNDLE (#446,
// 2026-10-05).
//
// One row per console page that has been converted: the path it is reached
// at, its title, the `/admin-api` operation whose answer it is drawn from,
// and the function that draws it. A page is converted when everything it
// shows is in that operation's answer and its renderer is a `web_` module
// (`web_kit.ts` argues the terms). A renderer sits beside the module whose
// page it draws, so some of them are in a protocol family's directory.
//
// **THIS FILE IS WHAT `build-typescript.sh` HANDS TO esbuild**, so what it
// reaches is exactly what the browser bundle (`admin-ui/console.bundle.js`,
// global `StsConsole`) holds. A page added to the console's static half
// costs a row here and nothing in the build.
//
// **NOTHING SERVES THE BUNDLE YET.** rcbj's decision is one cutover: until
// then the server-rendered console draws each converted page by calling the
// same renderer, and the bundle is held to the same answer in node
// (`tests/console_web_bundle.js`). The runtime that signs in, fetches and
// routes arrives with the cutover's own work, and will read this table.
// ---------------------------------------------------------------------------

import WebKit = require('./web_kit');
import webMessages = require('../common/web_messages');
import AcmePage = require('../acme/web_acme');
import ApplicationsPage = require('./web_applications');
import AuditPage = require('./web_audit');
import AuditExportPage = require('./web_audit_export');
import SignInAppearancePage = require('./web_sign_in_appearance');
import ServiceAccountsPage = require('./web_service_accounts');
import AuthorizationServersPage = require('./web_authorization_servers');
import AttributeSourcesPage =
  require('../attribute-sources/web_attribute_sources');
import CachesPage = require('./web_caches');
import CaepRiscPage = require('../ssf/web_caep_risc');
import CellsPage = require('./web_cells');
import ClaimsPage = require('./web_claims');
import ConfigPage = require('./web_config');
import ConfigDumpPage = require('./web_config_dump');
import ConsentPage = require('../oauth-oidc/web_consent');
import ClaimsProvidersPage =
  require('../oauth-oidc/web_claims_providers');
import CryptoMetadataPage = require('./web_crypto_metadata');
import DatabasePage = require('./web_database');
import DebuggerPage = require('../debugger/web_debugger');
import DevicesPage = require('./web_devices');
import EncryptionPage = require('./web_encryption');
import ErrorCodesPage = require('./web_error_codes');
import FederationPage = require('../federation/web_federation');
import EstPage = require('../est/web_est');
import GeolocationPage = require('./web_geolocation');
import GnapPage = require('../gnap/web_gnap');
import UmaPage = require('../uma/web_uma');
import GrantsPage = require('../oauth-oidc/web_grants');
import GroupsPage = require('./web_groups');
import KerberosPrincipalsPage =
  require('../kerberos/web_kerberos_principals');
import KerberosTrustsPage = require('../kerberos/web_kerberos_trusts');
import LogoutPage = require('../logout/web_logout');
import LdapPage = require('../ldap/web_ldap');
import ListenersPage = require('./web_listeners');
import MalwareScanPage = require('./web_malware_scan');
import CspReportsPage = require('./web_csp_reports');
import MailPage = require('./web_mail');
import MailOutboxPage = require('./web_mail_outbox');
import MetricsPage = require('./web_metrics');
import ModePage = require('./web_mode');
import BroadcastPage = require('./web_broadcast');
import NodeHealthPage = require('./web_node_health');
import PasskeyReportPage = require('./web_passkey_report');
import PostLoginActivitiesPage = require('./web_post_login_activities');
import HardwareTokensPage = require('./web_hardware_tokens');
import OpenPgpPage = require('./web_openpgp');
import PkiPage = require('./web_pki');
import ProtocolSettingsPage = require('./web_protocol_settings');
import PoliciesPage = require('./web_policies');
import OidfedPage = require('../oidfed/web_oidfed');
import ProviderCommandsPage =
  require('../oauth-oidc/web_provider_commands');
import OAuth2MonitorPage = require('../oauth-oidc/web_oauth2_monitor');
import RbacPage = require('./web_rbac');
import RealmsPage = require('./web_realms');
import RiskPage = require('./web_risk');
import RolesPage = require('./web_roles');
import SamlAssertionsPage = require('./web_saml_assertions');
import SamlPage = require('../saml/web_saml');
import SchedulerPage = require('./web_scheduler');
import ScimPage = require('../scim/web_scim');
import ScepPage = require('../scep/web_scep');
import SecretDestinationsPage = require('./web_secret_destinations');
import SecretsPage = require('./web_secrets');
import SessionsPage = require('../logout/web_sessions');
import SettingsForms = require('./web_settings');
import WebMessages = require('../common/web_messages');
import SignalsPage = require('../ssf/web_signals');
import SpiffePage = require('../spiffe/web_spiffe');
import SsfDeadLettersPage = require('../ssf/web_ssf_dead_letters');
import SsfPage = require('../ssf/web_ssf');
import SsfTransmittersPage = require('../ssf/web_ssf_transmitters');
import TlsTrustPage = require('../tls/web_tls_trust');
import PkiTrustPage = require('./web_pki_trust');
import TlsConnectionPage = require('../tls/web_tls_connection');
import TokenLifetimesPage = require('./web_token_lifetimes');
import TokensPage = require('./web_tokens');
import UsedAssertionsPage = require('./web_used_assertions');
import UsersPage = require('./web_users');
import VcClaimsPage = require('../oid4vc/web_vc_claims');
import VcStatusPage = require('./web_vc_status');
import VcVerifierConfigPage =
  require('../oid4vc/web_vc_verifier_config');
import XacmlPage = require('../xacml/web_xacml');
import WorkerPoolsPage = require('./web_worker_pools');
import DelegationPage = require('./web_delegation');
import DashboardPage = require('./web_dashboard');
import StsMetadataPage = require('./web_sts_metadata');
import ExplorerPage = require('./web_explorer');
import AccountApiPage = require('./web_account_api');
import WebAnswers = require('./web_answers');

type Json = any;

/**
 * One converted console page.
 */
interface WebPage {
  path: string;
  title: string;
  operation: string;
  // Other operations whose answers the view is composed with, by the member
  // each goes in. `composeWhen` limits a member to a query that names one of
  // its inputs; otherwise the operation is part of every view.
  compose?: Record<string, string>;
  composeWhen?: Record<string, string[]>;
  // THE MEMBER'S OWN NAMES (2026-10-12): where two tabs' lists share a
  // parameter's name, the page carries each under a name of its own
  // (`composeWhen` lists the page's), and the member's operation is asked
  // with the name it reads — `estCertificatesPage` is EST's
  // `certificatesPage`. `composeRequests()` is the one reading of it.
  composeParams?: Record<string, Record<string, string>>;
  // Members listed here are always composed, even when `composeWhen` names
  // query parameters that are absent. Those parameters are still forwarded.
  composeAlways?: string[];
  // Members listed here are drawn from their answer even when the status is
  // not 200, so a refusal is the page's to show. The certificate dialog is
  // the one: `GET /admin-api/certificates` answers 400, 404 or 500 with the
  // view the dialog draws as why it could not open.
  composeKeep?: string[];
  // THE DRILL-DOWN AT THE SAME PATH (#446): `/admin/groups?group=<dn>` is
  // one group, answered by the same operation asked with the same query, so
  // a drill-down is not a page of its own but a second renderer chosen when
  // the query names `param`. `sample` picks an item off the list's answer,
  // which is how the bundle check draws one without knowing the data.
  // THE OPERATION'S NAMES FOR THIS PAGE'S QUERY (#446): a page at a path
  // of its own whose operation answers it under another parameter —
  // `/admin/caep-sessions/session?id=` is `GET /admin-api/caep/sessions
  // ?session=` — maps the page's name to the operation's here, and the
  // page is asked for with the operation's.
  params?: Record<string, string>;
  // WHAT THE PAGE ALWAYS ASKS ITS OPERATION, beside its own query: the PKI
  // page's `rows=shown`, so the API reads only what the page draws.
  fixed?: Record<string, string>;
  drill?: {
    param: string;
    sample: (listView: Json) => string | null;
    render: (view: Json, ctx?: Json) => string;
  };
  // A DRILL-DOWN AT A PATH OF ITS OWN WHOSE LIST IS A TAB OF ANOTHER PAGE
  // (#1760): `/admin/xacml/pep?pep=` is one row of `/admin/xacml`'s Remote
  // PEPs tab, so its trail's section crumb, and the nav it marks, are that
  // page's. `fragment`, when given, lands the section crumb on a tab; the
  // XACML pages name their tab as a crumb of its own instead (`upVia`).
  upTo?: { path: string; fragment?: string };
  // AND THE CRUMBS BETWEEN THAT SECTION AND THE LEAF (#1760): EVERY
  // DRILL-DOWN'S TRAIL NAMES THE TAB IT WAS OPENED FROM (rcbj, 2026-11-14).
  // A remote PEP's page is XACML › Remote PEPs › the PEP, and a route's
  // XACML › Remote PEPs › the PEP › Reverse proxy › the route: each tab a
  // link to that tab, the PEP a link to its page. Each is `{ label, href }`
  // (`WebShell.trailBar()`), labelled in the reader's language by `t`.
  upVia?: (query: Json, t: Json) => Array<{ label: string; href: string }>;
  // NAMES THE PAGE READS ITSELF (`ctx.query`) AND NEVER ASKS ITS
  // OPERATION: a drill-down drawn from its parent's answer, such as a
  // remote PEP listener's page, whose `listener` the operation does not
  // declare and would refuse (#1476).
  ownParams?: string[];
  render: (view: Json, ctx?: Json) => string;
  // A PICTURE'S `?format=svg` (#444 phase 2b): the drawing as a document on
  // its own, with no links, drawn from the page's answer in the browser as
  // the page's own picture is. A page without it asks its operation for
  // `format=svg`, as every page did.
  document?: (view: Json) => string;  // STATIC FILES THE PAGE IS DRAWN OVER, by the member of the view each goes
  // in (#444 phase 2b): Geolocation's country outlines. The runtime fetches
  // each once per load and keeps it; a fetch that fails leaves the member
  // out, and the page says what it could not draw.
  assets?: Record<string, string>;
}

// PROTOCOLS → CERT ISSUANCE, ONE PAGE OF TABS (rcbj, 2026-10-12). ACME, EST,
// SCEP and SPIFFE's four pages were seven console pages; they are one, each
// a tab drawn by its own family's renderer from its own operation, SPIFFE's
// four as sub-tabs of one tab.
//
// ONE ADDRESS CARRIES THE WHOLE PAGE'S STATE, AND THE SEVEN SHARED NAMES.
// ACME, EST and SCEP all page a list on `certificatesPage`; ACME and SCEP
// one on `credentialsPage`; the three SPIFFE lists all search `q` and page
// on `page`. So on this page each tab's names carry the tab's prefix
// (`estCertificatesPage`, `entriesQ`): its operation is asked with its own
// names (`composeParams`), its renderer is handed them
// (`certContext()`), and what it draws is given the page's names back
// (`certTabLinks()`). `per` is shared, as on every page holding more than
// one list; `entry` and `agent`, the two drill-downs, are one tab's each.
const CERT_PANELS: Json = {
  acme: { path: '/admin/acme', operation: '/admin-api/acme',
          tab: 'cert-tab-acme', prefix: 'acme', routes: '/enroll/acme',
          names: ['certificatesPage', 'credentialsPage', 'accountsPage',
                  'hostNamesPage'] },
  est: { path: '/admin/est', operation: '/admin-api/est',
         tab: 'cert-tab-est', prefix: 'est', routes: '/.well-known/est',
         names: ['certificatesPage'] },
  scep: { path: '/admin/scep', operation: '/admin-api/scep',
          tab: 'cert-tab-scep', prefix: 'scep', routes: '/enroll/scep',
          names: ['certificatesPage', 'credentialsPage'] },
  spiffe: { path: '/admin/spiffe', operation: '/admin-api/spiffe',
            tab: 'cert-spiffe-overview', prefix: 'spiffe', routes: '/spiffe',
            names: [] },
  spiffeEntries: { path: '/admin/spiffe/entries',
                   operation: '/admin-api/spiffe/entries',
                   tab: 'cert-spiffe-entries', prefix: 'entries',
                   names: ['q', 'origin', 'page'], drill: 'entry' },
  spiffeAgents: { path: '/admin/spiffe/agents',
                  operation: '/admin-api/spiffe/agents',
                  tab: 'cert-spiffe-agents', prefix: 'agents',
                  names: ['q', 'page'], drill: 'agent' },
  spiffeBrokers: { path: '/admin/spiffe/brokers',
                   operation: '/admin-api/spiffe/brokers',
                   tab: 'cert-spiffe-brokers', prefix: 'brokers',
                   names: ['q', 'page'] }
};
const CERT_PAGE = '/admin/cert-issuance';

// ADDRESSES WHOSE CONTENT MOVED TO ANOTHER PAGE (#752), keyed by the path —
// and, for a tab, the path and its fragment — that somebody may still hold
// in a bookmark, a ticket or an old copy of the documentation. The runtime
// replaces such an address with the page's before it draws anything
// (`movedTo()`), so it lands on the content rather than on "not a console
// page" or on a combined page whose tab is gone. The query rides along: the
// combined page's `page` and `per` were the status tab's own. A tab folded
// into a combined page is the other direction and needs no row here — its
// former path's links are rewritten where they are drawn (`vcTabLinks()`).
const MOVED: Record<string, string> = {
  // The Credential status tab of Protocols → Verifiable Credentials, and
  // the page it had been before the tabs (2026-10-12).
  '/admin/vc#vc-tab-status': '/admin/vc/monitor',
  '/admin/vc-status': '/admin/vc/monitor'
};

/**
 * A tab's name for one of its own parameters on the combined page.
 *
 * @param key - the tab's key in `CERT_PANELS`
 * @param name - the parameter as the tab's operation reads it
 * @returns the page's name, such as `estCertificatesPage`
 */
function certName(key: string, name: string): string {
  const panel = CERT_PANELS[key];
  return panel.prefix + name.charAt(0).toUpperCase() + name.slice(1);
}

/**
 * The combined page's row members for every tab but the SPIFFE trust
 * domain's, whose operation is the page's own (it reads no parameter, so
 * no tab's names are the page's): what each is asked with, under which
 * names.
 *
 * @returns `{ compose, composeWhen, composeParams, composeAlways }`
 */
function certComposition(): Json {
  const out: Json = { compose: {}, composeWhen: {}, composeParams: {},
                      composeAlways: [] };
  Object.keys(CERT_PANELS).filter(function (key) {
    return key !== 'spiffe';
  }).forEach(function (key) {
    const panel = CERT_PANELS[key];
    const names: Json = { per: 'per' };
    panel.names.forEach(function (name: string) {
      names[certName(key, name)] = name;
    });
    if (panel.drill) {
      names[panel.drill] = panel.drill;
    }
    out.compose[key] = panel.operation;
    out.composeWhen[key] = Object.keys(names);
    out.composeParams[key] = names;
    out.composeAlways.push(key);
  });
  return out;
}

const CERT_COMPOSITION = certComposition();

// EVERY PROTOCOLS PAGE AS TABS, METADATA FIRST (rcbj, 2026-10-12), AND THE
// DIRECTORY PAGES WITH MORE THAN ONE SECTION. The pages that were drawn as
// one long column of sections are cut
// into tabs by `protocolTabs()`: a section whose heading carries
// `data-tab="<name>"` is that tab, and everything else — the lead notes, the
// endpoints, what explains the protocol or reports its state — is the
// Metadata tab, which is first. A renderer marks its own sections; this
// table names each page's tabs, in order, so the stylesheet can mark the
// tab being read (`admin.ts`, which reads `PROTOCOL_TAB_IDS`) and a test
// can hold the renderers to it: a tab name drawn and not listed here fails
// `tests/console_web_bundle.js`. A listed tab may be absent where the page
// draws nothing for it (PKI's issue forms before a hierarchy exists).
const PROTOCOL_TABS: Record<string, string[]> = {
  '/admin/delegation-settings': ['register', 'settings'],
  '/admin/federation': ['relationships', 'consumer', 'add', 'settings'],
  '/admin/oidfed': ['keys', 'subordinates', 'collection', 'anchors',
                    'marks', 'resolve', 'settings'],
  '/admin/commands': ['clients', 'send', 'accounts', 'tenants',
                      'deliveries'],
  '/admin/claim-providers': ['providers', 'register', 'links'],
  '/admin/gnap': ['grants', 'resources', 'settings'],
  // UMA 2.0 (#1195): GNAP's sibling, a tab per list.
  '/admin/uma': ['servers', 'resources', 'tokens', 'pending', 'owner',
                 'whatif', 'settings'],
  '/admin/totp': ['settings'],
  '/admin/backup-codes': ['settings'],
  '/admin/webauthn': ['settings'],
  '/admin/device-registration': ['settings'],
  // #2049: the hardware-token mechanisms and OpenPGP, Metadata then
  // Settings like the second factors beside them.
  '/admin/hardware-tokens-settings': ['settings'],
  '/admin/piv': ['settings'],
  '/admin/yubiotp': ['settings'],
  '/admin/oath-tokens': ['settings'],
  '/admin/ssh-user-ca': ['settings'],
  '/admin/openpgp-settings': ['settings'],
  '/admin/ldap': ['settings'],
  '/admin/wstrust': ['settings'],
  '/admin/wsfed': ['settings'],
  '/admin/pki': ['hierarchy', 'pinned', 'edit', 'build', 'applications',
                 'people', 'revocation', 'workbench', 'settings'],
  // #2118: the named truststores, the use cases, node's own store.
  '/admin/pki/trust': ['paranoid', 'signers', 'pins', 'client', 'truststores',
                       'usecases', 'system'],
  '/admin/tls': [],
  '/admin/tls/trust': ['anchors', 'add'],
  // DIRECTORY (rcbj, 2026-10-12): the pages with more than one section. A
  // page with one (Every entry, The directory service) is left as
  // it is; Policies draws tabs of its own, Metadata first. Users is tabbed
  // since #2070: the tiles, the people, the `Profile photos` settings.
  '/admin/users': ['people', 'settings'],
  '/admin/groups': ['groups', 'create', 'settings'],
  '/admin/roles': ['roles', 'create', 'member', 'authorizes', 'requiring',
                   'preview', 'settings'],
  '/admin/applications': ['applications', 'add', 'settings'],
  '/admin/devices': ['devices', 'register'],
  // #1955 P1: the register's list; P4: imported OATH tokens;
  // P2: PIV enrolment and escrowed keys; the #1955 review: a person's SSH
  // user certificates; #2071: imported YubiKey OTPs.
  '/admin/hardware-tokens': ['tokens', 'oath', 'yubiotp', 'enrol', 'escrow',
                             'ssh'],
  // #1955 P6: the person, the registration, the directory.
  '/admin/openpgp': ['person', 'register', 'directory'],
  '/admin/attribute-sources': ['sources', 'add', 'person', 'settings'],
  '/admin/secret-destinations': ['destinations', 'add'],
  // #1111, #1123: the started activities and their controls; the report
  // is /report's.
  '/admin/post-login-activities': ['activities', 'start'],
  '/admin/ldap/applications': ['entries'],
  '/admin/ldap/federations': ['entries'],
  '/admin/ldap/roles': ['entries'],
  '/admin/ldap/policies': ['entries'],
  '/admin/ldap/peps': ['entries'],
  '/admin/ldap/spiffe': ['entries', 'agents'],
  '/admin/ldap/devices': ['entries'],
  // MONITORING AND SERVER CONFIGURATION (rcbj, 2026-10-12), the pages with
  // more than one section; each renderer marks its own. Listeners draws
  // tabs of its own and is not here.
  '/admin/metrics': ['calls', 'tokens', 'artifacts', 'sessions'],
  '/admin/sessions': ['live', 'unauthenticated', 'accounts'],
  '/admin/tokens': ['invalidate', 'issued'],
  '/admin/delegation': ['happened', 'chains', 'register', 'kerberos',
                        'policy'],
  '/admin/caep-sessions': ['sessions', 'streams', 'applications'],
  '/admin/risc-accounts': ['accounts', 'streams', 'applications'],
  '/admin/signals': ['events', 'clear'],
  '/admin/ssf/transmitters': ['relationships', 'blocks', 'locks', 'arrived'],
  '/admin/ssf/dead-letters': ['when', 'why', 'streams', 'letters', 'process',
                              'settings'],
  // One tab per outbound delivery kind (`oauth-oidc/outbound_delivery.ts`):
  // a kind added there owes its id here.
  '/admin/deliveries': ['backchannel-logout', 'ciba', 'cell-ops',
                        'provider-commands'],
  '/admin/consent': ['globals', 'recorded'],
  '/admin/xacml/monitor': ['figures', 'points'],
  '/admin/gnap/monitor': ['formats', 'applications'],
  // The status lists' credentials (#752); the tiles, the note and where the
  // lists are served are Metadata.
  '/admin/vc/monitor': ['credentials'],
  '/admin/acme/monitor': ['operations', 'profiles', 'codes', 'statuses',
                          'principals', 'recent'],
  '/admin/est/monitor': ['operations', 'profiles', 'principals', 'codes',
                         'statuses', 'recent'],
  '/admin/scep/monitor': ['operations', 'failinfo', 'codes', 'profiles',
                          'principals', 'recent'],
  '/admin/oauth2/monitor': ['par', 'stepup'],
  '/admin/scim/monitor': ['calls', 'resources', 'clients', 'schemes',
                          'responses', 'recent', 'written'],
  '/admin/logout': ['lookup', 'backchannel', 'settings'],
  '/admin/database': ['server', 'activity', 'background', 'schema',
                      'configuration'],
  '/admin/encryption': ['classes', 'datakeys'],
  '/admin/secrets': ['keys', 'database', 'mail', 'stores'],
  '/admin/caches': ['caches', 'replay', 'nodes', 'entries'],
  '/admin/worker-pools': ['request', 'surface'],
  '/admin/node-health': ['cpu', 'memory', 'processes', 'ecs', 'machine'],
  '/admin/tls-connection': ['connection', 'forwarded'],
  '/admin/scheduler': ['leader', 'jobs', 'runs', 'commands', 'settings'],
  '/admin/devices/monitor': ['register', 'activity', 'days'],
  // The list is drawn only when the query names one (#942).
  '/admin/passkey-report': ['people', 'algorithms', 'models', 'profiles',
                            'attestation', 'list'],
  '/admin/risk': ['assessments', 'standings', 'lookup', 'datasets', 'import',
                  'providers', 'failures', 'settings'],
  '/admin/risk-scoring': ['assessments', 'signals', 'decisions', 'process'],
  '/admin/audit': ['events', 'settings'],
  '/admin/audit-export': ['destinations', 'add', 'status', 'settings'],
  '/admin/error-codes': ['subsystems', 'codes'],
  '/admin/realms': ['realms', 'define', 'settings'],
  '/admin/config': ['index', 'settings'],
  '/admin/mode': ['requirements', 'development', 'notyet'],
  '/admin/persistence': ['settings'],
  '/admin/cluster': ['settings'],
  '/admin/cells': ['cells', 'residents', 'rehome', 'settings'],
  '/admin/mail': ['test', 'verify', 'messages', 'settings'],
  '/admin/sign-in-appearance': ['colours', 'layout', 'preview', 'settings'],
  '/admin/rbac': ['holders', 'grant', 'settings'],
  '/admin/debugger': ['settings'],
  '/admin/sts-metadata': ['protocols', 'servers', 'endpoints',
                          'specifications'],
  '/admin/keys': ['rotation', 'keys', 'settings'],
  '/admin/crypto-metadata': ['families', 'material', 'hashing', 'signatures',
                             'algorithms', 'encryption', 'post-quantum',
                             'standards']
};

/**
 * The id prefix of a Protocols page's tabs: its path under `/admin`.
 *
 * @param path - the page's path
 * @returns `gnap`, `tls-trust`
 */
function protocolSlug(path: string): string {
  return String(path).replace(/^\/admin\//, '').replace(/[^a-z0-9]+/gi, '-');
}

/**
 * Every tab id `protocolTabs()` can draw: the stylesheet's list.
 *
 * @returns the ids
 */
function protocolTabIds(): string[] {
  const out: string[] = [];
  Object.keys(PROTOCOL_TABS).forEach(function (path) {
    const slug = protocolSlug(path);
    out.push(slug + '-tab-metadata');
    PROTOCOL_TABS[path].forEach(function (name) {
      out.push(slug + '-tab-' + name);
    });
  });
  return out;
}

const PAGES: WebPage[] = [
  { path: '/admin/acme/monitor', title: 'ACME enrollments',
    operation: '/admin-api/acme/monitor',
    render: function (view: Json, ctx?: Json): string {
      return AcmePage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/applications', title: 'Applications',
    operation: '/admin-api/applications',
    drill: {
      param: 'application',
      sample: function (list: Json): string | null {
        const rows = list.applications || [];
        return rows[0] ? rows[0].identifier : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return ApplicationsPage.detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return ApplicationsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/applications/new', title: 'New application',
    operation: '/admin-api/console/applications/new',
    render: function (view: Json, ctx?: Json): string {
      return ApplicationsPage.newApplicationBody(ctx || WebKit.context(),
                                                 view);
    } },
  { path: '/admin/attribute-sources', title: 'Attribute sources',
    operation: '/admin-api/attribute-sources',
    render: AttributeSourcesPage.render },
  // DIRECTORY → ATTRIBUTE SOURCES → ADD A SOURCE (#1132), reached from the
  // list's Add tab.
  { path: '/admin/attribute-sources/new', title: 'Add an attribute source',
    operation: '/admin-api/attribute-sources/new',
    render: function (view: Json, ctx?: Json): string {
      return AttributeSourcesPage.newBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/authorization-servers', title: 'Authorization servers',
    operation: '/admin-api/authorization-servers',
    drill: {
      param: 'profile',
      sample: function (list: Json): string | null {
        const rows = list.authorizationServers || [];
        return rows[0] ? rows[0].id : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return AuthorizationServersPage.detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return AuthorizationServersPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/caches', title: 'Caches', operation: '/admin-api/caches',
    render: CachesPage.render },
  { path: CERT_PAGE, title: 'Cert issuance',
    operation: CERT_PANELS.spiffe.operation,
    compose: CERT_COMPOSITION.compose,
    composeWhen: CERT_COMPOSITION.composeWhen,
    composeParams: CERT_COMPOSITION.composeParams,
    composeAlways: CERT_COMPOSITION.composeAlways,
    // A registration entry is drawn in place of the tabs (`?entry=`), and
    // so is an agent (`?agent=`, in `certIssuance()`); the entry is the
    // drill the runtime's trail and the bundle's check know.
    drill: {
      param: 'entry',
      sample: function (view: Json): string | null {
        const rows = (view.spiffeEntries && view.spiffeEntries.entries) || [];
        return rows[0] ? rows[0].id : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return WebPages.certIssuance(view, ctx || WebKit.context());
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return WebPages.certIssuance(view, ctx || WebKit.context());
    } },
  { path: '/admin/audit', title: 'Audit log',
    operation: '/admin-api/audit',
    render: function (view: Json, ctx?: Json): string {
      return AuditPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/audit-export', title: 'Audit export',
    operation: '/admin-api/audit-export',
    render: AuditExportPage.render },
  { path: '/admin/caep-sessions/session', title: 'CAEP sessions — one session',
    operation: '/admin-api/caep/sessions', params: { id: 'session' },
    render: function (view: Json, ctx?: Json): string {
      return CaepRiscPage.caepSessionBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/caep-sessions', title: 'CAEP sessions',
    operation: '/admin-api/caep/sessions',
    render: function (view: Json, ctx?: Json): string {
      return CaepRiscPage.caepSessionsBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/cells', title: 'Cells', operation: '/admin-api/cells',
    render: CellsPage.render },
  { path: '/admin/claim-providers', title: 'Claims Providers',
    operation: '/admin-api/claim-providers',
    render: ClaimsProvidersPage.render },
  { path: '/admin/commands', title: 'OpenID Provider Commands',
    operation: '/admin-api/commands', render: ProviderCommandsPage.render },
  { path: '/admin/claims', title: 'Custom claims',
    operation: '/admin-api/claims',
    render: function (view: Json, ctx?: Json): string {
      return ClaimsPage.claimsBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/config', title: 'Configuration',
    operation: '/admin-api/config',
    render: function (view: Json, ctx?: Json): string {
      return ConfigPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/config-dump', title: 'Configuration dump',
    operation: '/admin-api/config-dump',
    render: ConfigDumpPage.render },
  { path: '/admin/consent', title: 'Consent',
    operation: '/admin-api/consent',
    render: function (view: Json, ctx?: Json): string {
      return ConsentPage.body(ctx || WebKit.context(), view);
    } },
  // THE CERTIFICATE DIALOG, the same composition as `/admin/pki` below:
  // View details adds `?certificate=` and the page asks
  // `GET /admin-api/certificates` for `certificateDetails`. A refusal is
  // still that view (`composeKeep`).
  { path: '/admin/crypto-metadata', title: 'Cryptography',
    operation: '/admin-api/crypto',
    compose: { certificateDetails: '/admin-api/certificates' },
    composeWhen: { certificateDetails: ['certificate'] },
    composeKeep: ['certificateDetails'],
    render: CryptoMetadataPage.render },
  { path: '/admin', title: 'Admin console',
    operation: '/admin-api/console/dashboard',
    render: function (view: Json, ctx?: Json): string {
      return DashboardPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/api-explorer', title: 'API explorer',
    operation: '/admin-api/console/api-explorer',
    render: function (view: Json, ctx?: Json): string {
      return ExplorerPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/account-api', title: 'Account API',
    operation: '/admin-api/account-api', render: AccountApiPage.render },
  { path: '/admin/sts-metadata', title: 'Service metadata',
    operation: '/admin-api/sts-metadata',
    render: function (view: Json, ctx?: Json): string {
      return StsMetadataPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/delegation', title: 'Delegation',
    operation: '/admin-api/delegation',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.acts(ctx || WebKit.context(), view);
    } },
  { path: '/admin/delegation/allowed', title: 'The allowed mappings',
    operation: '/admin-api/console/delegation/allowed',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.allowed(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return DelegationPage.document(view);
    } },
  { path: '/admin/delegation/application',
    title: 'Delegation — one application',
    operation: '/admin-api/console/delegation/application',
    drill: {
      param: 'application',
      sample: function (list: Json): string | null {
        const rows = list.applications || [];
        return rows[0] ? rows[0].identifier : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return DelegationPage.application(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.application(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return DelegationPage.document(view);
    } },
  { path: '/admin/delegation-settings', title: 'Delegation',
    operation: '/admin-api/console/delegation-settings',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.settings(ctx || WebKit.context(), view);
    } },
  { path: '/admin/delegation/user', title: 'Delegation — one person',
    operation: '/admin-api/console/delegation/user',
    drill: {
      param: 'user',
      sample: function (list: Json): string | null {
        const rows = list.users || [];
        return rows[0] ? rows[0].key : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return DelegationPage.user(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.user(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return DelegationPage.document(view);
    } },
  { path: '/admin/delegation/cluster', title: 'Delegation — one group',
    operation: '/admin-api/console/delegation/cluster',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.cluster(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return DelegationPage.document(view);
    } },
  { path: '/admin/delegation/chain', title: 'Delegation — one relationship',
    operation: '/admin-api/console/delegation/chain',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.chain(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return DelegationPage.document(view);
    } },
  { path: '/admin/delegation/map', title: 'Delegation — the picture',
    operation: '/admin-api/console/delegation/map',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.map(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return DelegationPage.document(view);
    } },
  { path: '/admin/database', title: 'Database',
    operation: '/admin-api/database', render: DatabasePage.render },
  { path: '/admin/debugger', title: 'Protocol debugger',
    operation: '/admin-api/debugger', render: DebuggerPage.render },
  { path: '/admin/deliveries', title: 'Outbound deliveries',
    operation: '/admin-api/deliveries',
    render: function (view: Json, ctx?: Json): string {
      return ProviderCommandsPage.deliveriesBody(ctx || WebKit.context(),
                                                 view);
    } },
  { path: '/admin/device-registration', title: 'Device registration',
    operation: '/admin-api/device-registration',
    render: function (view: Json, ctx?: Json): string {
      return DevicesPage.registrationHtml(view, ctx);
    } },
  { path: '/admin/devices', title: 'Devices',
    operation: '/admin-api/devices', render: DevicesPage.render },
  // DIRECTORY → DEVICES → REGISTER A DEVICE (#1132), reached from the
  // list's Register tab.
  { path: '/admin/devices/new', title: 'Register a device',
    operation: '/admin-api/devices/new',
    render: function (view: Json, ctx?: Json): string {
      return DevicesPage.newBody(view, ctx || WebKit.context());
    } },
  { path: '/admin/devices/monitor', title: 'Devices (monitoring)',
    operation: '/admin-api/devices/monitor',
    render: function (view: Json, ctx?: Json): string {
      return DevicesPage.monitorHtml(view, ctx);
    } },
  // #221: the rotation's state per service account.
  { path: '/admin/service-accounts', title: 'Service accounts',
    operation: '/admin-api/service-accounts',
    render: ServiceAccountsPage.render },
  { path: '/admin/encryption', title: 'Encryption',
    operation: '/admin-api/encryption', render: EncryptionPage.render },
  { path: '/admin/error-codes', title: 'Error codes',
    operation: '/admin-api/error-codes',
    render: function (view: Json, ctx?: Json): string {
      return ErrorCodesPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/est/monitor', title: 'EST enrollments',
    operation: '/admin-api/est/monitor',
    render: function (view: Json, ctx?: Json): string {
      return EstPage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/federation/map', title: 'Federation — the picture',
    operation: '/admin-api/console/federation/map',
    render: function (view: Json, ctx?: Json): string {
      return FederationPage.map(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return FederationPage.mapDocument(view);
    } },
  { path: '/admin/federation', title: 'Federation',
    operation: '/admin-api/federation',
    drill: {
      param: 'relationship',
      sample: function (list: Json): string | null {
        const rows = list.relationships || [];
        return rows[0] ? rows[0].id : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return FederationPage.detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return FederationPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/geolocation', title: 'Geolocation',
    operation: '/admin-api/geolocation', render: GeolocationPage.render,
    assets: { countryOutlines: '/admin/geo-outlines.json' } },
  { path: '/admin/gnap', title: 'GNAP', operation: '/admin-api/gnap',
    render: GnapPage.render },
  { path: '/admin/gnap/monitor', title: 'GNAP grants',
    operation: '/admin-api/gnap/monitor',
    render: function (view: Json, ctx?: Json): string {
      return GnapPage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/grants', title: 'Grants', operation: '/admin-api/grants',
    render: GrantsPage.render },
  { path: '/admin/groups', title: 'Groups', operation: '/admin-api/groups',
    drill: {
      param: 'group',
      sample: function (list: Json): string | null {
        return list.groups && list.groups[0] ? list.groups[0].dn : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return GroupsPage.detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return GroupsPage.body(ctx || WebKit.context(), view);
    } },
  // DIRECTORY → GROUPS → NEW GROUP (#1132): the one create form, reached
  // from the list's Create tab, as New user is from Users.
  { path: '/admin/groups/new', title: 'New group',
    operation: '/admin-api/groups/new',
    render: function (view: Json, ctx?: Json): string {
      return GroupsPage.newGroupBody(ctx || WebKit.context(), view);
    } },
  // DIRECTORY → POLICIES → NEW POLICY (#1132): one kind's create form,
  // reached from that kind's New policy tab, drawn from the policies view.
  { path: '/admin/policies/new', title: 'New policy',
    operation: '/admin-api/policies/new',
    compose: { policies: '/admin-api/policies' },
    render: function (view: Json, ctx?: Json): string {
      return PoliciesPage.newPolicyBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/keys', title: 'Key pairs', operation: '/admin-api/keys',
    render: function (view: Json, ctx?: Json): string {
      return CryptoMetadataPage.keysBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/keys/history', title: 'Key pair history',
    operation: '/admin-api/keys/history',
    render: function (view: Json, ctx?: Json): string {
      return CryptoMetadataPage.renderHistory(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/directory', title: 'Every entry in the directory',
    operation: '/admin-api/ldap/directory',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.directory(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/peps', title: 'PEP entries',
    operation: '/admin-api/ldap/peps',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.peps(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/policies', title: 'Policy entries',
    operation: '/admin-api/ldap/policies',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.policies(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/service', title: 'The directory service',
    operation: '/admin-api/ldap/service',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.service(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/applications', title: 'Application entries',
    operation: '/admin-api/ldap/applications',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.applications(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/federations', title: 'Federation entries',
    operation: '/admin-api/ldap/federations',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.federations(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/devices', title: 'Device entries',
    operation: '/admin-api/ldap/devices',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.devices(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/roles', title: 'Role entries',
    operation: '/admin-api/ldap/roles',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.roles(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ldap/spiffe', title: 'SPIFFE entries',
    operation: '/admin-api/ldap/spiffe',
    render: function (view: Json, ctx?: Json): string {
      return LdapPage.spiffe(ctx || WebKit.context(), view);
    } },
  { path: '/admin/malware-scanning', title: 'Malware scanning',
    operation: '/admin-api/malware-scanning', render: MalwareScanPage.render },
  { path: '/admin/csp-reports', title: 'CSP reports',
    operation: '/admin-api/csp-reports', render: CspReportsPage.render },
  { path: '/admin/listeners', title: 'Listeners',
    operation: '/admin-api/listeners', render: ListenersPage.render },
  { path: '/admin/logout', title: 'Sign-out',
    operation: '/admin-api/logout',
    drill: {
      param: 'user',
      sample: function (): string | null {
        return 'alice';
      },
      render: function (view: Json, ctx?: Json): string {
        return LogoutPage.body(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return LogoutPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/mail', title: 'Mail', operation: '/admin-api/mail',
    render: MailPage.render },
  { path: '/admin/mail/outbox', title: 'Mail outbox',
    operation: '/admin-api/mail/outbox', render: MailOutboxPage.render },
  { path: '/admin/metrics', title: 'Metrics',
    operation: '/admin-api/metrics',
    render: function (view: Json, ctx?: Json): string {
      return MetricsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/mode', title: 'Mode', operation: '/admin-api/mode',
    render: ModePage.render },
  { path: '/admin/broadcast', title: 'Broadcast Announcement',
    operation: '/admin-api/broadcast', render: BroadcastPage.render },
  // SERVER CONFIGURATION → SIGN-IN APPEARANCE (#717): born static.
  { path: '/admin/sign-in-appearance', title: 'Sign-in appearance',
    operation: '/admin-api/branding', render: SignInAppearancePage.render },
  { path: '/admin/node-health', title: 'Node health',
    operation: '/admin-api/node-health', render: NodeHealthPage.render },
  { path: '/admin/oauth2/monitor', title: 'OAuth 2.0 / OIDC activity',
    operation: '/admin-api/oauth2/monitor',
    render: OAuth2MonitorPage.render },
  // MONITORING → PASSKEYS (#942): born static, its lists paged by the
  // query's `list`, `page` and `from`, which the operation reads as they are.
  { path: '/admin/passkey-report', title: 'Passkeys',
    operation: '/admin-api/passkey-report',
    render: PasskeyReportPage.render },
  // `rows=shown`: the page's own call reads the certificates of the rows
  // it draws and no others (#352).
  // DIRECTORY → POST-LOGIN ACTIVITIES (#1111, #1123): born static; the
  // controls of a started post-login activity, whose per-person progress is
  // a /report source.
  { path: '/admin/post-login-activities', title: 'Post-login activities',
    operation: '/admin-api/post-login-activities',
    render: PostLoginActivitiesPage.render },
  // #1955 P1: Directory → Hardware tokens, the physical keys and cards the
  // realm recorded from attestation, and the lost-key act.
  { path: '/admin/hardware-tokens', title: 'Hardware tokens',
    operation: '/admin-api/hardware-tokens',
    // #1955 P4: the OATH tab, always asked, under names of its own so its
    // filter and pager move its list and not the register's.
    // #2071: the YubiKey OTP tab, the same way under `yq`, `ystatus` and
    // `ypage`.
    compose: { oath: '/admin-api/hardware-tokens/oath',
               yubiotp: '/admin-api/hardware-tokens/yubiotp' },
    composeWhen: { oath: ['oq', 'ostatus', 'opage', 'per'],
                   yubiotp: ['yq', 'ystatus', 'ypage', 'per'] },
    composeParams: { oath: { oq: 'q', ostatus: 'status', opage: 'page',
                             per: 'per' },
                     yubiotp: { yq: 'q', ystatus: 'status', ypage: 'page',
                                per: 'per' } },
    composeAlways: ['oath', 'yubiotp'],
    render: HardwareTokensPage.render },
  // #1955 P6: Directory → OpenPGP keys, one person's OpenPGP key, its Web
  // Key Directory publication and their mail encryption.
  { path: '/admin/openpgp', title: 'OpenPGP keys',
    operation: '/admin-api/openpgp', render: OpenPgpPage.render },
  // #2118: the Truststores, Use cases and System truststore tabs are
  // `GET /admin-api/truststores`, always asked; `systemq` filters the System
  // truststore tab and is the page's own, never asked of either operation.
  { path: '/admin/pki/trust', title: 'PKI trust',
    operation: '/admin-api/pki/trust',
    compose: { truststores: '/admin-api/truststores' },
    ownParams: ['systemq'],
    render: PkiTrustPage.render },
  // THE CERTIFICATE DIALOG (#446). `GET /admin-api/pki` does not carry one
  // certificate. View details adds `?certificate=` and the page composes
  // `GET /admin-api/certificates` into `certificateDetails`; `composeKeep`
  // draws a refusal too, so the dialog opens and says why. The link's
  // fragment is the section, so the Hierarchy tab stays the one shown.
  { path: '/admin/pki', title: 'PKI', operation: '/admin-api/pki',
    fixed: { rows: 'shown' },
    compose: { certificateDetails: '/admin-api/certificates' },
    composeWhen: { certificateDetails: ['certificate'] },
    composeKeep: ['certificateDetails'],
    render: PkiPage.render },
  { path: '/admin/policies', title: 'Policies',
    operation: '/admin-api/policies',
    // THE EXPORT AND IMPORT TAB'S READ (#1713): this realm's export signer
    // and the signers it trusts, from `GET /admin-api/policies/transfer`,
    // asked on every view of the page.
    compose: { transfer: '/admin-api/policies/transfer' },
    render: function (view: Json, ctx?: Json): string {
      return PoliciesPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/rbac', title: 'Admin roles', operation: '/admin-api/rbac',
    render: function (view: Json, ctx?: Json): string {
      return RbacPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/realms', title: 'Trust realms',
    operation: '/admin-api/realms',
    // The drill-down picks its row out of the list's answer: there is no
    // GET operation for one realm, and every row is that realm whole.
    drill: {
      param: 'realm',
      sample: function (list: Json): string | null {
        const rows = list.realms || [];
        return rows[0] ? rows[0].id : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return RealmsPage.detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return RealmsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/risc-accounts/account',
    title: 'RISC accounts — one account',
    operation: '/admin-api/risc/accounts', params: { id: 'account' },
    render: function (view: Json, ctx?: Json): string {
      return CaepRiscPage.riscAccountBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/risc-accounts', title: 'RISC accounts',
    operation: '/admin-api/risc/accounts',
    render: function (view: Json, ctx?: Json): string {
      return CaepRiscPage.riscAccountsBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/risk', title: 'Risk', operation: '/admin-api/risk',
    render: RiskPage.render },
  { path: '/admin/risk-scoring', title: 'Risk scoring',
    operation: '/admin-api/risk/metrics',
    // The page's translator with it (#539): drawn without one, the browser
    // would draw the metrics' keys.
    render: function (view: Json, ctx?: Json): string {
      return RiskPage.metricsHtml(view, ctx);
    } },
  // DIRECTORY → ROLES → NEW ROLE (#1132), reached from the list's Create
  // tab.
  { path: '/admin/roles/new', title: 'New role',
    operation: '/admin-api/roles/new',
    render: function (view: Json, ctx?: Json): string {
      return RolesPage.newRoleBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/roles', title: 'Roles',
    operation: '/admin-api/roles',
    compose: { preview: '/admin-api/roles/preview',
               // A DYNAMIC ROLE'S ELIGIBILITY, TESTED (#1072), on its page:
               // asked only by the test form, under names of its own so the
               // drill-down's `role` never sets it off.
               eligibility: '/admin-api/roles/eligibility' },
    composeWhen: { preview: ['application', 'subject', 'subjectKind', 'kind'],
                   eligibility: ['eligibilityRole', 'eligibilityUser',
                                 'eligibilityApplication'] },
    composeParams: { eligibility: { eligibilityRole: 'role',
                                    eligibilityUser: 'user',
                                    eligibilityApplication: 'application' } },
    // ONE ROLE'S PAGE (#604): the same operation, asked with `role`.
    drill: {
      param: 'role',
      sample: function (list: Json): string | null {
        return list.roles && list.roles[0] ? list.roles[0].name : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return RolesPage.detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return RolesPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/saml2', title: 'SAML', operation: '/admin-api/saml2',
    // The tabs are separate API answers, but have no standalone console routes.
    compose: {
      saml11: '/admin-api/saml11',
      saml11Detail: '/admin-api/saml11',
      assertions: '/admin-api/saml-assertions',
      attributes: '/admin-api/saml-attributes',
      // THE IdP-INITIATED SSO TAB (#749): always asked, and handed its own
      // page (`idpInitiatedPage`) and the shared `per`, so its pager moves
      // its list and not the SAML 2.0 tab's `page`.
      idpInitiated: '/admin-api/saml-idp-initiated'
    },
    composeWhen: { saml11Detail: ['rp'],
                   idpInitiated: ['idpInitiatedPage', 'per'] },
    composeAlways: ['idpInitiated'],
    drill: {
      param: 'sp',
      sample: function (list: Json): string | null {
        const rows = list.serviceProviders || [];
        return rows[0] ? rows[0].identifier : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return SamlPage.saml2Detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return SamlPage.saml2Body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/scep/monitor', title: 'SCEP enrollments',
    operation: '/admin-api/scep/monitor',
    render: function (view: Json, ctx?: Json): string {
      return ScepPage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/scheduler', title: 'Scheduler',
    operation: '/admin-api/scheduler', render: SchedulerPage.render },
  // THE SECRET PUSH DESTINATIONS (#221 P3): Directory, beside Attribute
  // sources. Its controls follow the render context's `write`.
  { path: '/admin/secret-destinations', title: 'Secret destinations',
    operation: '/admin-api/secret-destinations',
    render: SecretDestinationsPage.render },
  // DIRECTORY → SECRET DESTINATIONS → ADD A DESTINATION (#1132), reached
  // from the list's Add tab.
  { path: '/admin/secret-destinations/new', title: 'Add a secret destination',
    operation: '/admin-api/secret-destinations/new',
    render: function (view: Json, ctx?: Json): string {
      return SecretDestinationsPage.newBody(view, ctx || WebKit.context());
    } },
  { path: '/admin/oidfed', title: 'OpenID Federation',
    operation: '/admin-api/oidfed', render: OidfedPage.render },
  { path: '/admin/scim', title: 'SCIM',
    operation: '/admin-api/scim',
    render: function (view: Json, ctx?: Json): string {
      const context = ctx || WebKit.context();
      return ScimPage.body(context, view,
        WebPages.withEndpoints('', view, context.t));
    },
    // ONE OUTBOUND SCIM CLIENT'S PAGE (#552): `?client=` on the same
    // operation, which answers `scimClients.client`.
    drill: {
      param: 'client',
      sample: function (list: Json): string | null {
        const rows = (list.scimClients && list.scimClients.clients) || [];
        return rows[0] ? rows[0].identifier : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return ScimPage.clientDetail(ctx || WebKit.context(), view);
      }
    } },
  { path: '/admin/scim/monitor', title: 'SCIM activity',
    operation: '/admin-api/scim/monitor',
    render: function (view: Json, ctx?: Json): string {
      return ScimPage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/secrets', title: 'Secret store',
    operation: '/admin-api/secrets', render: SecretsPage.render },
  { path: '/admin/sessions', title: 'Sessions',
    operation: '/admin-api/sessions',
    render: function (view: Json, ctx?: Json): string {
      return SessionsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/signals', title: 'Signals',
    operation: '/admin-api/signals',
    render: function (view: Json, ctx?: Json): string {
      return SignalsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ssf', title: 'SSF',
    operation: '/admin-api/ssf',
    compose: {
      caep: '/admin-api/caep',
      risc: '/admin-api/risc'
    },
    composeAlways: ['caep', 'risc'],
    render: function (view: Json, ctx?: Json): string {
      const context = ctx || WebKit.context();
      if (!view.caep || !view.risc) {
        throw new Error('The SSF page is missing a vocabulary view.');
      }
      const panels = [
        { id: 'ssf-tab-metadata',
          label: context.t.text('consoleProtocolSettings.metadataHeading'),
          html: WebPages.withEndpoints('', view, context.t) },
        { id: 'ssf-tab-ssf', label: context.t.text('console.nav.ssf'),
          html: SsfPage.body(context, view, ['SSF']) },
        { id: 'ssf-tab-caep', label: context.t.text('console.nav.caep'),
          html: CaepRiscPage.caepBody(context, view.caep, ['CAEP']) },
        { id: 'ssf-tab-risc', label: context.t.text('console.nav.risc'),
          html: CaepRiscPage.riscBody(context, view.risc, ['RISC']) }
      ];
      const rendered = panels.map(function (one) {
        return { id: one.id, label: one.label,
          html: WebPages.ssfTabLinks(one.html) };
      });
      return WebKit.tabbedPanels('ssf-pages', rendered);
    } },
  { path: '/admin/ssf/dead-letters', title: 'Dead letters',
    operation: '/admin-api/ssf/dead-letters',
    render: function (view: Json, ctx?: Json): string {
      return SsfDeadLettersPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/ssf/transmitters', title: 'Signals from partners',
    operation: '/admin-api/ssf/transmitters',
    render: SsfTransmittersPage.render },
  { path: '/admin/tls-connection', title: 'TLS connection',
    operation: '/admin-api/tls-connection',
    render: TlsConnectionPage.render },
  { path: '/admin/tls/trust', title: 'Client-certificate truststore',
    operation: '/admin-api/tls/trust',
    render: function (view: Json, ctx?: Json): string {
      return TlsTrustPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/token-lifetimes', title: 'Token lifetimes',
    operation: '/admin-api/token-lifetimes',
    render: function (view: Json, ctx?: Json): string {
      return TokenLifetimesPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/tokens/credential', title: 'Tokens — one credential',
    operation: '/admin-api/tokens/credential',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.credential(ctx || WebKit.context(), view);
    },
    document: function (view: Json): string {
      return DelegationPage.document(view);
    } },
  { path: '/admin/tokens', title: 'Tokens',
    operation: '/admin-api/tokens',
    render: function (view: Json, ctx?: Json): string {
      return TokensPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/tokens/set', title: 'Tokens — one issuance',
    operation: '/admin-api/tokens/set',
    render: function (view: Json, ctx?: Json): string {
      return TokensPage.setBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/uma', title: 'UMA 2.0', operation: '/admin-api/uma',
    render: UmaPage.render },
  { path: '/admin/used-assertions', title: 'Used assertions',
    operation: '/admin-api/used-assertions',
    render: function (view: Json, ctx?: Json): string {
      return UsedAssertionsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/userinfo-claims', title: 'UserInfo claims',
    operation: '/admin-api/userinfo-claims',
    render: function (view: Json, ctx?: Json): string {
      return ClaimsPage.userinfoClaimsBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/users', title: 'Users', operation: '/admin-api/users',
    // A PERSON'S TOKENS AND KEYS (#2052): the central Directory pages'
    // operations, asked with the person, for the drill's Credentials
    // sub-tabs. Only when the query names a person, and each kept when it
    // refuses, so a refusal is a note on its sub-tab and not a page that
    // could not be drawn.
    compose: {
      personTokens: '/admin-api/hardware-tokens',
      personOath: '/admin-api/hardware-tokens/oath',
      // #2071: the YubiKey OTPs on the person's entry.
      personYubi: '/admin-api/hardware-tokens/yubiotp',
      personOpenpgp: '/admin-api/openpgp'
    },
    composeWhen: {
      personTokens: ['user'],
      personOath: ['user'],
      personYubi: ['user'],
      personOpenpgp: ['user']
    },
    composeParams: {
      personTokens: { user: 'q' },
      personOath: { user: 'q' },
      personYubi: { user: 'q' },
      personOpenpgp: { user: 'user' }
    },
    composeKeep: ['personTokens', 'personOath', 'personYubi',
                  'personOpenpgp'],
    drill: {
      param: 'user',
      sample: function (list: Json): string | null {
        const rows = list.users || [];
        return rows[0] ? rows[0].key : null;
      },
      // `known: false` is the third answer, a name nothing here knows.
      render: function (view: Json, ctx?: Json): string {
        return view.known === false
          ? UsersPage.unknown(ctx || WebKit.context(), view)
          : UsersPage.detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return UsersPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/users/new', title: 'New user',
    operation: '/admin-api/users/new',
    render: function (view: Json, ctx?: Json): string {
      return UsersPage.newUserBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/vc', title: 'Verifiable Credentials',
    operation: '/admin-api/credential-claims',
    compose: {
      oid4vciSettings: '/admin-api/oid4vci-settings',
      oid4vpSettings: '/admin-api/oid4vp-settings',
      verifierRequest: '/admin-api/verifier-request'
    },
    render: function (view: Json, ctx?: Json): string {
      return VcClaimsPage.body(ctx || WebKit.context(), view);
    } },
  // MONITORING → VERIFIABLE CREDENTIALS (#752): the status lists and every
  // issued credential's status, which was the Credential status tab of the
  // page above (`web_vc_status.ts` says why it moved).
  { path: '/admin/vc/monitor', title: 'Verifiable Credentials (monitoring)',
    operation: '/admin-api/vc-status',
    render: function (view: Json, ctx?: Json): string {
      return VcStatusPage.render(view, ctx || WebKit.context());
    } },
  { path: '/admin/kerberos', title: 'Kerberos',
    operation: '/admin-api/kerberos',
    compose: {
      kerberosClaims: '/admin-api/kerberos/claims',
      kerberosPrincipals: '/admin-api/kerberos/principals',
      kerberosTrusts: '/admin-api/kerberos/trusts'
    },
    composeWhen: {
      kerberosClaims: ['user'],
      kerberosPrincipals: ['per', 'peoplePage', 'servicesPage'],
      kerberosTrusts: ['per', 'trustsPage', 'trust']
    },
    composeAlways: ['kerberosClaims', 'kerberosPrincipals',
                    'kerberosTrusts'],
    render: function (view: Json, ctx?: Json): string {
      return ProtocolSettingsPage.render(view, ctx || WebKit.context());
    } },
  // ONE REMOTE PEP (#1760), reached from a row of the Remote PEPs tab: the
  // same operation asked with `pep`, as `/admin/applications` is with
  // `application`.
  { path: '/admin/xacml/pep', title: 'Remote PEP',
    operation: '/admin-api/xacml/peps',
    upTo: { path: '/admin/xacml' },
    upVia: function (query: Json, t: Json): Array<{ label: string;
                                                     href: string }> {
      return [XacmlPage.pepsTabCrumb(t)];
    },
    drill: {
      param: 'pep',
      sample: function (list: Json): string | null {
        const rows = list.peps || [];
        return rows[0] ? rows[0].name : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return XacmlPage.pepDetail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.pepsBody(ctx || WebKit.context(), view);
    } },
  // MONITORING → REMOTE PEPS. The same answer as the Protocols page, read
  // for traffic: listener stats, thread pools, per-path requests and
  // memory. `pep` drills to one PEP. Not a Protocols page, so it has no
  // protocol-endpoints row.
  { path: '/admin/xacml/pep/monitor', title: 'Remote PEPs',
    operation: '/admin-api/xacml/peps',
    drill: {
      param: 'pep',
      sample: function (list: Json): string | null {
        const rows = list.peps || [];
        return rows[0] ? rows[0].name : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return XacmlPage.pepMonitorDetail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.pepMonitorIndex(ctx || WebKit.context(), view);
    } },
  // ONE ROUTE OF A REMOTE PEP'S REVERSE PROXY (#1760), reached from a route
  // id on the PEP's Reverse proxy tab: the same operation asked with `pep`
  // and `route`. Without `route` it lists every PEP's routes as links.
  { path: '/admin/xacml/pep/route', title: 'Remote PEP route',
    operation: '/admin-api/xacml/peps',
    upTo: { path: '/admin/xacml' },
    upVia: function (query: Json, t: Json): Array<{ label: string;
                                                     href: string }> {
      const pep = String((query && query.pep) || '');
      return [XacmlPage.pepsTabCrumb(t)].concat(pep
        ? [{ label: pep, href: XacmlPage.pepHref(pep) },
           { label: t.text('consoleXacml.pepPage.tab.proxy'),
             href: XacmlPage.proxyHref(pep) },
           // THE SUB-TAB TOO (rcbj, 2026-11-15): the trail names every
           // level the reader went down, Configured Routes the last link.
           { label: t.text('consoleXacml.proxy.tab.routes'),
             href: XacmlPage.proxyTabHref(pep) }]
        : []);
    },
    drill: {
      param: 'route',
      sample: function (list: Json): string | null {
        const held = (list.peps || []).filter(function (one: Json) {
          return one.proxy && one.proxy.routes && one.proxy.routes.length;
        })[0];
        return held ? held.proxy.routes[0].id : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return XacmlPage.routeDetail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.routeIndex(ctx || WebKit.context(), view);
    } },
  // ONE LISTENER OF A REMOTE PEP (rcbj, 2026-11-15), reached from a
  // listener id on the PEP's Configured Listeners: the PEP's own answer,
  // the listener one row of its `listenerRows`, so `listener` is the
  // page's own name and never asked of the operation (`ownParams`, rule 7:
  // the operation is unchanged). Without `listener` it lists every PEP's
  // listeners as links.
  { path: '/admin/xacml/pep/listener', title: 'Remote PEP listener',
    operation: '/admin-api/xacml/peps',
    ownParams: ['listener'],
    upTo: { path: '/admin/xacml' },
    upVia: function (query: Json, t: Json): Array<{ label: string;
                                                     href: string }> {
      const pep = String((query && query.pep) || '');
      return [XacmlPage.pepsTabCrumb(t)].concat(pep
        ? [{ label: pep, href: XacmlPage.pepHref(pep) },
           { label: t.text('consoleXacml.pepPage.tab.listener'),
             href: XacmlPage.listenerTabHref(pep) },
           { label: t.text('consoleXacml.listeners.tab.configured'),
             href: XacmlPage.listenersHref(pep) }]
        : []);
    },
    drill: {
      param: 'listener',
      sample: function (list: Json): string | null {
        const held = (list.peps || []).filter(function (one: Json) {
          return (one.listenerRows || []).length;
        })[0];
        return held ? held.listenerRows[0].id : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return XacmlPage.listenerDetail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.listenerIndex(ctx || WebKit.context(), view);
    } },
  // ONE REMOTE PEP CLUSTER (#1760), reached from a row of the PEP clusters
  // tab: `/admin-api/xacml/pep-clusters` asked with `cluster`.
  { path: '/admin/xacml/pep-cluster', title: 'Remote PEP cluster',
    operation: '/admin-api/xacml/pep-clusters',
    upTo: { path: '/admin/xacml' },
    upVia: function (query: Json, t: Json): Array<{ label: string;
                                                     href: string }> {
      return [XacmlPage.clustersTabCrumb(t)];
    },
    drill: {
      param: 'cluster',
      sample: function (list: Json): string | null {
        const rows = list.clusters || [];
        return rows[0] ? rows[0].name : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return XacmlPage.clusterDetail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.clustersBody(ctx || WebKit.context(), view);
    } },
  // ONE ROUTE OF A CLUSTER'S REVERSE PROXY (#1760): the PEP route page's
  // arrangement, its trail XACML › PEP clusters › the cluster › Reverse
  // proxy › Configured Routes.
  { path: '/admin/xacml/pep-cluster/route', title: 'Remote PEP cluster route',
    operation: '/admin-api/xacml/pep-clusters',
    upTo: { path: '/admin/xacml' },
    upVia: function (query: Json, t: Json): Array<{ label: string;
                                                     href: string }> {
      const cluster = String((query && query.cluster) || '');
      return [XacmlPage.clustersTabCrumb(t)].concat(cluster
        ? [{ label: cluster, href: XacmlPage.clusterHref(cluster) },
           { label: t.text('consoleXacml.pepPage.tab.proxy'),
             href: XacmlPage.clusterHref(cluster) + '#' +
                   XacmlPage.PROXY_TAB },
           { label: t.text('consoleXacml.proxy.tab.routes'),
             href: XacmlPage.clusterHref(cluster) + '#' +
                   XacmlPage.PROXY_ROUTES_TAB }]
        : []);
    },
    drill: {
      param: 'route',
      sample: function (list: Json): string | null {
        const held = (list.clusters || []).filter(function (one: Json) {
          return one.proxy && one.proxy.routes && one.proxy.routes.length;
        })[0];
        return held ? held.proxy.routes[0].id : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return XacmlPage.clusterRouteDetail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.clusterRouteIndex(ctx || WebKit.context(), view);
    } },
  { path: '/admin/xacml', title: 'XACML', operation: '/admin-api/xacml',
    compose: {
      xacmlPolicies: '/admin-api/xacml/policies',
      xacmlEditor: '/admin-api/xacml/editor',
      xacmlPeps: '/admin-api/xacml/peps',
      xacmlPepClusters: '/admin-api/xacml/pep-clusters',
      xacmlDecide: '/admin-api/xacml/decide',
      xacmlAuthzen: '/admin-api/xacml/authzen'
    },
    composeWhen: {
      xacmlEditor: ['policy'],
      xacmlDecide: ['subject', 'action', 'resource'],
      xacmlAuthzen: ['caller']
    },
    composeAlways: [
      'xacmlPolicies', 'xacmlEditor', 'xacmlPeps', 'xacmlDecide',
      'xacmlAuthzen', 'xacmlPepClusters'
    ],
    render: XacmlPage.render },
  { path: '/admin/xacml/monitor', title: 'XACML decisions',
    operation: '/admin-api/xacml/monitor',
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.monitorBody(ctx || WebKit.context(), view);
    } },
  // The generated settings pages (#446), a status block drawn by
  // `web_protocol_settings.ts` where the page has one.
  { path: '/admin/backup-codes', title: 'Recovery codes',
    operation: '/admin-api/backup-codes',
    render: ProtocolSettingsPage.render },
  { path: '/admin/persistence', title: 'Persistence',
    operation: '/admin-api/persistence',
    render: ProtocolSettingsPage.render },
  // THE CLUSTER PAGE WAS NEVER CONVERTED (#446), so Platform → Cluster
  // answered "not a console page" and its settings were drawn nowhere;
  // `tests/setting_homes_drawn.js` found it (#2049). Its settings and
  // prose are drawn here, and since #2070 its status block (members,
  // leases, other cells) too, by `web_cluster_status.ts`.
  { path: '/admin/cluster', title: 'Cluster',
    operation: '/admin-api/cluster',
    render: ProtocolSettingsPage.render },
  { path: '/admin/totp', title: 'TOTP MFA',
    operation: '/admin-api/totp',
    render: ProtocolSettingsPage.render },
  { path: '/admin/webauthn', title: 'WebAuthn',
    operation: '/admin-api/webauthn',
    render: ProtocolSettingsPage.render },
  { path: '/admin/hardware-tokens-settings', title: 'Hardware tokens',
    operation: '/admin-api/hardware-tokens-settings',
    render: ProtocolSettingsPage.render },
  { path: '/admin/piv', title: 'PIV',
    operation: '/admin-api/piv',
    render: ProtocolSettingsPage.render },
  { path: '/admin/yubiotp', title: 'YubiKey OTP',
    operation: '/admin-api/yubiotp',
    render: ProtocolSettingsPage.render },
  { path: '/admin/oath-tokens', title: 'OATH tokens',
    operation: '/admin-api/oath-tokens',
    render: ProtocolSettingsPage.render },
  { path: '/admin/ssh-user-ca', title: 'SSH user certificates',
    operation: '/admin-api/ssh-user-ca',
    render: ProtocolSettingsPage.render },
  { path: '/admin/openpgp-settings', title: 'OpenPGP',
    operation: '/admin-api/openpgp-settings',
    render: ProtocolSettingsPage.render },
  { path: '/admin/oauth2', title: 'OAuth 2.0 / OIDC settings',
    operation: '/admin-api/oauth2',
    compose: {
      authorizationServers: '/admin-api/authorization-servers',
      tokenLifetimes: '/admin-api/token-lifetimes',
      claims: '/admin-api/claims',
      userinfoClaims: '/admin-api/userinfo-claims'
    },
    render: ProtocolSettingsPage.render },
  { path: '/admin/ldap', title: 'LDAP / LDAPS',
    operation: '/admin-api/ldap', render: ProtocolSettingsPage.render },
  { path: '/admin/wstrust', title: 'WS-Trust',
    operation: '/admin-api/wstrust', render: ProtocolSettingsPage.render },
  { path: '/admin/wsfed', title: 'WS-Federation',
    operation: '/admin-api/wsfed', render: ProtocolSettingsPage.render },
  { path: '/admin/tls', title: 'TLS / mutual TLS',
    operation: '/admin-api/tls', render: ProtocolSettingsPage.render },
  { path: '/admin/worker-pools', title: 'Worker pools',
    operation: '/admin-api/worker-pools', render: WorkerPoolsPage.render }
];

/**
 * The static console's pages: which console paths are drawn in the browser,
 * from which operation, by which renderer. The entry of the browser bundle.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WebPages {
  /**
   * Every converted page.
   */
  static readonly PAGES = PAGES;

  /**
   * The Protocols pages drawn as tabs by `protocolTabs()`, and their tabs.
   */
  static readonly PROTOCOL_TABS = PROTOCOL_TABS;

  /**
   * Every tab id `protocolTabs()` can draw, for the stylesheet.
   */
  static readonly PROTOCOL_TAB_IDS = protocolTabIds();

  /**
   * The rendering kit, for the runtime that draws the shell around a page.
   */
  static readonly kit = WebKit;

  /**
   * The Settings block every page that owns settings draws, from the
   * `settings` member of that page's operation.
   */
  static readonly settings = SettingsForms;
  // The message formatter and translator (#539), so a caller that loads the
  // bundle without the runtime — `tests/console_web_bundle.js` — can give
  // it the default translator the runtime gives it in a browser.
  static readonly messages = WebMessages;

  /**
   * What a form's answer draws where a notice is not enough
   * (`web_answers.ts`): in the bundle so a protocol job can draw a secret
   * shown once as the console does.
   */
  static readonly answers = WebAnswers;

  /**
   * Every address whose content moved to another page, and that page.
   */
  static readonly MOVED = MOVED;

  /**
   * Says where an address whose content moved is now: its tab first, then
   * its path.
   *
   * @param path - the realm-relative console path
   * @param hash - the address's fragment, with its `#`, or ''
   * @returns the page's path, or null when nothing moved from there
   */
  static movedTo(path: string, hash?: string): string | null {
    const wanted = String(path || '');
    const tab = hash ? wanted + String(hash) : '';
    if (tab && Object.prototype.hasOwnProperty.call(MOVED, tab)) {
      return MOVED[tab];
    }
    return Object.prototype.hasOwnProperty.call(MOVED, wanted)
      ? MOVED[wanted] : null;
  }

  /**
   * Draws a page's picture as a standalone SVG document from its answer,
   * for the page's `?format=svg` link.
   *
   * @param path - the realm-relative console path
   * @param view - the page's answer
   * @returns the document, or null when the page draws none here
   */
  static documentOf(path: string, view: Json): string | null {
    const page = WebPages.pageFor(path);
    if (!page || typeof page.document !== 'function' || !view) {
      return null;
    }
    return page.document(view);
  }

  /**
   * Finds the converted page at a console path.
   *
   * @param path - the realm-relative console path, such as `/admin/mode`
   * @returns the page's row, or null when the page is not converted
   */
  static pageFor(path: string): WebPage | null {
    const wanted = String(path || '');
    for (let i = 0; i < PAGES.length; i++) {
      if (PAGES[i].path === wanted) {
        return PAGES[i];
      }
    }
    return null;
  }

  /**
   * Draws a converted page's body from its operation's answer — its
   * drill-down's, when the query names the item the drill-down is of.
   *
   * @param path - the console path
   * @param view - the operation's answer
   * @param ctx - optional; the render context (`WebKit.context()`): the
   *   page's query and whether the reader may write. A reader with no query
   *   who may not write when left out.
   * @returns the body as HTML, or null when the page is not converted
   */
  // THE ASSERTION GROUPS' ROWS THE ASSERTION FORM DOES NOT CARRY (#2049).
  // The form draws `SAML_ASSERTION_SETTINGS` (`admin-core/admin_actions.ts`),
  // a fixed list that is also the narrow door's; `saml2.publishAlgorithmSupport`
  // and `saml11.doNotCacheCondition` joined the two groups after it and were
  // drawn nowhere until `tests/setting_homes_drawn.js` found them. Each is
  // drawn here from the page's own settings block, as every other group is,
  // and saved through `set-many`.
  /**
   * Draws, under the assertion form, the rows of the two SAML assertion
   * groups that form does not carry.
   *
   * @param view - the SAML page's answer (`settings`, `assertions`)
   * @param context - the render context
   * @returns the HTML, empty when the form carries every row
   */
  static samlAssertionLeftovers(view: Json, context: Json): string {
    const drawn = ((view.assertions && view.assertions.settings) || [])
      .map(function (setting: Json): string { return setting.key; });
    const block = view.settings || { groups: [] };
    return (block.groups || []).filter(function (group: Json): boolean {
      return group.group === 'SAML 2.0 assertions' ||
             group.group === 'SAML 1.1 assertions';
    }).map(function (group: Json): Json {
      return Object.assign({}, group, {
        settings: (group.settings || []).filter(function (setting: Json) {
          return drawn.indexOf(setting.key) < 0;
        })
      });
    }).filter(function (group: Json): boolean {
      return group.settings.length > 0;
    }).map(function (group: Json): string {
      return WebKit.frame(SettingsForms.section(group, '/admin/saml2',
                                                block.context, context.t));
    }).join('');
  }

  /**
   * Translates a page's query into its operation's, by the row's `params`.
   *
   * @param path - the console path
   * @param query - the page's query
   * @param declared - the names the operation declares (#1476), when known;
   *   a name of the page's own, which it would refuse, is left out
   * @returns the query the page's operation is asked with
   */
  static operationQuery(path: string, query: Json,
                        declared?: string[]): Json {
    const page = WebPages.pageFor(path);
    const out: Json = {};
    const own = (page && page.ownParams) || [];
    Object.keys(query || {}).forEach(function (name) {
      if (own.indexOf(name) >= 0) {
        return;
      }
      const mapped = page && page.params && page.params[name];
      const asked = mapped || name;
      if (!declared || declared.indexOf(asked) >= 0) {
        out[asked] = query[name];
      }
    });
    // What the page always asks its operation, whatever its own query.
    Object.keys((page && page.fixed) || {}).forEach(function (name) {
      out[name] = page.fixed[name];
    });
    return out;
  }

  /**
   * What a page's composed members are asked: each member its query sets
   * off, with the parameters its `composeWhen` names, under the names its
   * `composeParams` gives. The runtime and the jobs that draw a page as the
   * console does all ask this, so there is one reading of the row.
   *
   * @param page - the page's row
   * @param query - the page's query
   * @returns `{ member, operation, params }` per member asked
   */
  static composeRequests(page: WebPage, query: Json):
      Array<{ member: string; operation: string;
              params: Record<string, string> }> {
    const asked = query || {};
    const has = function (name: string): boolean {
      return Object.prototype.hasOwnProperty.call(asked, name);
    };
    return Object.keys((page && page.compose) || {}).filter(
      function (member) {
        const when = (page.composeWhen || {})[member];
        return !when || (page.composeAlways || []).indexOf(member) >= 0 ||
          when.some(has);
      }).map(function (member) {
      const names = (page.composeParams || {})[member] || {};
      const params: Record<string, string> = {};
      ((page.composeWhen || {})[member] || []).forEach(function (name) {
        if (has(name)) {
          params[names[name] || name] = asked[name];
        }
      });
      return { member: member, operation: page.compose[member],
               params: params };
    });
  }

  /**
   * Whether a composed member's answer is drawn. A 200 whose body is an
   * object is. A member named in `composeKeep` is too when that body is an
   * object and not an array, because the page draws the refusal. Anything
   * else, including no body, is a failure of the page. `answer` is the
   * runtime's `{ status, json }` or a draw helper's `{ status, body }`.
   *
   * @param page - the page's row
   * @param member - the composed member
   * @param answer - `{ status, json }` or `{ status, body }`, or null
   * @returns whether the page draws this answer
   */
  static composeKept(page: WebPage, member: string, answer: Json): boolean {
    let body = null;
    if (answer && answer.json !== undefined && answer.json !== null) {
      body = answer.json;
    } else if (answer && answer.body !== undefined &&
               answer.body !== null) {
      body = answer.body;
    }
    // A 200 of any object, an array included, is what the draw helpers
    // already accepted. A refusal kept for the dialog is an object.
    if (!answer || body === null || typeof body !== 'object') {
      return false;
    }
    if (answer.status === 200) {
      return true;
    }
    if (Array.isArray(body)) {
      return false;
    }
    const keep = (page && page.composeKeep) || [];
    return keep.indexOf(member) >= 0;
  }

  /**
   * Draws Protocols → Cert issuance: Metadata, a tab each for ACME, EST and
   * SCEP, and one for SPIFFE whose four former pages are sub-tabs — or, with
   * `entry` or `agent` in the query, that one registration entry or agent.
   *
   * @param view - the SPIFFE trust domain's answer, the other six tabs'
   *   composed in
   * @param context - the render context
   * @returns the page as HTML
   */
  static certIssuance(view: Json, context: Json): string {
    const missing = Object.keys(CERT_COMPOSITION.compose).filter(
      function (member) {
        return !view[member];
      });
    if (missing.length) {
      throw new Error('The Cert issuance page is missing a tab view: ' +
                      missing.join(', ') + '.');
    }
    const t = context.t;
    const query = context.query || {};
    const draw = function (key: string, html: string): string {
      return WebPages.certTabLinks(html, key);
    };
    const ctxOf = function (key: string): Json {
      return WebPages.certContext(context, key);
    };
    if (query.entry) {
      return draw('spiffeEntries', SpiffePage.entry(ctxOf('spiffeEntries'),
                                                    view.spiffeEntries));
    }
    if (query.agent) {
      return draw('spiffeAgents', SpiffePage.agent(ctxOf('spiffeAgents'),
                                                   view.spiffeAgents));
    }
    // Every tab's endpoints, once each, on Metadata alone: the seven
    // operations mirror this one page, so each answers the whole list.
    // They are drawn by protocol (`certMetadata()`).
    const endpoints: Json[] = [];
    const seen: Json = {};
    [view].concat(Object.keys(CERT_COMPOSITION.compose).map(
      function (member) {
        return view[member];
      })).forEach(function (answer: Json) {
      (Array.isArray(answer.protocolEndpoints)
        ? answer.protocolEndpoints : []).forEach(function (row: Json) {
        const key = String(row.name) + '\n' + String(row.url);
        if (!seen[key]) {
          seen[key] = true;
          endpoints.push(row);
        }
      });
    });
    const spiffe = WebKit.subTabbedPanels(t.text('console.nav.spiffe'), [
      { id: CERT_PANELS.spiffe.tab,
        label: t.text('console.nav.spiffe-trust-domain'),
        html: draw('spiffe', SpiffePage.overview(ctxOf('spiffe'), view)) },
      { id: CERT_PANELS.spiffeEntries.tab,
        label: t.text('console.nav.spiffe-entries'),
        html: draw('spiffeEntries', SpiffePage.entries(
          ctxOf('spiffeEntries'), view.spiffeEntries)) },
      { id: CERT_PANELS.spiffeAgents.tab,
        label: t.text('console.nav.spiffe-agents'),
        html: draw('spiffeAgents', SpiffePage.agents(ctxOf('spiffeAgents'),
                                                     view.spiffeAgents)) },
      { id: CERT_PANELS.spiffeBrokers.tab,
        label: t.text('console.nav.spiffe-brokers'),
        html: draw('spiffeBrokers', SpiffePage.brokers(
          ctxOf('spiffeBrokers'), view.spiffeBrokers)) }
    ]);
    return WebKit.tabbedPanels('cert-pages', [
      { id: 'cert-tab-metadata',
        label: t.text('consoleProtocolSettings.metadataHeading'),
        html: WebPages.certMetadata(view, endpoints, t) },
      { id: CERT_PANELS.acme.tab, label: t.text('console.nav.acme'),
        html: draw('acme', AcmePage.render(view.acme, ctxOf('acme'))) },
      { id: CERT_PANELS.est.tab, label: t.text('console.nav.est'),
        html: draw('est', EstPage.render(view.est, ctxOf('est'))) },
      { id: CERT_PANELS.scep.tab, label: t.text('console.nav.scep'),
        html: draw('scep', ScepPage.render(view.scep, ctxOf('scep'))) },
      { id: 'cert-tab-spiffe', label: t.text('console.nav.spiffe'),
        html: spiffe }
    ]);
  }

  // THE SPLITTER (2026-10-12). It cuts only at a heading at the TOP LEVEL
  // of the page — outside every form, table, list and block — so no panel
  // can hold half an element. An `<h2>` starts a section; an `<h3>` starts
  // one only where no `<h2>` section is open (PKI, Provider Commands and
  // Claims Providers head their sections with `<h3>`; elsewhere an `<h3>`
  // is a heading inside its `<h2>`'s section), or where it is marked as a
  // tab (Roles' sections are `<h3>`s under one `<h2>`). A section is a tab when its
  // heading carries `data-tab`, which the tab's label then replaces; two
  // sections naming one tab are one tab. A block marked `data-metadata`
  // (a page's closing links) returns to Metadata. The rest, in page order,
  // is Metadata.
  /**
   * Draws a Protocols page as tabs, Metadata first.
   *
   * @param path - the page's path, a key of `PROTOCOL_TABS`
   * @param html - the page as drawn, its endpoints added
   * @param t - the page's translator
   * @returns the page as tabs
   */
  static protocolTabs(path: string, html: string, t: Json): string {
    const slug = protocolSlug(path);
    const blocks = ['div', 'form', 'table', 'details', 'section', 'ul', 'ol',
                    'fieldset', 'nav', 'dl', 'p', 'aside'];
    // A block marked `data-outside-tabs` — the certificate details dialog —
    // is drawn after the tabs, not inside whichever one it followed.
    const outside: string[] = [];
    let text = String(html || '');
    let cut = /<([a-zA-Z0-9]+)\b[^>]*\bdata-outside-tabs\b[^>]*>/.exec(text);
    while (cut) {
      const inner = /<(\/?)([a-zA-Z0-9]+)\b[^>]*?(\/?)>/g;
      inner.lastIndex = cut.index;
      let level = 0;
      let end = text.length;
      let one = inner.exec(text);
      while (one) {
        if (blocks.indexOf(one[2].toLowerCase()) >= 0 && !one[3]) {
          level += one[1] ? -1 : 1;
          if (level === 0) {
            end = one.index + one[0].length;
            break;
          }
        }
        one = inner.exec(text);
      }
      outside.push(text.slice(cut.index, end));
      text = text.slice(0, cut.index) + text.slice(end);
      cut = /<([a-zA-Z0-9]+)\b[^>]*\bdata-outside-tabs\b[^>]*>/.exec(text);
    }
    const tag = /<(\/?)([a-zA-Z0-9]+)\b[^>]*?(\/?)>/g;
    const sections: Json[] = [{ level: 0, tab: null, at: 0, start: 0 }];
    let depth = 0;
    let m = tag.exec(text);
    while (m) {
      const name = m[2].toLowerCase();
      if (blocks.indexOf(name) >= 0) {
        // A block marked `data-metadata` — a page's closing links — goes
        // back to Metadata from whatever tab it follows.
        if (!m[1] && depth === 0 && /\bdata-metadata\b/.test(m[0])) {
          sections.push({ level: 0, tab: null, at: m.index,
                          start: m.index });
        }
        depth += m[1] ? -1 : (m[3] ? 0 : 1);
      } else if (!m[1] && depth === 0 && (name === 'h2' || name === 'h3') &&
                 (name === 'h2' || /\bdata-tab="/.test(m[0]) ||
                  sections[sections.length - 1].level !== 2)) {
        const close = text.indexOf('</' + name + '>', m.index);
        const end = close < 0 ? m.index + m[0].length
                              : close + name.length + 3;
        const marked = /\bdata-tab="([^"]+)"/.exec(m[0]);
        const id = /\bid="([^"]+)"/.exec(m[0]);
        sections.push({ level: name === 'h2' ? 2 : 3,
                        tab: marked ? marked[1] : null, at: m.index,
                        start: end, id: id ? id[1] : '',
                        label: WebPages.textOf(
                          text.slice(m.index + m[0].length,
                                     close < 0 ? end : close)) });
      }
      m = tag.exec(text);
    }
    // A page that draws no marked section this time — the mail page's one
    // template, a list with no rows to act on — is drawn as it was: a bar
    // holding one Metadata tab says nothing.
    if (!sections.some(function (one: Json) { return !!one.tab; })) {
      return String(html || '');
    }
    let metadata = '';
    const tabs: Json = {};
    const order: string[] = [];
    sections.forEach(function (one: Json, n: number) {
      const stop = n + 1 < sections.length ? sections[n + 1].at : text.length;
      if (!one.tab) {
        metadata += text.slice(one.at, stop);
        return;
      }
      if (!tabs[one.tab]) {
        tabs[one.tab] = { label: one.label, html: '' };
        order.push(one.tab);
      }
      // The heading goes, its label being the tab's; an id it carried
      // stays, since a form's answer may return to it.
      tabs[one.tab].html += (one.id
        ? '<span id="' + WebKit.esc(one.id) + '"></span>' : '') +
        text.slice(one.start, stop);
    });
    return WebKit.tabbedPanels(slug + '-pages', [
      { id: slug + '-tab-metadata',
        label: t.text('consoleProtocolSettings.metadataHeading'),
        html: metadata }
    ].concat(order.map(function (name) {
      return { id: slug + '-tab-' + name, label: tabs[name].label,
               html: tabs[name].html };
    }))) + outside.join('');
  }

  // A heading's text, for a tab's label (which `tabbedPanels()` escapes):
  // its markup taken off and the entities the renderers write put back.
  /**
   * The text of a fragment of markup.
   *
   * @param html - the fragment
   * @returns its text
   */
  static textOf(html: string): string {
    const named: Json = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
                          nbsp: ' ', mdash: '—', ndash: '–', rsaquo: '›',
                          lsaquo: '‹', hellip: '…', middot: '·' };
    return webMessages.WebMessages.stripTags(String(html || ''))
      .replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi,
        function (whole: string, code: string): string {
          if (code.charAt(0) === '#') {
            const n = code.charAt(1).toLowerCase() === 'x'
              ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
            return isFinite(n) ? String.fromCodePoint(n) : whole;
          }
          return Object.prototype.hasOwnProperty.call(named,
            code.toLowerCase()) ? named[code.toLowerCase()] : whole;
        }).replace(/\s+/g, ' ').trim();
  }

  // METADATA, ONE SECTION PER PROTOCOL (rcbj, 2026-10-12): forty-odd rows
  // in one table did not say which protocol a row was, so each family's
  // HTTP endpoints are a table of their own under its name — chosen by
  // the route's prefix (`CERT_PANELS`' `routes`) — with what its tab used to
  // say about them: EST's label form, what SCEP answers, and SPIFFE's gRPC
  // listeners, which are the sockets the endpoint list would otherwise name
  // with less. The four tabs list no endpoint.
  /**
   * Draws Cert issuance's Metadata tab: each protocol's endpoints under its
   * name.
   *
   * @param view - the page's composed view
   * @param endpoints - every row of the page's endpoint list, once each
   * @param t - the page's translator
   * @returns the tab as HTML
   */
  static certMetadata(view: Json, endpoints: Json[], t: Json): string {
    const families = ['acme', 'est', 'scep', 'spiffe'];
    const familyOf = function (row: Json): string | null {
      const route = String(row.route || '');
      return families.filter(function (key) {
        const prefix = CERT_PANELS[key].routes;
        return route === prefix || route.indexOf(prefix + '/') === 0;
      })[0] || null;
    };
    const extras: Json = {
      acme: '',
      est: EstPage.labelFormNote(view.est, t),
      scep: ScepPage.sectionCapabilities(view.scep, t),
      // A frame inside SPIFFE's (`secframe`, rcbj 2026-11-16).
      spiffe: WebKit.frame(SpiffePage.listenersSection(t, view))
    };
    const sections = families.map(function (key) {
      const rows = endpoints.filter(function (row) {
        return familyOf(row) === key;
      });
      // The heading is the tab's own label; the key is built in a variable
      // for `titleOf()`'s reason.
      // FRAMED AS KEY PAIRS IS (`secframe`, rcbj 2026-11-16): each
      // protocol's section, its heading inside.
      const label = 'console.nav.' + key;
      return WebKit.frame('<h2 id="cert-metadata-' + key + '">' +
        WebKit.esc(t.text(label)) + '</h2>' +
        WebPages.endpointTable(rows, t) + extras[key]);
    });
    // A row no family's prefix claims is still listed, under the section
    // every Protocols page has.
    const other = endpoints.filter(function (row) {
      return row.route && !familyOf(row);
    });
    return sections.join('') + (other.length
      ? WebPages.withEndpoints('', { protocolEndpoints: other }, t) : '');
  }

  /**
   * One tab's render context: the page's query with the tab's own names
   * given back as its renderer reads them, the other tabs' left as they are.
   *
   * @param context - the page's render context
   * @param key - the tab's key in `CERT_PANELS`
   * @returns the tab's render context
   */
  static certContext(context: Json, key: string): Json {
    const query = Object.assign({}, context.query || {});
    CERT_PANELS[key].names.forEach(function (name: string) {
      const own = certName(key, name);
      delete query[name];
      if (Object.prototype.hasOwnProperty.call(query, own)) {
        query[name] = query[own];
      }
      delete query[own];
    });
    return Object.assign({}, context, { query: query });
  }

  /**
   * Keeps one Cert issuance tab's links on the page: a link to one of the
   * four families' former pages opens its tab, with the tab's own names
   * given the page's; a link to a former page's document is to its
   * operation's; and a filter form's action, names and ids are the tab's,
   * so two tabs' forms are not one control. A POST form is left to post
   * where it did — the operation that mirrors it is unchanged.
   *
   * @param html - one tab's rendered HTML
   * @param key - the tab's key in `CERT_PANELS`
   * @returns the HTML with the page's links
   */
  static certTabLinks(html: string, key: string): string {
    const panel = CERT_PANELS[key];
    const own = function (name: string): string {
      return panel.names.indexOf(name) >= 0 ? certName(key, name) : name;
    };
    const keyOf = function (path: string): string {
      return Object.keys(CERT_PANELS).filter(function (one) {
        return CERT_PANELS[one].path === path;
      })[0];
    };
    // A query as drawn — escaped, so `&amp;` — with this tab's names renamed
    // and every value as it was.
    const renamed = function (search: string, target: string): string {
      if (!search) {
        return '';
      }
      return '?' + search.slice(1).split(/(&amp;|&)/).map(function (part,
                                                                    n) {
        if (n % 2 === 1 || target !== key) {
          return part;
        }
        const at = part.indexOf('=');
        const name = at < 0 ? part : part.slice(0, at);
        let plain = name;
        try {
          plain = decodeURIComponent(name);
        } catch (e) {
          return part;
        }
        return own(plain) === plain ? part
          : encodeURIComponent(own(plain)) + (at < 0 ? '' : part.slice(at));
      }).join('');
    };
    const routes = '/admin/(?:acme|est|scep|spiffe(?:/entries|/agents|' +
                   '/brokers)?)';
    html = String(html || '').replace(new RegExp('href="(' + routes +
      ')(\\?[^"#]*)?(#[^"]*)?"', 'g'),
    function (_match: string, path: string, search: string,
              fragment: string): string {
      const target = keyOf(path);
      // The page as a document is its operation's answer: the console
      // cannot draw a former page in another shape.
      if (/[?&;]format=/.test(search || '')) {
        const kept = (search || '').slice(1).split(/&amp;|&/)
          .filter(function (part) {
            return part && !/^format=/.test(part);
          });
        return 'href="' + CERT_PANELS[target].operation +
          (kept.length ? '?' + kept.join('&amp;') : '') + '"';
      }
      const list = /^#list-(.+)$/.exec(fragment || '');
      const goes = list && target === key ? '#list-' + own(list[1])
        : fragment || '#' + CERT_PANELS[target].tab;
      return 'href="' + CERT_PAGE + renamed(search || '', target) + goes +
        '"';
    });
    // A pager's anchor, and the table it heads, named for this tab's list.
    html = html.replace(/\bid="list-([A-Za-z]+)"/g,
      function (_match: string, name: string): string {
        return 'id="list-' + own(name) + '"';
      });
    return html.replace(/<form\b[^>]*\bmethod="get"[^>]*>[\s\S]*?<\/form>/gi,
      function (form: string): string {
        return form.replace(new RegExp('\\baction="(' + routes +
          ')(?:\\?[^"#]*)?(#[^"]*)?"'),
        function (_match: string, path: string, fragment: string): string {
          return 'action="' + CERT_PAGE +
            (fragment || '#' + CERT_PANELS[keyOf(path)].tab) + '"';
        }).replace(/\b(name|id|for)="([^"]+)"/g,
        function (_match: string, attr: string, value: string): string {
          return attr === 'name' ? 'name="' + own(value) + '"'
                                 : attr + '="' + panel.prefix + '-' + value +
                                   '"';
        });
      });
  }

  // EVERY PAGE'S LINKS INTO THE XACML TABS GO THROUGH ONE REWRITE (rcbj,
  // 2026-11-15). `/admin/xacml/policies`, `editor`, `peps`, `decide` and
  // `authzen` are TABS of `/admin/xacml`, not pages, and the renderers still
  // write them as paths — a policy's editor link, Remote PEPs, Try a
  // decision. Rewritten only on `/admin/xacml` itself, so the Deciding
  // policy link on a PEP route's page answered "/admin/xacml/editor is not a
  // page of this console", and so did the Roles, Applications and Policies
  // pages' links. Every page drawn is passed through `xacmlTabLinks()` now,
  // in its navigation-only form: an `href` and a GET form move onto the tab,
  // a POST form keeps its action, because the runtime resolves a POST by its
  // page (`/admin/xacml/peps` is what a PEP's route forms are told apart by,
  // `WebAnswers.PEP_ROUTES_PAGE`), and a POST is never a navigation.
  /**
   * Draws a console page's body, its links into the XACML tabs rewritten.
   *
   * @param path - the console path
   * @param view - the page's answer
   * @param ctx - optional; the rendering context
   * @returns the HTML, or null for a path that is not a page
   */
  static render(path: string, view: Json, ctx?: Json): string | null {
    const html = WebPages.renderPage(path, view, ctx);
    return html === null ? null : WebPages.xacmlTabLinks(html, false);
  }

  /**
   * Draws a console page's body as its renderer writes it.
   *
   * @param path - the console path
   * @param view - the page's answer
   * @param ctx - optional; the rendering context
   * @returns the HTML, or null for a path that is not a page
   */
  static renderPage(path: string, view: Json, ctx?: Json): string | null {
    const page = WebPages.pageFor(path);
    const context = ctx || WebKit.context();
    if (!page) {
      return null;
    }
    if (page.path === '/admin/kerberos') {
      if (!view.kerberosClaims || !view.kerberosPrincipals ||
          !view.kerberosTrusts) {
        throw new Error('The Kerberos page is missing a tab view.');
      }
      const endpoints: Json[] = [];
      const seen: Json = {};
      [view, view.kerberosClaims, view.kerberosPrincipals,
       view.kerberosTrusts]
        .forEach(function (answer) {
          (Array.isArray(answer.protocolEndpoints)
            ? answer.protocolEndpoints : []).forEach(function (row: Json) {
            const key = String(row.name) + '\n' + String(row.url);
            if (!seen[key]) {
              seen[key] = true;
              endpoints.push(row);
            }
          });
        });
      const metadataView = Object.assign({}, view, {
        settings: Object.assign({}, view.settings, { groups: [] }),
        status: null
      });
      const metadata = WebPages.withEndpoints(
        ProtocolSettingsPage.render(metadataView, context), {
          protocolEndpoints: endpoints
        }, context.t);
      const settings = ProtocolSettingsPage.kerberosPreauthStatus(
        view.status, context.t) +
        SettingsForms.forms(view.settings,
          '/admin/kerberos#kerberos-tab-settings', ['Kerberos'], context.t);
      const panels = [
        { id: 'kerberos-tab-metadata',
          label: context.t.text('consoleProtocolSettings.metadataHeading'),
          html: metadata },
        { id: 'kerberos-tab-settings',
          label: context.t.text('consoleProtocolSettings.globalSettings'),
          html: settings },
        { id: 'kerberos-tab-claims',
          label: context.t.text('console.nav.kerberos-claims'),
          html: ClaimsPage.kerberosClaimsBody(context,
            view.kerberosClaims) },
        { id: 'kerberos-tab-principals',
          label: context.t.text('console.nav.kerberos-principals'),
          html: KerberosPrincipalsPage.body(context,
            view.kerberosPrincipals) },
        // THE TRUSTS (#430 Phase 4): the realm's trust records, their
        // health, and the forms that add, change, rotate, pair and remove
        // them.
        { id: 'kerberos-tab-trusts',
          label: context.t.text('consoleKerberosTrusts.tab'),
          html: KerberosTrustsPage.body(context, view.kerberosTrusts) }
      ];
      const rendered = panels.map(function (one) {
        return { id: one.id, label: one.label,
          html: WebPages.kerberosTabLinks(one.html) };
      });
      return WebKit.tabbedPanels('kerberos-pages', rendered);
    }
    if (page.path === '/admin/oauth2') {
      const authorizationServers =
        WebPages.pageFor('/admin/authorization-servers');
      const tokenLifetimes = WebPages.pageFor('/admin/token-lifetimes');
      const claims = WebPages.pageFor('/admin/claims');
      const userinfoClaims = WebPages.pageFor('/admin/userinfo-claims');
      if (!authorizationServers || !tokenLifetimes || !claims ||
          !userinfoClaims) {
        throw new Error('The OAuth 2.0 / OIDC page is missing a tab.');
      }
      const panels: Array<{ id: string; page: WebPage; view: Json;
                            label: string; render?: () => string;
                            endpoints?: boolean }> = [
        { id: 'oauth-tab-metadata',
          page: page,
          view: view,
          label: context.t.text('consoleProtocolSettings.metadataHeading'),
          endpoints: true,
          render: function (): string {
            return ProtocolSettingsPage.oauthMetadata(view, context.t);
          } },
        { id: 'oauth-tab-global-settings',
          page: page,
          view: view,
          label: context.t.text('consoleProtocolSettings.globalSettings'),
          endpoints: false },
        { id: 'oauth-tab-authorization-servers',
          page: authorizationServers,
          view: view.authorizationServers,
          label: WebPages.titleOf(authorizationServers, context.t) },
        { id: 'oauth-tab-token-lifetimes',
          page: tokenLifetimes,
          view: view.tokenLifetimes,
          label: WebPages.titleOf(tokenLifetimes, context.t) },
        { id: 'oauth-tab-claims',
          page: claims,
          view: view.claims,
          label: WebPages.titleOf(claims, context.t) },
        { id: 'oauth-tab-userinfo-claims',
          page: userinfoClaims,
          view: view.userinfoClaims,
          label: WebPages.titleOf(userinfoClaims, context.t) }
      ];
      const rendered = panels.map(function (one) {
        const html = one.render ? one.render() : one.page && one.view
          ? one.page.render(one.view, context) : '';
        return { id: one.id, label: one.label,
          html: one.page && one.view
            ? WebPages.oauthTabLinks(one.endpoints === false ? html
              : WebPages.withEndpoints(html, one.view, context.t))
            : '' };
      });
      return WebKit.tabbedPanels('oauth-pages', rendered);
    }
    if (page.path === '/admin/saml2' && context.query &&
        context.query.sp) {
      return SamlPage.saml2Detail(context, view);
    }
    if (page.path === '/admin/saml2' && context.query &&
        context.query.rp) {
      if (!view.saml11Detail) {
        throw new Error('The SAML 1.1 detail view is missing.');
      }
      return SamlPage.saml11Detail(context, view.saml11Detail);
    }
    if (page.path === '/admin/saml2') {
      if (!view.saml11 || !view.assertions || !view.attributes ||
          !view.idpInitiated) {
        throw new Error('The SAML page is missing a tab view.');
      }
      const endpoints: Json[] = [];
      const endpointKeys: Json = {};
      [view, view.saml11, view.assertions, view.attributes]
        .forEach(function (answer) {
          (Array.isArray(answer.protocolEndpoints)
            ? answer.protocolEndpoints : []).forEach(function (row: Json) {
            const key = String(row.name) + '\n' + String(row.url);
            if (!endpointKeys[key]) {
              endpointKeys[key] = true;
              endpoints.push(row);
            }
          });
        });
      const metadata = WebPages.withEndpoints(
        SamlPage.metadataBody(context), { protocolEndpoints: endpoints },
        context.t);
      const globalSettings =
        SettingsForms.forms(view.settings, '/admin/saml2', ['SAML 2.0'],
                            context.t) +
        SettingsForms.forms(view.settings, '/admin/saml2', ['SAML 1.1'],
                            context.t);
      const sharedSettings =
        SettingsForms.forms(view.settings, '/admin/saml2', ['SAML'],
                            context.t);
      const saml2Body = SamlPage.saml2Body(context, view, {
        includeMetadata: false, includeSettings: false
      });
      const saml11Body = SamlPage.saml11Body(context, view.saml11, {
        includeMetadata: false, includeSettings: false
      });
      // The compatibility assertion page also edits the shared clock skew.
      // In the combined page that control lives in the shared-settings tab;
      // retain the timing data so the assertion warnings still use its value.
      const assertionView = Object.assign({}, view.assertions, {
        settings: view.assertions.settings.filter(function (setting: Json) {
          return setting.key !== 'saml.clockSkewS';
        })
      });
      const panels = [
        { id: 'saml-tab-metadata',
          label: context.t.text('consoleProtocolSettings.metadataHeading'),
          html: metadata },
        { id: 'saml-tab-global-settings',
          label: context.t.text('consoleProtocolSettings.globalSettings'),
          html: globalSettings },
        { id: 'saml-tab-shared-settings',
          label: context.t.text(
            'consoleProtocolSettings.sharedProfileSettings'),
          html: sharedSettings },
        { id: 'saml-tab-saml2',
          label: 'SAML 2.0 IdP',
          html: saml2Body },
        { id: 'saml-tab-saml11',
          label: 'SAML 1.1 IdP',
          html: saml11Body },
        // After the two identity providers whose applications it lists
        // (#749), before the assertion and attribute tabs.
        { id: 'saml-tab-idp-initiated',
          label: context.t.text('consoleSaml.idpInitiated.tab'),
          html: SamlPage.idpInitiatedBody(context, view.idpInitiated) },
        { id: 'saml-tab-assertions',
          label: context.t.text('consolePages.title.saml-assertions'),
          html: SamlAssertionsPage.body(context, assertionView) +
            WebPages.samlAssertionLeftovers(view, context) },
        { id: 'saml-tab-attributes',
          label: context.t.text('consolePages.title.saml-attributes'),
          html: ClaimsPage.samlAttributesBody(context, view.attributes) }
      ];
      const rendered = panels.map(function (one) {
        return { id: one.id, label: one.label,
          html: WebPages.samlTabLinks(one.html) };
      });
      return WebKit.tabbedPanels('saml-pages', rendered);
    }
    if (page.path === '/admin/vc') {
      if (!view.oid4vciSettings || !view.oid4vpSettings ||
          !view.verifierRequest) {
        throw new Error('The Verifiable Credentials page is missing a tab ' +
                        'view.');
      }
      const metadata = WebPages.withEndpoints(
        WebPages.vcMetadata(view.oid4vciSettings,
                            view.oid4vpSettings, context.t),
        view, context.t);
      const vciSettings = SettingsForms.forms(
        view.oid4vciSettings.settings,
        // `Person DIDs` (#1291) is homed on this page and carried in the
        // view, and was left out of this list until #2049's check found it.
        '/admin/vc#vc-tab-oid4vci', ['OID4VCI', 'W3C VC API', 'Person DIDs'],
        context.t);
      const vpSettings = SettingsForms.forms(
        view.oid4vpSettings.settings,
        '/admin/vc#vc-tab-oid4vp', ['OID4VP'], context.t);
      const panels = [
        { id: 'vc-tab-metadata',
          label: context.t.text('consoleProtocolSettings.metadataHeading'),
          html: metadata },
        { id: 'vc-tab-oid4vci',
          label: context.t.text('console.nav.oid4vci'),
          html: vciSettings },
        { id: 'vc-tab-claims',
          label: context.t.text('console.nav.vc-claims'),
          html: VcClaimsPage.body(context, view) },
        { id: 'vc-tab-oid4vp',
          label: context.t.text('console.nav.oid4vp'),
          html: vpSettings },
        { id: 'vc-tab-verifier-request',
          label: context.t.text('console.nav.vc-verifier-config'),
          html: VcVerifierConfigPage.body(context, view.verifierRequest) }
      ];
      const rendered = panels.map(function (one) {
        return { id: one.id, label: one.label,
          html: WebPages.vcTabLinks(one.html) };
      });
      return WebKit.tabbedPanels('vc-pages', rendered);
    }
    if (page.path === '/admin/xacml') {
      if (!view.xacmlPolicies || !view.xacmlEditor || !view.xacmlPeps ||
          !view.xacmlDecide) {
        throw new Error('The XACML page is missing a tab view.');
      }
      // The tabs and their order are `XacmlPage.xacmlTabs()`'s, which a
      // PEP's page and a route's draw as their first row (2026-11-15).
      const bodies: { [id: string]: string } = {
        'xacml-tab-metadata': WebPages.withEndpoints('', view, context.t),
        'xacml-tab-settings': XacmlPage.render(view, context),
        'xacml-tab-policies':
          XacmlPage.policiesBody(context, view.xacmlPolicies),
        'xacml-tab-editor': XacmlPage.editorBody(context, view.xacmlEditor),
        'xacml-tab-peps': XacmlPage.pepsBody(context, view.xacmlPeps),
        'xacml-tab-pep-clusters':
          XacmlPage.clustersBody(context, view.xacmlPepClusters || {}),
        'xacml-tab-decide': XacmlPage.decideBody(context, view.xacmlDecide),
        'xacml-tab-authzen':
          XacmlPage.authzenBody(context, view.xacmlAuthzen)
      };
      const rendered = XacmlPage.xacmlTabs(context.t).map(function (one) {
        return { id: one.id, label: one.label,
          html: WebPages.xacmlTabLinks(bodies[one.id]) };
      });
      return WebKit.tabbedPanels('xacml-pages', rendered);
    }
    if (page.path === '/admin/scim') {
      if (context.query && context.query.client && page.drill) {
        return page.drill.render(view, context);
      }
      return page.render(view, context);
    }
    if (page.path === '/admin/ssf') {
      return page.render(view, context);
    }
    if (page.path === CERT_PAGE) {
      return WebPages.certIssuance(view, context);
    }
    if (page.drill && context.query && context.query[page.drill.param]) {
      return page.drill.render(view, context);
    }
    if (PROTOCOL_TABS[page.path]) {
      return WebPages.protocolTabs(page.path,
        WebPages.withEndpoints(page.render(view, context), view, context.t),
        context.t);
    }
    return WebPages.withEndpoints(page.render(view, context), view,
                                  context.t);
  }

  /**
   * Keeps links between the five OAuth pages inside their combined tabbed
   * page, without changing their direct routes.
   *
   * @param html - one OAuth page's rendered HTML
   * @returns the HTML with intra-page links
   */
  static oauthTabLinks(html: string): string {
    const paths = {
      '/admin/oauth2': 'oauth-tab-global-settings',
      '/admin/authorization-servers': 'oauth-tab-authorization-servers',
      '/admin/token-lifetimes': 'oauth-tab-token-lifetimes',
      '/admin/claims': 'oauth-tab-claims',
      '/admin/userinfo-claims': 'oauth-tab-userinfo-claims'
    };
    Object.keys(paths).forEach(function (path) {
      html = html.split('href="' + path + '"')
        .join('href="#' + paths[path] + '"');
    });
    return html;
  }

  /**
   * Keeps links and forms between the XACML views on their tabs: the ONE
   * mapping of the old sub-paths to the tabs of `/admin/xacml`.
   *
   * On `/admin/xacml` itself (`whole`, the default) a bare `/admin/xacml`
   * link opens the Settings tab and a POST form moves onto its tab too, as
   * the tabs' forms always did. On every other page (`whole` false,
   * `WebPages.render()`) only the five sub-paths move, and only where they
   * navigate — a link or a GET form — so a plain link to the section and a
   * POST form's action are left as their page wrote them.
   *
   * @param html - one page's rendered HTML
   * @param whole - optional; false for the navigation-only form
   * @returns the HTML with links and forms onto the tabs
   */
  static xacmlTabLinks(html: string, whole?: boolean): string {
    const every = whole !== false;
    const paths: { [path: string]: string } = {
      '/admin/xacml/policies': 'xacml-tab-policies',
      '/admin/xacml/editor': 'xacml-tab-editor',
      '/admin/xacml/peps': 'xacml-tab-peps',
      '/admin/xacml/pep-clusters': 'xacml-tab-pep-clusters',
      '/admin/xacml/decide': 'xacml-tab-decide',
      // The AuthZEN tab's forms (#563) name it so, and are moved onto it.
      '/admin/xacml/authzen': 'xacml-tab-authzen'
    };
    if (every) {
      paths['/admin/xacml'] = 'xacml-tab-settings';
    }
    const route = Object.keys(paths).join('|');
    html = html.replace(new RegExp('href="(' + route +
      ')(\\?[^"#]*)?(#[^"]*)?"', 'g'),
    function (_match: string, path: string, query: string,
              fragment: string): string {
      return 'href="/admin/xacml' + (query || '') +
        (fragment || '#' + paths[path]) + '"';
    });
    html = html.replace(
      /<form\b([^>]*)>/gi,
      function (match: string, attrs: string): string {
        const action = /action="([^"]*)"/i.exec(attrs);
        if (!action) {
          return match;
        }
        if (!every && !/\bmethod="get"/i.test(attrs)) {
          return match;
        }
        const target = /^([^?#]*)(\?[^#]*)?(#.*)?$/.exec(action[1]);
        if (!target || !Object.prototype.hasOwnProperty.call(
          paths, target[1])) {
          return match;
        }
        return match.replace(action[0],
          'action="/admin/xacml' + (target[2] || '') + '#' +
          paths[target[1]] + '"');
      });
    return html;
  }

  /**
   * Keeps links between Shared Signals and its vocabulary tabs in the
   * combined SSF page.
   *
   * @param html - one SSF view's rendered HTML
   * @returns the HTML with intra-page links
   */
  static ssfTabLinks(html: string): string {
    const paths = {
      '/admin/ssf': 'ssf-tab-ssf',
      '/admin/caep': 'ssf-tab-caep',
      '/admin/risc': 'ssf-tab-risc'
    };
    // A link may carry a fragment of its own (`#find-sessq`, the CAEP search
    // box): that anchor is inside its tab's panel, so it opens the tab and is
    // kept; a link with none gets the tab's.
    html = html.replace(
      /href="(\/admin\/ssf|\/admin\/caep|\/admin\/risc)(\?[^"#]*)?(#[^"]*)?"/g,
      function (_match: string, path: string, query: string,
                fragment: string): string {
        return 'href="/admin/ssf' + (query || '') +
          (fragment || '#' + paths[path]) + '"';
      });
    // A GET form (the CAEP and RISC searches) submits to its action, and
    // /admin/caep and /admin/risc are tabs of this page, not pages: a search
    // pressed there answered 404 (sts_admin_console, 2026-10-12). A POST form
    // is an act the console resolves through its operation's `mirrors`, which
    // still name those paths, so it is left alone.
    return html.replace(
      /<form\b([^>]*)>/gi,
      function (match: string, attrs: string): string {
        if (/method="post"/i.test(attrs)) {
          return match;
        }
        const action = /action="([^"]*)"/i.exec(attrs);
        if (!action) {
          return match;
        }
        const target = /^([^?#]*)(\?[^#]*)?(#.*)?$/.exec(action[1]);
        if (!target || !Object.prototype.hasOwnProperty.call(
          paths, target[1])) {
          return match;
        }
        return match.replace(action[0], 'action="/admin/ssf' +
          (target[2] || '') + (target[3] || '#' + paths[target[1]]) + '"');
      });
  }

  /**
   * Keeps links and forms between the Kerberos views on their page tabs.
   *
   * @param html - one Kerberos view's rendered HTML
   * @returns the HTML with intra-page links and forms
   */
  static kerberosTabLinks(html: string): string {
    const paths = {
      '/admin/kerberos': 'kerberos-tab-settings',
      '/admin/kerberos/claims': 'kerberos-tab-claims',
      '/admin/kerberos/principals': 'kerberos-tab-principals',
      '/admin/kerberos/trusts': 'kerberos-tab-trusts'
    };
    html = html.replace(
      /href="(\/admin\/kerberos(?:\/claims|\/principals|\/trusts)?)(\?[^"#]*)?(#[^"]*)?"/g,
      function (_match: string, path: string, query: string): string {
        return 'href="/admin/kerberos' + (query || '') + '#' + paths[path] +
          '"';
      });
    html = html.replace(
      /(<input\b[^>]*\bname="back"[^>]*\bvalue=")(\/admin\/kerberos(?:\/claims|\/principals|\/trusts)?)(\?[^"]*)?(")/gi,
      function (_match: string, before: string, path: string,
                query: string, after: string): string {
        return before + '/admin/kerberos' + (query || '') + '#' + paths[path] +
          after;
      });
    return html.replace(
      /<form\b([^>]*)>/gi,
      function (match: string, attrs: string): string {
        const action = /action="([^"]*)"/i.exec(attrs);
        if (!action) {
          return match;
        }
        const target = /^([^?#]*)(\?[^#]*)?(#.*)?$/.exec(action[1]);
        if (!target || !Object.prototype.hasOwnProperty.call(
          paths, target[1])) {
          return match;
        }
        return match.replace(action[0],
          'action="/admin/kerberos' + (target[2] || '') + '#' +
          paths[target[1]] + '"');
      });
  }

  /**
   * Keeps navigation between the SAML views inside their combined page.
   *
   * @param html - one SAML page's rendered HTML
   * @returns the HTML with intra-page links
   */
  static samlTabLinks(html: string): string {
    const paths = {
      '/admin/saml2': 'saml-tab-saml2',
      '/admin/saml11': 'saml-tab-saml11',
      '/admin/saml-assertions': 'saml-tab-assertions',
      '/admin/saml-attributes': 'saml-tab-attributes'
    };
    const tabHref = function (path: string, query: string): string {
      const tab = paths[path];
      return path === '/admin/saml2' && query
        ? 'href="' + path + query + '#' + tab + '"'
        : 'href="/admin/saml2' + query + '#' + tab + '"';
    };
    // A fragment that already names a SAML tab is where the link was going
    // (the IdP-Initiated SSO tab's turn-it-on link names Global settings).
    // A list anchor other than `#list-page` lives inside one panel, and the
    // tab stylesheet opens the panel that holds `:target`, so the anchor is
    // the tab. `#list-page` is the exception: the SAML 2.0 and SAML 1.1
    // tables share the paging parameter `page`, so that anchor is not unique
    // and the path's own tab is what tells them apart. Putting that tab in
    // front of a fragment this rewrite did not consume is what sent the
    // IdP-Initiated SSO pager to SAML 2.0 (#749).
    html = html.replace(
      /href="(\/admin\/saml2|\/admin\/saml11|\/admin\/saml-assertions|\/admin\/saml-attributes)(\?[^"#]*)?(#[^"]*)?"/g,
      function (_match: string, path: string, query: string,
                fragment: string): string {
        const q = query || '';
        if (fragment && (fragment.indexOf('#saml-tab-') === 0 ||
            (fragment.indexOf('#list-') === 0 &&
             fragment !== '#list-page'))) {
          return 'href="/admin/saml2' + q + fragment + '"';
        }
        return tabHref(path, q);
      });
    html = html.replace(
      /<form\b([^>]*)>/gi,
      function (match: string, attrs: string): string {
        const action = /action="([^"]*)"/i.exec(attrs);
        if (!action) {
          return match;
        }
        const target = /^([^?#]*)(\?[^#]*)?(#.*)?$/.exec(action[1]);
        if (!target || !Object.prototype.hasOwnProperty.call(
          paths, target[1])) {
          return match;
        }
        return match.replace(action[0],
          'action="/admin/saml2' + (target[2] || '') + '#' +
          paths[target[1]] + '"');
      });
    return html;
  }

  /**
   * Keeps links and forms between the Verifiable Credentials views on their
   * corresponding tabs of the combined page.
   *
   * @param html - one VC view's rendered HTML
   * @returns the HTML with intra-page links and forms
   */
  static vcTabLinks(html: string): string {
    const paths = {
      '/admin/oid4vci': 'vc-tab-oid4vci',
      '/admin/vc': 'vc-tab-claims',
      '/admin/oid4vp': 'vc-tab-oid4vp',
      '/admin/vc-verifier-config': 'vc-tab-verifier-request'
    };
    html = html.replace(
      /href="(\/admin\/oid4vci|\/admin\/vc|\/admin\/oid4vp|\/admin\/vc-verifier-config)(\?[^"#]*)?"/g,
      function (_match: string, path: string, query: string): string {
        return 'href="/admin/vc' + (query || '') + '#' + paths[path] + '"';
      });
    html = html.replace(
      /<form\b([^>]*)>/gi,
      function (match: string, attrs: string): string {
        const action = /action="([^"]*)"/i.exec(attrs);
        if (!action) {
          return match;
        }
        const target = /^([^?#]*)(\?[^#]*)?(#.*)?$/.exec(action[1]);
        if (!target || !Object.prototype.hasOwnProperty.call(
          paths, target[1])) {
          return match;
        }
        return match.replace(action[0],
          'action="/admin/vc' + (target[2] || '') + '#' +
          paths[target[1]] + '"');
      });
    return html;
  }

  /**
   * Keeps the issuer and verifier guidance from their former pages with the
   * unified endpoint inventory on Metadata, not in either settings tab.
   *
   * @param issuer - the OpenID4VCI settings operation's page prose
   * @param verifier - the OpenID4VP settings operation's page prose
   * @param t - translator for the two page labels
   * @returns the shared metadata panel's descriptive sections
   */
  static vcMetadata(issuer: Json, verifier: Json, t: Json): string {
    const esc = WebKit.esc;
    const sections = [
      { label: t.text('console.nav.oid4vci'), view: issuer },
      { label: t.text('console.nav.oid4vp'), view: verifier }
    ];
    return sections.map(function (section): string {
      const view = section.view;
      const links = (view.links || []).map(function (link: Json): string {
        return '<li><a href="' + esc(link.href) + '">' +
          esc(link.what) + '</a></li>';
      }).join('');
      const notes = (view.alsoHtml || []).map(function (note: string) {
        return '<p>' + note + '</p>';
      }).join('');
      return '<details class="fold vc-metadata"><summary>' +
        esc(section.label) + '</summary>' + (view.leadHtml || '') + notes +
        (links ? '<ul>' + links + '</ul>' : '') + '</details>';
    }).join('');
  }

  // A PAGE'S TITLE IN THE READER'S LANGUAGE (#539 phase 5), drawn in the
  // browser's tab and the heading. The key is derived from the path —
  // `/admin/xacml/policies` is `consolePages.title.xacml-policies` — and
  // built in a variable, since a literal beside `t.text(` is what the
  // catalog test reads as a key. A row with no message is drawn with the
  // table's English, so a page added here is never drawn as a key.
  /**
   * A page's title in the reader's language.
   *
   * @param page - the page's row
   * @param t - optional; the translator, the default when left out
   * @returns the title, as text
   */
  static titleOf(page: WebPage, t?: Json): string {
    const translator = t || WebKit.context().t;
    const slug = String(page.path || '').replace(/^\/admin(\/|$)/, '')
      .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const key = 'consolePages.title.' + (slug || 'home');
    return translator.has(key) ? translator.text(key) : page.title;
  }

  // THE ENDPOINTS OF THIS REALM ON A PROTOCOLS PAGE (2026-10-01), drawn by
  // the server-rendered console from the `protocolEndpoints` member its
  // answer carries (`admin-core/protocol_endpoints.ts`) and, since #446,
  // here: every URL with a Copy button the runtime reveals, the methods or
  // transport beside it, and whether it is registered and listening. A
  // drill-down is about one thing and goes without it. Placed before the
  // page's first heading — after the lead notes that say what the page is —
  // or at the foot of a page with none.
  /**
   * Adds the Endpoints section to a page whose answer lists its endpoints.
   *
   * @param html - the page as drawn
   * @param view - the page's answer
   * @param t - optional; the translator, the default when left out
   * @returns the page with the section, or as it was
   */
  static withEndpoints(html: string, view: Json, t?: Json): string {
    const rows = view && Array.isArray(view.protocolEndpoints)
      ? view.protocolEndpoints : null;
    if (!rows) {
      return html;
    }
    t = t || WebKit.context().t;
    // FRAMED AS KEY PAIRS IS (`secframe`, rcbj 2026-11-16), and marked for
    // Metadata, where `protocolTabs()` kept it when its heading was at the
    // top level. A first heading that opens a frame is gone before by its
    // frame, so the section is not drawn inside another one.
    const section = WebKit.metadataFrame('<h2>' +
      t.html('consolePages.endpoints') + '</h2>' +
      WebPages.endpointTable(rows, t));
    const text = String(html || '');
    let at = text.indexOf('<h2');
    while (at > 0) {
      const opens = /<section class="secframe"[^>]*>$/.exec(text.slice(0, at));
      if (!opens) {
        break;
      }
      at = opens.index;
    }
    return at < 0 ? text + section
                  : text.slice(0, at) + section + text.slice(at);
  }

  /**
   * Draws endpoint rows as the table every Protocols page's Endpoints
   * section is: each URL with its Copy button, its methods or transport, and
   * whether it is registered and listening.
   *
   * @param rows - `protocolEndpoints` rows
   * @param t - optional; the translator, the default when left out
   * @returns the table as HTML
   */
  static endpointTable(rows: Json[], t?: Json): string {
    t = t || WebKit.context().t;
    const esc = WebKit.esc;
    const body = rows.length ? rows.map(function (row: Json): string {
      const methods = Array.isArray(row.methods) ? row.methods : [];
      const how = methods.length ? methods.join(', ')
                                 : String(row.transport || '');
      return '<tr><th>' + esc(row.name) + '</th><td><code>' + esc(row.url) +
        '</code>' + WebKit.copyButton(row.url) +
        (how ? ' <span class="sub">' + esc(how) + '</span>' : '') +
        (row.registered === false
          ? ' <span class="sub">' +
            t.html('consolePages.endpoints.notRegistered') + '</span>'
          : '') +
        (row.listening === false
          ? ' <span class="sub">' +
            t.html('consolePages.endpoints.notListening') + '</span>'
          : '') + '</td></tr>';
    }).join('') : '<tr><td class="sub">' +
                  t.html('consolePages.endpoints.none') + '</td></tr>';
    return '<table class="kv">' + body + '</table>';
  }
}

export = WebPages;
