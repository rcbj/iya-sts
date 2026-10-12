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
import AcmePage = require('../acme/web_acme');
import ApplicationsPage = require('./web_applications');
import AuditPage = require('./web_audit');
import ServiceAccountsPage = require('./web_service_accounts');
import AuthorizationServersPage = require('./web_authorization_servers');
import AttributeSourcesPage =
  require('../attribute-sources/web_attribute_sources');
import CachesPage = require('./web_caches');
import CaepRiscPage = require('../ssf/web_caep_risc');
import CellsPage = require('./web_cells');
import ClaimsPage = require('./web_claims');
import ConfigPage = require('./web_config');
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
import GrantsPage = require('../oauth-oidc/web_grants');
import GroupsPage = require('./web_groups');
import KerberosPrincipalsPage =
  require('../kerberos/web_kerberos_principals');
import LogoutPage = require('../logout/web_logout');
import LdapPage = require('../ldap/web_ldap');
import ListenersPage = require('./web_listeners');
import MailPage = require('./web_mail');
import MailOutboxPage = require('./web_mail_outbox');
import MetricsPage = require('./web_metrics');
import ModePage = require('./web_mode');
import NodeHealthPage = require('./web_node_health');
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
import WebMessages = require('./web_messages');
import SignalsPage = require('../ssf/web_signals');
import SpiffePage = require('../spiffe/web_spiffe');
import SsfDeadLettersPage = require('../ssf/web_ssf_dead_letters');
import SsfPage = require('../ssf/web_ssf');
import SsfTransmittersPage = require('../ssf/web_ssf_transmitters');
import TlsTrustPage = require('../tls/web_tls_trust');
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
  render: (view: Json, ctx?: Json) => string;
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
  { path: '/admin/consent', title: 'Consent',
    operation: '/admin-api/consent',
    render: function (view: Json, ctx?: Json): string {
      return ConsentPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/crypto-metadata', title: 'Cryptography',
    operation: '/admin-api/crypto', render: CryptoMetadataPage.render },
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
    } },
  { path: '/admin/delegation/cluster', title: 'Delegation — one group',
    operation: '/admin-api/console/delegation/cluster',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.cluster(ctx || WebKit.context(), view);
    } },
  { path: '/admin/delegation/chain', title: 'Delegation — one relationship',
    operation: '/admin-api/console/delegation/chain',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.chain(ctx || WebKit.context(), view);
    } },
  { path: '/admin/delegation/map', title: 'Delegation — the picture',
    operation: '/admin-api/console/delegation/map',
    render: function (view: Json, ctx?: Json): string {
      return DelegationPage.map(ctx || WebKit.context(), view);
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
    operation: '/admin-api/geolocation', render: GeolocationPage.render },
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
  { path: '/admin/node-health', title: 'Node health',
    operation: '/admin-api/node-health', render: NodeHealthPage.render },
  { path: '/admin/oauth2/monitor', title: 'OAuth 2.0 / OIDC activity',
    operation: '/admin-api/oauth2/monitor',
    render: OAuth2MonitorPage.render },
  // `rows=shown`: the page's own call reads the certificates of the rows
  // it draws and no others (#352).
  { path: '/admin/pki', title: 'PKI', operation: '/admin-api/pki',
    fixed: { rows: 'shown' }, render: PkiPage.render },
  { path: '/admin/policies', title: 'Policies',
    operation: '/admin-api/policies',
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
  { path: '/admin/roles', title: 'Roles',
    operation: '/admin-api/roles',
    compose: { preview: '/admin-api/roles/preview' },
    composeWhen: { preview: ['application', 'subject', 'subjectKind', 'kind'] },
    render: function (view: Json, ctx?: Json): string {
      return RolesPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/saml2', title: 'SAML', operation: '/admin-api/saml2',
    // The tabs are separate API answers, but have no standalone console routes.
    compose: {
      saml11: '/admin-api/saml11',
      saml11Detail: '/admin-api/saml11',
      assertions: '/admin-api/saml-assertions',
      attributes: '/admin-api/saml-attributes'
    },
    composeWhen: { saml11Detail: ['rp'] },
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
      vcStatus: '/admin-api/vc-status',
      oid4vpSettings: '/admin-api/oid4vp-settings',
      verifierRequest: '/admin-api/verifier-request'
    },
    composeWhen: { vcStatus: ['page', 'per'] },
    composeAlways: ['vcStatus'],
    render: function (view: Json, ctx?: Json): string {
      return VcClaimsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/kerberos', title: 'Kerberos',
    operation: '/admin-api/kerberos',
    compose: {
      kerberosClaims: '/admin-api/kerberos/claims',
      kerberosPrincipals: '/admin-api/kerberos/principals'
    },
    composeWhen: {
      kerberosClaims: ['user'],
      kerberosPrincipals: ['per', 'peoplePage', 'servicesPage']
    },
    composeAlways: ['kerberosClaims', 'kerberosPrincipals'],
    render: function (view: Json, ctx?: Json): string {
      return ProtocolSettingsPage.render(view, ctx || WebKit.context());
    } },
  { path: '/admin/xacml', title: 'XACML', operation: '/admin-api/xacml',
    compose: {
      xacmlPolicies: '/admin-api/xacml/policies',
      xacmlEditor: '/admin-api/xacml/editor',
      xacmlPeps: '/admin-api/xacml/peps',
      xacmlDecide: '/admin-api/xacml/decide'
    },
    composeWhen: {
      xacmlEditor: ['policy'],
      xacmlDecide: ['subject', 'action', 'resource']
    },
    composeAlways: [
      'xacmlPolicies', 'xacmlEditor', 'xacmlPeps', 'xacmlDecide'
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
  { path: '/admin/totp', title: 'TOTP MFA',
    operation: '/admin-api/totp',
    render: ProtocolSettingsPage.render },
  { path: '/admin/webauthn', title: 'WebAuthn',
    operation: '/admin-api/webauthn',
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
  /**
   * Translates a page's query into its operation's, by the row's `params`.
   *
   * @param path - the console path
   * @param query - the page's query
   * @returns the query the page's operation is asked with
   */
  static operationQuery(path: string, query: Json): Json {
    const page = WebPages.pageFor(path);
    const out: Json = {};
    Object.keys(query || {}).forEach(function (name) {
      const mapped = page && page.params && page.params[name];
      out[mapped || name] = query[name];
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
      spiffe: SpiffePage.listenersSection(t, view)
    };
    const sections = families.map(function (key) {
      const rows = endpoints.filter(function (row) {
        return familyOf(row) === key;
      });
      // The heading is the tab's own label; the key is built in a variable
      // for `titleOf()`'s reason.
      const label = 'console.nav.' + key;
      return '<h2 id="cert-metadata-' + key + '">' +
        WebKit.esc(t.text(label)) + '</h2>' +
        WebPages.endpointTable(rows, t) + extras[key];
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

  static render(path: string, view: Json, ctx?: Json): string | null {
    const page = WebPages.pageFor(path);
    const context = ctx || WebKit.context();
    if (!page) {
      return null;
    }
    if (page.path === '/admin/kerberos') {
      if (!view.kerberosClaims || !view.kerberosPrincipals) {
        throw new Error('The Kerberos page is missing a tab view.');
      }
      const endpoints: Json[] = [];
      const seen: Json = {};
      [view, view.kerberosClaims, view.kerberosPrincipals]
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
            view.kerberosPrincipals) }
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
      if (!view.saml11 || !view.assertions || !view.attributes) {
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
        { id: 'saml-tab-assertions',
          label: context.t.text('consolePages.title.saml-assertions'),
          html: SamlAssertionsPage.body(context, assertionView) },
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
      if (!view.oid4vciSettings || !view.vcStatus ||
          !view.oid4vpSettings || !view.verifierRequest) {
        throw new Error('The Verifiable Credentials page is missing a tab ' +
                        'view.');
      }
      const metadata = WebPages.withEndpoints(
        WebPages.vcMetadata(view.oid4vciSettings,
                            view.oid4vpSettings, context.t),
        view, context.t);
      const vciSettings = SettingsForms.forms(
        view.oid4vciSettings.settings,
        '/admin/vc#vc-tab-oid4vci', ['OID4VCI'], context.t);
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
        { id: 'vc-tab-status',
          label: context.t.text('console.nav.vc-status'),
          html: VcStatusPage.render(view.vcStatus, context) },
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
      const panels = [
        { id: 'xacml-tab-metadata',
          label: context.t.text('consoleProtocolSettings.metadataHeading'),
          html: WebPages.withEndpoints('', view, context.t) },
        { id: 'xacml-tab-settings',
          label: context.t.text('consoleProtocolSettings.globalSettings'),
          html: XacmlPage.render(view, context) },
        { id: 'xacml-tab-policies',
          label: context.t.text('console.nav.xacml-policies'),
          html: XacmlPage.policiesBody(context, view.xacmlPolicies) },
        { id: 'xacml-tab-editor',
          label: context.t.text('console.nav.xacml-editor'),
          html: XacmlPage.editorBody(context, view.xacmlEditor) },
        { id: 'xacml-tab-peps',
          label: context.t.text('console.nav.xacml-peps'),
          html: XacmlPage.pepsBody(context, view.xacmlPeps) },
        { id: 'xacml-tab-decide',
          label: context.t.text('console.nav.xacml-decide'),
          html: XacmlPage.decideBody(context, view.xacmlDecide) }
      ];
      const rendered = panels.map(function (one) {
        return { id: one.id, label: one.label,
          html: WebPages.xacmlTabLinks(one.html) };
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
   * Keeps links and forms between the XACML views on their tabs.
   *
   * @param html - one XACML view's rendered HTML
   * @returns the HTML with intra-page links and forms
   */
  static xacmlTabLinks(html: string): string {
    const paths = {
      '/admin/xacml/policies': 'xacml-tab-policies',
      '/admin/xacml/editor': 'xacml-tab-editor',
      '/admin/xacml/peps': 'xacml-tab-peps',
      '/admin/xacml/decide': 'xacml-tab-decide',
      '/admin/xacml': 'xacml-tab-settings'
    };
    const route = '/admin/xacml/policies|/admin/xacml/editor|' +
      '/admin/xacml/peps|/admin/xacml/decide|/admin/xacml';
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
    return html.replace(
      /href="(\/admin\/ssf|\/admin\/caep|\/admin\/risc)(\?[^"#]*)?"/g,
      function (_match: string, path: string, query: string): string {
        return 'href="/admin/ssf' + (query || '') + '#' + paths[path] + '"';
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
      '/admin/kerberos/principals': 'kerberos-tab-principals'
    };
    html = html.replace(
      /href="(\/admin\/kerberos(?:\/claims|\/principals)?)(\?[^"#]*)?(#[^"]*)?"/g,
      function (_match: string, path: string, query: string): string {
        return 'href="/admin/kerberos' + (query || '') + '#' + paths[path] +
          '"';
      });
    html = html.replace(
      /(<input\b[^>]*\bname="back"[^>]*\bvalue=")(\/admin\/kerberos(?:\/claims|\/principals)?)(\?[^"]*)?(")/gi,
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
    html = html.replace(
      /href="(\/admin\/saml2|\/admin\/saml11|\/admin\/saml-assertions|\/admin\/saml-attributes)(\?[^"#]*)?"/g,
      function (_match: string, path: string, query: string): string {
        return tabHref(path, query || '');
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
      '/admin/vc-status': 'vc-tab-status',
      '/admin/oid4vp': 'vc-tab-oid4vp',
      '/admin/vc-verifier-config': 'vc-tab-verifier-request'
    };
    html = html.replace(
      /href="(\/admin\/oid4vci|\/admin\/vc|\/admin\/vc-status|\/admin\/oid4vp|\/admin\/vc-verifier-config)(\?[^"#]*)?"/g,
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
    const section = '<h2>' + t.html('consolePages.endpoints') + '</h2>' +
                    WebPages.endpointTable(rows, t);
    const text = String(html || '');
    const at = text.indexOf('<h2');
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
