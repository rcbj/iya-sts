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
import AuthorizationServersPage = require('./web_authorization_servers');
import AttributeSourcesPage =
  require('../attribute-sources/web_attribute_sources');
import CachesPage = require('./web_caches');
import CaepRiscPage = require('../ssf/web_caep_risc');
import CellsPage = require('./web_cells');
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
import SecretsPage = require('./web_secrets');
import SessionsPage = require('../logout/web_sessions');
import SettingsForms = require('./web_settings');
import SignalsPage = require('../ssf/web_signals');
import SsfDeadLettersPage = require('../ssf/web_ssf_dead_letters');
import SsfPage = require('../ssf/web_ssf');
import SsfTransmittersPage = require('../ssf/web_ssf_transmitters');
import TlsTrustPage = require('../tls/web_tls_trust');
import TokenLifetimesPage = require('./web_token_lifetimes');
import TokensPage = require('./web_tokens');
import UsersPage = require('./web_users');
import VcStatusPage = require('./web_vc_status');
import VcVerifierConfigPage =
  require('../oid4vc/web_vc_verifier_config');
import XacmlPage = require('../xacml/web_xacml');
import WorkerPoolsPage = require('./web_worker_pools');

type Json = any;

/**
 * One converted console page.
 */
interface WebPage {
  path: string;
  title: string;
  operation: string;
  // Other operations whose answers the view is composed with, by the member
  // each goes in: asked only when the page's query asks for it (#446).
  compose?: Record<string, string>;
  // THE DRILL-DOWN AT THE SAME PATH (#446): `/admin/groups?group=<dn>` is
  // one group, answered by the same operation asked with the same query, so
  // a drill-down is not a page of its own but a second renderer chosen when
  // the query names `param`. `sample` picks an item off the list's answer,
  // which is how the bundle check draws one without knowing the data.
  drill?: {
    param: string;
    sample: (listView: Json) => string | null;
    render: (view: Json, ctx?: Json) => string;
  };
  render: (view: Json, ctx?: Json) => string;
}

const PAGES: WebPage[] = [
  { path: '/admin/acme', title: 'ACME', operation: '/admin-api/acme',
    render: AcmePage.render },
  { path: '/admin/acme/monitor', title: 'ACME enrollments',
    operation: '/admin-api/acme/monitor',
    render: function (view: Json, ctx?: Json): string {
      return AcmePage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/applications', title: 'Applications',
    operation: '/admin-api/applications',
    render: function (view: Json, ctx?: Json): string {
      return ApplicationsPage.body(ctx || WebKit.context(), view);
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
  { path: '/admin/audit', title: 'Audit log',
    operation: '/admin-api/audit',
    render: function (view: Json, ctx?: Json): string {
      return AuditPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/caep', title: 'CAEP',
    operation: '/admin-api/caep',
    render: function (view: Json, ctx?: Json): string {
      return CaepRiscPage.caepBody(ctx || WebKit.context(), view);
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
    render: function (view: Json): string {
      return DevicesPage.registrationHtml(view);
    } },
  { path: '/admin/devices', title: 'Devices',
    operation: '/admin-api/devices', render: DevicesPage.render },
  { path: '/admin/devices/monitor', title: 'Devices (monitoring)',
    operation: '/admin-api/devices/monitor',
    render: function (view: Json): string {
      return DevicesPage.monitorHtml(view);
    } },
  { path: '/admin/encryption', title: 'Encryption',
    operation: '/admin-api/encryption', render: EncryptionPage.render },
  { path: '/admin/error-codes', title: 'Error codes',
    operation: '/admin-api/error-codes',
    render: function (view: Json, ctx?: Json): string {
      return ErrorCodesPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/est', title: 'EST', operation: '/admin-api/est',
    render: EstPage.render },
  { path: '/admin/est/monitor', title: 'EST enrollments',
    operation: '/admin-api/est/monitor',
    render: function (view: Json, ctx?: Json): string {
      return EstPage.monitorBody(ctx || WebKit.context(), view);
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
  { path: '/admin/kerberos/principals', title: 'Kerberos principals',
    operation: '/admin-api/kerberos/principals',
    render: function (view: Json, ctx?: Json): string {
      return KerberosPrincipalsPage.body(ctx || WebKit.context(), view);
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
  { path: '/admin/listeners', title: 'Listeners',
    operation: '/admin-api/listeners', render: ListenersPage.render },
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
  { path: '/admin/pki', title: 'PKI', operation: '/admin-api/pki',
    render: PkiPage.render },
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
    render: function (view: Json, ctx?: Json): string {
      return RealmsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/risc', title: 'RISC',
    operation: '/admin-api/risc',
    render: function (view: Json, ctx?: Json): string {
      return CaepRiscPage.riscBody(ctx || WebKit.context(), view);
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
    render: function (view: Json): string {
      return RiskPage.metricsHtml(view);
    } },
  { path: '/admin/roles', title: 'Roles',
    operation: '/admin-api/roles',
    compose: { preview: '/admin-api/roles/preview' },
    render: function (view: Json, ctx?: Json): string {
      return RolesPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/saml2', title: 'SAML 2.0', operation: '/admin-api/saml2',
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
  { path: '/admin/saml11', title: 'SAML 1.1',
    operation: '/admin-api/saml11',
    drill: {
      param: 'rp',
      sample: function (list: Json): string | null {
        const rows = list.relyingParties || [];
        return rows[0] ? rows[0].identifier : null;
      },
      render: function (view: Json, ctx?: Json): string {
        return SamlPage.saml11Detail(ctx || WebKit.context(), view);
      }
    },
    render: function (view: Json, ctx?: Json): string {
      return SamlPage.saml11Body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/saml-assertions', title: 'SAML assertions',
    operation: '/admin-api/saml-assertions',
    render: function (view: Json, ctx?: Json): string {
      return SamlAssertionsPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/scep', title: 'SCEP', operation: '/admin-api/scep',
    render: ScepPage.render },
  { path: '/admin/scep/monitor', title: 'SCEP enrollments',
    operation: '/admin-api/scep/monitor',
    render: function (view: Json, ctx?: Json): string {
      return ScepPage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/scheduler', title: 'Scheduler',
    operation: '/admin-api/scheduler', render: SchedulerPage.render },
  { path: '/admin/oidfed', title: 'OpenID Federation',
    operation: '/admin-api/oidfed', render: OidfedPage.render },
  { path: '/admin/scim', title: 'SCIM',
    operation: '/admin-api/scim',
    render: function (view: Json, ctx?: Json): string {
      return ScimPage.body(ctx || WebKit.context(), view);
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
  { path: '/admin/ssf', title: 'Shared Signals',
    operation: '/admin-api/ssf',
    render: function (view: Json, ctx?: Json): string {
      return SsfPage.body(ctx || WebKit.context(), view);
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
  { path: '/admin/tokens', title: 'Tokens',
    operation: '/admin-api/tokens',
    render: function (view: Json, ctx?: Json): string {
      return TokensPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/users', title: 'Users', operation: '/admin-api/users',
    render: function (view: Json, ctx?: Json): string {
      return UsersPage.body(ctx || WebKit.context(), view);
    } },
  { path: '/admin/vc-status', title: 'Credential status',
    operation: '/admin-api/vc-status', render: VcStatusPage.render },
  { path: '/admin/xacml', title: 'XACML', operation: '/admin-api/xacml',
    render: XacmlPage.render },
  { path: '/admin/xacml/decide', title: 'Try a decision',
    operation: '/admin-api/xacml/decide',
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.decideBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/xacml/monitor', title: 'XACML decisions',
    operation: '/admin-api/xacml/monitor',
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.monitorBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/xacml/peps', title: 'Remote PEPs',
    operation: '/admin-api/xacml/peps',
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.pepsBody(ctx || WebKit.context(), view);
    } },
  { path: '/admin/xacml/policies', title: 'XACML policies',
    operation: '/admin-api/xacml/policies',
    render: function (view: Json, ctx?: Json): string {
      return XacmlPage.policiesBody(ctx || WebKit.context(), view);
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
  { path: '/admin/kerberos', title: 'Kerberos settings',
    operation: '/admin-api/kerberos',
    render: ProtocolSettingsPage.render },
  { path: '/admin/oauth2', title: 'OAuth 2.0 / OIDC settings',
    operation: '/admin-api/oauth2', render: ProtocolSettingsPage.render },
  { path: '/admin/oid4vci', title: 'OpenID4VCI',
    operation: '/admin-api/oid4vci-settings',
    render: ProtocolSettingsPage.render },
  { path: '/admin/oid4vp', title: 'OpenID4VP',
    operation: '/admin-api/oid4vp-settings',
    render: ProtocolSettingsPage.render },
  { path: '/admin/ldap', title: 'LDAP / LDAPS',
    operation: '/admin-api/ldap', render: ProtocolSettingsPage.render },
  { path: '/admin/wstrust', title: 'WS-Trust',
    operation: '/admin-api/wstrust', render: ProtocolSettingsPage.render },
  { path: '/admin/wsfed', title: 'WS-Federation',
    operation: '/admin-api/wsfed', render: ProtocolSettingsPage.render },
  { path: '/admin/tls', title: 'TLS / mutual TLS',
    operation: '/admin-api/tls', render: ProtocolSettingsPage.render },
  { path: '/admin/vc-verifier-config', title: 'Verifier request',
    operation: '/admin-api/verifier-request',
    render: function (view: Json, ctx?: Json): string {
      return VcVerifierConfigPage.body(ctx || WebKit.context(), view);
    } },
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
  static render(path: string, view: Json, ctx?: Json): string | null {
    const page = WebPages.pageFor(path);
    const context = ctx || WebKit.context();
    if (!page) {
      return null;
    }
    if (page.drill && context.query && context.query[page.drill.param]) {
      return page.drill.render(view, context);
    }
    return page.render(view, context);
  }
}

export = WebPages;
