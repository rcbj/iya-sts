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
import AttributeSourcesPage =
  require('../attribute-sources/web_attribute_sources');
import CachesPage = require('./web_caches');
import CellsPage = require('./web_cells');
import ClaimsProvidersPage =
  require('../oauth-oidc/web_claims_providers');
import CryptoMetadataPage = require('./web_crypto_metadata');
import DatabasePage = require('./web_database');
import DebuggerPage = require('../debugger/web_debugger');
import DevicesPage = require('./web_devices');
import EncryptionPage = require('./web_encryption');
import EstPage = require('../est/web_est');
import GeolocationPage = require('./web_geolocation');
import GnapPage = require('../gnap/web_gnap');
import GrantsPage = require('../oauth-oidc/web_grants');
import ListenersPage = require('./web_listeners');
import MailPage = require('./web_mail');
import MailOutboxPage = require('./web_mail_outbox');
import MetricsPage = require('./web_metrics');
import ModePage = require('./web_mode');
import NodeHealthPage = require('./web_node_health');
import PkiPage = require('./web_pki');
import OidfedPage = require('../oidfed/web_oidfed');
import ProviderCommandsPage =
  require('../oauth-oidc/web_provider_commands');
import OAuth2MonitorPage = require('../oauth-oidc/web_oauth2_monitor');
import RiskPage = require('./web_risk');
import SamlAssertionsPage = require('./web_saml_assertions');
import SchedulerPage = require('./web_scheduler');
import ScepPage = require('../scep/web_scep');
import SecretsPage = require('./web_secrets');
import SettingsForms = require('./web_settings');
import SsfTransmittersPage = require('../ssf/web_ssf_transmitters');
import TokenLifetimesPage = require('./web_token_lifetimes');
import VcStatusPage = require('./web_vc_status');
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
  { path: '/admin/attribute-sources', title: 'Attribute sources',
    operation: '/admin-api/attribute-sources',
    render: AttributeSourcesPage.render },
  { path: '/admin/caches', title: 'Caches', operation: '/admin-api/caches',
    render: CachesPage.render },
  { path: '/admin/cells', title: 'Cells', operation: '/admin-api/cells',
    render: CellsPage.render },
  { path: '/admin/claim-providers', title: 'Claims Providers',
    operation: '/admin-api/claim-providers',
    render: ClaimsProvidersPage.render },
  { path: '/admin/commands', title: 'OpenID Provider Commands',
    operation: '/admin-api/commands', render: ProviderCommandsPage.render },
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
  { path: '/admin/est', title: 'EST', operation: '/admin-api/est',
    render: EstPage.render },
  { path: '/admin/est/monitor', title: 'EST enrollments',
    operation: '/admin-api/est/monitor',
    render: function (view: Json, ctx?: Json): string {
      return EstPage.monitorBody(ctx || WebKit.context(), view);
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
  { path: '/admin/risk', title: 'Risk', operation: '/admin-api/risk',
    render: RiskPage.render },
  { path: '/admin/risk-scoring', title: 'Risk scoring',
    operation: '/admin-api/risk/metrics',
    render: function (view: Json): string {
      return RiskPage.metricsHtml(view);
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
  { path: '/admin/secrets', title: 'Secret store',
    operation: '/admin-api/secrets', render: SecretsPage.render },
  { path: '/admin/ssf/transmitters', title: 'Signals from partners',
    operation: '/admin-api/ssf/transmitters',
    render: SsfTransmittersPage.render },
  { path: '/admin/token-lifetimes', title: 'Token lifetimes',
    operation: '/admin-api/token-lifetimes',
    render: function (view: Json, ctx?: Json): string {
      return TokenLifetimesPage.body(ctx || WebKit.context(), view);
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
   * Draws a converted page's body from its operation's answer.
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
    return page ? page.render(view, ctx || WebKit.context()) : null;
  }
}

export = WebPages;
