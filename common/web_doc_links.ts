// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_doc_links.ts
//
// ---------------------------------------------------------------------------
// A LINK TO THE PUBLIC DOCUMENTATION, ON EVERY CONSOLE AND PORTAL PAGE (#895).
//
// The pages are https://rcbj.github.io/iya-sts/ (the front door already
// names that origin). A link is absolute so it works from any deployment.
// Pages are published from main; a heading that exists only on develop
// still opens the page, and the fragment resolves once that heading is
// published. The fragment is a kramdown id of the local markdown: lower
// case, anything but a letter, a digit, a space or a hyphen removed, spaces
// turned into hyphens, repeated hyphens kept.
//
// WHERE IT IS DRAWN. A tabbed page holds one link at the top of each leaf
// panel, so the tab the reader is in names the page that explains it. A
// panel whose markup already contains tabs is only a container — the ACME
// tab above its sub-tabs, a user's credentials tab above the factor tabs —
// and gets none of its own. An untabbed page gets one link under the
// console's trail, or at the top of the portal's main column. The public
// sign-out page uses the same tab helper and is not a console page: its
// ids (`logout-signout`, `logout-details`) are absent here, so it draws
// no link.
//
// A listener's tabs are minted from each listener's id (`tab-` plus that
// id). That shape is also a policy kind's (`tab-password`), so a prefix
// would attach the wrong page. Those panels set `docs` themselves.
// `server` and `clients` are exact for the same reason: the words are not
// this service's.
//
// A `web_` MODULE: it requires nothing, logs nothing, and names nothing of
// node's. `admin-ui/CLAUDE.md` and `portal/CLAUDE.md` say where the link
// is drawn.
// ---------------------------------------------------------------------------

type Json = any;

// Relative to ORIGIN. A value is a page, or a page and a fragment that
// the local markdown actually has.
const CONSOLE: Record<string, string> = {
  '/admin': 'admin-console.html#how-the-console-is-laid-out',
  '/admin/cluster': 'configuration.html#cluster',
  '/admin/acme': 'acme.html',
  '/admin/acme/monitor': 'acme.html',
  '/admin/est': 'est.html',
  '/admin/est/monitor': 'est.html',
  '/admin/scep': 'scep.html',
  '/admin/scep/monitor': 'scep.html',
  '/admin/spiffe': 'spiffe.html',
  '/admin/spiffe/entries': 'spiffe.html',
  '/admin/spiffe/agents': 'spiffe.html',
  '/admin/spiffe/brokers': 'spiffe.html',
  '/admin/applications':
    'applications.html#the-console-page-and-the-api',
  '/admin/applications/new': 'applications.html#adminapplicationsnew',
  '/admin/attribute-sources': 'attribute-sources.html',
  '/admin/authorization-servers':
    'oauth-oidc.html#multiple-authorization-servers--adminauthorization-servers',
  '/admin/caches': 'caches.html',
  '/admin/cert-issuance': 'configure-enrollment.html',
  '/admin/audit': 'admin-console.html#audit-log--adminaudit',
  '/admin/caep-sessions': 'caep-events.html',
  '/admin/caep-sessions/session': 'caep-events.html',
  '/admin/cells': 'cells.html',
  '/admin/claim-providers': 'oauth-oidc.html',
  '/admin/commands': 'oauth-oidc.html',
  '/admin/claims': 'oauth-oidc.html#custom-claims--adminclaims',
  '/admin/config': 'configuration.html',
  '/admin/consent': 'oauth-oidc.html#consent',
  '/admin/crypto-metadata':
    'endpoints.html#the-index-of-its-own-cryptography',
  '/admin/api-explorer': 'management-api.html',
  '/admin/account-api': 'account-api.html',
  '/admin/sts-metadata': 'endpoints.html',
  '/admin/delegation': 'delegation.html',
  '/admin/delegation/allowed': 'delegation.html',
  '/admin/delegation/application': 'delegation.html',
  '/admin/delegation-settings': 'delegation.html',
  '/admin/delegation/user': 'delegation.html',
  '/admin/delegation/cluster': 'delegation.html',
  '/admin/delegation/chain': 'delegation.html',
  '/admin/delegation/map': 'delegation.html',
  '/admin/database': 'persistence.html#checking-on-it',
  '/admin/debugger':
    'admin-console.html#the-embedded-protocol-debugger',
  '/admin/deliveries': 'signing-out.html',
  '/admin/device-registration': 'devices.html',
  '/admin/devices': 'devices.html',
  '/admin/devices/monitor': 'devices.html',
  '/admin/service-accounts': 'service-accounts.html',
  '/admin/encryption': 'encryption-at-rest.html',
  '/admin/error-codes': 'error-codes.html',
  '/admin/federation': 'federation.html',
  '/admin/federation/map': 'federation.html',
  '/admin/geolocation': 'risk-scoring.html',
  '/admin/gnap': 'gnap.html',
  '/admin/gnap/monitor': 'gnap.html',
  '/admin/grants':
    'oauth-oidc.html#grant-management-grant-management-for-oauth-20',
  '/admin/groups': 'admin-console.html#groups--admingroups',
  '/admin/keys':
    'pki.html#signing-key-generations-and-the-crypto-metadata-document',
  '/admin/keys/history':
    'pki.html#signing-key-generations-and-the-crypto-metadata-document',
  '/admin/ldap': 'ldap.html',
  '/admin/ldap/directory': 'ldap.html',
  '/admin/ldap/peps': 'ldap.html',
  '/admin/ldap/policies': 'ldap.html',
  '/admin/ldap/service': 'ldap.html',
  '/admin/ldap/applications': 'ldap.html',
  '/admin/ldap/federations': 'ldap.html',
  '/admin/ldap/devices': 'ldap.html',
  '/admin/ldap/roles': 'ldap.html',
  '/admin/ldap/spiffe': 'spiffe.html',
  '/admin/listeners': 'listeners.html',
  '/admin/logout': 'signing-out.html',
  '/admin/mail': 'mail.html',
  '/admin/broadcast': 'shared-signals.html#broadcast-announcements',
  '/admin/mail/outbox': 'mail.html#where-to-look',
  '/admin/metrics': 'admin-console.html#metrics--adminmetrics',
  '/admin/mode': 'what-is-not-checked.html',
  '/admin/node-health': 'admin-console.html#node-health--adminnode-health',
  '/admin/oauth2': 'oauth-oidc.html',
  '/admin/oauth2/monitor': 'oauth-oidc.html',
  '/admin/post-login-activities':
    'post-login-activities.html#starting-an-activity',
  '/admin/passkey-report':
    'admin-console.html#passkeys--adminpasskey-report',
  '/admin/pki': 'pki.html',
  '/admin/policies': 'admin-console.html#policies--adminpolicies',
  '/admin/rbac': 'admin-console.html#who-may-use-the-console',
  '/admin/realms': 'trust-realms.html',
  '/admin/risc-accounts': 'signals-received.html',
  '/admin/risc-accounts/account': 'signals-received.html',
  '/admin/risk': 'risk-scoring.html',
  '/admin/risk-scoring': 'risk-scoring.html',
  '/admin/roles': 'admin-console.html#roles--adminroles',
  '/admin/saml2': 'saml2-sso.html',
  '/admin/scheduler': 'configuration.html#scheduler',
  '/admin/secret-destinations': 'secret-destinations.html',
  '/admin/oidfed': 'oidfed.html',
  '/admin/scim': 'scim.html',
  '/admin/scim/monitor': 'scim.html',
  '/admin/secrets':
    'encryption-at-rest.html#seeing-the-state-of-it-adminsecrets',
  '/admin/sessions': 'sessions.html',
  '/admin/signals': 'shared-signals.html',
  '/admin/ssf': 'shared-signals.html',
  '/admin/ssf/dead-letters': 'shared-signals.html',
  '/admin/ssf/transmitters': 'shared-signals.html',
  '/admin/tls': 'tls.html',
  '/admin/tls-connection': 'tls.html',
  '/admin/tls/trust': 'tls.html',
  '/admin/token-lifetimes':
    'oauth-oidc.html#token-lifetimes--admintoken-lifetimes',
  '/admin/tokens': 'admin-console.html#tokens--admintokens',
  '/admin/tokens/credential': 'admin-console.html#tokens--admintokens',
  '/admin/tokens/set': 'admin-console.html#tokens--admintokens',
  '/admin/used-assertions': 'jwt-assertions.html',
  '/admin/userinfo-claims':
    'oauth-oidc.html#userinfo-claims--adminuserinfo-claims',
  '/admin/users': 'admin-console.html#users--adminusers',
  '/admin/users/new':
    'admin-console.html#creating-a-person--adminusersnew',
  '/admin/vc': 'verifiable-credentials.html',
  '/admin/vc/monitor':
    'admin-console.html#verifiable-credentials--adminvcmonitor',
  '/admin/kerberos': 'kerberos.html',
  '/admin/xacml': 'xacml.html',
  '/admin/xacml/monitor': 'xacml.html',
  '/admin/backup-codes': 'authentication.html#recovery-codes',
  '/admin/persistence': 'persistence.html',
  '/admin/totp': 'authentication.html#totp-mfa',
  '/admin/webauthn': 'authentication.html#webauthn',
  '/admin/wstrust': 'ws-trust.html',
  '/admin/wsfed': 'ws-federation.html',
  '/admin/worker-pools':
    'admin-console.html#worker-pools--adminworker-pools'
};

// A tab id that does not follow `<slug>-tab-<name>` of its page, or that
// explains a different page than the one it sits on. Checked before the
// slug of the page.
const EXACT: Record<string, string> = {
  'oauth-tab-metadata': 'oauth-oidc.html',
  'oauth-tab-global-settings': 'oauth-oidc.html',
  'oauth-tab-authorization-servers':
    'oauth-oidc.html#multiple-authorization-servers--adminauthorization-servers',
  'oauth-tab-token-lifetimes':
    'oauth-oidc.html#token-lifetimes--admintoken-lifetimes',
  'oauth-tab-claims': 'oauth-oidc.html#custom-claims--adminclaims',
  'oauth-tab-userinfo-claims':
    'oauth-oidc.html#userinfo-claims--adminuserinfo-claims',
  'saml-tab-metadata': 'saml2-sso.html',
  'saml-tab-global-settings': 'configure-saml.html',
  'saml-tab-shared-settings': 'configure-saml.html',
  'saml-tab-saml2': 'saml2-sso.html',
  'saml-tab-saml11': 'saml11.html',
  'saml-tab-idp-initiated': 'idp-initiated-sso.html',
  'saml-tab-assertions': 'saml-assertions.html',
  'saml-tab-attributes':
    'admin-console.html#claims--adminclaims-adminuserinfo-claims-adminsaml-attributes',
  'vc-tab-oid4vci': 'oid4vci.html',
  'vc-tab-claims':
    'admin-console.html#credential-claims-tab--adminvcvc-tab-claims',
  'vc-tab-oid4vp': 'oid4vp.html',
  'vc-tab-verifier-request':
    'admin-console.html#verifier-request-tab--adminvcvc-tab-verifier-request',
  'xacml-tab-settings': 'configure-xacml.html',
  'xacml-tab-peps': 'remote-pep.html',
  'xacml-tab-authzen': 'authzen.html',
  'ssf-tab-caep': 'caep-events.html',
  'ssf-tab-risc': 'signals-received.html',
  'kerberos-tab-settings': 'configure-kerberos.html',
  'cert-tab-metadata': 'configure-enrollment.html',
  'cert-tab-acme': 'acme.html',
  'cert-tab-est': 'est.html',
  'cert-tab-scep': 'scep.html',
  'cert-tab-spiffe': 'spiffe.html',
  'federation-tab-consumer': 'federation-consumer-providers.html',
  'federation-tab-settings': 'configure-federation.html',
  'oidfed-tab-settings': 'configure-oidfed.html',
  'gnap-tab-settings': 'configure-gnap.html',
  'database-tab-schema': 'postgres-schema.html',
  'database-tab-server': 'persistence.html#checking-on-it',
  'deliveries-tab-backchannel-logout':
    'signing-out.html#back-channel-logout',
  'deliveries-tab-ciba': 'configure-oidc-flows.html',
  'deliveries-tab-cell-ops': 'cells.html',
  'deliveries-tab-provider-commands': 'oauth-oidc.html',
  'scim-tab-metadata': 'scim.html',
  'server': 'scim.html',
  'clients': 'scim.html#the-outbound-scim-client',
  'listeners-tab-metadata': 'listeners.html',
  'tab-listeners': 'listeners.html',
  'tab-custom': 'listeners.html',
  'tab-applications': 'listeners.html',
  'tab-defaults': 'listeners.html',
  'policies-tab-metadata': 'admin-console.html#policies--adminpolicies',
  'tab-password': 'authentication.html#passwords',
  'tab-authn': 'authentication.html#the-authentication-policy',
  'tab-serviceAccount': 'service-accounts.html',
  'tab-passkey': 'authentication.html#the-passkey-policy',
  'tab-locale': 'languages.html#the-locale-policy',
  'tab-attributes':
    'configure-scim.html#the-attribute-policy-in-product-mode',
  'tab-profiles': 'admin-console.html#policies--adminpolicies',
  'cfg-families': 'applications.html#the-console-page-and-the-api',
  'cfg-every': 'applications.html#the-console-page-and-the-api',
  'cfg-oauth': 'oauth-oidc.html',
  'cfg-mtls': 'tls.html',
  'cfg-saml': 'configure-saml.html',
  'cfg-saml2': 'saml2-sso.html',
  'cfg-saml11': 'saml11.html',
  'cfg-wsfed': 'ws-federation.html',
  'cfg-wstrust': 'ws-trust.html',
  'cfg-krb5': 'kerberos.html',
  'cfg-vc': 'verifiable-credentials.html',
  'cfg-federation': 'federation.html',
  'cfg-ldap': 'ldap.html',
  'cfg-scim': 'scim.html',
  'cfg-spiffe': 'spiffe.html',
  'cfg-ssf': 'shared-signals.html',
  'cfg-gnap': 'gnap.html',
  'cfg-did': 'applications.html#a-did-describing-an-application',
  'cfg-enroll':
    'applications.html#certificate-enrollment-acme-est-scep',
  'cfg-secret-destination':
    'applications.html#a-secret-push-destination',
  'cfg-scim-client': 'scim.html#the-outbound-scim-client',
  'tab-overview': 'applications.html#the-console-page-and-the-api',
  'tab-config': 'applications.html#the-console-page-and-the-api',
  'tab-metadata': 'applications.html#the-console-page-and-the-api',
  'tab-remove': 'applications.html#the-console-page-and-the-api',
  'tab-authentications':
    'applications.html#what-it-has-been-seen-doing',
  'tab-credentials':
    'pki.html#an-applications-credentials-on-its-own-page',
  'tab-origins':
    'applications.html#cors-which-pages-may-read-an-answer',
  'tab-statements':
    'applications.html#software-statements-rfc-7591-section-23',
  'tab-import-export':
    'applications.html#exporting-and-importing-an-application-as-ldif',
  'tab-scope-claims': 'oauth-oidc.html#custom-claims--adminclaims',
  'tab-signals': 'shared-signals.html',
  'tab-owners': 'management-api.html#owners',
  'tab-roles': 'admin-console.html#roles--adminroles',
  'tab-entry': 'ldap.html',
  'tab-access-types': 'gnap.html#access-types-and-the-issuance-policy',
  'tab-addresses': 'applications.html#the-console-page-and-the-api',
  'tab-permissions': 'delegation.html',
  'utab-overview': 'admin-console.html#users--adminusers',
  'utab-authentications': 'admin-console.html#users--adminusers',
  'utab-activity': 'sessions.html#adminsessions--what-is-live-right-now',
  'utab-attributes':
    'admin-console.html#changing-a-persons-attributes',
  'utab-credentials': 'admin-console.html#users--adminusers',
  'ucred-factors':
    'authentication.html#which-second-factor-is-asked-for',
  'ucred-password': 'authentication.html#passwords',
  'ucred-service': 'service-accounts.html',
  'ucred-keys': 'pki.html#a-persons-credentials-on-their-own-page',
  'ucred-kerberos': 'kerberos.html',
  'utab-federation': 'federation.html',
  'utab-gnap': 'gnap.html',
  'utab-entry': 'admin-console.html#the-persons-directory-entry',
  'utab-signout': 'signing-out.html',
  'gtab-group': 'admin-console.html#groups--admingroups',
  'gtab-owners': 'management-api.html#owners',
  'rtab-role': 'admin-console.html#roles--adminroles',
  'rtab-owners': 'management-api.html#owners'
};

// The longest matching prefix wins. `tab-` is not one: a listener id and
// a policy kind would share it. An unknown application-config family
// still lands on the applications page.
const PREFIXES: Record<string, string> = {
  'ufg-': 'admin-console.html#changing-a-persons-attributes',
  'cfg-': 'applications.html#the-console-page-and-the-api',
  'cert-acme-': 'acme.html',
  'cert-est-': 'est.html',
  'cert-scep-': 'scep.html',
  'cert-spiffe-': 'spiffe.html',
  'tab-custom-': 'listeners.html',
  'passkey-sub-': 'authentication.html#the-passkey-policy'
};

const PORTAL: Record<string, string> = {
  '/portal': 'user-facing-pages.html#the-user-portal',
  '/portal/applications': 'user-facing-pages.html#the-user-portal',
  '/portal/signals': 'shared-signals.html',
  '/portal/sign-ins':
    'risk-scoring.html#what-people-say-about-their-own-sign-ins',
  '/portal/consents': 'oauth-oidc.html#consent',
  '/portal/gnap': 'gnap.html#what-a-person-sees-portalgnap',
  '/portal/email': 'mail.html',
  '/portal/owned/roles': 'admin-console.html#roles--adminroles',
  '/portal/owned/groups': 'admin-console.html#groups--admingroups',
  '/portal/owned/service-accounts': 'service-accounts.html',
  '/portal/owned/applications': 'applications.html',
  '/portal/password': 'authentication.html#passwords',
  '/portal/keys': 'passkeys.html',
  '/portal/mfa': 'authentication.html',
  '/portal/signing-key': 'jwt-assertions.html',
  '/portal/certificates': 'pki.html',
  '/portal/app-passwords':
    'authentication.html#the-password-only-doors-and-app-passwords',
  '/portal/kerberos': 'kerberos.html',
  '/portal/delegate': 'delegation.html',
  '/portal/self-issued': 'oid4vp.html',
  '/portal/self-issued/did': 'oid4vp.html',
  '/portal/wallet': 'oid4vci.html',
  '/portal/devices': 'devices.html',
  '/portal/ciba': 'configure-oidc-flows.html',
  '/portal/device': 'configure-oidc-flows.html',
  '/portal/claim-sources': 'oauth-oidc.html',
  '/portal/connected-accounts': 'federation-consumer-providers.html',
  '/portal/activate': 'user-facing-pages.html#the-user-portal',
  '/portal/reset-password': 'authentication.html#passwords',
  '/portal/verify-email': 'mail.html',
  '/portal/forgot-password': 'mail.html'
};

// `<slug>-tab-<name>` falls back to the page the slug is. `/admin` is not
// a slug: its path does not match the prefix the tab ids are built from.
const SLUGS: Record<string, string> = {};
Object.keys(CONSOLE).forEach(function (consolePath) {
  if (consolePath.indexOf('/admin/') !== 0) {
    return;
  }
  const slug = consolePath.replace(/^\/admin\//, '')
    .replace(/[^a-z0-9]+/gi, '-');
  SLUGS[slug] = CONSOLE[consolePath];
});

/**
 * The documentation link the console and the portal draw.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WebDocLinks {
  /**
   * The published documentation site, with its trailing slash.
   */
  static readonly ORIGIN = 'https://rcbj.github.io/iya-sts/';

  /**
   * Turns a site-relative page into an absolute URL. An absolute URL is
   * returned as it was given.
   *
   * @param rel - `admin-console.html` or that plus a fragment
   * @returns the absolute URL, or '' when there is nothing to link
   */
  static abs(rel: string): string {
    if (!rel) {
      return '';
    }
    if (rel.indexOf('https://') === 0) {
      return rel;
    }
    return WebDocLinks.ORIGIN + rel;
  }

  /**
   * Escapes a URL or a label for an attribute or a text node. Kept here
   * so this module does not require the console's kit.
   *
   * @param value - the text
   * @returns the escaped text
   */
  static esc(value: string): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /**
   * Whether this markup already draws a tab bar. A link is not added
   * above one: the leaf panels carry it.
   *
   * @param html - a panel or a page body
   * @returns true when a tab or sub-tab bar is in it
   */
  static holdsTabs(html: string): boolean {
    return /class="tabs |class="subtabs"/.test(String(html || ''));
  }

  /**
   * The link element, or '' when there is no URL.
   *
   * @param href - an absolute URL
   * @param label - the words, already the reader's
   * @returns the paragraph
   */
  static markup(href: string, label: string): string {
    if (!href) {
      return '';
    }
    return '<p class="doclink"><a href="' + WebDocLinks.esc(href) +
      '" target="_blank" rel="noopener noreferrer">' +
      WebDocLinks.esc(label) + '</a></p>';
  }

  /**
   * The console's link. The English word is what a translator without
   * the catalog draws, so a key name is never the label.
   *
   * @param href - an absolute URL, or null
   * @param t - the page's translator
   * @returns the paragraph, or ''
   */
  static consoleHtml(href: string | null, t?: Json): string {
    if (!href) {
      return '';
    }
    let label = 'Documentation';
    if (t && typeof t.has === 'function' &&
        t.has('consoleKit.docsLink') &&
        typeof t.text === 'function') {
      label = t.text('consoleKit.docsLink');
    }
    return WebDocLinks.markup(href, label);
  }

  /**
   * The portal's link. Same shape as the console's, its own catalog key.
   *
   * @param href - an absolute URL, or null
   * @param t - the page's translator
   * @returns the paragraph, or ''
   */
  static portalHtml(href: string | null, t?: Json): string {
    if (!href) {
      return '';
    }
    let label = 'Documentation';
    if (t && typeof t.has === 'function' &&
        t.has('portal.docsLink') &&
        typeof t.text === 'function') {
      label = t.text('portal.docsLink');
    }
    return WebDocLinks.markup(href, label);
  }

  /**
   * The documentation for a console path, including a page the static
   * table does not list (`/admin/cluster`, which the server still draws).
   *
   * @param consolePath - `/admin/...`
   * @returns the absolute URL, or null
   */
  static forConsolePage(consolePath: string): string | null {
    const rel = CONSOLE[String(consolePath || '')];
    if (!rel) {
      return null;
    }
    return WebDocLinks.abs(rel);
  }

  /**
   * The documentation for one tab id. An exact id, then the longest
   * prefix, then the page whose slug the id starts with. Nothing matches
   * the public sign-out tabs.
   *
   * @param id - the panel's id
   * @returns the absolute URL, or null
   */
  static forConsoleTab(id: string): string | null {
    const key = String(id || '');
    if (!key) {
      return null;
    }
    if (EXACT[key]) {
      return WebDocLinks.abs(EXACT[key]);
    }
    let best = '';
    let rel = '';
    Object.keys(PREFIXES).forEach(function (prefix) {
      if (key.indexOf(prefix) === 0 && prefix.length > best.length) {
        best = prefix;
        rel = PREFIXES[prefix];
      }
    });
    if (best) {
      return WebDocLinks.abs(rel);
    }
    const at = key.indexOf('-tab-');
    if (at > 0) {
      const page = SLUGS[key.slice(0, at)];
      if (page) {
        return WebDocLinks.abs(page);
      }
    }
    return null;
  }

  /**
   * The documentation for a portal path, signed in or not.
   *
   * @param portalPath - `/portal/...`
   * @returns the absolute URL, or null
   */
  static forPortalPage(portalPath: string): string | null {
    const rel = PORTAL[String(portalPath || '')];
    if (!rel) {
      return null;
    }
    return WebDocLinks.abs(rel);
  }
}

export = WebDocLinks;
