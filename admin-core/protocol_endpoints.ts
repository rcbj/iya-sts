'use strict';
//
// File: protocol_endpoints.ts
//
// ---------------------------------------------------------------------------
// WHAT EACH PROTOCOLS PAGE LISTS AS "THE ENDPOINTS OF THIS REALM" (2026-09-13).
//
// rcbj asked that every page under Protocols list the concrete endpoints the
// current trust realm answers on for that protocol, the way Protocols -> GNAP
// already did. GNAP's list is written out in `gnap/gnap_console.ts` and stays
// there; this file is the same thing for every other page, and it is ONE TABLE
// rather than forty hand-written lists for three reasons:
//
// * **THE NAME OF AN ENDPOINT ALREADY HAS A HOME.** `sts_metadata.js`'s
//   `ENDPOINTS` describes every route this service registers, and its own job
//   fails when one is undescribed. A page here names a ROUTE and the name comes
//   from there, so there is one copy of what `/saml2/ars` is called.
// * **THE URL IS COMPUTED, NEVER WRITTEN.** `baseUrlOf(req)` carries the
//   ambient realm's prefix, so the same row reads
//   `https://host/realm/acme/oauth2/token` under that realm and
//   `https://host/oauth2/token` in the default one — which is the whole of
//   "concrete for the current realm".
// * **THE TWO SURFACES READ IT AT THEIR TRANSPORT EDGES.** `admin.respond()`
//   adds `protocolEndpoints` to a Protocols page's JSON and draws the section,
//   and `mgmt-api/admin_api.ts` adds the same member to the operation that
//   `mirrors` that page, so no view function had to learn a new argument and
//   the page and the operation cannot disagree (rule 7).
//
// **WHICH ROUTES A PAGE LISTS IS A JUDGEMENT, AND IT IS WRITTEN HERE ONCE.** A
// family's own page lists the family's protocol endpoints; a page about one
// aspect of a family lists the endpoints that aspect changes the answer of —
// Token lifetimes lists what issues a token, not the discovery documents.
// Console pages and the management API are never listed: they are not the
// protocol, and the realm's copy of them is the page the reader is on.
//
// **SOCKETS ARE WRITTEN BY HAND, AND ONLY THERE.** The KDC, the protected
// Kerberos service, both directory listeners and SPIFFE's gRPC sockets
// register no route, so the router cannot see them —
// the blind spot `sts_metadata.js` states about itself. Their rows are built
// here from the settings those listeners bind from, and SPIFFE's from the
// realm's actual bindings, since a SPIFFE realm is told apart by ADDRESS. The
// KDC's sockets and the main port's client-certificate handshake are shared by
// every realm and carry no prefix — the KDC row names this realm's Kerberos
// realm, which is what routes a request there (since 2026-09-15); the
// directory's rows carry the realm's own base DN.
//
// ---------------------------------------------------------------------------
// WHY EVERY ROUTE-REGISTERING MODULE IS READ OUT OF `require.cache`.
//
// This file is required by `admin-ui/admin.ts` at 18. `sts_metadata.js` must be
// required LAST, and `ldap/ldap_server.js`, `spiffe/spiffe_server.ts` and the
// Kerberos modules register routes when first required (rule 1), so a require
// of any of them from here would either close a cycle or drag routes ahead of
// the console. (Since #50's R1 (2026-09-16) `spiffe_server.ts` registers
// nothing when required — `common/protocol_stack.ts` registers its routes at
// 23 — but it requires the console, so a require of it from here is still a
// cycle; `ldap_server.js`, `sts_metadata.js` and the Kerberos modules are
// still JavaScript and still register when required.)
// `certificate_views.ts` answers the same problem with a require
// inside the function, which is a cache hit once the stack is up; this file
// goes one step further and NEVER loads one: `loaded()` hands back the module
// only if something else already did. An in-process test that loads the
// console without the stack gets rows named by their paths, and no router is
// reordered by asking.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ProtocolEndpoints` takes `path`, `require.cache` and this file's
// directory (for `loaded()`), `config`, `realms`, the logger, the base-URL
// reader and the authorization-server registry through its constructor.
// THE TABLE and the socket builders call the row builders, which are
// methods now, so the constructor builds both. Since R2 the composition root
// (`common/protocol_stack.ts`) builds the instance, and the three old names
// are FACADES that forward to it, for `admin-ui/admin.ts`,
// `mgmt-api/admin_api.ts` and the test; a process without the root builds a
// default at load, which is when the tables were built before.
// `ProtocolEndpoints` is exported beside them for the root.
// ---------------------------------------------------------------------------

import path = require('path');
import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import authorizationServers = require('../oauth-oidc/authorization_servers');
import InstanceSlot = require('../common/instance_slot');

const OAUTH_ISSUING = ['/oauth2/authorize', '/oauth2/token',
                       '/oauth2/introspect', '/oauth2/revoke'];
const SAML_ISSUING = ['/saml2/sso', '/saml2/ars', '/saml11/sso',
                      '/saml11/responder', '/sts', '/wsfed'];
const SSF_DELIVERY = ['/.well-known/ssf-configuration', '/ssf/stream',
                      '/ssf/status', '/ssf/subjects/add',
                      '/ssf/subjects/remove', '/ssf/verify', '/ssf/poll',
                      '/ssf/receive', '/ssf/received'];
// The Protocols pages with no row, each with the reason. A page here is one
// that lists its endpoints itself; `tests/protocol_endpoints.js` fails on a
// Protocols page that is in neither table.
const EXEMPT = {
  '/admin/gnap': 'draws its own list from gnap/gnap_console.ts, and was the ' +
                 'model for this table'
};

// One entry of THE TABLE: a route, a route per named server, or a socket.
interface Entry {
  route?: string;
  perServer?: boolean;
  shape?: string | null;
  socket?: string;
}

// One row a page lists.
interface EndpointRow {
  name: string;
  methods: string[];
  url: string;
  route?: string;
  transport?: string;
  registered?: boolean;
  listening?: boolean;
}

// A listener the router cannot see, built for the realm's host.
type SocketBuilder = (host?: string) => EndpointRow[];

interface ProtocolEndpointsDeps {
  path: typeof path;
  // Where a loaded module is looked for, and the directory `loaded()`'s
  // relative paths start from — `require.cache` and this file's directory.
  cache: typeof require.cache;
  dir: string;
  config: typeof config;
  log: typeof helpers.log;
  baseUrlOf: typeof helpers.baseUrlOf;
  realms: typeof realms;
  authorizationServers: typeof authorizationServers;
}

class ProtocolEndpoints {
  // THE TABLE and the socket builders, built once when the instance is — by
  // the composition root, or at load for a process without one, which is
  // when they were built before.
  private readonly pagesTable: Record<string, Entry[]>;
  private readonly sockets: Record<string, SocketBuilder>;

  constructor(private readonly deps: ProtocolEndpointsDeps) {
    deps.log.debug("Entering ProtocolEndpoints.constructor().");
    this.pagesTable = this.buildPages();
    this.sockets = this.buildSockets();
    deps.log.debug("Leaving ProtocolEndpoints.constructor().");
  }

  // What the composition root passes, from the real modules: `require.cache`
  // and this file's directory for `loaded()`, as before.
  static defaultDeps(): ProtocolEndpointsDeps {
    helpers.log.debug("Entering ProtocolEndpoints.defaultDeps().");
    helpers.log.debug("Leaving ProtocolEndpoints.defaultDeps().");
    return {
      path: path,
      cache: require.cache,
      dir: __dirname,
      config: config,
      log: helpers.log,
      baseUrlOf: helpers.baseUrlOf,
      realms: realms,
      authorizationServers: authorizationServers
    };
  }

  // ---------------------------------------------------------------------------
  // THE TABLE. Keyed by the console path, which is what `SECTIONS`,
  // `respond()`'s `active` and the management API's `mirrors` all already
  // carry. Every page under Protocols but `/admin/gnap` has a row, and
  // `tests/protocol_endpoints.js` fails on a Protocols page without one — GNAP
  // is exempt because it draws its own list and was the model for this one.
  // ---------------------------------------------------------------------------
  private buildPages(): Record<string, Entry[]> {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.buildPages().");
    const route = this.route.bind(this);
    const namedServerRoutes = [
      this.perServer('/.well-known/oauth-authorization-server/*',
                     '/.well-known/oauth-authorization-server/{as}'),
      this.perServer('/*/.well-known/openid-configuration',
                     '/{as}/.well-known/openid-configuration'),
      this.perServer('/:as/oauth2/authorize'),
      this.perServer('/:as/oauth2/token'),
      this.perServer('/:as/oauth2/par'),
      this.perServer('/:as/oauth2/userinfo'),
      this.perServer('/:as/oauth2/introspect'),
      this.perServer('/:as/oauth2/revoke'),
      this.perServer('/:as/oauth2/register'),
      this.perServer('/:as/oauth2/logout'),
      this.perServer('/:as/oauth2/fapi'),
      this.perServer('/:as/oauth2/jwks')
    ];
    log.debug("Leaving ProtocolEndpoints.buildPages().");
    return {
      '/admin/oauth2': [
        '/.well-known/openid-configuration',
        '/.well-known/oauth-authorization-server', '/oauth2/authorize',
        '/oauth2/par', '/oauth2/token', '/oauth2/userinfo', '/oauth2/jwks',
        '/oauth2/introspect',
        '/oauth2/revoke', '/oauth2/register', '/oauth2/register/:client_id',
        '/oauth2/logout', '/oauth2/consent', '/oauth2/rfc9700',
        '/oauth2/oauth21',
        '/oauth2/fapi',
        '/dpop/nonce-mode'
      ].map(route),
      '/admin/authorization-servers': namedServerRoutes,
      '/admin/token-lifetimes': OAUTH_ISSUING.map(route),
      '/admin/claims': ['/oauth2/token', '/oauth2/userinfo',
                        '/oauth2/introspect'].map(route),
      '/admin/userinfo-claims': [this.route('/oauth2/userinfo'),
                                 this.perServer('/:as/oauth2/userinfo')],
      '/admin/saml2': [
        '/saml2', '/saml2/metadata', '/saml2/metadata/:sp', '/saml2/sso',
        '/saml2/sso/:sp', '/saml2/ars', '/saml2/ars/:sp', '/saml2/slo',
        '/saml2/slo/:sp', '/saml2/sp'
      ].map(route),
      '/admin/saml11': [
        '/saml11', '/saml11/metadata', '/saml11/metadata/:rp', '/saml11/sso',
        '/saml11/sso/:rp', '/saml11/responder', '/saml11/responder/:rp',
        '/saml11/rp'
      ].map(route),
      '/admin/saml-assertions': SAML_ISSUING.map(route),
      '/admin/saml-attributes': SAML_ISSUING.map(route),
      '/admin/oid4vci': [
        '/.well-known/openid-credential-issuer', '/.well-known/jwt-vc-issuer',
        '/oid4vci/nonce', '/oid4vci/credential', '/oid4vci/deferred_credential',
        '/oid4vci/notification', '/oid4vci/credential-offer/:id', '/issuer',
        '/issuer/offer', '/bbs/keys/:id', '/.well-known/did.json', '/did.json',
        '/.well-known/did-configuration.json'
      ].map(route),
      '/admin/vc': ['/.well-known/openid-credential-issuer',
                    '/oid4vci/credential',
                    '/oid4vci/deferred_credential', '/issuer/offer'].map(route),
      '/admin/oid4vp': [
        '/oid4vp/verifier', '/oid4vp/start', '/oid4vp/request/:id',
        '/oid4vp/response', '/oid4vp/result/:state', '/oid4vp/done',
        // The wallet sign-in (#38), whose four settings are on this page.
        '/authn/wallet', '/authn/wallet/wait'
      ].map(route),
      // THE STATUS LISTS (#38's follow-ups): what a verifier fetches to ask
      // whether a credential this realm issued is still good, and the
      // credential endpoints that put the reference in it.
      '/admin/vc-status': [
        '/oid4vci/status-lists/1', '/oid4vci/status-lists',
        '/oid4vci/status-lists/bitstring/:purpose', '/oid4vci/credential',
        '/oid4vci/deferred_credential'
      ].map(route),
      '/admin/vc-verifier-config': ['/oid4vp/verifier', '/oid4vp/start',
                                    '/oid4vp/request/:id',
                                    '/oid4vp/response'].map(route),
      '/admin/spiffe': [this.route('/spiffe'), this.route('/spiffe/bundle'),
                        this.route('/spiffe/federated/:trustDomain'),
                        this.socket('spiffe-workload'),
                        this.socket('spiffe-server')],
      '/admin/spiffe/entries': [this.socket('spiffe-server'),
                                this.socket('spiffe-workload')],
      '/admin/spiffe/agents': [this.socket('spiffe-server'),
                               this.route('/spiffe/bundle')],
      // The SPIFFE Broker API's own listener (#170).
      '/admin/spiffe/brokers': [this.socket('spiffe-broker'),
                                this.route('/spiffe/bundle')],
      '/admin/xacml': [
        '/xacml', '/xacml/pdp', '/xacml/policies', '/xacml/protected',
        '/xacml/pep/register', '/xacml/pep/policies', '/xacml/pep/heartbeat',
        '/xacml/pip'
      ].map(route),
      '/admin/xacml/policies': ['/xacml/policies',
                                '/xacml/pep/policies'].map(route),
      '/admin/xacml/editor': ['/xacml/policies', '/xacml/pdp'].map(route),
      '/admin/xacml/peps': ['/xacml/pep/register', '/xacml/pep/policies',
                            '/xacml/pep/heartbeat', '/xacml/pip'].map(route),
      '/admin/xacml/decide': ['/xacml/pdp', '/xacml/protected',
                              '/xacml/pip'].map(route),
      '/admin/scim': [
        '/scim', '/scim/v2/ServiceProviderConfig', '/scim/v2/ResourceTypes',
        '/scim/v2/ResourceTypes/:id', '/scim/v2/Schemas',
        '/scim/v2/Schemas/:id',
        '/scim/v2/Users', '/scim/v2/Users/.search', '/scim/v2/Users/:id',
        '/scim/v2/Groups', '/scim/v2/Groups/.search', '/scim/v2/Groups/:id',
        '/scim/v2/.search', '/scim/v2/Bulk', '/scim/v2/Me',
        '/.well-known/hoba/register'
      ].map(route),
      '/admin/ssf': ['/ssf'].concat(SSF_DELIVERY).map(route),
      '/admin/caep': SSF_DELIVERY.map(route),
      '/admin/risc': SSF_DELIVERY.map(route),
      '/admin/federation': ['/federation', '/federation/login/:id',
                            '/federation/acs/:id', '/federation/link/:handle',
                            '/federation/metadata/:id',
                            '/federation/slo/:id',
                            '/federation/backchannel-logout/:id',
                            '/federation/frontchannel-logout/:id',
                            '/authn/select-idp'].map(route),
      '/admin/totp': ['/authn/totp', '/portal/mfa'].map(route),
      '/admin/backup-codes': ['/authn/backup-code', '/portal/mfa'].map(route),
      '/admin/webauthn': ['/authn/webauthn', '/portal/keys',
                          '/portal/remove-key'].map(route),
      '/admin/kerberos': [this.socket('kdc'), this.socket('krb5-service'),
                          this.route('/KdcProxy'),
                          this.route('/krb5/principals'),
                          this.route('/krb5/service'), this.route('/spnego'),
                          this.route('/spnego/protected'),
                          this.route('/authn/spnego')],
      '/admin/kerberos/principals': [this.socket('kdc'),
                                     this.route('/KdcProxy'),
                                     this.route('/krb5/principals')],
      '/admin/ldap': [this.socket('ldap')],
      '/admin/wstrust': ['/sts', '/sts/cert'].map(route),
      '/admin/wsfed': ['/wsfed',
                       '/FederationMetadata/2007-06/FederationMetadata.xml',
                       '/wsfed/rp'].map(route),
      '/admin/pki': ['/pki/revocation', '/pki/ca/:scope/:ca',
                     '/pki/crl/:scope/:ca', '/pki/ocsp/:scope/:ca',
                     '/pki/chain/:scope/:certificate'].map(route),
      '/admin/tls': [this.socket('tls'), this.route('/tls'),
                     this.route('/tls/forwarded'),
                     this.route('/tls/server-certificate'),
                     this.route('/tls/trust'),
                     this.route('/tls/trust/clear')],
      '/admin/tls/trust': [this.socket('tls'), this.route('/tls/trust'),
                           this.route('/tls/trust/clear')],
      // CERTIFICATE ENROLLMENT (2026-09-13). Each row is the family's
      // registered Express paths, owned by that family's build; see acme/, est/
      // and scep/.
      // ===== ACME endpoints row =====
      '/admin/acme': [
        '/enroll/acme/directory', '/enroll/acme/new-nonce',
        '/enroll/acme/new-account', '/enroll/acme/new-order',
        '/enroll/acme/account/:id', '/enroll/acme/account/:id/orders',
        '/enroll/acme/order/:id', '/enroll/acme/order/:id/finalize',
        '/enroll/acme/authz/:id', '/enroll/acme/challenge/:id',
        '/enroll/acme/cert/:id', '/enroll/acme/revoke-cert',
        '/enroll/acme/key-change', '/enroll/acme/renewal-info/:id'
      ].map(route),
      // ===== EST endpoints row =====
      '/admin/est': [
        '/.well-known/est/cacerts', '/.well-known/est/simpleenroll',
        '/.well-known/est/simplereenroll', '/.well-known/est/serverkeygen',
        '/.well-known/est/csrattrs', '/.well-known/est/fullcmc',
        '/.well-known/est/:label/cacerts',
        '/.well-known/est/:label/simpleenroll',
        '/.well-known/est/:label/simplereenroll',
        '/.well-known/est/:label/serverkeygen',
        '/.well-known/est/:label/csrattrs', '/.well-known/est/:label/fullcmc'
      ].map(route),
      // ===== OpenID Federation endpoints row (#132) =====
      '/admin/oidfed': [
        '/.well-known/openid-federation', '/oidfed/fetch', '/oidfed/list',
        '/oidfed/resolve', '/oidfed/trust-mark', '/oidfed/trust-mark-status',
        '/oidfed/trust-mark-list', '/oidfed/historical-keys',
        '/oidfed/register', '/oidfed/extended-list', '/oidfed/collection',
        '/oidfed/subordinate-events'
      ].map(route),
      // ===== SCEP endpoints row =====
      '/admin/scep': [
        '/enroll/scep', '/enroll/scep/pkiclient.exe', '/enroll/scep/:profile',
        '/enroll/scep/:profile/pkiclient.exe'
      ].map(route)
    };
  }

  // The listeners the router cannot see. Each builder takes the realm's host.
  private buildSockets(): Record<string, SocketBuilder> {
    const { log, config } = this.deps;
    const self = this;
    log.debug("Entering ProtocolEndpoints.buildSockets().");
    log.debug("Leaving ProtocolEndpoints.buildSockets().");
    return {
      kdc: function (host) {
        log.debug("Entering the kdc socket builder.");
        const kdc = self.loaded('../kerberos/krb5_kdc');
        const port = config.value('krb5.kdcPort');
        const realm = kdc ? ' (realm ' + kdc.REALM + ')' : '';
        log.debug("Leaving the kdc socket builder.");
        return [
          { name: 'Key Distribution Center' + realm, methods: [],
            url: 'tcp://' + host + ':' + port, transport: 'TCP' },
          { name: 'Key Distribution Center' + realm, methods: [],
            url: 'udp://' + host + ':' + port, transport: 'UDP' }
        ];
      },
      'krb5-service': function (host) {
        log.debug("Entering the krb5-service socket builder.");
        log.debug("Leaving the krb5-service socket builder.");
        return [{ name: 'The protected Kerberos service (AP-REQ)', methods: [],
                  url: 'tcp://' + host + ':' + config.value('krb5.servicePort'),
                  transport: 'TCP' }];
      },
      ldap: function (host) {
        log.debug("Entering the ldap socket builder.");
        const directory = self.loaded('../ldap/ldap_server');
        // The realm's own tree, rooted at its domain — what a client of this
        // realm searches under on the one shared socket.
        const dn = directory ? directory.baseDn()
                             : realms.baseDnOf(realms.current());
        const rows = [];
        if (config.value('ldap.plainListener')) {
          rows.push({ name: 'LDAP', methods: [],
                      url: 'ldap://' + host + ':' + config.value('ldap.port') +
                           '/' + dn,
                      transport: 'TCP' });
        }
        rows.push({ name: 'LDAPS', methods: [],
                    url: 'ldaps://' + host + ':' +
                         config.value('ldap.tlsPort') +
                         '/' + dn,
                    transport: 'TLS' });
        log.debug("Leaving the ldap socket builder.");
        return rows;
      },
      tls: function (host) {
        log.debug("Entering the tls socket builder.");
        // ONE ROW SINCE 2026-09-16, and it is the MAIN port. This was the 8443
        // and 9443 listeners, both deleted; what a client certificate is
        // presented to is the port everything else answers on, which asks for
        // one and requires none.
        //
        // SHARED BY EVERY REALM: a TLS handshake has no path to carry a realm
        // in, so this answers the same under every prefix and carries none.
        log.debug("Leaving the tls socket builder.");
        return [
          { name: 'Client certificates on the main port', methods: [],
            url: 'https://' + host + ':' + config.value('global.port') + '/',
            transport: 'TLS (a client certificate asked for, never required)' }
        ];
      },
      'spiffe-workload': function () {
        log.debug("Entering the spiffe-workload socket builder.");
        log.debug("Leaving the spiffe-workload socket builder.");
        return self.spiffeRows('workload');
      },
      'spiffe-server': function () {
        log.debug("Entering the spiffe-server socket builder.");
        log.debug("Leaving the spiffe-server socket builder.");
        return self.spiffeRows('server');
      },
      'spiffe-broker': function () {
        log.debug("Entering the spiffe-broker socket builder.");
        log.debug("Leaving the spiffe-broker socket builder.");
        return self.spiffeRows('broker');
      }
    };
  }

  // A route, by its Express path, exactly as `sts_metadata.js` keys it.
  private route(expressPath: string): Entry {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.route().");
    log.debug("Leaving ProtocolEndpoints.route().");
    return { route: expressPath };
  }

  // A route repeated once per NAMED authorization server in this realm, with
  // `:as` (or the `*` of a well-known document) filled with each one's id. The
  // default server is the page's family route and is never repeated here.
  private perServer(expressPath: string, shape?: string): Entry {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.perServer().");
    log.debug("Leaving ProtocolEndpoints.perServer().");
    return { route: expressPath, perServer: true, shape: shape || null };
  }

  // A listener that registers no route. `kind` selects a builder in SOCKETS.
  private socket(kind: string): Entry {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.socket().");
    log.debug("Leaving ProtocolEndpoints.socket().");
    return { socket: kind };
  }

  // The module at `relative` if something has ALREADY loaded it, and null
  // otherwise. See the header: asking must never be what loads it.
  private loaded(relative) {
    const { path, log, cache, dir } = this.deps;
    log.debug("Entering ProtocolEndpoints.loaded(). module=" + relative);
    const cached = cache[path.join(dir, relative) + '.js'];
    log.debug("Leaving ProtocolEndpoints.loaded(). " + (cached ? "loaded" :
                                                        "not loaded"));
    return cached ? cached.exports : null;
  }

  // `:name` becomes `{name}` and a trailing `*` becomes `{path}`, which is how
  // GNAP's list writes a variable segment and how a reader copies one.
  private templated(expressPath) {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.templated().");
    log.debug("Leaving ProtocolEndpoints.templated().");
    return expressPath.replace(/:([A-Za-z_]+)/g, '{$1}')
                      .replace(/\*$/, '{path}');
  }

  // The host a client reaches this service by, for the sockets that share it.
  private hostOf(base) {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.hostOf().");
    let host = '';
    try {
      host = new URL(base).hostname;
    } catch (e) {
      // A base URL that does not parse is `global.publicBaseUrl` set to
      // something odd; the sockets are still worth listing, by setting name.
      log.debug("Caught in ProtocolEndpoints.hostOf(): " + ((e && e.message) ||
                                                            e));
    }
    log.debug("Leaving ProtocolEndpoints.hostOf().");
    return host || 'localhost';
  }

  // `sts_metadata.js`'s description of each route, joined to the router's own
  // methods. Empty maps when that module is not loaded.
  private catalogue() {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.catalogue().");
    const metadata = this.loaded('../sts_metadata');
    const names = new Map();
    const methods = new Map();
    if (metadata) {
      metadata.ENDPOINTS.forEach(function (row) {
        names.set(row.path, row.name);
      });
      metadata.registeredRoutes().forEach(function (row) {
        methods.set(row.path, row.methods);
      });
    }
    log.debug("Leaving ProtocolEndpoints.catalogue(). loaded=" + !!metadata);
    return { loaded: !!metadata, names: names, methods: methods };
  }

  // The named authorization servers of this realm, default excluded.
  private namedServers() {
    const { log, authorizationServers } = this.deps;
    log.debug("Entering ProtocolEndpoints.namedServers().");
    const ids = authorizationServers.list().map(function (profile) {
      return profile.id;
    }).filter(function (id) {
      return id && id !== authorizationServers.DEFAULT_ID;
    });
    log.debug("Leaving ProtocolEndpoints.namedServers(). " + ids.length +
              " server(s).");
    return ids;
  }

  // SPIFFE's bindings for THIS realm only. `bindings()` reports every realm's
  // sockets and marks each with its realm, empty for the default.
  private spiffeRows(surface) {
    const { log, realms } = this.deps;
    log.debug("Entering ProtocolEndpoints.spiffeRows(). surface=" + surface);
    const server = this.loaded('../spiffe/spiffe_server');
    if (!server) {
      log.debug("Leaving ProtocolEndpoints.spiffeRows(). SPIFFE is not " +
                "loaded.");
      return [];
    }
    const here = realms.currentId() === realms.DEFAULT_ID ? '' :
                 realms.currentId();
    const now = server.bindings();
    const list = surface === 'workload' ? now.workload
      : surface === 'broker' ? (now.broker || []) : now.api;
    const rows = list.filter(function (binding) {
      return String(binding.realm || '') === here;
    }).map(function (binding) {
      return {
        name: surface === 'workload' ? 'SPIFFE Workload API (gRPC)' :
              surface === 'broker' ? 'SPIFFE Broker API (gRPC)' :
              'SPIRE Server API (gRPC)',
        methods: [],
        url: binding.address,
        transport: binding.socket ? 'unix socket' :
                   (binding.tls ? 'gRPC over TLS' : 'gRPC'),
        listening: !!binding.listening
      };
    });
    log.debug("Leaving ProtocolEndpoints.spiffeRows(). " + rows.length +
              " row(s).");
    return rows;
  }

  // One HTTP row. `registered` is false when the stack is up and the router has
  // no such route — a rename that left this table behind, which the page shows
  // and `tests/protocol_endpoints.js` fails on rather than listing a dead URL
  // as though it answered.
  private httpRow(base, known, expressPath, shownPath?,
                  name?): EndpointRow {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.httpRow().");
    const row: EndpointRow = {
      name: name || known.names.get(expressPath) || expressPath,
      methods: known.methods.get(expressPath) || [],
      url: base + (shownPath || this.templated(expressPath)),
      route: expressPath
    };
    if (known.loaded && !known.methods.has(expressPath)) {
      row.registered = false;
    }
    log.debug("Leaving ProtocolEndpoints.httpRow().");
    return row;
  }

  // ---------------------------------------------------------------------------
  // The endpoints `page` lists in the current realm, or null for a page that is
  // not a Protocols page in the table. An array, always, for a page that is —
  // empty is an answer (a SPIFFE realm with nothing bound, no named server).
  // ---------------------------------------------------------------------------
  forPage(req, page) {
    const { log, baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering ProtocolEndpoints.forPage(). page=" + page);
    const entries = this.pagesTable[page];
    if (!entries) {
      log.debug("Leaving ProtocolEndpoints.forPage(). Not a listed page.");
      return null;
    }
    const base = baseUrlOf(req);
    const host = this.hostOf(base);
    const known = this.catalogue();
    const servers = entries.some(function (entry) { return entry.perServer; }) ?
                    this.namedServers() : [];
    const rows = [];
    entries.forEach(function (entry) {
      if (entry.socket) {
        self.sockets[entry.socket](host)
          .forEach(function (row) { rows.push(row); });
        return;
      }
      if (!entry.perServer) {
        rows.push(self.httpRow(base, known, entry.route));
        return;
      }
      servers.forEach(function (id) {
        const shown = (entry.shape || self.templated(entry.route))
                        .replace('{as}', encodeURIComponent(id));
        const described = known.names.get(entry.route) || entry.route;
        rows.push(self.httpRow(base, known, entry.route, shown,
                               described + ' — ' + id));
      });
    });
    log.debug("Leaving ProtocolEndpoints.forPage(). " + rows.length +
              " row(s).");
    return rows;
  }

  // The console paths this file has a row for, for the test and the API.
  pages() {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.pages().");
    log.debug("Leaving ProtocolEndpoints.pages().");
    return Object.keys(this.pagesTable);
  }

  // The pages exempt from the table, and why.
  exempt() {
    const { log } = this.deps;
    log.debug("Entering ProtocolEndpoints.exempt().");
    log.debug("Leaving ProtocolEndpoints.exempt().");
    return Object.assign({}, EXEMPT);
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
const slot = new InstanceSlot<ProtocolEndpoints>(
  'admin-core/protocol_endpoints',
  () => new ProtocolEndpoints(ProtocolEndpoints.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  ProtocolEndpoints: ProtocolEndpoints,
  installInstance: (instance: ProtocolEndpoints): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  forPage: slot.forward('forPage'),
  pages: slot.forward('pages'),
  exempt: slot.forward('exempt')
};
