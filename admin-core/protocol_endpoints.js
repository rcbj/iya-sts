'use strict';
//
// File: protocol_endpoints.js
//
// ---------------------------------------------------------------------------
// WHAT EACH PROTOCOLS PAGE LISTS AS "THE ENDPOINTS OF THIS REALM" (2026-09-13).
//
// rcbj asked that every page under Protocols list the concrete endpoints the
// current trust realm answers on for that protocol, the way Protocols -> GNAP
// already did. GNAP's list is written out in `gnap/gnap_console.js` and stays
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
//   and `mgmt-api/admin_api.js` adds the same member to the operation that
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
// Kerberos service, both directory listeners, the 8443/9443 TLS listeners and
// SPIFFE's gRPC sockets register no route, so the router cannot see them —
// the blind spot `sts_metadata.js` states about itself. Their rows are built
// here from the settings those listeners bind from, and SPIFFE's from the
// realm's actual bindings, since a SPIFFE realm is told apart by ADDRESS. A
// KDC and a TLS listener are shared by every realm and carry no prefix; the
// directory's rows carry the realm's own base DN.
//
// ---------------------------------------------------------------------------
// WHY EVERY ROUTE-REGISTERING MODULE IS READ OUT OF `require.cache`.
//
// This file is required by `admin-ui/admin.js` at 18. `sts_metadata.js` must be
// required LAST, and `ldap/ldap_server.js`, `spiffe/spiffe_server.js` and the
// Kerberos modules register routes when first required (rule 1), so a require
// of any of them from here would either close a cycle or drag routes ahead of
// the console. `certificate_views.js` answers the same problem with a require
// inside the function, which is a cache hit once the stack is up; this file
// goes one step further and NEVER loads one: `loaded()` hands back the module
// only if something else already did. An in-process test that loads the
// console without the stack gets rows named by their paths, and no router is
// reordered by asking.
// ---------------------------------------------------------------------------

const path = require('path');
const { log, baseUrlOf } = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
const authorizationServers = require('../oauth-oidc/authorization_servers');

// A route, by its Express path, exactly as `sts_metadata.js` keys it.
function route(expressPath) {
  log.debug("Entering route().");
  log.debug("Leaving route().");
  return { route: expressPath };
}

// A route repeated once per NAMED authorization server in this realm, with
// `:as` (or the `*` of a well-known document) filled with each one's id. The
// default server is the page's family route and is never repeated here.
function perServer(expressPath, shape) {
  log.debug("Entering perServer().");
  log.debug("Leaving perServer().");
  return { route: expressPath, perServer: true, shape: shape || null };
}

// A listener that registers no route. `kind` selects a builder in SOCKETS.
function socket(kind) {
  log.debug("Entering socket().");
  log.debug("Leaving socket().");
  return { socket: kind };
}

const OAUTH_ISSUING = ['/oauth2/authorize', '/oauth2/token',
                       '/oauth2/introspect', '/oauth2/revoke'];
const SAML_ISSUING = ['/saml2/sso', '/saml2/ars', '/saml11/sso',
                      '/saml11/responder', '/sts', '/wsfed'];
const SSF_DELIVERY = ['/.well-known/ssf-configuration', '/ssf/stream',
                      '/ssf/status', '/ssf/subjects/add',
                      '/ssf/subjects/remove', '/ssf/verify', '/ssf/poll',
                      '/ssf/receive', '/ssf/received'];
const NAMED_SERVER_ROUTES = [
  perServer('/.well-known/oauth-authorization-server/*',
            '/.well-known/oauth-authorization-server/{as}'),
  perServer('/*/.well-known/openid-configuration',
            '/{as}/.well-known/openid-configuration'),
  perServer('/:as/oauth2/authorize'),
  perServer('/:as/oauth2/token'),
  perServer('/:as/oauth2/par'),
  perServer('/:as/oauth2/userinfo'),
  perServer('/:as/oauth2/introspect'),
  perServer('/:as/oauth2/revoke'),
  perServer('/:as/oauth2/register'),
  perServer('/:as/oauth2/logout'),
  perServer('/:as/oauth2/jwks')
];

// ---------------------------------------------------------------------------
// THE TABLE. Keyed by the console path, which is what `SECTIONS`, `respond()`'s
// `active` and the management API's `mirrors` all already carry. Every page
// under Protocols but `/admin/gnap` has a row, and
// `tests/protocol_endpoints.js` fails on a Protocols page without one — GNAP
// is exempt because it draws its own list and was the model for this one.
// ---------------------------------------------------------------------------
const PAGES = {
  '/admin/oauth2': [
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server', '/oauth2/authorize',
    '/oauth2/par', '/oauth2/token', '/oauth2/userinfo', '/oauth2/jwks', '/oauth2/introspect',
    '/oauth2/revoke', '/oauth2/register', '/oauth2/register/:client_id',
    '/oauth2/logout', '/oauth2/consent', '/oauth2/rfc9700',
    '/oauth2/oauth21',
    '/dpop/nonce-mode'
  ].map(route),
  '/admin/authorization-servers': NAMED_SERVER_ROUTES,
  '/admin/token-lifetimes': OAUTH_ISSUING.map(route),
  '/admin/claims': ['/oauth2/token', '/oauth2/userinfo',
                    '/oauth2/introspect'].map(route),
  '/admin/userinfo-claims': [route('/oauth2/userinfo'),
                             perServer('/:as/oauth2/userinfo')],
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
    '/issuer/offer', '/bbs/keys/1', '/.well-known/did.json', '/did.json',
    '/.well-known/did-configuration.json'
  ].map(route),
  '/admin/vc': ['/.well-known/openid-credential-issuer', '/oid4vci/credential',
                '/oid4vci/deferred_credential', '/issuer/offer'].map(route),
  '/admin/oid4vp': [
    '/oid4vp/verifier', '/oid4vp/start', '/oid4vp/request/:id',
    '/oid4vp/response', '/oid4vp/result/:state', '/oid4vp/done'
  ].map(route),
  '/admin/vc-verifier-config': ['/oid4vp/verifier', '/oid4vp/start',
                                '/oid4vp/request/:id',
                                '/oid4vp/response'].map(route),
  '/admin/spiffe': [route('/spiffe'), route('/spiffe/bundle'),
                    route('/spiffe/federated/:trustDomain'),
                    socket('spiffe-workload'), socket('spiffe-server')],
  '/admin/spiffe/entries': [socket('spiffe-server'),
                            socket('spiffe-workload')],
  '/admin/spiffe/agents': [socket('spiffe-server'), route('/spiffe/bundle')],
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
    '/scim/v2/ResourceTypes/:id', '/scim/v2/Schemas', '/scim/v2/Schemas/:id',
    '/scim/v2/Users', '/scim/v2/Users/.search', '/scim/v2/Users/:id',
    '/scim/v2/Groups', '/scim/v2/Groups/.search', '/scim/v2/Groups/:id',
    '/scim/v2/.search', '/scim/v2/Bulk', '/scim/v2/Me',
    '/.well-known/hoba/register'
  ].map(route),
  '/admin/ssf': ['/ssf'].concat(SSF_DELIVERY).map(route),
  '/admin/caep': SSF_DELIVERY.map(route),
  '/admin/risc': SSF_DELIVERY.map(route),
  '/admin/federation': ['/federation', '/federation/login/:id',
                        '/federation/acs/:id', '/federation/metadata/:id',
                        '/authn/select-idp'].map(route),
  '/admin/totp': ['/authn/totp', '/portal/mfa'].map(route),
  '/admin/backup-codes': ['/authn/backup-code', '/portal/mfa'].map(route),
  '/admin/webauthn': ['/authn/webauthn', '/portal/keys',
                      '/portal/remove-key'].map(route),
  '/admin/kerberos': [socket('kdc'), socket('krb5-service'),
                      route('/KdcProxy'), route('/krb5/principals'),
                      route('/krb5/service'), route('/spnego'),
                      route('/spnego/protected'), route('/authn/spnego')],
  '/admin/kerberos/principals': [socket('kdc'), route('/KdcProxy'),
                                 route('/krb5/principals')],
  '/admin/ldap': [socket('ldap')],
  '/admin/wstrust': ['/sts', '/sts/cert'].map(route),
  '/admin/wsfed': ['/wsfed',
                   '/FederationMetadata/2007-06/FederationMetadata.xml',
                   '/wsfed/rp'].map(route),
  '/admin/pki': ['/pki/revocation', '/pki/ca/:scope/:ca',
                 '/pki/crl/:scope/:ca', '/pki/ocsp/:scope/:ca',
                 '/pki/chain/:scope/:certificate'].map(route),
  '/admin/tls': [socket('tls'), route('/tls'), route('/tls/forwarded'),
                 route('/tls/server-certificate'), route('/tls/trust'),
                 route('/tls/trust/clear')],
  '/admin/tls/trust': [socket('tls'), route('/tls/trust'),
                       route('/tls/trust/clear')],
  // CERTIFICATE ENROLLMENT (2026-09-13). Each row is the family's registered
  // Express paths, owned by that family's build; see acme/, est/ and scep/.
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
    '/.well-known/est/:label/cacerts', '/.well-known/est/:label/simpleenroll',
    '/.well-known/est/:label/simplereenroll',
    '/.well-known/est/:label/serverkeygen',
    '/.well-known/est/:label/csrattrs', '/.well-known/est/:label/fullcmc'
  ].map(route),
  // ===== SCEP endpoints row =====
  '/admin/scep': [
    '/enroll/scep', '/enroll/scep/pkiclient.exe', '/enroll/scep/:profile',
    '/enroll/scep/:profile/pkiclient.exe'
  ].map(route)
};

// The Protocols pages with no row, each with the reason. A page here is one
// that lists its endpoints itself; `tests/protocol_endpoints.js` fails on a
// Protocols page that is in neither table.
const EXEMPT = {
  '/admin/gnap': 'draws its own list from gnap/gnap_console.js, and was the ' +
                 'model for this table'
};

// The module at `relative` if something has ALREADY loaded it, and null
// otherwise. See the header: asking must never be what loads it.
function loaded(relative) {
  log.debug("Entering loaded(). module=" + relative);
  const cached = require.cache[path.join(__dirname, relative) + '.js'];
  log.debug("Leaving loaded(). " + (cached ? "loaded" : "not loaded"));
  return cached ? cached.exports : null;
}

// `:name` becomes `{name}` and a trailing `*` becomes `{path}`, which is how
// GNAP's list writes a variable segment and how a reader copies one.
function templated(expressPath) {
  log.debug("Entering templated().");
  log.debug("Leaving templated().");
  return expressPath.replace(/:([A-Za-z_]+)/g, '{$1}')
                    .replace(/\*$/, '{path}');
}

// The host a client reaches this service by, for the sockets that share it.
function hostOf(base) {
  log.debug("Entering hostOf().");
  let host = '';
  try {
    host = new URL(base).hostname;
  } catch (e) {
    // A base URL that does not parse is `global.publicBaseUrl` set to
    // something odd; the sockets are still worth listing, by setting name.
    log.debug("Caught in hostOf(): " + ((e && e.message) || e));
  }
  log.debug("Leaving hostOf().");
  return host || 'localhost';
}

// `sts_metadata.js`'s description of each route, joined to the router's own
// methods. Empty maps when that module is not loaded.
function catalogue() {
  log.debug("Entering catalogue().");
  const metadata = loaded('../sts_metadata');
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
  log.debug("Leaving catalogue(). loaded=" + !!metadata);
  return { loaded: !!metadata, names: names, methods: methods };
}

// The named authorization servers of this realm, default excluded.
function namedServers() {
  log.debug("Entering namedServers().");
  const ids = authorizationServers.list().map(function (profile) {
    return profile.id;
  }).filter(function (id) {
    return id && id !== authorizationServers.DEFAULT_ID;
  });
  log.debug("Leaving namedServers(). " + ids.length + " server(s).");
  return ids;
}

// SPIFFE's bindings for THIS realm only. `bindings()` reports every realm's
// sockets and marks each with its realm, empty for the default.
function spiffeRows(surface) {
  log.debug("Entering spiffeRows(). surface=" + surface);
  const server = loaded('../spiffe/spiffe_server');
  if (!server) {
    log.debug("Leaving spiffeRows(). SPIFFE is not loaded.");
    return [];
  }
  const here = realms.currentId() === realms.DEFAULT_ID ? '' :
               realms.currentId();
  const now = server.bindings();
  const list = surface === 'workload' ? now.workload : now.api;
  const rows = list.filter(function (binding) {
    return String(binding.realm || '') === here;
  }).map(function (binding) {
    return {
      name: surface === 'workload' ? 'SPIFFE Workload API (gRPC)' :
            'SPIRE Server API (gRPC)',
      methods: [],
      url: binding.address,
      transport: binding.socket ? 'unix socket' :
                 (binding.tls ? 'gRPC over TLS' : 'gRPC'),
      listening: !!binding.listening
    };
  });
  log.debug("Leaving spiffeRows(). " + rows.length + " row(s).");
  return rows;
}

// The listeners the router cannot see. Each builder takes the realm's host.
const SOCKETS = {
  kdc: function (host) {
    log.debug("Entering the kdc socket builder.");
    const kdc = loaded('../kerberos/krb5_kdc');
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
    const directory = loaded('../ldap/ldap_server');
    // The realm's own subtree, `dc=<id>` beneath `ldap.baseDn` — what a client
    // of this realm searches under on the one shared socket.
    const dn = directory ? directory.baseDn() : config.value('ldap.baseDn');
    const rows = [];
    if (config.value('ldap.plainListener')) {
      rows.push({ name: 'LDAP', methods: [],
                  url: 'ldap://' + host + ':' + config.value('ldap.port') +
                       '/' + dn,
                  transport: 'TCP' });
    }
    rows.push({ name: 'LDAPS', methods: [],
                url: 'ldaps://' + host + ':' + config.value('ldap.tlsPort') +
                     '/' + dn,
                transport: 'TLS' });
    log.debug("Leaving the ldap socket builder.");
    return rows;
  },
  tls: function (host) {
    log.debug("Entering the tls socket builder.");
    // SHARED BY EVERY REALM: a TLS handshake has no path to carry a realm in,
    // so these two answer the same under every prefix and carry none.
    log.debug("Leaving the tls socket builder.");
    return [
      { name: 'TLS listener', methods: [],
        url: 'https://' + host + ':' + config.value('tls.port') + '/',
        transport: 'TLS' },
      { name: 'Mutual-TLS listener', methods: [],
        url: 'https://' + host + ':' + config.value('tls.mutualPort') + '/',
        transport: 'mutual TLS' }
    ];
  },
  'spiffe-workload': function () {
    log.debug("Entering the spiffe-workload socket builder.");
    log.debug("Leaving the spiffe-workload socket builder.");
    return spiffeRows('workload');
  },
  'spiffe-server': function () {
    log.debug("Entering the spiffe-server socket builder.");
    log.debug("Leaving the spiffe-server socket builder.");
    return spiffeRows('server');
  }
};

// One HTTP row. `registered` is false when the stack is up and the router has
// no such route — a rename that left this table behind, which the page shows
// and `tests/protocol_endpoints.js` fails on rather than listing a dead URL
// as though it answered.
function httpRow(base, known, expressPath, shownPath, name) {
  log.debug("Entering httpRow().");
  const row = {
    name: name || known.names.get(expressPath) || expressPath,
    methods: known.methods.get(expressPath) || [],
    url: base + (shownPath || templated(expressPath)),
    route: expressPath
  };
  if (known.loaded && !known.methods.has(expressPath)) {
    row.registered = false;
  }
  log.debug("Leaving httpRow().");
  return row;
}

// ---------------------------------------------------------------------------
// The endpoints `page` lists in the current realm, or null for a page that is
// not a Protocols page in the table. An array, always, for a page that is —
// empty is an answer (a SPIFFE realm with nothing bound, no named server).
// ---------------------------------------------------------------------------
function forPage(req, page) {
  log.debug("Entering forPage(). page=" + page);
  const entries = PAGES[page];
  if (!entries) {
    log.debug("Leaving forPage(). Not a listed page.");
    return null;
  }
  const base = baseUrlOf(req);
  const host = hostOf(base);
  const known = catalogue();
  const servers = entries.some(function (entry) { return entry.perServer; }) ?
                  namedServers() : [];
  const rows = [];
  entries.forEach(function (entry) {
    if (entry.socket) {
      SOCKETS[entry.socket](host).forEach(function (row) { rows.push(row); });
      return;
    }
    if (!entry.perServer) {
      rows.push(httpRow(base, known, entry.route));
      return;
    }
    servers.forEach(function (id) {
      const shown = (entry.shape || templated(entry.route))
                      .replace('{as}', encodeURIComponent(id));
      const described = known.names.get(entry.route) || entry.route;
      rows.push(httpRow(base, known, entry.route, shown,
                        described + ' — ' + id));
    });
  });
  log.debug("Leaving forPage(). " + rows.length + " row(s).");
  return rows;
}

// The console paths this file has a row for, for the test and the API.
function pages() {
  log.debug("Entering pages().");
  log.debug("Leaving pages().");
  return Object.keys(PAGES);
}

// The pages exempt from the table, and why.
function exempt() {
  log.debug("Entering exempt().");
  log.debug("Leaving exempt().");
  return Object.assign({}, EXEMPT);
}

module.exports = {
  forPage: forPage,
  pages: pages,
  exempt: exempt
};
