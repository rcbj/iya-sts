// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: hosted_applications.js
//
// ===========================================================================
// THE HOSTED APPLICATIONS: WHICH APPLICATION A PATH BELONGS TO (#472,
// 2026-10-07).
//
// rcbj: "I want to be able to define custom listeners and map the hosted
// applications to specific listeners. Those hosted applications include: The
// management API, the admin console, the user portal, the authentication
// service, protocol subsystems."
//
// THIS FILE IS THE CATALOGUE AND NOTHING ELSE. An application is a fixed id,
// a label and the paths it answers — prefixes matched on a segment boundary
// and exact paths — and `classify(path)` answers which application a path
// (with the realm prefix already taken off) belongs to. What an application
// is MAPPED to, and where its URLs are built, is `common/listener_map.js`.
//
// **THE CATALOGUE IS CLOSED AND HELD TO THE ROUTER.** An administrator maps
// applications; they never define one, because what an application IS is
// which routes this service registered, and only this file can say that.
// `tests/hosted_applications.js` reads every path `sts_metadata.ts`
// describes — which `tests/vendored/sts_metadata.js` holds to the running
// router in both directions — and fails on one that no application claims,
// so a new route family cannot arrive unmapped and quietly answer on every
// listener.
//
// **TWO PATHS ARE EVERYWHERE**: `/healthcheck`, which a load balancer in
// front of ANY listener asks, and since #570 everything under `/web` — the
// card stylesheet and the locale catalogs every static public surface draws
// with (`common/public_assets.ts`), which a listener answering any of those
// surfaces must answer. Neither is an application's, and `classify()`
// answers `EVERYWHERE` for them. A path nothing claims (an unrouted one)
// answers null, and is admitted everywhere, so Express's own `Cannot GET`
// body — what the metadata test tells an unrouted path from a 404 by — is
// unchanged.
//
// **NAMED AUTHORIZATION SERVERS** (`/<as>/oauth2/...`, `/<as>/gnap`, and
// `/<as>/.well-known/openid-configuration`) have a first segment the
// administrator chose, so they are matched on their SECOND segment, and only
// when the first is no application's own.
//
// A LEAF IN JAVASCRIPT: `common/helpers.js` requires it at load, through
// `common/listener_map.js`, to build every URL by the application it is for,
// and a leaf requires nothing of this service.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('./config');

const log = bunyan.createLogger({ name: 'sts-hosted-applications' });
config.registerLogger(log);

/**
 * What `classify()` answers for a path every listener answers.
 */
const EVERYWHERE = '*everywhere*';

// THE CATALOGUE. `prefixes` match the path itself or anything under it on a
// segment boundary (`/oauth2` matches `/oauth2` and `/oauth2/token`, never
// `/oauth2x`); `exact` match only themselves. `session: true` marks the
// applications that read the sign-on session's cookie, which is what the
// cookie-domain rule in `listener_map.js` is about.
//
// THE DEMONSTRATIONS (#585): `demoPrefixes` are the prefixes under which
// nothing but a demonstration, mock or test-control endpoint is registered,
// and `demo: true` an application that is nothing else. A product realm is
// served none of them (`common/app.js`'s `demoOnly`), so `list()` offers
// neither there — a listener page must not invite an operator to map a
// prefix to a socket when nothing answers under it. `classify()` is not
// changed: it is about where a path WOULD be answered, and a demonstration's
// request still has to reach the router to be passed on to its 404.
const APPLICATIONS = [
  { id: 'home', label: 'Front door',
    what: 'GET /, its image, the documentation, terms and policy pages and ' +
          'the realm list.',
    // `/home-api`, `/home.js` and `/home.css` are the static front door's
    // API, script and stylesheet (#579), beside the shell they serve.
    prefixes: ['/home-api'],
    exact: ['/', '/home.js', '/home.css', '/logo.png', '/docs', '/tos',
            '/policy', '/realms'] },
  { id: 'authn', label: 'Authentication service', session: true,
    what: 'The sign-in service and its second factors, the wallet, ' +
          'SPNEGO and certificate sign-ins, and the sign-out.',
    // `/authn-api` is the sign-in screen's API (#571): one application with
    // the shells it draws, so the screen never has to be told where it is.
    prefixes: ['/authn', '/authn-api', '/logout', '/.well-known/hoba'],
    exact: ['/tls/sign-in'] },
  // `/account-api` IS THE PORTAL'S (#568): the portal is a static
  // application that draws every page from it, so the two are one
  // application on one listener and the portal never has to be told where
  // its own API is.
  { id: 'portal', label: 'User portal', session: true,
    what: 'The pages that belong to the person looking at them, and the ' +
          'account API they are drawn from.',
    prefixes: ['/portal', '/account-api'], exact: [] },
  { id: 'admin-console', label: 'Admin console', rescued: true,
    what: 'The console at /admin, its script and its pages.',
    prefixes: ['/admin'], exact: [] },
  { id: 'management-api', label: 'Management API', rescued: true,
    what: '/admin-api, every console control reachable by a machine.',
    prefixes: ['/admin-api'], exact: [] },
  { id: 'oauth-oidc', label: 'OAuth 2.0 / OpenID Connect', session: true,
    what: 'The authorization server and OpenID provider, their discovery ' +
          'documents and the access-token status list.',
    prefixes: ['/oauth2', '/status-lists', '/dpop',
               '/.well-known/openid-configuration',
               '/.well-known/oauth-authorization-server',
               '/.well-known/webfinger'],
    demoPrefixes: ['/dpop'],
    exact: [] },
  { id: 'saml2', label: 'SAML 2.0', session: true,
    what: 'The SAML 2.0 identity provider.',
    prefixes: ['/saml2'], exact: [] },
  { id: 'saml11', label: 'SAML 1.1', session: true,
    what: 'The SAML 1.1 identity provider.',
    prefixes: ['/saml11'], exact: [] },
  { id: 'ws-trust', label: 'WS-Trust',
    what: 'The WS-Trust security token service.',
    prefixes: ['/sts'], exact: [] },
  { id: 'ws-federation', label: 'WS-Federation', session: true,
    what: 'The passive requestor profile and its metadata.',
    prefixes: ['/wsfed', '/FederationMetadata'], exact: [] },
  { id: 'federation', label: 'Federation', session: true,
    what: 'Federation relationships with foreign identity services.',
    prefixes: ['/federation'], exact: [] },
  { id: 'oidfed', label: 'OpenID Federation',
    what: 'The Entity Configuration and the federation endpoints.',
    prefixes: ['/oidfed', '/.well-known/openid-federation'], exact: [] },
  { id: 'oid4vc', label: 'Verifiable credentials',
    what: 'OpenID4VCI, OpenID4VP, DIDs and the status lists.',
    demoPrefixes: ['/issuer', '/did', '/vc-api'],
    prefixes: ['/oid4vci', '/oid4vp', '/issuer', '/did', '/applications',
               '/bbs', '/vc-api', '/.well-known/did.json',
               '/.well-known/did-configuration.json',
               '/.well-known/openid-credential-issuer',
               '/.well-known/jwt-vc-issuer'],
    exact: ['/did.json'] },
  { id: 'scim', label: 'SCIM 2.0',
    what: 'Provisioning into the directory.',
    prefixes: ['/scim'], exact: [] },
  { id: 'ssf', label: 'Shared Signals',
    what: 'The Shared Signals transmitter and receiver.',
    prefixes: ['/ssf', '/.well-known/ssf-configuration'], exact: [] },
  { id: 'gnap', label: 'GNAP', session: true,
    what: 'The GNAP authorization server and its interaction pages.',
    prefixes: ['/gnap', '/.well-known/gnap-as-rs'], exact: [] },
  { id: 'xacml', label: 'XACML',
    what: 'The policy decision point, its policies and the remote PEPs\' ' +
          'doors.',
    prefixes: ['/xacml'], exact: [] },
  { id: 'acme', label: 'ACME', what: 'Certificate enrollment by ACME.',
    prefixes: ['/enroll/acme'], exact: [] },
  { id: 'est', label: 'EST', what: 'Certificate enrollment by EST.',
    prefixes: ['/.well-known/est'], exact: [] },
  { id: 'scep', label: 'SCEP', what: 'Certificate enrollment by SCEP.',
    prefixes: ['/enroll/scep'], exact: [] },
  { id: 'pki', label: 'Certificate authority',
    what: 'CRLs, OCSP, the CA certificates and chains, and the ' +
          'cryptographic metadata documents.',
    prefixes: ['/pki', '/crypto'], exact: [] },
  { id: 'kerberos', label: 'Kerberos',
    what: 'MS-KKDCP and the Kerberos HTTP views.',
    prefixes: ['/KdcProxy', '/krb5', '/spnego'], demoPrefixes: ['/spnego'],
    exact: [] },
  { id: 'spiffe', label: 'SPIFFE',
    what: 'The SPIFFE bundle endpoint.',
    prefixes: ['/spiffe'], exact: [] },
  { id: 'tls', label: 'TLS diagnostics',
    what: 'The TLS views and the client truststore\'s door.',
    prefixes: ['/tls'], exact: [] },
  { id: 'devices', label: 'Device registration', demo: true,
    what: 'The device register\'s test controls.',
    prefixes: ['/devices'], exact: [] }
];

const byId = {};
APPLICATIONS.forEach(function (one) {
  byId[one.id] = one;
});

// Every prefix with its application, longest first, so `/admin-api` is found
// before `/admin` and `/enroll/acme` before anything shorter.
const PREFIXES = [];
APPLICATIONS.forEach(function (one) {
  one.prefixes.forEach(function (prefix) {
    PREFIXES.push({ prefix: prefix, id: one.id });
  });
});
PREFIXES.sort(function (a, b) {
  return b.prefix.length - a.prefix.length;
});

const EXACT = {};
APPLICATIONS.forEach(function (one) {
  one.exact.forEach(function (path) {
    EXACT[path] = one.id;
  });
});

// A hot path — every request is classified at least once, and every URL
// built through `helpers.urlOf()` — so no Entering/Leaving pair: it would
// drown the log around one lookup.
function underPrefix(path) {
  for (let i = 0; i < PREFIXES.length; i += 1) {
    const p = PREFIXES[i].prefix;
    if (path === p || path.indexOf(p + '/') === 0) {
      return PREFIXES[i].id;
    }
  }
  return null;
}

/**
 * Which application a path belongs to.
 *
 * A hot path: no Entering/Leaving pair, which would drown the log around a
 * table lookup on every request.
 *
 * @param path - the path, without the realm prefix and without a query
 * @returns the application's id, `EVERYWHERE` for `/healthcheck` and
 *   `/web`, or null for a path no application claims
 */
function classify(path) {
  const p = String(path || '').split('?')[0].split('#')[0] || '/';
  if (p === '/healthcheck' || p === '/web' || p.indexOf('/web/') === 0) {
    return EVERYWHERE;
  }
  if (Object.prototype.hasOwnProperty.call(EXACT, p)) {
    return EXACT[p];
  }
  const found = underPrefix(p);
  if (found) {
    return found;
  }
  // A NAMED AUTHORIZATION SERVER: `/<as>/oauth2/...`, `/<as>/gnap...`,
  // `/<as>/.well-known/openid-configuration`. Its first segment is the
  // administrator's, and no application's own (that was asked above).
  const parts = p.split('/');
  if (parts.length >= 3 && parts[1] !== '') {
    const second = '/' + parts.slice(2).join('/');
    if (/^\/oauth2(\/|$)/.test(second) ||
        /^\/\.well-known\/openid-configuration(\/|$)/.test(second)) {
      return 'oauth-oidc';
    }
    if (/^\/gnap(\/|$)/.test(second)) {
      return 'gnap';
    }
  }
  return null;
}

/**
 * The catalogue, for the Listeners page, the management API and the tests.
 *
 * @returns each application's `id`, `label`, `what`, `prefixes`, `exact`,
 *   `session` and `rescued`
 */
function list() {
  log.debug("Entering list().");
  // Required HERE, lazily: this file is a leaf `helpers.js` requires at load,
  // and the mode is read in the ambient realm, so per call (#585). A call
  // made while `mode.js` is still loading (a settings check at startup names
  // the applications in a refusal) finds no predicate yet and lists them
  // all, which is the development answer and only ever a message's text.
  const modeModule = require('./mode');
  const demos = typeof modeModule.servesDemoEndpoints === 'function'
    ? modeModule.servesDemoEndpoints() : true;
  const out = APPLICATIONS.filter(function (one) {
    return demos || !one.demo;
  }).map(function (one) {
    const hidden = demos ? [] : (one.demoPrefixes || []);
    return { id: one.id, label: one.label, what: one.what,
             prefixes: one.prefixes.filter(function (prefix) {
               return hidden.indexOf(prefix) < 0;
             }), exact: one.exact.slice(),
             session: !!one.session, rescued: !!one.rescued };
  });
  log.debug("Leaving list(). " + out.length);
  return out;
}

/**
 * Whether an id names an application.
 *
 * @param id - the id
 * @returns true when it is one
 */
function isApplication(id) {
  log.debug("Entering isApplication().");
  log.debug("Leaving isApplication().");
  return Object.prototype.hasOwnProperty.call(byId, String(id));
}

/**
 * The applications that read the sign-on session's cookie.
 *
 * @returns their ids
 */
function sessionApplications() {
  log.debug("Entering sessionApplications().");
  const out = APPLICATIONS.filter(function (one) {
    return !!one.session;
  }).map(function (one) {
    return one.id;
  });
  log.debug("Leaving sessionApplications().");
  return out;
}

/**
 * The applications `listeners.adminOnMain` puts back on the main port.
 *
 * @returns their ids
 */
function rescuedApplications() {
  log.debug("Entering rescuedApplications().");
  const out = APPLICATIONS.filter(function (one) {
    return !!one.rescued;
  }).map(function (one) {
    return one.id;
  });
  log.debug("Leaving rescuedApplications().");
  return out;
}

/**
 * One application's label.
 *
 * @param id - the id
 * @returns the label, or the id where it names none
 */
function labelOf(id) {
  log.debug("Entering labelOf().");
  log.debug("Leaving labelOf().");
  return byId[String(id)] ? byId[String(id)].label : String(id);
}

// THE LISTENERS NAMESPACE OF THE SERVER'S PROSE (#543 phase 2b), this file's
// part: each application's label and sentence, which `GET
// /admin-api/listeners` carries in `applications` (`listener_map.js`'s
// `mappingView()`). The ids, prefixes and paths are not prose.
/**
 * The `/admin-api` routes whose answers carry this file's prose (#543).
 */
const PROSE_ROUTES = ['/admin-api/listeners'];

/**
 * Extracts this file's part of the listeners namespace (#543 phase 2b):
 * each hosted application's label and sentence.
 *
 * `server_prose` is required here, LAZILY: `helpers.js` requires this file at
 * load and `server_prose` requires `helpers.js`.
 *
 * @returns key → English
 */
function prose() {
  log.debug("Entering prose().");
  const out = require('./server_prose').harvest('listeners.applications',
                                                APPLICATIONS,
                                                ['label', 'what']);
  log.debug("Leaving prose(). " + Object.keys(out).length);
  return out;
}

module.exports = {
  EVERYWHERE: EVERYWHERE,
  classify: classify,
  list: list,
  isApplication: isApplication,
  sessionApplications: sessionApplications,
  rescuedApplications: rescuedApplications,
  labelOf: labelOf,
  PROSE_ROUTES: PROSE_ROUTES,
  prose: prose
};
