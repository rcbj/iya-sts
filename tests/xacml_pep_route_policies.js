// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/xacml_pep_route_policies.js
//
// ===========================================================================
// A REVERSE-PROXY ROUTE'S AUTHORIZATION (#1760, rcbj 2026-11-15).
//
// "force them to pick one of these two policies or Public. But, that still
// results in a generated XACML policy representing the public access for
// this path. All authorization decisions are made in XACML", and "None
// should mean no methods allowed, essentially deny all".
//
// In a throwaway realm, through the real store, ALFA reader, XML writer and
// engine (`xacml_pdp.js` with the PIP answering `urn:sts:xacml:role` off
// the directory), and the real actions (`admin-core/admin_actions.ts`):
//
//   1. the grammar: `methods` and `authorization` required, each refusal
//      by its code, empty methods kept as deny-all, the generated name;
//   2. the save's checks: an existing policy missing, disabled or
//      withheld, a role nobody configured, a generated name held by a
//      hand-written policy;
//   3. a simple route's generated policy: its text, its mark, never the
//      root, and its decisions for each action and role — a role holder
//      permitted, a non-holder denied, another resource denied;
//   4. a public route's policy: the anonymous subject permitted the
//      route's methods, nothing else; and empty methods a deny-all;
//   5. the default resource and the application's home page;
//   6. rename, switch to an existing policy, remove (refused without
//      confirmation), generate again;
//   7. the repository's search for the policy chooser, and the pull.
//
// The PEP's half (the route's policy deciding, not the root; the action
// models; deny-all) is `cargo test -p xacml-pep`.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'xacml_pep_route_policies',
  level: process.env.LOG_LEVEL || 'info' });

delete process.env.CONFIG_FILE;

const NAME = 'pprpep';
const BASE = 'https://pep.example:9543';
const ROLE_ATTR = 'urn:sts:xacml:role';

function run(t) {
  log.debug("Entering run().");
  // The modules this file drives, as `fga_policies.js` loads them, and not
  // the whole stack: `common/protocol_stack` installs every module's
  // instance, which a file sharing `npm test`'s one process with others
  // must not do.
  require('../common/config');
  require('../common/app');
  require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const applications = require('../common/applications');
  const roles = require('../common/roles');
  const ldap = require('../ldap/ldap_server');
  const store = require('../xacml/xacml_store');
  const xml = require('../xacml/xacml_xml');
  const alfa = require('../xacml/xacml_alfa');
  const json = require('../xacml/xacml_json');
  const model = require('../xacml/xacml_model');
  const surface = require('../xacml/xacml');
  const peps = require('../xacml/xacml_pep_registry');
  const pepProxy = require('../xacml/xacml_pep_proxy');
  const routePolicies = require('../xacml/xacml_pep_route_policies');
  const pap = require('../xacml/xacml_admin');
  const adminActions = require('../admin-core/admin_actions');

  const id = 'ppr-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  const k = { t, errorCodes, applications, roles, ldap, store, xml, alfa,
              json, model, surface, peps, pepProxy, routePolicies, pap,
              adminActions };
  try {
    realms.run(made.realm, function () {
      log.debug("Entering realmBody().");
      setUp(k);
      grammar(k);
      saveChecks(k);
      simplePolicy(k);
      publicPolicy(k);
      defaults(k);
      lifecycle(k);
      search(k);
      parts(k);
      log.debug("Leaving realmBody().");
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

// The action, as the management API and the console call it.
function act(k, body) {
  log.debug("Entering act().");
  log.debug("Leaving act().");
  return k.adminActions.xacmlAction(Object.assign({ name: NAME }, body));
}

function codeOf(k, answer) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return k.errorCodes.codeOf(answer) || (answer && answer.code) || '';
}

// A decision about one request, through the engine with the PIP resolving
// the subject's roles off the directory.
function decide(k, policyName, subject, resource, action) {
  log.debug("Entering decide().");
  const row = k.store.read(policyName);
  const attributes = { Action: { Attribute: [
                         { AttributeId: k.model.ATTRIBUTE.ACTION_ID,
                           Value: action }] },
                       Resource: { Attribute: [
                         { AttributeId: k.model.ATTRIBUTE.RESOURCE_ID,
                           Value: resource,
                           DataType: 'http://www.w3.org/2001/XMLSchema#' +
                                     'anyURI' }] } };
  if (subject) {
    attributes.AccessSubject = { Attribute: [
      { AttributeId: k.model.ATTRIBUTE.SUBJECT_ID, Value: subject }] };
  }
  const request = k.json.parseRequest(JSON.stringify({ Request: attributes }));
  const answer = k.surface.decidePolicy(k.store.parseDocument(row.document),
                                        request, { resolve: true });
  log.debug("Leaving decide(). " + answer.decision);
  return answer.decision;
}

function setUp(k) {
  log.debug("Entering setUp().");
  const { t, roles, ldap, peps, applications } = k;
  ['ppr-reader', 'ppr-writer', 'ppr-nobody'].forEach(function (name) {
    ldap.createUser(name, { invent: false });
  });
  t.check(roles.write('ppr-readers', { users: ['ppr-reader', 'ppr-writer'] })
            .ok &&
          roles.write('ppr-writers', { users: ['ppr-writer'] }).ok,
          '0a. two configured roles: readers (both) and writers (one)');
  const registered = peps.register({ name: NAME,
    identity: 'cn=' + NAME + ',ou=users,dc=example,dc=com',
    certificateSubject: 'CN=' + NAME, thumbprint: 'test-' + NAME,
    authenticated: true, bias: 'deny', resource: BASE });
  t.check(registered && registered.ok, '0b. a remote PEP registered',
          JSON.stringify(registered));
  applications.createApplication({ identifier: 'ppr-api',
    protocols: ['oauth2'],
    fields: { oauthClientId: 'ppr-api',
              oauthAudience: ['https://api.example/'],
              appHomePageUrl: 'https://app.example/home' } });
  const empty = act(k, { action: 'set-pep-proxy', proxy: {
    upstream: 'http://upstream.example:8080', publicBaseUrl: BASE,
    routes: [] } });
  t.check(empty.ok, '0c. it holds a configuration with no route',
          JSON.stringify(empty));
  log.debug("Leaving setUp().");
}

function grammar(k) {
  log.debug("Entering grammar().");
  const { t, pepProxy } = k;
  t.log.info('=== 1. the grammar ===');
  const doc = function (route) {
    return { upstream: 'http://u.example', routes: [route] };
  };
  const cases = [
    ['no methods member', { id: 'a', path: '/a',
      authorization: { kind: 'public', resource: BASE + '/a' } },
     'STS-XACML-0262'],
    ['no authorization', { id: 'a', path: '/a', methods: ['GET'],
      mechanisms: ['basic'], application: 'ppr-api' }, 'STS-XACML-0263'],
    ['the retired public member', { id: 'a', path: '/a', methods: ['GET'],
      public: true }, 'STS-XACML-0185'],
    ['an unknown kind', { id: 'a', path: '/a', methods: ['GET'],
      authorization: { kind: 'open' } }, 'STS-XACML-0263'],
    ['a stray authorization member', { id: 'a', path: '/a',
      methods: ['GET'], authorization: { kind: 'public', who: 'x' } },
     'STS-XACML-0263'],
    ['an existing policy naming none', { id: 'a', path: '/a',
      methods: ['GET'], mechanisms: ['basic'], application: 'ppr-api',
      authorization: { kind: 'policy' } }, 'STS-XACML-0264'],
    ['a simple route on the method model', { id: 'a', path: '/a',
      methods: ['GET'], mechanisms: ['basic'], application: 'ppr-api',
      authorization: { kind: 'simple', resource: BASE + '/a',
                       actionModel: 'method',
                       roles: { read: ['ppr-readers'] } } },
     'STS-XACML-0264'],
    ['a public route on crud', { id: 'a', path: '/a', methods: ['GET'],
      authorization: { kind: 'public', resource: BASE + '/a',
                       actionModel: 'crud' } }, 'STS-XACML-0264'],
    ['roles on an existing policy', { id: 'a', path: '/a',
      methods: ['GET'], mechanisms: ['basic'], application: 'ppr-api',
      authorization: { kind: 'policy', policy: 'p',
                       roles: { read: ['ppr-readers'] } } },
     'STS-XACML-0264'],
    ['write under crud', { id: 'a', path: '/a', methods: ['GET'],
      mechanisms: ['basic'], application: 'ppr-api',
      authorization: { kind: 'simple', resource: BASE + '/a',
                       actionModel: 'crud',
                       roles: { write: ['ppr-writers'] } } },
     'STS-XACML-0264'],
    ['an action with no role', { id: 'a', path: '/a', methods: ['GET'],
      mechanisms: ['basic'], application: 'ppr-api',
      authorization: { kind: 'simple', resource: BASE + '/a',
                       actionModel: 'read-write', roles: { read: [] } } },
     'STS-XACML-0264'],
    ['a simple resource that is not a URL', { id: 'a', path: '/a',
      methods: ['GET'], mechanisms: ['basic'], application: 'ppr-api',
      authorization: { kind: 'simple', resource: 'urn:x:y',
                       actionModel: 'read-write',
                       roles: { read: ['ppr-readers'] } } },
     'STS-XACML-0264'],
    ['a public route with a mechanism', { id: 'a', path: '/a',
      methods: ['GET'], mechanisms: ['basic'],
      authorization: { kind: 'public', resource: BASE + '/a' } },
     'STS-XACML-0196']
  ];
  cases.forEach(function (one, i) {
    const got = pepProxy.validate(doc(one[1]), NAME);
    t.check(!got.ok && got.code === one[2],
            '1.' + (i + 1) + ' refused: ' + one[0] + ' (' + one[2] + ')',
            JSON.stringify(got));
  });
  const none = pepProxy.validate(doc({ id: 'shut', path: '/shut',
    methods: [], authorization: { kind: 'public',
                                  resource: BASE + '/shut' } }), NAME);
  t.check(none.ok && none.proxy.routes[0].methods.length === 0 &&
          none.proxy.routes[0].authorization.policy === 'pep-' + NAME +
            '-shut',
          '1.20 an empty methods list is kept, deny-all, and a public ' +
          'route\'s policy is the generated name', JSON.stringify(none));
  t.check(pepProxy.generatedPolicyName('a b/c', 'r') === 'pep-a_b_c-r' &&
          pepProxy.generatedPolicyName('x'.repeat(200), 'r').length ===
            128,
          '1.21 the generated name holds only a name\'s characters, and ' +
          'at most 128');
  const other = pepProxy.validate(doc({ id: 'p', path: '/p',
    methods: ['GET'], authorization: { kind: 'public',
      policy: 'pep-otherpep-p', resource: BASE + '/p' } }), NAME);
  t.check(other.ok && other.proxy.routes[0].authorization.policy ===
            'pep-' + NAME + '-p',
          '1.22 another PEP\'s generated name (a loaded file) becomes this ' +
          'PEP\'s', JSON.stringify(other));
  // REMOTE PEP CLUSTERS (#1760): a cluster's owner is `@<cluster>`, its one
  // policy per route `pepc-<cluster>-<route>`, marked `@<cluster>/<route>`.
  const ours = pepProxy.validate(doc({ id: 'p', path: '/p',
    methods: ['GET'], authorization: { kind: 'public',
      policy: 'pep-' + NAME + '-p', resource: BASE + '/p' } }), '@orders');
  t.check(ours.ok && ours.proxy.routes[0].authorization.policy ===
            'pepc-orders-p' &&
          pepProxy.generatedPolicyName('@a b', 'r') === 'pepc-a_b-r' &&
          pepProxy.generatedPolicyName('@' + 'x'.repeat(200), 'r').length ===
            128 &&
          k.routePolicies.markOf('@orders', 'p') === '@orders/p' &&
          k.routePolicies.ownerLabel('@orders') ===
            'remote PEP cluster orders' &&
          k.routePolicies.ownerLabel(NAME) === 'remote PEP ' + NAME &&
          pepProxy.ownerOf({ name: 'pep-1', cluster: 'orders' }) ===
            '@orders' &&
          pepProxy.ownerOf({ name: 'pep-1' }) === 'pep-1',
          '1.23 a cluster\'s owner names its policy pepc-<cluster>-<route> ' +
          'and marks it @<cluster>/<route>; a PEP\'s is unchanged',
          JSON.stringify(ours));
  log.debug("Leaving grammar().");
}

function saveChecks(k) {
  log.debug("Entering saveChecks().");
  const { t, store, xml, alfa } = k;
  t.log.info('=== 2. what a save asks ===');
  const write = function (name, enabled) {
    return store.write(name, xml.writePolicy(alfa.parse(
      'namespace x { policy ' + name.replace(/[^a-z]/g, '') +
      ' { apply denyUnlessPermit rule r { permit } } }')),
      { enabled: enabled });
  };
  t.check(write('ppr-handwritten', true).ok &&
          write('ppr-disabled', false).ok &&
          write('access-control', true).ok,
          '2.0 a hand-written, a disabled and a service-named policy');
  const base = { action: 'set-pep-route', id: 'r', path: '/r',
                 methods: ['GET'], mechanisms: ['basic'],
                 application: 'ppr-api' };
  const missing = act(k, Object.assign({}, base, { authzKind: 'policy',
    authzPolicy: 'no-such-policy' }));
  const disabled = act(k, Object.assign({}, base, { authzKind: 'policy',
    authzPolicy: 'ppr-disabled' }));
  const withheld = act(k, Object.assign({}, base, { authzKind: 'policy',
    authzPolicy: 'access-control' }));
  t.check(codeOf(k, missing) === 'STS-XACML-0265' &&
          codeOf(k, disabled) === 'STS-XACML-0265' &&
          codeOf(k, withheld) === 'STS-XACML-0265',
          '2.1 an existing policy missing, disabled or never sent to a PEP ' +
          'is refused (STS-XACML-0265)',
          [codeOf(k, missing), codeOf(k, disabled),
           codeOf(k, withheld)].join(' '));
  const noRole = act(k, Object.assign({}, base, { authzKind: 'simple',
    authzActionModel: 'read-write', authzActions: ['read'],
    'authzRole.read': ['no-such-role'] }));
  const builtIn = act(k, Object.assign({}, base, { authzKind: 'simple',
    authzActionModel: 'read-write', authzActions: ['read'],
    'authzRole.read': ['ALL_AUTHENTICATED_USERS'] }));
  t.check(codeOf(k, noRole) === 'STS-XACML-0266' &&
          codeOf(k, builtIn) === 'STS-XACML-0266',
          '2.2 a role that is not a configured role, a built-in one ' +
          'included, is refused (STS-XACML-0266)',
          codeOf(k, noRole) + ' ' + codeOf(k, builtIn));
  t.check(write('pep-' + NAME + '-taken', true).ok, '2.3 a hand-written ' +
          'policy holding a route\'s generated name');
  const taken = act(k, Object.assign({}, base, { id: 'taken',
    path: '/taken', authzKind: 'public', mechanisms: [],
    application: '' }));
  t.check(codeOf(k, taken) === 'STS-XACML-0267' &&
          !!store.read('pep-' + NAME + '-taken') &&
          !store.read('pep-' + NAME + '-taken').pepRoute,
          '2.4 is never overwritten (STS-XACML-0267)',
          JSON.stringify(taken));
  const noChoice = act(k, { action: 'set-pep-route', id: 'none',
    path: '/none', methods: ['GET'], mechanisms: ['basic'],
    application: 'ppr-api' });
  t.check(codeOf(k, noChoice) === 'STS-XACML-0263',
          '2.5 a route saved with no authorization choice is refused ' +
          '(STS-XACML-0263)', JSON.stringify(noChoice));
  const noMethods = act(k, { action: 'set-pep-route', id: 'none',
    path: '/none', mechanisms: ['basic'], application: 'ppr-api',
    authzKind: 'policy', authzPolicy: 'ppr-handwritten' });
  t.check(codeOf(k, noMethods) === 'STS-XACML-0262',
          '2.6 a route saved with no methods stated is refused ' +
          '(STS-XACML-0262)', JSON.stringify(noMethods));
  const all = act(k, { action: 'set-pep-route', id: 'all', path: '/all',
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    methodsGiven: 'true', mechanisms: ['basic'], application: 'ppr-api',
    authzKind: 'policy', authzPolicy: 'ppr-handwritten' });
  const shut = act(k, { action: 'set-pep-route', id: 'shut', path: '/shut',
    methodsGiven: 'true', mechanisms: ['basic'], application: 'ppr-api',
    authzKind: 'policy', authzPolicy: 'ppr-handwritten' });
  const routeOf = function (answer, wanted) {
    return answer && answer.proxy && answer.proxy.routes.filter(
      function (one) {
        return one.id === wanted;
      })[0];
  };
  t.check(all.ok && routeOf(all, 'all').methods.length === 7 &&
          shut.ok && routeOf(shut, 'shut').methods.length === 0,
          '2.7 All stores the seven methods; the form with none ticked ' +
          'stores the empty list (deny-all)',
          JSON.stringify([routeOf(all, 'all'), routeOf(shut, 'shut')]));
  const chosen = routeOf(all, 'all').authorization;
  t.check(chosen.kind === 'policy' && chosen.policy === 'ppr-handwritten' &&
          chosen.actionModel === 'method' && chosen.resource === '',
          '2.8 an existing policy is stored by name, the method model and ' +
          'the path by default', JSON.stringify(chosen));
  act(k, { action: 'remove-pep-route', route: 'all' });
  act(k, { action: 'remove-pep-route', route: 'shut' });
  log.debug("Leaving saveChecks().");
}

function simplePolicy(k) {
  log.debug("Entering simplePolicy().");
  const { t, store, model } = k;
  t.log.info('=== 3. a simple route\'s generated policy ===');
  const saved = act(k, { action: 'set-pep-route', id: 'api',
    path: '/api', methods: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
    methodsGiven: 'true', mechanisms: ['basic'], application: 'ppr-api',
    authzKind: 'simple', authzActionModel: 'read-write',
    authzActions: ['read', 'write', 'create'],
    'authzRole.read': ['ppr-readers'], 'authzRole.write': ['ppr-writers'],
    'authzRole.create': ['ppr-writers'] });
  const name = 'pep-' + NAME + '-api';
  const route = saved.ok ? saved.proxy.routes.filter(function (one) {
    return one.id === 'api';
  })[0] : null;
  t.check(saved.ok && route &&
          route.authorization.resource === BASE + '/api' &&
          Object.keys(route.authorization.roles).sort().join(',') ===
            'read,write' &&
          saved.policies.generated.indexOf(name) >= 0,
          '3.1 the save fills the default resource, drops an action of the ' +
          'other model, and generates ' + name, JSON.stringify(saved));
  const row = store.read(name);
  t.check(!!row && row.enabled && row.pepRoute === NAME + '/api' &&
          !row.isRoot && /GENERATED/.test(row.document) &&
          /urn:sts:xacml:role/.test(row.document),
          '3.2 it is enabled, marked xacmlPepRoute = <pep>/<route>, not the ' +
          'root, and names the role attribute', row ? row.pepRoute : 'none');
  // With every other policy disabled the generated one is the only
  // enabled policy, which is the case the store's "only enabled policy"
  // fallback would make the root.
  const others = store.all().filter(function (one) {
    return one.enabled && !one.pepRoute;
  });
  others.forEach(function (one) {
    store.write(one.name, one.document, { enabled: false });
  });
  const root = store.root();
  others.forEach(function (one) {
    store.write(one.name, one.document, { enabled: true });
  });
  t.check(others.length > 0 && !root,
          '3.3 it is never the root, even where it is the only enabled ' +
          'policy', root ? root.name : 'no root');
  const P = model.DECISION.PERMIT;
  const D = model.DECISION.DENY;
  const R = BASE + '/api';
  const got = [
    ['a reader reads', decide(k, name, 'ppr-reader', R, 'read'), P],
    ['a writer reads', decide(k, name, 'ppr-writer', R, 'read'), P],
    ['a writer writes', decide(k, name, 'ppr-writer', R, 'write'), P],
    ['a reader may not write', decide(k, name, 'ppr-reader', R, 'write'),
     D],
    ['a non-holder may not read', decide(k, name, 'ppr-nobody', R,
                                         'read'), D],
    ['nobody signed in may not read', decide(k, name, '', R, 'read'), D],
    ['another resource is denied', decide(k, name, 'ppr-writer',
                                          BASE + '/other', 'read'), D],
    ['an action the model has not is denied', decide(k, name, 'ppr-writer',
                                                     R, 'GET'), D]
  ];
  got.forEach(function (one, i) {
    t.check(one[1] === one[2], '3.' + (4 + i) + ' ' + one[0] + ': ' +
            one[2], one[1]);
  });
  const crud = act(k, { action: 'set-pep-route-authorization',
    route: 'api', authorization: { kind: 'simple', actionModel: 'crud',
      roles: { read: ['ppr-readers'], delete: ['ppr-writers'] } } });
  t.check(crud.ok &&
          decide(k, name, 'ppr-writer', R, 'delete') === P &&
          decide(k, name, 'ppr-reader', R, 'delete') === D &&
          decide(k, name, 'ppr-writer', R, 'update') === D &&
          decide(k, name, 'ppr-reader', R, 'read') === P,
          '3.12 set-pep-route-authorization rewrites it under CRUD: a ' +
          'writer deletes, nobody updates', JSON.stringify(crud));
  log.debug("Leaving simplePolicy().");
}

function publicPolicy(k) {
  log.debug("Entering publicPolicy().");
  const { t, store, model } = k;
  t.log.info('=== 4. a public route\'s policy, and deny-all ===');
  const pub = act(k, { action: 'set-pep-route', id: 'open', path: '/open',
    methods: ['GET', 'HEAD'], methodsGiven: 'true',
    mechanisms: ['basic'], application: 'ppr-api', authzKind: 'public' });
  const route = pub.ok ? pub.proxy.routes.filter(function (one) {
    return one.id === 'open';
  })[0] : null;
  t.check(pub.ok && route && route.mechanisms.length === 0 &&
          route.application === '' &&
          route.authorization.kind === 'public',
          '4.1 a public route keeps no mechanism and no application',
          JSON.stringify(route));
  const name = 'pep-' + NAME + '-open';
  const R = BASE + '/open';
  t.check(decide(k, name, '', R, 'GET') === model.DECISION.PERMIT &&
          decide(k, name, 'ppr-nobody', R, 'HEAD') ===
            model.DECISION.PERMIT,
          '4.2 its policy permits the anonymous subject, and anybody, the ' +
          'route\'s methods');
  t.check(decide(k, name, '', R, 'POST') === model.DECISION.DENY &&
          decide(k, name, '', BASE + '/elsewhere', 'GET') ===
            model.DECISION.DENY,
          '4.3 and denies another method and another resource');
  const shut = act(k, { action: 'set-pep-route', id: 'open', from: 'open',
    path: '/open', methodsGiven: 'true', authzKind: 'public' });
  t.check(shut.ok && decide(k, name, '', R, 'GET') === model.DECISION.DENY &&
          !/permitAnyone/.test(store.read(name).document) &&
          /deny-all/.test(store.read(name).document),
          '4.4 with no method the generated policy is a deny-all',
          JSON.stringify(shut).slice(0, 300));
  log.debug("Leaving publicPolicy().");
}

function defaults(k) {
  log.debug("Entering defaults().");
  const { t, routePolicies, pap } = k;
  t.log.info('=== 5. the default resource and the application\'s URL ===');
  const fromBase = routePolicies.defaultResource({ name: NAME }, BASE + '/',
                                                 '/api/');
  const fromListener = routePolicies.defaultResource({ name: NAME,
    hostname: 'pep-host.internal',
    listenersInUse: { listeners: [{ id: 'proxy-https', port: 8443 }] } },
    '', '/api');
  const bare = routePolicies.defaultResource({ name: NAME }, '', '/');
  t.check(fromBase.resource === BASE + '/api' &&
          fromBase.source === 'publicBaseUrl' &&
          fromListener.resource === 'https://pep-host.internal:8443/api' &&
          fromListener.source === 'listener' &&
          bare.resource === 'https://' + NAME + ':9543/',
          '5.1 the default is the public base URL and the path, else the ' +
          'HTTPS proxy listener the PEP reported (its hostname and port), ' +
          'else its name and 9543',
          JSON.stringify([fromBase, fromListener, bare]));
  const offered = routePolicies.applicationUrl('ppr-api', '/api',
                                               BASE + '/api');
  const agrees = routePolicies.applicationUrl('ppr-api', '/api',
                                              'https://app.example/api');
  const none = routePolicies.applicationUrl('no-such-app', '/api',
                                            BASE + '/api');
  t.check(offered.attribute === 'appHomePageUrl' &&
          offered.url === 'https://app.example/home' &&
          offered.resource === 'https://app.example/api' &&
          offered.mismatch === true && agrees.mismatch === false &&
          none.url === '' && none.mismatch === false,
          '5.2 the application\'s home page suggests its origin and the ' +
          'path, and a different origin is flagged',
          JSON.stringify([offered, agrees, none]));
  const page = pap.pepsJson(NAME, 'api');
  const detail = page.routeDetail;
  t.check(detail && detail.found && detail.authorization &&
          detail.authorization.defaultResource === BASE + '/api' &&
          detail.authorization.applicationUrl.mismatch === true &&
          detail.authorization.policy.generated === true &&
          detail.authorization.policy.problem === null &&
          page.peps[0].proxyRoutes.filter(function (one) {
            return one.route === 'api';
          })[0].policy === 'pep-' + NAME + '-api',
          '5.3 the route page answers the policy\'s state, the default ' +
          'resource and the cross-reference',
          JSON.stringify(detail && detail.authorization));
  log.debug("Leaving defaults().");
}

function lifecycle(k) {
  log.debug("Entering lifecycle().");
  const { t, store } = k;
  t.log.info('=== 6. rename, switch, remove, generate again ===');
  const oldName = 'pep-' + NAME + '-api';
  const renamed = act(k, { action: 'set-pep-route', from: 'api',
    id: 'api2', path: '/api', methods: ['GET', 'DELETE'],
    methodsGiven: 'true', mechanisms: ['basic'], application: 'ppr-api' });
  const newName = 'pep-' + NAME + '-api2';
  t.check(renamed.ok && !store.read(oldName) && !!store.read(newName) &&
          store.read(newName).pepRoute === NAME + '/api2' &&
          renamed.policies.removed.indexOf(oldName) >= 0,
          '6.1 a rename renames the generated policy',
          JSON.stringify(renamed.policies));
  const switched = act(k, { action: 'set-pep-route-authorization',
    route: 'api2', authorization: { kind: 'policy',
                                    policy: 'ppr-handwritten' } });
  t.check(switched.ok && !!store.read(newName) &&
          switched.policies.unreferenced.indexOf(newName) >= 0,
          '6.2 switching to an existing policy leaves the generated one, ' +
          'and says no route references it', JSON.stringify(switched));
  const unconfirmed = act(k, { action: 'remove-pep-route', route: 'open' });
  t.check(codeOf(k, unconfirmed) === 'STS-XACML-0268' &&
          !!store.read('pep-' + NAME + '-open'),
          '6.3 a route with a generated policy is not removed without ' +
          'removePolicy (STS-XACML-0268)', JSON.stringify(unconfirmed));
  const confirmed = act(k, { action: 'remove-pep-route', route: 'open',
                             removePolicy: 'true' });
  t.check(confirmed.ok && !store.read('pep-' + NAME + '-open') &&
          confirmed.policies.removed.indexOf('pep-' + NAME + '-open') >= 0,
          '6.4 with it, the route and its policy go',
          JSON.stringify(confirmed));
  const back = act(k, { action: 'set-pep-route-authorization',
    route: 'api2', authorization: { kind: 'simple',
      actionModel: 'read-write', roles: { read: ['ppr-readers'] } } });
  store.remove(newName);
  const again = act(k, { action: 'generate-pep-route-policy',
                         route: 'api2' });
  const nothing = act(k, { action: 'generate-pep-route-policy',
                           route: 'api2' });
  t.check(back.ok && again.ok && again.written === true &&
          !!store.read(newName) && nothing.ok && nothing.written === false,
          '6.5 generate-pep-route-policy writes a deleted policy again, ' +
          'and nothing when it already says what the route chooses',
          JSON.stringify([again, nothing]));
  const asRoot = store.write(newName, store.read(newName).document,
                             { isRoot: true });
  t.check(!asRoot.ok && codeOf(k, asRoot) === 'STS-XACML-0267',
          '6.6 a generated policy cannot be made the root (STS-XACML-0267)',
          JSON.stringify(asRoot));
  const policyKind = act(k, { action: 'set-pep-route-authorization',
    route: 'api2', authorization: { kind: 'policy',
                                    policy: 'ppr-handwritten' } });
  const notGenerated = act(k, { action: 'generate-pep-route-policy',
                                route: 'api2' });
  t.check(policyKind.ok && codeOf(k, notGenerated) === 'STS-XACML-0264',
          '6.7 an existing-policy route has nothing to generate',
          JSON.stringify(notGenerated));
  log.debug("Leaving lifecycle().");
}

function search(k) {
  log.debug("Entering search().");
  const { t, pap, peps, pepProxy } = k;
  t.log.info('=== 7. the policy search, and the pull ===');
  const found = pap.policiesJson({ q: 'ppr-', per: '1', routable: 'true' });
  const names = function (answer) {
    return (answer.policies || []).map(function (one) {
      return one.name;
    });
  };
  const everything = pap.policiesJson({ q: 'ppr', per: '50',
                                        routable: 'true' });
  const whole = pap.policiesJson();
  t.check(found.matched >= 1 && found.policies.length === 1 &&
          found.pages === found.matched && found.page === 1 &&
          names(everything).indexOf('ppr-handwritten') >= 0 &&
          names(everything).indexOf('ppr-disabled') < 0 &&
          whole.matched === undefined && whole.policies.length >= 3,
          '7.1 the search pages by `per`, keeps only what a route may ' +
          'choose with `routable`, and without it the answer is the ' +
          'repository whole', JSON.stringify(names(everything)));
  const withheld = pap.policiesJson({ q: 'access-control',
                                      routable: 'true' });
  t.check(withheld.matched === 0,
          '7.2 this service\'s own access policy is not routable');
  const row = peps.read(NAME);
  const pulled = pepProxy.pull(BASE, row, NAME).body;
  const route = pulled.proxy.routes.filter(function (one) {
    return one.id === 'api2';
  })[0];
  t.check(route && route.authorization.policy === 'ppr-handwritten' &&
          route.public === undefined && route.resource === undefined &&
          route.action === undefined && route.resolved.usable === true,
          '7.3 the pull carries each route\'s authorization and no retired ' +
          'member', JSON.stringify(route));
  log.debug("Leaving search().");
}

// THE ROUTE PAGE'S TABS (rcbj, 2026-11-15): each tab a form of its own,
// `set-pep-route` with `part`, which reads only that tab's members and
// keeps every other member of the stored route. Each form below also
// carries the OTHER tabs' members with wrong values, which must be
// ignored: a Save on one tab never changes or loses another's.
function parts(k) {
  log.debug("Entering parts().");
  const { t, store, pap } = k;
  t.log.info('=== 8. the route page\'s tabs, each its own Save ===');
  const routeOf = function (answer, wanted) {
    return answer && answer.proxy && answer.proxy.routes.filter(
      function (one) {
        return one.id === wanted;
      })[0];
  };
  const made = act(k, { action: 'set-pep-route', id: 'tabs', path: '/tabs',
    match: 'exact', methods: ['GET', 'POST'], methodsGiven: 'true',
    mechanisms: ['basic', 'oauth2'], application: 'ppr-api',
    authzKind: 'simple', authzActionModel: 'read-write',
    authzActions: ['read'], 'authzRole.read': ['ppr-readers'],
    forwardCredentials: 'true', signals: 'false', mode: 'headers',
    headerName: ['X-User'], headerClaim: ['username'], separator: ';' });
  const before = routeOf(made, 'tabs');
  t.check(made.ok && !!before && before.identity.headers.length === 1,
          '8.0 a route to edit tab by tab', JSON.stringify(made));
  // The wrong values every form carries for the members it does not own.
  const noise = { path: '/wrong', match: 'prefix', application: '',
    methods: ['DELETE'], methodsGiven: 'true', mechanisms: [],
    authzKind: 'public', forwardCredentials: 'false', signals: 'true',
    multipleAccounts: 'false', mode: 'jwt' };
  const same = function (after, keep) {
    return keep.every(function (member) {
      return JSON.stringify(after[member]) === JSON.stringify(before[member]);
    });
  };
  const ALL = ['path', 'match', 'application', 'methods', 'mechanisms',
               'authorization', 'forwardCredentials', 'signals',
               'multipleAccounts', 'identity'];
  const outside = function (owned) {
    return ALL.filter(function (one) {
      return owned.indexOf(one) < 0;
    });
  };
  const authn = act(k, Object.assign({}, noise, { action: 'set-pep-route',
    from: 'tabs', id: 'tabs', part: 'authentication',
    mechanisms: ['basic'], signals: 'true' }));
  const a = routeOf(authn, 'tabs');
  t.check(authn.ok && a.mechanisms.join() === 'basic' && a.signals === true &&
          same(a, outside(['mechanisms', 'signals', 'multipleAccounts'])),
          '8.1 Authentication saves its members and keeps every other ' +
          'tab\'s', JSON.stringify(a));
  const authz = act(k, Object.assign({}, noise, { action: 'set-pep-route',
    from: 'tabs', id: 'tabs', part: 'authorization',
    methods: ['GET'], methodsGiven: 'true', authzKind: 'policy',
    authzPolicy: 'ppr-handwritten', authzPolicyActionModel: 'method' }));
  const z = routeOf(authz, 'tabs');
  t.check(authz.ok && z.methods.join() === 'GET' &&
          z.authorization.kind === 'policy' &&
          z.authorization.policy === 'ppr-handwritten' &&
          z.mechanisms.join() === 'basic' &&
          JSON.stringify(z.identity) === JSON.stringify(before.identity) &&
          z.path === '/tabs' && z.forwardCredentials === true,
          '8.2 Authorization saves the methods and the choice and keeps the ' +
          'rest', JSON.stringify(z));
  const ident = act(k, Object.assign({}, noise, { action: 'set-pep-route',
    from: 'tabs', id: 'tabs', part: 'identity', authzKind: 'public',
    forwardCredentials: 'false', mode: 'headers',
    headerName: ['X-Mail'], headerClaim: ['email'], separator: ',' }));
  const i = routeOf(ident, 'tabs');
  t.check(ident.ok && i.forwardCredentials === false &&
          i.identity.headers.length === 1 &&
          i.identity.headers[0].name === 'X-Mail' &&
          i.authorization.kind === 'policy' && i.methods.join() === 'GET' &&
          i.path === '/tabs' && i.match === 'exact',
          '8.3 Identity sent to backend saves forwarding and the identity ' +
          'and keeps the rest', JSON.stringify(i));
  const settings = act(k, Object.assign({}, noise, {
    action: 'set-pep-route', from: 'tabs', id: 'tabs2', part: 'settings',
    path: '/tabs2', match: 'prefix', application: 'ppr-api',
    mode: 'jwt' }));
  const st = routeOf(settings, 'tabs2');
  t.check(settings.ok && !routeOf(settings, 'tabs') && !!st &&
          st.path === '/tabs2' && st.match === 'prefix' &&
          st.methods.join() === 'GET' && st.mechanisms.join() === 'basic' &&
          st.identity.headers[0].name === 'X-Mail' &&
          st.forwardCredentials === false &&
          st.authorization.policy === 'ppr-handwritten',
          '8.4 Settings renames the route and saves its matching, keeping ' +
          'every other tab\'s', JSON.stringify(st));
  const whole = act(k, { action: 'set-pep-route', from: 'tabs2',
    id: 'tabs2', path: '/tabs2', methodsGiven: 'true',
    mechanisms: ['basic'], application: 'ppr-api', mode: 'headers' });
  const w = routeOf(whole, 'tabs2');
  t.check(whole.ok && w.methods.length === 0 && w.forwardCredentials === false &&
          w.identity.headers.length === 0,
          '8.5 without `part` the form members are the whole route, as ' +
          'before', JSON.stringify(w));
  const unknown = act(k, Object.assign({}, noise, {
    action: 'set-pep-route', from: 'tabs2', id: 'tabs2', part: 'order' }));
  const missing = act(k, { action: 'set-pep-route', from: 'nope',
    id: 'nope', part: 'authentication', mechanisms: ['basic'] });
  const fresh = act(k, { action: 'set-pep-route', id: 'nope2',
    part: 'identity', mode: 'headers' });
  t.check(codeOf(k, unknown) === 'STS-XACML-0256' &&
          codeOf(k, missing) === 'STS-XACML-0230' &&
          codeOf(k, fresh) === 'STS-XACML-0230',
          '8.6 a part that names no tab is STS-XACML-0256, and a part ' +
          'on a route that does not exist STS-XACML-0230',
          JSON.stringify([unknown, missing, fresh]));
  // A GENERATED POLICY IS REWRITTEN BY ANY TAB'S SAVE, which is what the
  // editor's warning says: hand-edited, then a save of the route's
  // Authentication tab, which names no authorization member.
  const simple = act(k, { action: 'set-pep-route', from: 'tabs2',
    id: 'tabs2', part: 'authorization', methods: ['GET'],
    methodsGiven: 'true', authzKind: 'simple',
    authzActionModel: 'read-write', authzActions: ['read'],
    'authzRole.read': ['ppr-readers'] });
  const name = 'pep-' + k.peps.read(NAME).name + '-tabs2';
  const held = store.read(name);
  const edited = held && held.document.replace('?>',
    '?><!-- edited by hand -->');
  const handWritten = held && store.write(name, edited.indexOf('edited') > 0
    ? edited : '<!-- edited by hand -->' + held.document,
    { enabled: true, isRoot: false });
  const stored = store.read(name);
  const marked = !!stored && stored.document.indexOf('edited by hand') >= 0;
  const againSaved = act(k, { action: 'set-pep-route', from: 'tabs2',
    id: 'tabs2', part: 'authentication', mechanisms: ['basic'],
    signals: 'true' });
  const after = store.read(name);
  t.check(simple.ok && !!held && handWritten && handWritten.ok && marked &&
          againSaved.ok && after.document.indexOf('edited by hand') < 0 &&
          after.pepRoute === NAME + '/tabs2',
          '8.7 a hand edit of a route\'s generated policy is replaced by a ' +
          'save of any of the route\'s tabs, not only Authorization',
          JSON.stringify({ simple: simple.ok, held: !!held,
                           hand: handWritten, marked: marked,
                           saved: againSaved.ok }));
  const editorOf = pap.editorJson(name);
  const ordinary = pap.editorJson('ppr-handwritten');
  t.check(editorOf.policy.pepRoute === NAME + '/tabs2' &&
          ordinary.policy.pepRoute === null,
          '8.8 the editor\'s answer names the route a generated policy is ' +
          'for, and null for an ordinary one',
          JSON.stringify([editorOf.policy, ordinary.policy]));
  act(k, { action: 'remove-pep-route', route: 'tabs2', removePolicy: true });
  log.debug("Leaving parts().");
}

module.exports = {
  name: 'xacml_pep_route_policies',
  describe: 'a reverse-proxy route\'s authorization (#1760): the choice, ' +
            'the generated simple and public policies decided through the ' +
            'engine, deny-all, the default resource and the lifecycle',
  run: run
};
