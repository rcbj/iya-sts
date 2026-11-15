// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/xacml_pep_proxy.js
//
// ===========================================================================
// THE REMOTE PEP AS A REVERSE PROXY, THE SERVICE'S HALF (#1760, phase 1).
//
// In a CHILD PROCESS with the whole stack, over real handshakes on a listener
// with the main port's posture (the arrangement `authzen_evaluation.js` has):
//
//   A. the configuration grammar (`xacml/xacml_pep_proxy.ts`'s
//      `validate()`): the issue's example normalised, and every refusal by
//      its code, product's https rule through a PepProxy built with it;
//   B. the register carrying `xacmlPepProxy` across a re-registration and a
//      heartbeat, which rewrite the whole entry;
//   C. the pull, `GET /xacml/pep/proxy`: the gate, `configured: false`
//      before a configuration, the members after it, the ETag and 304, a
//      token that moves with the configuration and not with a policy, and a
//      value an `ldapmodify` wrote that does not validate pulled as
//      `configured: false`;
//   D. the four validation doors: the gate on each, Basic valid, refused
//      with nothing said and blocked 429 with `retryAfterS`, introspection
//      active and inactive, a SAML assertion valid, altered, for another
//      audience, expired and encrypted, and a session live and then ended;
//   E. a route referencing an application (D10): the session client's
//      facts on the pull, a secret rotation moving the token, nothing on the
//      console, the application's page, each save refusal, and a deleted
//      application leaving its route unusable;
//   F. the administrative actions' refusals and the `/admin-api` view;
//   H. how the identity reaches the application (D11): the identity
//      grammar's refusals (in A), the Basic ticket, `POST
//      /xacml/pep/identity` in modes headers, jwt and saml, forged and
//      foreign evidence, a route and a ticket of another PEP, an expired
//      ticket, the issuance policy's refusal, and the console's per-route
//      action;
//   S. a remote PEP's managed settings: every refusal by its code,
//      product's refusal of a verification turned off, the form's empty
//      boxes, `GET /xacml/pep/settings` (the gate, the ETag and 304, a
//      token that moves), the register keeping them, the PEP's report of
//      what it has in force held to its members, the page's `?pep=` view,
//      the managed notify URL the nudge dials, and a stored value that
//      does not validate;
//   G. Basic in product.
//
// The over-HTTP half against the Rust container is
// `tests/protocol/sts_xacml_remote_pep.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const https = require('https');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_XACML_PEP_PROXY_CHILD';
const MARK = 'XACML-PEP-PROXY-CHILD ';
const REALM = 'pepproxy';
const PREFIX = '/realm/' + REALM;
const AUDIENCE = 'https://app.example/api';
const CALLBACK = 'https://xacml-pep:9543/.iya-pep/callback';
const WEB_SECRET = 'ppx-web-secret-0123456789abcdef0123456789';

const CA_PEM = { value: '' };

const log = require('bunyan').createLogger({ name: 'xacml_pep_proxy',
  level: process.env.LOG_LEVEL || 'info' });

// The issue's D2 example.
function example() {
  log.debug("Entering example().");
  log.debug("Leaving example().");
  return {
    enabled: true,
    upstream: 'http://companion:8090/pep-app',
    publicBaseUrl: 'https://xacml-pep:9543',
    upstreamTimeoutMs: 10000,
    maxBodyBytes: 1048576,
    routes: [
      { id: 'public', path: '/public', match: 'prefix',
        methods: ['GET', 'HEAD'], public: true },
      { id: 'api', path: '/api', match: 'prefix', methods: ['GET', 'POST'],
        mechanisms: ['oauth2', 'basic'], application: 'ppx-api',
        resource: '', action: '',
        identity: { mode: 'headers',
                    headers: [{ name: 'X-Remote-User', claim: 'username' },
                              { name: 'X-Remote-Groups', claim: 'groups' }],
                    separator: ',' },
        forwardCredentials: false }
    ]
  };
}

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function request(port, method, urlPath, cred, body, headers) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const text = body === undefined ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const sent = Object.assign({ 'content-type': 'application/json',
                                 'content-length': Buffer.byteLength(text) },
                               headers || {});
    const req = https.request({ host: '127.0.0.1', port: port,
      path: urlPath, method: method, headers: sent, ca: CA_PEM.value,
      cert: cred ? cred.certPem : undefined,
      key: cred ? cred.keyPem : undefined, agent: false }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: raw,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end(text);
  });
}

// The members each closed answer may hold.
const CLOSED = {
  basic: ['valid', 'sub', 'username', 'retryAfterS', 'ticket'],
  introspect: ['active', 'sub', 'username', 'scope', 'client_id', 'aud',
               'iss', 'exp', 'iat', 'token_type', 'cnf'],
  saml: ['valid', 'subject', 'username', 'issuer', 'notOnOrAfter',
         'sessionIndex'],
  session: ['live', 'sub', 'username'],
  pull: ['syncToken', 'pep', 'configured', 'proxy', 'realm', 'validation',
         'note'],
  realm: ['issuer', 'jwksUri', 'authorizationEndpoint', 'tokenEndpoint',
          'endSessionEndpoint', 'samlIssuer', 'signingCertificates',
          'tlsCaChain', 'clients'],
  error: ['error', 'error_description']
};

function closedTo(json, kind) {
  log.debug("Entering closedTo(). " + kind);
  const allowed = CLOSED[kind];
  const stray = Object.keys(json || {}).filter(function (key) {
    return allowed.indexOf(key) < 0;
  });
  log.debug("Leaving closedTo().");
  return !!json && stray.length === 0;
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const tls = require(ROOT + '/tls/tls_server');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const authn = require(ROOT + '/authn/authn');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const store = require(ROOT + '/xacml/xacml_store');
  const xml = require(ROOT + '/xacml/xacml_xml');
  const alfa = require(ROOT + '/xacml/xacml_alfa');
  const peps = require(ROOT + '/xacml/xacml_pep_registry');
  const pepProxy = require(ROOT + '/xacml/xacml_pep_proxy');
  const saml2 = require(ROOT + '/saml/saml2');
  const testCa = require('./protocol/outbound_test_ca');
  const outsideCa = require('./tools/pep-credential.js');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };
  const markedSince = function (since, code) {
    log.debug("Entering markedSince().");
    log.debug("Leaving markedSince().");
    return marks.slice(since).indexOf(code) >= 0;
  };

  // -------------------------------------------------------------------------
  // A. THE GRAMMAR.
  // -------------------------------------------------------------------------
  // A document whose api route's identity is replaced, for the refusals.
  const ident = function (identity) {
    log.debug("Entering ident().");
    const doc = example();
    doc.routes[1].identity = typeof identity === 'object' &&
      !identity.mode && !identity.headers && !identity.separator
      ? identity : (typeof identity === 'object' && !identity.mode
        ? Object.assign({ mode: 'headers' }, identity) : identity);
    log.debug("Leaving ident().");
    return { routes: doc.routes };
  };
  const good = pepProxy.validate(example());
  t.check(good.ok && good.proxy.routes.length === 2 &&
          good.proxy.publicBaseUrl === 'https://xacml-pep:9543' &&
          good.proxy.routes[0].mechanisms.length === 0 &&
          good.proxy.routes[0].application === '' &&
          good.proxy.routes[1].application === 'ppx-api' &&
          good.proxy.routes[1].signals === true &&
          good.proxy.routes[0].forwardCredentials === false &&
          good.proxy.routes[1].identity.mode === 'headers' &&
          good.proxy.routes[1].identity.headers[1].claim === 'groups' &&
          good.proxy.routes[0].identity.mode === 'headers' &&
          good.proxy.routes[0].identity.headers.length === 0,
          'A1. the issue\'s example validates, normalised with every member ' +
          'present', JSON.stringify(good));
  const asText = pepProxy.validate(JSON.stringify(example()));
  t.check(asText.ok, 'A2. the same document as JSON text validates');
  const refusals = [
    ['not JSON', '{nope', 'STS-XACML-0184'],
    ['an array', [], 'STS-XACML-0184'],
    ['a stray top-level member', { extra: 1 }, 'STS-XACML-0185'],
    ['a stray route member', { routes: [{ id: 'a', path: '/a',
      public: true, color: 'red' }] }, 'STS-XACML-0185'],
    ['enabled as a string', { enabled: 'yes' }, 'STS-XACML-0186'],
    ['an upstream with a query', { upstream: 'http://h/app?x=1' },
     'STS-XACML-0187'],
    ['an upstream with a fragment', { upstream: 'http://h/app#f' },
     'STS-XACML-0187'],
    ['an upstream with userinfo', { upstream: 'http://u:p@h/app' },
     'STS-XACML-0187'],
    ['an ftp upstream', { upstream: 'ftp://h/app' }, 'STS-XACML-0187'],
    ['a relative upstream', { upstream: '/app' }, 'STS-XACML-0187'],
    ['a publicBaseUrl with a path', { publicBaseUrl: 'https://p/x' },
     'STS-XACML-0188'],
    ['a session route with no publicBaseUrl', { publicBaseUrl: '',
      routes: [{ id: 's', path: '/s', mechanisms: ['session'],
                 application: 'ppx-web' }] }, 'STS-XACML-0188'],
    ['a session route on a plain-http publicBaseUrl', {
      publicBaseUrl: 'http://xacml-pep:9180',
      routes: [{ id: 's', path: '/s', mechanisms: ['session'],
                 application: 'ppx-web' }] }, 'STS-XACML-0188'],
    ['upstreamTimeoutMs 0', { upstreamTimeoutMs: 0 }, 'STS-XACML-0189'],
    ['upstreamTimeoutMs 120001', { upstreamTimeoutMs: 120001 },
     'STS-XACML-0189'],
    ['maxBodyBytes -1', { maxBodyBytes: -1 }, 'STS-XACML-0190'],
    ['maxBodyBytes a decimal', { maxBodyBytes: 1.5 }, 'STS-XACML-0190'],
    ['65 routes', { routes: Array.from({ length: 65 }, function (x, i) {
      return { id: 'r' + i, path: '/r' + i, public: true };
    }) }, 'STS-XACML-0191'],
    ['a route that is not an object', { routes: ['x'] }, 'STS-XACML-0191'],
    ['a route id with a space', { routes: [{ id: 'a b', path: '/a',
      public: true }] }, 'STS-XACML-0192'],
    ['two routes with one id', { routes: [
      { id: 'a', path: '/a', public: true },
      { id: 'a', path: '/b', public: true }] }, 'STS-XACML-0192'],
    ['a path with ..', { routes: [{ id: 'a', path: '/a/../b',
      public: true }] }, 'STS-XACML-0193'],
    ['a path with .', { routes: [{ id: 'a', path: '/./b',
      public: true }] }, 'STS-XACML-0193'],
    ['a path with //', { routes: [{ id: 'a', path: '/a//b',
      public: true }] }, 'STS-XACML-0193'],
    ['a path with %', { routes: [{ id: 'a', path: '/a%2e',
      public: true }] }, 'STS-XACML-0193'],
    ['a path with a backslash', { routes: [{ id: 'a', path: '/a\\b',
      public: true }] }, 'STS-XACML-0193'],
    ['a path with no leading slash', { routes: [{ id: 'a', path: 'a',
      public: true }] }, 'STS-XACML-0193'],
    ['match glob', { routes: [{ id: 'a', path: '/a', match: 'glob',
      public: true }] }, 'STS-XACML-0194'],
    ['an unknown method', { routes: [{ id: 'a', path: '/a',
      methods: ['TRACE'], public: true }] }, 'STS-XACML-0195'],
    ['a method twice', { routes: [{ id: 'a', path: '/a',
      methods: ['GET', 'GET'], public: true }] }, 'STS-XACML-0195'],
    ['a public route naming a mechanism', { routes: [{ id: 'a',
      path: '/a', public: true, mechanisms: ['basic'] }] },
     'STS-XACML-0196'],
    ['a route with no mechanism', { routes: [{ id: 'a', path: '/a' }] },
     'STS-XACML-0196'],
    ['an unknown mechanism', { routes: [{ id: 'a', path: '/a',
      mechanisms: ['kerberos'] }] }, 'STS-XACML-0196'],
    ['a route with no application', { routes: [{ id: 'a', path: '/a',
      mechanisms: ['oauth2'] }] }, 'STS-XACML-0197'],
    ['a public route naming an application', { routes: [{ id: 'a',
      path: '/a', public: true, application: 'ppx-api' }] },
     'STS-XACML-0197'],
    ['the retired audience member', { routes: [{ id: 'a', path: '/a',
      mechanisms: ['oauth2'], application: 'ppx-api', audience: 'x' }] },
     'STS-XACML-0185'],
    ['signals as a string', { routes: [{ id: 'a', path: '/a',
      mechanisms: ['basic'], application: 'ppx-api', signals: 'yes' }] },
     'STS-XACML-0199'],
    ['the retired subjectHeader member', { routes: [{ id: 'a', path: '/a',
      mechanisms: ['basic'], application: 'ppx-api',
      subjectHeader: 'X-Remote-User' }] }, 'STS-XACML-0185'],
    ['identity not an object', ident('headers'), 'STS-XACML-0224'],
    ['an unknown identity mode', ident({ mode: 'cookie' }),
     'STS-XACML-0224'],
    ['a stray identity member', ident({ mode: 'headers', extra: 1 }),
     'STS-XACML-0185'],
    ['headers in mode jwt', ident({ mode: 'jwt',
      headers: [{ name: 'X-U', claim: 'sub' }] }), 'STS-XACML-0224'],
    ['an identity on a public route', { routes: [{ id: 'a', path: '/a',
      public: true, identity: { mode: 'jwt' } }] }, 'STS-XACML-0224'],
    ['17 identity headers', ident({ mode: 'headers',
      headers: Array.from({ length: 17 }, function (x, i) {
        return { name: 'X-H' + i, claim: 'sub' };
      }) }), 'STS-XACML-0225'],
    ['a header row with a stray member', ident({ headers: [
      { name: 'X-U', claim: 'sub', value: 'x' }] }), 'STS-XACML-0225'],
    ['a header name with a space', ident({ headers: [
      { name: 'X Remote', claim: 'sub' }] }), 'STS-XACML-0198'],
    ['Authorization as an identity header', ident({ headers: [
      { name: 'Authorization', claim: 'sub' }] }), 'STS-XACML-0198'],
    ['Cookie as an identity header', ident({ headers: [
      { name: 'cookie', claim: 'sub' }] }), 'STS-XACML-0198'],
    ['Forwarded as an identity header', ident({ headers: [
      { name: 'Forwarded', claim: 'sub' }] }), 'STS-XACML-0198'],
    ['X-Forwarded-For as an identity header', ident({ headers: [
      { name: 'X-Forwarded-For', claim: 'sub' }] }), 'STS-XACML-0198'],
    ['Transfer-Encoding as an identity header', ident({ headers: [
      { name: 'Transfer-Encoding', claim: 'sub' }] }), 'STS-XACML-0198'],
    ['one header twice, in two cases', ident({ headers: [
      { name: 'X-U', claim: 'sub' }, { name: 'x-u', claim: 'email' }] }),
     'STS-XACML-0225'],
    ['an unknown claim', ident({ headers: [
      { name: 'X-U', claim: 'password' }] }), 'STS-XACML-0226'],
    ['an inherited claim name', ident({ headers: [
      { name: 'X-U', claim: 'constructor' }] }), 'STS-XACML-0226'],
    ['a two-character separator', ident({ separator: ',,' }),
     'STS-XACML-0227'],
    ['a letter as the separator', ident({ separator: 'a' }),
     'STS-XACML-0227'],
    ['a space as the separator', ident({ separator: ' ' }),
     'STS-XACML-0227'],
    ['forwardCredentials as a string', { routes: [{ id: 'a', path: '/a',
      mechanisms: ['basic'], application: 'ppx-api', forwardCredentials: 'no' }] },
     'STS-XACML-0199'],
    ['public as a string', { routes: [{ id: 'a', path: '/a',
      public: 'yes' }] }, 'STS-XACML-0199'],
    ['an application with a newline', { routes: [{ id: 'a', path: '/a',
      mechanisms: ['oauth2'], application: 'a\nb' }] }, 'STS-XACML-0199']
  ];
  refusals.forEach(function (one, i) {
    const doc = typeof one[1] === 'string' || Array.isArray(one[1])
      ? one[1] : Object.assign(example(), one[1]);
    const got = pepProxy.validate(doc);
    t.check(!got.ok && got.code === one[2] &&
            errorCodes.codeOf(got) === one[2] && /\S/.test(got.why),
            'A3.' + (i + 1) + ' refused: ' + one[0] + ' (' + one[2] + ')',
            JSON.stringify(got));
  });
  const productProxy = new pepProxy.PepProxy(Object.assign(
    pepProxy.PepProxy.defaultDeps(), {
      clearOriginAllowed: function () {
        log.debug("Entering clearOriginAllowed().");
        log.debug("Leaving clearOriginAllowed().");
        return false;
      } }));
  const clear = productProxy.validate(Object.assign(example(),
    { publicBaseUrl: 'http://xacml-pep:9180' }));
  t.check(!clear.ok && clear.code === 'STS-XACML-0188',
          'A4. in product a plain-http publicBaseUrl is refused ' +
          '(STS-XACML-0188)', JSON.stringify(clear));
  const devClear = pepProxy.validate(Object.assign(example(),
    { publicBaseUrl: 'http://xacml-pep:9180' }));
  t.check(devClear.ok, 'A5. in development it is accepted',
          JSON.stringify(devClear));

  // -------------------------------------------------------------------------
  // THE STACK: a realm, a remote PEP's credential, a listener.
  // -------------------------------------------------------------------------
  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  const pepCred = await outsideCa.mint({ subject: 'CN=ppxpep,O=Outside',
                                         crlBase: '' });
  tls.addAnchors(pepCred.anchorPem);
  const derOf = function (minted) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return new nodeCrypto.X509Certificate(minted.leaf.pem).raw;
  };
  inRealm(function () {
    ['ppxpep', 'ppxalice'].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    // THE APPLICATIONS THE ROUTES FRONT (D10).
    const made = [
      applications.createApplication({ identifier: 'ppx-api',
        protocols: ['oauth2'],
        fields: { oauthClientId: 'ppx-api',
                  oauthAudience: [AUDIENCE] } }),
      applications.createApplication({ identifier: 'ppx-web',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'ppx-web', oauthClientSecret: WEB_SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_basic',
                  oauthGrantType: ['authorization_code'],
                  oauthRedirectUri: [CALLBACK] } }),
      applications.createApplication({ identifier: 'ppx-public',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'ppx-public',
                  oauthTokenEndpointAuthMethod: 'none',
                  oauthGrantType: ['authorization_code'],
                  oauthRedirectUri: [CALLBACK] } }),
      applications.createApplication({ identifier: 'ppx-nocb',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'ppx-nocb', oauthClientSecret: WEB_SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_post',
                  oauthGrantType: ['authorization_code'],
                  oauthRedirectUri: ['https://elsewhere.example/cb'] } }),
      applications.createApplication({ identifier: 'ppx-nocode',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthClientId: 'ppx-nocode', oauthClientSecret: WEB_SECRET,
                  oauthTokenEndpointAuthMethod: 'client_secret_basic',
                  oauthGrantType: ['client_credentials'],
                  oauthRedirectUri: [CALLBACK] } })
    ];
    made.forEach(function (one, i) {
      t.check(one && one.ok !== false, 'setup: application ' + i +
              ' created', JSON.stringify(one).slice(0, 300));
    });
    ldap.changeStoredCertificate('person', 'ppxpep', { add: derOf(pepCred) });
    adminActions.groupsAction({ action: 'add-member',
      group: String(config.value('roles.remotePepGroup')),
      member: 'ppxpep' });
  });
  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  CA_PEM.value = serverCa.certPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  tls.trustClientCertificatesOn(listener, 'the xacml_pep_proxy listener',
    function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 400);
  };
  const PULL = PREFIX + '/xacml/pep/proxy';

  // -------------------------------------------------------------------------
  // B. THE REGISTER CARRIES THE ATTRIBUTE.
  // -------------------------------------------------------------------------
  let r = await request(port, 'POST', PREFIX + '/xacml/pep/register',
                        pepCred, { version: 'test' });
  t.check(r.status === 201 || r.status === 200,
          'B1. the PEP registers in the realm', brief(r));
  const NAME = r.json ? r.json.name : '';
  const before = await request(port, 'GET', PULL, pepCred);
  t.check(before.status === 200 && before.json &&
          before.json.configured === false && !before.json.proxy &&
          before.json.pep === NAME && closedTo(before.json, 'pull') &&
          before.headers['cache-control'] === 'no-store',
          'C1. an unconfigured PEP pulls configured: false, no proxy, ' +
          'no-store', brief(before));
  const set = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                                      proxy: example() });
  });
  t.check(set && set.ok && set.proxy && set.clientId === undefined,
          'F1. set-pep-proxy saves the example; nothing is created',
          JSON.stringify(set));
  r = await request(port, 'POST', PREFIX + '/xacml/pep/register', pepCred,
                    { version: 'again' });
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                    { decisions: 3, allowed: 2, refused: 1 });
  const row = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(r.status === 200 && row && row.proxy &&
          JSON.parse(row.proxy).routes.length === 2 && row.decisions === 3,
          'B2. a re-registration and a heartbeat keep xacmlPepProxy', row &&
          String(row.proxy).slice(0, 120));

  // -------------------------------------------------------------------------
  // B'. THE SIGNAL-STREAM HEALTH (#1760). An older PEP sends none and is
  // "not reported"; a newer one's is kept as counts and ages only, whatever
  // else it sent; a heartbeat without it keeps it, null clears it, and a
  // registration (a new process) drops it.
  // -------------------------------------------------------------------------
  t.check(row && row.signals === null,
          'B3. a PEP that never reported signal health is null (not ' +
          'reported), not zero', row && JSON.stringify(row.signals));
  const reported = {
    receivers: 2, healthy: 1, stale: 1, staleAfterMs: 60000,
    pollIntervalMs: 5000, oldestSuccessAgeMs: 73000,
    mostConsecutiveFailures: 4, setsAccepted: 9, setsRefused: 1,
    sessionsEnded: 3,
    librarySessions: { held: 5, max: 20000, ttlSec: 28800, evicted: 0,
                       expired: 2, lastError: 'connect ECONNREFUSED ' +
                       'https://sts.internal.example:8081/ssf/poll' },
    // What the PEP promises never to send, sent anyway.
    clientId: 'ppx-secret-client', lastError: 'refused by ' +
      'https://sts.internal.example:8081', url: 'https://evil.example/',
    at: '1999-01-01T00:00:00Z'
  };
  const tampered = Object.assign({}, reported,
    { healthy: -3, setsAccepted: '12', sessionsEnded: 1.5 });
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                    { decisions: 4, signals: tampered });
  let health = inRealm(function () {
    return peps.read(NAME);
  });
  const held = health && health.signals;
  const keys = held ? Object.keys(held).sort().join(',') : '';
  t.check(r.status === 200 && held && keys ===
            'at,healthy,librarySessions,mostConsecutiveFailures,' +
            'oldestSuccessAgeMs,pollIntervalMs,receivers,sessionsEnded,' +
            'setsAccepted,setsRefused,stale,staleAfterMs' &&
          Object.keys(held.librarySessions).sort().join(',') ===
            'evicted,expired,held,max,ttlSec' &&
          !/ppx-secret-client|https?:|ECONNREFUSED|evil/
            .test(JSON.stringify(held)),
          'B4. only the counts and ages are kept: no client id, URL or ' +
          'error text, at either level', JSON.stringify(held));
  t.check(held && held.receivers === 2 && held.stale === 1 &&
          held.oldestSuccessAgeMs === 73000 &&
          held.mostConsecutiveFailures === 4 &&
          held.librarySessions.held === 5 &&
          held.librarySessions.max === 20000 &&
          held.healthy === 0 && held.setsAccepted === 0 &&
          held.sessionsEnded === 0,
          'B5. each value is a non-negative integer or 0 (a negative, a ' +
          'string and a fraction are 0)', JSON.stringify(held));
  t.check(held && held.at !== '1999-01-01T00:00:00.000Z' &&
          Math.abs(Date.parse(held.at) - Date.now()) < 60000,
          'B6. `at` is when this service received it, not what the PEP ' +
          'said', held && held.at);
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                    { decisions: 5 });
  health = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(r.status === 200 && health && health.signals &&
          health.signals.receivers === 2 && health.decisions === 5,
          'B7. a heartbeat without signals (an older PEP, or the pull\'s ' +
          'own) keeps the last snapshot', JSON.stringify(health &&
          health.signals));
  const listedSignals = inRealm(function () {
    return require(ROOT + '/xacml/xacml_admin').pepsJson();
  });
  const mineSignals = (listedSignals.peps || []).filter(function (one) {
    return one.name === NAME;
  })[0];
  t.check(mineSignals && mineSignals.signals &&
          mineSignals.signals.stale === 1 &&
          mineSignals.signals.librarySessions.expired === 2,
          'B8. GET /admin-api/xacml/peps\' row carries the snapshot',
          JSON.stringify(mineSignals && mineSignals.signals));
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                    { signals: null });
  health = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(r.status === 200 && health && health.signals === null &&
          health.proxy,
          'B9. a heartbeat with signals: null clears it, and keeps the ' +
          'proxy', JSON.stringify(health && health.signals));
  await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                { signals: reported });
  r = await request(port, 'POST', PREFIX + '/xacml/pep/register', pepCred,
                    { version: 'restarted' });
  health = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(health && health.signals === null && health.proxy,
          'B10. a re-registration (a new process) drops the snapshot and ' +
          'keeps the proxy', JSON.stringify(health && health.signals));
  // The stored value is read through the same function, so text an
  // ldapmodify wrote is "not reported" and an object is held to the members.
  const fromStore = peps.signalsOf('{"receivers":3,"lastError":"x://y",' +
                                   '"at":"2026-11-14T00:00:00Z"}');
  t.check(peps.signalsOf('not json') === null &&
          peps.signalsOf('[1,2]') === null && peps.signalsOf('') === null &&
          fromStore && fromStore.receivers === 3 &&
          fromStore.at === '2026-11-14T00:00:00.000Z' &&
          fromStore.lastError === undefined,
          'B11. a stored value that is not a JSON object is not reported, ' +
          'and one that is is held to the members', JSON.stringify(fromStore));
  // The console's panel, drawn from the row as `/admin-api` answers it.
  const XacmlPage = require(ROOT + '/xacml/web_xacml');
  const consoleT = require(ROOT + '/admin-ui/web_kit').context({}, true).t;
  const notReported = XacmlPage.signalsPanel(consoleT, null);
  const drawn = XacmlPage.signalsPanel(consoleT,
    peps.signalsOf(reported, '2026-11-14T12:00:00.000Z'));
  const quiet = XacmlPage.signalsPanel(consoleT,
    peps.signalsOf({ receivers: 0 }, '2026-11-14T12:00:00.000Z'));
  t.check(/not reported/.test(notReported) &&
          /CAEP\/RISC signal streams/.test(notReported) &&
          /2 stream\(s\): 1 healthy, 1 stale/.test(drawn) &&
          /xacml-alert/.test(drawn) && /73000 ms/.test(drawn) &&
          /20000/.test(drawn) && /2026-11-14T12:00:00.000Z/.test(drawn) &&
          !/xacml-alert/.test(quiet) && /No signal streams/.test(quiet) &&
          !/consoleXacml\./.test(notReported + drawn + quiet),
          'B12. the console draws "not reported", a stale stream as an ' +
          'alert with its counts, and a proxy with no streams', drawn);

  // -------------------------------------------------------------------------
  // C. THE PULL.
  // -------------------------------------------------------------------------
  let since = marks.length;
  r = await request(port, 'GET', PULL, null);
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0007'),
          'C2. the pull is behind the gate: no certificate is 403 ' +
          '(STS-XACML-0007)', brief(r));
  const pulled = await request(port, 'GET', PULL, pepCred);
  const body = pulled.json || {};
  t.check(pulled.status === 200 && body.configured === true &&
          body.proxy && body.proxy.upstream === example().upstream &&
          closedTo(body, 'pull') && closedTo(body.realm, 'realm') &&
          body.realm.signingCertificates.length > 0 &&
          /BEGIN CERTIFICATE/.test(body.realm.signingCertificates[0]) &&
          /BEGIN CERTIFICATE/.test(body.realm.tlsCaChain) &&
          JSON.stringify(body.realm.clients) === '{}' &&
          body.proxy.routes[0].resolved.usable === true &&
          body.proxy.routes[1].resolved.usable === true &&
          JSON.stringify(body.proxy.routes[1].resolved.audiences) ===
            JSON.stringify([AUDIENCE]) &&
          /\/oauth2\/jwks$/.test(body.realm.jwksUri) &&
          body.realm.samlIssuer === body.realm.issuer &&
          /\/realm\/pepproxy\/xacml\/pep\/basic$/.test(body.validation.basic) &&
          /\/realm\/pepproxy\/xacml\/pep\/identity$/
            .test(body.validation.identity),
          'C3. a configured PEP pulls the document, the realm facts and ' +
          'the five validation URLs', brief(pulled));
  t.check(pulled.headers.etag === '"' + body.syncToken + '"',
          'C4. the ETag is the sync token', pulled.headers.etag);
  r = await request(port, 'GET', PULL + '?since=' +
                    encodeURIComponent(body.syncToken), pepCred);
  t.check(r.status === 304, 'C5. an unchanged pull answers 304', brief(r));
  r = await request(port, 'GET', PULL + '?since=stale-token', pepCred);
  t.check(r.status === 200, 'C6. a stale since is answered whole', brief(r));
  inRealm(function () {
    store.write('ppx-root', xml.writePolicy(alfa.parse([
      'namespace ppx {',
      '    policy ppxRoot {',
      '        apply denyUnlessPermit',
      '        rule allowAll {',
      '            permit',
      '        }',
      '    }',
      '}'].join('\n'))), { enabled: true, isRoot: true });
  });
  r = await request(port, 'GET', PULL, pepCred);
  t.check(r.json && r.json.syncToken === body.syncToken,
          'C7. a policy written does not move the proxy\'s token',
          r.json && r.json.syncToken);
  const changed = example();
  changed.upstreamTimeoutMs = 5000;
  inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                                      proxy: changed });
  });
  r = await request(port, 'GET', PULL + '?since=' +
                    encodeURIComponent(body.syncToken), pepCred);
  t.check(r.status === 200 && r.json && r.json.syncToken !== body.syncToken &&
          r.json.proxy.upstreamTimeoutMs === 5000,
          'C8. a configuration change moves the token', brief(r));
  // AN LDAPMODIFY WRITES A VALUE THE GRAMMAR REFUSES.
  inRealm(function () {
    peps.setProxy(NAME, JSON.stringify({ upstream: 'ftp://nope' }));
  });
  r = await request(port, 'GET', PULL, pepCred);
  t.check(r.status === 200 && r.json && r.json.configured === false &&
          !r.json.proxy && /does not validate/.test(r.json.note),
          'C9. a stored value that does not validate is pulled as ' +
          'configured: false', brief(r));

  // -------------------------------------------------------------------------
  // D. THE FOUR VALIDATION DOORS.
  // -------------------------------------------------------------------------
  inRealm(function () {
    adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                               proxy: example() });
  });
  const doors = ['introspect', 'basic', 'saml', 'session'];
  for (let i = 0; i < doors.length; i++) {
    since = marks.length;
    r = await request(port, 'POST', PREFIX + '/xacml/pep/' + doors[i], null,
                      {});
    t.check(r.status === 403 && markedSince(since, 'STS-XACML-0007'),
            'D1.' + (i + 1) + ' /xacml/pep/' + doors[i] + ' with no ' +
            'certificate is 403 (STS-XACML-0007)', brief(r));
  }
  const BASIC = PREFIX + '/xacml/pep/basic';
  r = await request(port, 'POST', BASIC, pepCred,
                    { username: 'ppxalice', password: 'anything' });
  t.check(r.status === 200 && r.json && r.json.valid === true &&
          r.json.username === 'ppxalice' && /^urn:uuid:/.test(r.json.sub) &&
          closedTo(r.json, 'basic') &&
          r.headers['cache-control'] === 'no-store',
          'D2. Basic: development accepts the password and answers valid, ' +
          'sub and username', brief(r));
  since = marks.length;
  r = await request(port, 'POST', BASIC, pepCred,
                    { username: 'ppxalice', password: 'invalid' });
  t.check(r.status === 200 && r.json &&
          JSON.stringify(r.json) === '{"valid":false}',
          'D3. Basic: the reserved password is { valid: false } and nothing ' +
          'else', brief(r));
  r = await request(port, 'POST', BASIC, pepCred, { username: 'ppxalice' });
  t.check(r.status === 400 && closedTo(r.json, 'error'),
          'D4. Basic: a body with no password is 400', brief(r));

  const INTROSPECT = PREFIX + '/xacml/pep/introspect';
  const tokenAnswer = await request(port, 'POST', PREFIX + '/oauth2/token',
    null, 'grant_type=client_credentials&client_id=ppx-client&' +
    'client_secret=ppx-secret',
    { 'content-type': 'application/x-www-form-urlencoded' });
  const accessToken = tokenAnswer.json && tokenAnswer.json.access_token;
  r = await request(port, 'POST', INTROSPECT, pepCred, { token: accessToken });
  t.check(accessToken && r.status === 200 && r.json &&
          r.json.active === true && r.json.client_id === 'ppx-client' &&
          closedTo(r.json, 'introspect'),
          'D7. introspection: a token this realm issued is active, with ' +
          'only RFC 7662\'s members', brief(r) + ' token: ' +
          brief(tokenAnswer));
  r = await request(port, 'POST', INTROSPECT, pepCred,
                    { token: 'not.a.token' });
  t.check(r.status === 200 && JSON.stringify(r.json) === '{"active":false}',
          'D8. introspection: a forged token is { active: false }', brief(r));
  r = await request(port, 'POST', INTROSPECT, pepCred, {});
  t.check(r.status === 400, 'D9. introspection: no token is 400', brief(r));

  const SAML = PREFIX + '/xacml/pep/saml';
  const issuer = body.realm.issuer;
  const signed = inRealm(function () {
    return saml2.buildSamlAssertion('ppxalice', AUDIENCE, 5,
      { issuer: issuer, sign: true, sessionIndex: 'sx-1' });
  });
  const b64 = function (text) {
    log.debug("Entering b64().");
    log.debug("Leaving b64().");
    return Buffer.from(text, 'utf8').toString('base64');
  };
  r = await request(port, 'POST', SAML, pepCred,
                    { assertion: b64(signed), audience: AUDIENCE });
  t.check(r.status === 200 && r.json && r.json.valid === true &&
          r.json.subject && r.json.issuer === issuer &&
          r.json.sessionIndex === 'sx-1' && r.json.notOnOrAfter &&
          closedTo(r.json, 'saml'),
          'D10. SAML: an assertion this realm signed is valid', brief(r));
  since = marks.length;
  r = await request(port, 'POST', SAML, pepCred,
                    { assertion: b64(signed.replace('ppxalice', 'ppxmallory')),
                      audience: AUDIENCE });
  t.check(r.json && JSON.stringify(r.json) === '{"valid":false}' &&
          markedSince(since, 'STS-XACML-0210'),
          'D11. SAML: an altered assertion is refused (STS-XACML-0210)',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', SAML, pepCred,
                    { assertion: b64(signed), audience: 'https://other' });
  t.check(r.json && r.json.valid === false &&
          markedSince(since, 'STS-XACML-0213'),
          'D12. SAML: another audience is refused (STS-XACML-0213)',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', SAML, pepCred,
    { assertion: b64('<saml:EncryptedAssertion xmlns:saml="urn:oasis:names' +
                     ':tc:SAML:2.0:assertion"/>'), audience: AUDIENCE });
  t.check(r.json && r.json.valid === false &&
          markedSince(since, 'STS-XACML-0209'),
          'D13. SAML: an EncryptedAssertion is refused by name ' +
          '(STS-XACML-0209)', brief(r));
  const later = new pepProxy.PepProxy(Object.assign(
    pepProxy.PepProxy.defaultDeps(), {
      now: function () {
        log.debug("Entering now().");
        log.debug("Leaving now().");
        return Date.now() + 3 * 3600 * 1000;
      } }));
  const base = issuer.replace(/\/$/, '');
  const expired = inRealm(function () {
    return later.saml({ assertion: b64(signed), audience: AUDIENCE }, base);
  });
  const fresh = inRealm(function () {
    return pepProxy.saml({ assertion: b64(signed), audience: AUDIENCE },
                         base);
  });
  t.check(fresh.body.valid === true && expired.body.valid === false &&
          expired.code === 'STS-XACML-0212',
          'D14. SAML: three hours later the assertion is expired ' +
          '(STS-XACML-0212)', JSON.stringify(expired) + ' / ' +
          JSON.stringify(fresh.body));
  const unsigned = inRealm(function () {
    return saml2.buildSamlAssertion('ppxalice', AUDIENCE, 5,
      { issuer: issuer, sign: false });
  });
  since = marks.length;
  r = await request(port, 'POST', SAML, pepCred,
                    { assertion: b64(unsigned), audience: AUDIENCE });
  t.check(r.json && r.json.valid === false &&
          markedSince(since, 'STS-XACML-0210'),
          'D15. SAML: an unsigned assertion is refused (STS-XACML-0210)',
          brief(r));

  const foreign = inRealm(function () {
    return saml2.buildSamlAssertion('ppxalice', AUDIENCE, 5,
      { issuer: 'https://not-this-realm.example', sign: true });
  });
  since = marks.length;
  r = await request(port, 'POST', SAML, pepCred,
                    { assertion: b64(foreign), audience: AUDIENCE });
  t.check(r.json && r.json.valid === false &&
          markedSince(since, 'STS-XACML-0211'),
          'D18. SAML: an assertion naming another issuer is refused ' +
          '(STS-XACML-0211)', brief(r));
  // SIGNATURE WRAPPING: the signed assertion nested inside an unsigned one
  // whose subject was changed.
  const outer = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
    'assertion" ID="_outer" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '"><saml:Issuer>' + issuer +
    '</saml:Issuer><saml:Advice>' +
    signed.replace(/^<\?xml[^>]*>/, '') + '</saml:Advice></saml:Assertion>';
  since = marks.length;
  r = await request(port, 'POST', SAML, pepCred,
                    { assertion: b64(outer), audience: AUDIENCE });
  t.check(r.json && r.json.valid === false &&
          markedSince(since, 'STS-XACML-0210'),
          'D19. SAML: a signed assertion wrapped in an unsigned one is ' +
          'refused (STS-XACML-0210)', brief(r));

  // THE SIGNATURE MOVED to an unsigned outer assertion, still referencing
  // the signed one nested in it: it verifies over #<inner>, which is not the
  // root's ID.
  const sigMatch = /<ds:Signature[\s\S]*<\/ds:Signature>/.exec(signed);
  const innerNoSig = signed.replace(/^<\?xml[^>]*>/, '')
    .replace(sigMatch ? sigMatch[0] : '', '');
  const moved = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
    'assertion" ID="_moved" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '"><saml:Issuer>' + issuer +
    '</saml:Issuer>' + (sigMatch ? sigMatch[0] : '') + '<saml:Advice>' +
    innerNoSig + '</saml:Advice></saml:Assertion>';
  since = marks.length;
  r = await request(port, 'POST', SAML, pepCred,
                    { assertion: b64(moved), audience: AUDIENCE });
  t.check(sigMatch && r.json && r.json.valid === false &&
          markedSince(since, 'STS-XACML-0210'),
          'D20. SAML: a signature moved to an unsigned root, naming the ' +
          'nested assertion, is refused (STS-XACML-0210)', brief(r));

  const SESSION = PREFIX + '/xacml/pep/session';
  const started = inRealm(function () {
    return authn.startSession({ set: function () {}, req: null }, 'ppxalice',
                              ['pwd'], '1', 'test',
                              { key: 'ppx-key-1', cookie: false });
  });
  r = await request(port, 'POST', SESSION, pepCred, { sid: started.id });
  t.check(r.status === 200 && r.json && r.json.live === true &&
          r.json.username === 'ppxalice' && closedTo(r.json, 'session'),
          'D16. session: a live session is live, with its person', brief(r));
  inRealm(function () {
    authn.endSessionById(started.id, 'test');
  });
  r = await request(port, 'POST', SESSION, pepCred, { sid: started.id });
  t.check(r.status === 200 && JSON.stringify(r.json) === '{"live":false}',
          'D17. session: after a sign-out it is { live: false }', brief(r));

  // -------------------------------------------------------------------------
  // E. A ROUTE REFERENCES AN APPLICATION (D10).
  // -------------------------------------------------------------------------
  const withSession = example();
  withSession.routes.push({ id: 'app', path: '/app',
                            mechanisms: ['session'], application: 'ppx-web' });
  const saved = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                                      proxy: withSession });
  });
  t.check(saved && saved.ok && !inRealm(function () {
    return applications.get('xacml-pep-' + NAME);
  }), 'E1. a session route naming a confidential client saves, and ' +
          'nothing is created', JSON.stringify(saved).slice(0, 300));
  r = await request(port, 'GET', PULL, pepCred);
  const web = r.json && r.json.realm && r.json.realm.clients['ppx-web'];
  const appRoute = r.json && r.json.proxy.routes[2];
  t.check(web && web.clientSecret === WEB_SECRET &&
          web.tokenEndpointAuthMethod === 'client_secret_basic' &&
          web.redirectUri === CALLBACK && web.scopes.indexOf('openid') >= 0 &&
          Object.keys(web).sort().join(',') ===
            'clientSecret,redirectUri,scopes,tokenEndpointAuthMethod' &&
          appRoute && appRoute.resolved.usable === true &&
          appRoute.resolved.clientId === 'ppx-web' &&
          appRoute.signals === true,
          'E2. the pull carries the client\'s opened secret, method, ' +
          'redirect URI and scopes, and the route resolves to it',
          JSON.stringify(r.json && r.json.realm.clients).length);
  const tokenBefore = r.json && r.json.syncToken;
  const rotated = inRealm(function () {
    return applications.regenerateClientSecret('ppx-web', { actor: 'test' });
  });
  r = await request(port, 'GET', PULL + '?since=' +
                    encodeURIComponent(String(tokenBefore)), pepCred);
  t.check(rotated && rotated.ok && r.status === 200 && r.json &&
          r.json.syncToken !== tokenBefore &&
          r.json.realm.clients['ppx-web'].clientSecret !== WEB_SECRET,
          'E3. a regenerated secret moves the token and reaches the pull',
          brief(r).slice(0, 200));
  const xacmlAdminE = require(ROOT + '/xacml/xacml_admin');
  const listedE = inRealm(function () {
    return xacmlAdminE.pepsJson();
  });
  t.check(JSON.stringify(listedE).indexOf(WEB_SECRET) < 0 &&
          JSON.stringify(listedE).indexOf(
            String(rotated && rotated.secret)) < 0,
          'E4. the console\'s view carries no client secret');
  const adminViews = require(ROOT + '/admin-core/admin_views');
  const fronting = inRealm(function () {
    return adminViews.pepRoutesFronting('ppx-web');
  });
  t.check(fronting.length === 1 && fronting[0].pep === NAME &&
          fronting[0].route === 'app' && fronting[0].path === '/app',
          'E5. the application\'s page lists the PEP route that fronts it',
          JSON.stringify(fronting));
  // E5b. AND THE ANSWER CARRYING IT MEETS ITS CLOSED MODEL (8081, 2026-11-15:
  // `pepRoutes` on the application page was declared on the list's model
  // and not the page's, so every application page answered 500,
  // STS-API-0139). Held through the service's own check, over the
  // document the management API serves.
  const answerProblem = function (method, apiPath, status, body) {
    log.debug("Entering answerProblem().");
    const { ResponseModels } = require(ROOT + '/common/response_models');
    const models = new ResponseModels({
      log: { debug: function () {}, error: function () {} },
      mark: function () {},
      tag: function (code) {
        return '[' + code + '] ';
      }
    });
    const spec = require(ROOT + '/mgmt-api/admin_api_spec');
    const adminApiE = require(ROOT + '/mgmt-api/admin_api');
    const doc = spec.buildSpec(adminApiE.ROUTES, { authRequired: true });
    const installed = models.installed(function () {
      return doc;
    });
    log.debug("Leaving answerProblem().");
    return models.problemOf(installed,
      { method: method, baseUrl: '', path: apiPath },
      { statusCode: status, get: function () {
        return 'application/json';
      } }, JSON.stringify(body));
  };
  const appPage = inRealm(function () {
    return adminViews.applicationsJson({ query: { application: 'ppx-web' },
                                         headers: {}, method: 'GET' });
  });
  const appProblem = answerProblem('GET', '/admin-api/applications', 200,
                                   appPage);
  t.check(appPage && appPage.page && appPage.page.pepRoutes &&
          appPage.page.pepRoutes.length === 1 && appProblem === null,
          'E5b. an application fronted by a PEP route: its page answer, ' +
          'pepRoutes and all, meets the getApplications model',
          JSON.stringify(appProblem));
  const refusing = [
    ['an unknown application', { mechanisms: ['session'],
      application: 'nope-app' }, 'STS-XACML-0217'],
    ['a public client', { mechanisms: ['session'],
      application: 'ppx-public' }, 'STS-XACML-0220'],
    ['a client without the code grant', { mechanisms: ['session'],
      application: 'ppx-nocode' }, 'STS-XACML-0221'],
    ['a client without the callback', { mechanisms: ['session'],
      application: 'ppx-nocb' }, 'STS-XACML-0222'],
    ['an oauth2 route whose application has no audience', {
      mechanisms: ['oauth2'], application: 'ppx-web' }, 'STS-XACML-0218'],
    ['a saml2 route whose application has no entity ID', {
      mechanisms: ['saml2'], application: 'ppx-api' }, 'STS-XACML-0219']
  ];
  refusing.forEach(function (one, i) {
    const doc = example();
    doc.routes.push(Object.assign({ id: 'x', path: '/x' }, one[1]));
    const got = inRealm(function () {
      return adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                                        proxy: doc });
    });
    t.check(got && !got.ok && errorCodes.codeOf(got) === one[2],
            'E6.' + (i + 1) + ' refused at the save: ' + one[0] + ' (' +
            one[2] + ')', JSON.stringify(got).slice(0, 300));
  });
  // AN APPLICATION DELETED AFTER THE SAVE leaves its route unusable.
  inRealm(function () {
    return applications.deleteApplication('ppx-web', { actor: 'test' });
  });
  r = await request(port, 'GET', PULL, pepCred);
  const gone = r.json && r.json.proxy && r.json.proxy.routes[2];
  t.check(gone && gone.resolved.usable === false &&
          gone.resolved.code === 'STS-XACML-0217' &&
          JSON.stringify(r.json.realm.clients) === '{}',
          'E7. a deleted application leaves its route usable: false and ' +
          'no client', brief(r).slice(0, 300));
  const listedGone = inRealm(function () {
    return xacmlAdminE.pepsJson();
  });
  const rowGone = (listedGone.peps || []).filter(function (one) {
    return one.name === NAME;
  })[0];
  t.check(rowGone && rowGone.proxyRoutes.some(function (one) {
    return one.route === 'app' && one.usable === false && one.why;
  }), 'E8. the console\'s row says the route is not usable',
          JSON.stringify(rowGone && rowGone.proxyRoutes));
  const cleared = inRealm(function () {
    return adminActions.xacmlAction({ action: 'clear-pep-proxy',
                                      name: NAME });
  });
  r = await request(port, 'GET', PULL, pepCred);
  t.check(cleared && cleared.ok && r.json && r.json.configured === false,
          'E9. clear-pep-proxy removes the configuration',
          JSON.stringify(cleared));

  // -------------------------------------------------------------------------
  // F. THE ACTIONS' REFUSALS AND THE VIEW.
  // -------------------------------------------------------------------------
  const nobody = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy',
                                      name: 'not-registered',
                                      proxy: example() });
  });
  t.check(nobody && !nobody.ok && errorCodes.codeOf(nobody) &&
          /not-registered/.test((nobody.errors || []).join(' ')),
          'F2. set-pep-proxy for a PEP not registered is refused',
          JSON.stringify(nobody));
  const noDoc = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME });
  });
  t.check(noDoc && !noDoc.ok && (noDoc.errors || []).length === 1,
          'F3. set-pep-proxy with no document is refused (STS-XACML-0201)',
          JSON.stringify(noDoc));
  const bad = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
      proxy: Object.assign(example(), { upstream: 'ftp://x' }) });
  });
  t.check(bad && !bad.ok && /upstream/.test((bad.errors || []).join(' ')),
          'F4. a refused document is answered with the validator\'s ' +
          'sentence', JSON.stringify(bad));
  const unknown = inRealm(function () {
    return adminActions.xacmlAction({ action: 'nope' });
  });
  t.check(unknown && /set-pep-proxy/.test(JSON.stringify(unknown)) &&
          /clear-pep-proxy/.test(JSON.stringify(unknown)) &&
          /set-pep-route-identity/.test(JSON.stringify(unknown)),
          'F5. the unknown-action sentence names the three new actions',
          JSON.stringify(unknown).slice(0, 300));
  inRealm(function () {
    adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                               proxy: example() });
  });
  const xacmlAdmin = require(ROOT + '/xacml/xacml_admin');
  const listed = inRealm(function () {
    return xacmlAdmin.pepsJson();
  });
  const mine = (listed.peps || []).filter(function (one) {
    return one.name === NAME;
  })[0];
  t.check(mine && mine.proxy && mine.proxy.routes.length === 2 &&
          mine.proxyProblem === null && mine.proxyRoutes.length === 2 &&
          mine.proxyRoutes.every(function (one) {
            return one.usable === true;
          }) && typeof mine.proxy === 'object',
          'F6. GET /admin-api/xacml/peps\' row carries the document, no ' +
          'problem and each route usable', JSON.stringify(mine).slice(0, 300));

  // -------------------------------------------------------------------------
  // H. HOW THE IDENTITY REACHES THE APPLICATION (D11): the Basic ticket,
  // POST /xacml/pep/identity in each mode, forged and foreign evidence, a
  // route and a ticket of another PEP, an expired ticket, and the console's
  // per-route action.
  // -------------------------------------------------------------------------
  const IDENTITY = PREFIX + '/xacml/pep/identity';
  const SP = 'https://sp.ppx.example';
  const ACS = 'https://sp.ppx.example/acs';
  const madeH = inRealm(function () {
    ldap.createUser('ppxcarol', { invent: false });
    return [
      applications.createApplication({ identifier: 'ppx-saml',
        protocols: ['saml2'],
        fields: { samlEntityId: SP, samlAssertionConsumerService: [ACS] } }),
      applications.createApplication({ identifier: 'ppx-sp-noacs',
        protocols: ['saml2'],
        fields: { samlEntityId: 'https://noacs.ppx.example' } })
    ];
  });
  t.check(madeH.every(function (one) {
    return one && one.ok !== false;
  }), 'H0. setup: the SAML applications', JSON.stringify(madeH).slice(0, 300));
  const withIdentity = example();
  withIdentity.routes.push(
    { id: 'jwt', path: '/jwt', mechanisms: ['oauth2', 'basic'],
      application: 'ppx-api', identity: { mode: 'jwt' } },
    { id: 'sso', path: '/sso', mechanisms: ['saml2', 'basic'],
      application: 'ppx-saml', identity: { mode: 'saml' } });
  const savedH = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                                      proxy: withIdentity });
  });
  t.check(savedH && savedH.ok, 'H1. routes in modes jwt and saml save',
          JSON.stringify(savedH).slice(0, 300));
  const noAcs = example();
  noAcs.routes.push({ id: 'x', path: '/x', mechanisms: ['basic'],
                      application: 'ppx-sp-noacs',
                      identity: { mode: 'saml' } });
  const noAud = example();
  noAud.routes.push({ id: 'x', path: '/x', mechanisms: ['basic'],
                      application: 'ppx-saml', identity: { mode: 'jwt' } });
  [[noAcs, 'STS-XACML-0228', 'mode saml for an application with no ACS'],
   [noAud, 'STS-XACML-0218', 'mode jwt for an application with no audience']]
    .forEach(function (one, i) {
      const got = inRealm(function () {
        return adminActions.xacmlAction({ action: 'set-pep-proxy',
                                          name: NAME, proxy: one[0] });
      });
      t.check(got && !got.ok && errorCodes.codeOf(got) === one[1],
              'H2.' + (i + 1) + ' refused at the save: ' + one[2] + ' (' +
              one[1] + ')', JSON.stringify(got).slice(0, 300));
    });

  // THE TICKET.
  r = await request(port, 'POST', BASIC, pepCred,
                    { username: 'ppxalice', password: 'anything' });
  const ticket = r.json && r.json.ticket;
  t.check(r.status === 200 && typeof ticket === 'string' &&
          /^[A-Za-z0-9_-]{43}$/.test(ticket) && closedTo(r.json, 'basic'),
          'H3. a valid Basic answers an opaque ticket', brief(r));
  const heldTicket = inRealm(function () {
    return pepProxy.PepProxy.defaultDeps().tickets.get(
      require(ROOT + '/common/crypto').credentialDigest(ticket));
  });
  t.check(heldTicket && heldTicket.pep === NAME &&
          heldTicket.username === 'ppxalice' &&
          heldTicket.exp - heldTicket.at === pepProxy.TICKET_LIFETIME_S &&
          JSON.stringify(heldTicket).indexOf(ticket) < 0,
          'H4. the ticket is kept under its digest, bound to the PEP and ' +
          'the subject, for 120 s', JSON.stringify(heldTicket));

  // MODE HEADERS.
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'ticket', value: ticket } });
  t.check(r.status === 200 && r.json && r.json.claims &&
          r.json.claims.username === 'ppxalice' &&
          Array.isArray(r.json.claims.groups) &&
          Object.keys(r.json).join(',') === 'claims' &&
          Object.keys(r.json.claims).every(function (k) {
            return k === 'username' || k === 'groups';
          }) && r.headers['cache-control'] === 'no-store',
          'H5. headers: a ticket answers the route\'s claims, groups a list',
          brief(r));
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'ticket', value: ticket } ,
      claims: ['username'] });
  t.check(r.status === 200 && r.json &&
          JSON.stringify(Object.keys(r.json.claims)) === '["username"]',
          'H6. headers: `claims` narrows to the route\'s claims', brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'ticket', value: ticket },
      claims: ['email'] });
  t.check(r.status === 400 && markedSince(since, 'STS-XACML-0229') &&
          closedTo(r.json, 'error'),
          'H7. headers: a claim the route\'s headers do not name is 400 ' +
          '(STS-XACML-0229)', brief(r));

  // MODE JWT, from the ticket.
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'jwt', evidence: { kind: 'ticket', value: ticket } });
  const issued = r.json && r.json.accessToken;
  const issuedRead = issued ? inRealm(function () {
    return require(ROOT + '/oauth-oidc/oauth2').introspectionFor(issued);
  }) : {};
  const issuedAud = [].concat(issuedRead.aud || []);
  t.check(r.status === 200 && r.json && r.json.tokenType === 'Bearer' &&
          r.json.expiresIn > 0 && issuedRead.active === true &&
          issuedRead.username === 'ppxalice' &&
          issuedRead.client_id === 'ppx-api' &&
          issuedAud.indexOf(AUDIENCE) >= 0 &&
          Object.keys(r.json).sort().join(',') ===
            'accessToken,expiresIn,tokenType',
          'H8. jwt: an access token about the person, issued to and for ' +
          'the application', brief(r).slice(0, 200) + ' ' +
          JSON.stringify(issuedRead));
  // The token is evidence too: the headers route accepts it.
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'access_token', value: issued } });
  t.check(r.status === 200 && r.json && r.json.claims &&
          r.json.claims.username === 'ppxalice',
          'H9. an access token for the application is evidence for its ' +
          'headers route', brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'access_token',
                                value: 'eyJhbGciOiJub25lIn0.e30.' } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0231'),
          'H10. a forged access token is 403 (STS-XACML-0231)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'access_token',
                                value: String(accessToken || '') } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0231'),
          'H11. a token of another client, about nobody, is 403 ' +
          '(STS-XACML-0231)', brief(r));

  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'sso', evidence: { kind: 'access_token', value: issued } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0231'),
          'H11b. a person\'s token for another application is 403 ' +
          '(STS-XACML-0231)', brief(r));

  // MODE SAML, from a SAML assertion and from the ticket.
  const forSp = inRealm(function () {
    return saml2.buildSamlAssertion('ppxalice', SP, 5,
      { issuer: issuer, sign: true });
  });
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'sso', evidence: { kind: 'saml_assertion', value: b64(forSp) } });
  const response = r.json && r.json.samlResponse
    ? Buffer.from(r.json.samlResponse, 'base64').toString('utf8') : '';
  t.check(r.status === 200 && r.json && r.json.acsUrl === ACS &&
          r.json.notOnOrAfter && /<samlp:Response[^>]*Destination="/
            .test(response) && response.indexOf(ACS) >= 0 &&
          /Signature/.test(response) && response.indexOf('ppxalice') >= 0 &&
          !/InResponseTo="[^"]/.test(response) &&
          Object.keys(r.json).sort().join(',') ===
            'acsUrl,notOnOrAfter,samlResponse',
          'H12. saml: an assertion for the application answers a signed ' +
          'Response to its ACS, InResponseTo absent', brief(r).slice(0, 300));
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'sso', evidence: { kind: 'ticket', value: ticket } });
  t.check(r.status === 200 && r.json && r.json.samlResponse,
          'H13. saml: a ticket answers a Response too', brief(r).slice(0, 200));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'sso', evidence: { kind: 'saml_assertion',
                                value: b64(signed) } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0231'),
          'H14. an assertion for another audience is 403 (STS-XACML-0231)',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'sso', evidence: { kind: 'saml_assertion',
      value: b64(forSp.replace('ppxalice', 'ppxmallory')) } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0231'),
          'H15. an altered assertion is 403 (STS-XACML-0231)', brief(r));

  // A ROUTE AND A TICKET OF ANOTHER PEP.
  const otherCred = await outsideCa.mint({ subject: 'CN=ppxpep2,O=Outside',
                                           crlBase: '' });
  tls.addAnchors(otherCred.anchorPem);
  inRealm(function () {
    ldap.createUser('ppxpep2', { invent: false });
    ldap.changeStoredCertificate('person', 'ppxpep2',
                                 { add: derOf(otherCred) });
    adminActions.groupsAction({ action: 'add-member',
      group: String(config.value('roles.remotePepGroup')),
      member: 'ppxpep2' });
  });
  r = await request(port, 'POST', PREFIX + '/xacml/pep/register',
                    otherCred, { version: 'test' });
  const OTHER = r.json ? r.json.name : '';
  const otherDoc = example();
  otherDoc.routes[1].id = 'theirs';
  inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-proxy', name: OTHER,
                                      proxy: otherDoc });
  });
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'theirs', evidence: { kind: 'ticket', value: ticket } });
  t.check(OTHER && OTHER !== NAME && r.status === 403 &&
          markedSince(since, 'STS-XACML-0230'),
          'H16. a route of another PEP is 403 (STS-XACML-0230)',
          OTHER + ' ' + brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, otherCred,
    { route: 'theirs', evidence: { kind: 'ticket', value: ticket } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0232'),
          'H17. a ticket handed to another PEP is 403 (STS-XACML-0232)',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'public', evidence: { kind: 'ticket', value: ticket } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0230'),
          'H18. a public route forwards nobody: 403 (STS-XACML-0230)',
          brief(r));

  // AN EXPIRED TICKET.
  const laterH = new pepProxy.PepProxy(Object.assign(
    pepProxy.PepProxy.defaultDeps(), {
      now: function () {
        log.debug("Entering now().");
        log.debug("Leaving now().");
        return Date.now() + (pepProxy.TICKET_LIFETIME_S + 5) * 1000;
      } }));
  const expiredTicket = await inRealm(function () {
    return laterH.identity({ route: 'api',
                             evidence: { kind: 'ticket', value: ticket } },
                           NAME, peps.read(NAME), base);
  });
  t.check(expiredTicket.status === 403 &&
          expiredTicket.code === 'STS-XACML-0232',
          'H19. a ticket past 120 s is refused (STS-XACML-0232)',
          JSON.stringify(expiredTicket));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'ticket', value: 'not-a-ticket' } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0232'),
          'H20. a ticket nobody was handed is 403 (STS-XACML-0232)',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'api', evidence: { kind: 'password', value: 'x' } });
  t.check(r.status === 400 && markedSince(since, 'STS-XACML-0229'),
          'H21. an unknown evidence kind is 400 (STS-XACML-0229)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, null,
    { route: 'api', evidence: { kind: 'ticket', value: ticket } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0007'),
          'H22. the identity door is behind the gate (STS-XACML-0007)',
          brief(r));

  // THE ISSUANCE POLICY: a disabled person is issued nothing.
  r = await request(port, 'POST', BASIC, pepCred,
                    { username: 'ppxcarol', password: 'anything' });
  const carolTicket = r.json && r.json.ticket;
  inRealm(function () {
    return require(ROOT + '/common/account_state')
      .setDisabled('ppxcarol', true, { actor: 'test' });
  });
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'jwt', evidence: { kind: 'ticket', value: carolTicket } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0234'),
          'H23. jwt: the issuance policy\'s refusal is 403 (STS-XACML-0234)',
          brief(r));
  since = marks.length;
  r = await request(port, 'POST', IDENTITY, pepCred,
    { route: 'sso', evidence: { kind: 'ticket', value: carolTicket } });
  t.check(r.status === 403 && markedSince(since, 'STS-XACML-0234'),
          'H24. saml: the issuance policy\'s refusal is 403 (STS-XACML-0234)',
          brief(r));

  // THE CONSOLE'S PER-ROUTE ACTION.
  const perRoute = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-route-identity',
      name: NAME, route: 'api', mode: 'headers',
      headerName: ['X-Remote-Sub', '', 'X-Remote-Mail'],
      headerClaim: ['sub', 'email', 'email'], separator: ';' });
  });
  const afterRoute = perRoute && perRoute.proxy &&
    perRoute.proxy.routes.filter(function (one) {
      return one.id === 'api';
    })[0];
  t.check(perRoute && perRoute.ok && afterRoute &&
          JSON.stringify(afterRoute.identity) === JSON.stringify(
            { mode: 'headers',
              headers: [{ name: 'X-Remote-Sub', claim: 'sub' },
                        { name: 'X-Remote-Mail', claim: 'email' }],
              separator: ';' }),
          'H25. set-pep-route-identity replaces one route\'s identity, an ' +
          'empty row unused', JSON.stringify(perRoute).slice(0, 400));
  const toJwt = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-route-identity',
      name: NAME, route: 'sso', mode: 'jwt' });
  });
  t.check(toJwt && !toJwt.ok && errorCodes.codeOf(toJwt) === 'STS-XACML-0218',
          'H26. set-pep-route-identity is held to the save\'s checks: jwt ' +
          'for an application with no audience (STS-XACML-0218)',
          JSON.stringify(toJwt).slice(0, 300));
  const badClaim = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-route-identity',
      name: NAME, route: 'api', mode: 'headers', headerName: ['X-A'],
      headerClaim: [''] });
  });
  t.check(badClaim && !badClaim.ok &&
          errorCodes.codeOf(badClaim) === 'STS-XACML-0226',
          'H27. a header row with no claim is refused (STS-XACML-0226)',
          JSON.stringify(badClaim).slice(0, 300));
  const noRoute = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-route-identity',
      name: NAME, route: 'nope', mode: 'jwt' });
  });
  t.check(noRoute && !noRoute.ok &&
          errorCodes.codeOf(noRoute) === 'STS-XACML-0230',
          'H28. a route the PEP does not have is refused (STS-XACML-0230)',
          JSON.stringify(noRoute).slice(0, 300));
  inRealm(function () {
    adminActions.xacmlAction({ action: 'set-pep-proxy', name: NAME,
                               proxy: example() });
  });

  // -------------------------------------------------------------------------
  // S. THE MANAGED SETTINGS (#1760): what an administrator sets on the PEP's
  // page, validated whole, kept across a registration, pulled from GET
  // /xacml/pep/settings under a token of its own, the PEP's report of what
  // it has in force held to its members, and the nudge dialling the managed
  // notify URL.
  // -------------------------------------------------------------------------
  const pepSettings = require(ROOT + '/xacml/xacml_pep_settings');
  const SETTINGS_PULL = PREFIX + '/xacml/pep/settings';
  let sp = await request(port, 'GET', SETTINGS_PULL, pepCred);
  t.check(sp.status === 200 && sp.json && sp.json.configured === false &&
          sp.json.settings === undefined && sp.json.pep === NAME &&
          sp.headers['cache-control'] === 'no-store' &&
          sp.headers.etag === '"' + sp.json.syncToken + '"',
          'S1. a PEP with no managed settings pulls configured: false, ' +
          'no-store, with an ETag', brief(sp));
  r = await request(port, 'GET', SETTINGS_PULL, null);
  t.check(r.status === 401 || r.status === 403,
          'S2. the settings pull is behind the PEP gate', brief(r));
  const setS = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-settings', name: NAME,
      settings: { bias: 'permit-biased', pollIntervalMs: 4000,
                  logLevel: 'debug', pip: false,
                  notifyUrl: 'https://pep.example/notify',
                  authzenPdpIdentifier: 'https://pdp.example/' } });
  });
  t.check(setS && setS.ok && setS.settings &&
          setS.settings.pollIntervalMs === 4000 &&
          setS.settings.authzenPdpIdentifier === 'https://pdp.example' &&
          setS.settings.timeoutMs === undefined,
          'S3. set-pep-settings saves what is set, normalised, and nothing ' +
          'else', JSON.stringify(setS));
  const firstToken = sp.json && sp.json.syncToken;
  sp = await request(port, 'GET', SETTINGS_PULL, pepCred);
  t.check(sp.status === 200 && sp.json && sp.json.configured === true &&
          sp.json.settings && sp.json.settings.bias === 'permit-biased' &&
          sp.json.settings.pip === false &&
          Object.keys(sp.json.settings).length === 6 &&
          sp.json.syncToken !== firstToken,
          'S4. the pull carries exactly the settings set, under a new token',
          brief(sp));
  r = await request(port, 'GET', SETTINGS_PULL + '?since=' +
                    encodeURIComponent(sp.json.syncToken), pepCred);
  t.check(r.status === 304,
          'S5. ?since= the token it holds answers 304', brief(r));
  // Every refusal, by its code; nothing is written by any of them.
  const settingRefusals = [
    [{ settings: { pollIntervalMs: 999 } }, 'STS-XACML-0238'],
    [{ settings: { timeoutMs: 'soon' } }, 'STS-XACML-0237'],
    [{ settings: { bias: 'lenient' } }, 'STS-XACML-0237'],
    [{ settings: { logLevel: 'loud' } }, 'STS-XACML-0237'],
    [{ settings: { pip: 'maybe' } }, 'STS-XACML-0237'],
    [{ settings: { pdpUrl: 'https://elsewhere' } }, 'STS-XACML-0236'],
    [{ settings: [] }, 'STS-XACML-0236'],
    [{ settings: { description: 'a\nb' } }, 'STS-XACML-0239'],
    [{ settings: { notifyUrl: 'https://u:p@pep.example/' } },
     'STS-XACML-0239'],
    [{ settings: { authzenPdpIdentifier: 'https://pdp.example/x' } },
     'STS-XACML-0239'],
    [{ settings: { proxyMaxSessions: 0 } }, 'STS-XACML-0238']
  ];
  settingRefusals.forEach(function (one, i) {
    const got = inRealm(function () {
      return adminActions.xacmlAction(Object.assign(
        { action: 'set-pep-settings', name: NAME }, one[0]));
    });
    t.check(got && !got.ok && errorCodes.codeOf(got) === one[1] &&
            (got.errors || []).length === 1,
            'S6.' + i + '. set-pep-settings refuses ' +
            JSON.stringify(one[0].settings) + ' with ' + one[1],
            JSON.stringify(got) + ' ' + errorCodes.codeOf(got));
  });
  const still = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(still && JSON.parse(still.settings).pollIntervalMs === 4000,
          'S7. a refused save changes nothing', still && still.settings);
  // The console's form: flat members, an empty box is "not set".
  const settingsForm = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-settings', name: NAME,
      bias: '', pollIntervalMs: '8000', pip: 'true', logLevel: '',
      description: '', proxySessionRecheckMs: '0' });
  });
  t.check(settingsForm && settingsForm.ok && settingsForm.settings &&
          settingsForm.settings.pollIntervalMs === 8000 &&
          settingsForm.settings.pip === true &&
          settingsForm.settings.proxySessionRecheckMs === 0 &&
          settingsForm.settings.bias === undefined &&
          Object.keys(settingsForm.settings).length === 3,
          'S8. the form\'s members replace the document; an empty box is not ' +
          'set and 0 is a value', JSON.stringify(settingsForm));
  // Product refuses a verification turned off, and allows it off.
  inRealm(function () {
    config.setOverride('global.mode', 'product');
  });
  const insecure = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-settings', name: NAME,
      settings: { proxyUpstreamInsecure: true } });
  });
  const rpInsecure = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-settings', name: NAME,
      settings: { proxyRpAllowInsecure: true } });
  });
  const secure = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-settings', name: NAME,
      settings: { proxyUpstreamInsecure: false, pollIntervalMs: 8000,
                  pip: true, proxySessionRecheckMs: 0 } });
  });
  const productCatalogue = inRealm(function () {
    return pepSettings.catalogue();
  });
  inRealm(function () {
    config.clearOverride('global.mode');
  });
  t.check(insecure && !insecure.ok &&
          errorCodes.codeOf(insecure) === 'STS-XACML-0240' &&
          rpInsecure && !rpInsecure.ok &&
          errorCodes.codeOf(rpInsecure) === 'STS-XACML-0240' &&
          secure && secure.ok,
          'S9. product refuses proxyUpstreamInsecure and ' +
          'proxyRpAllowInsecure true (STS-XACML-0240), and takes false',
          JSON.stringify([insecure, rpInsecure, secure]));
  const devCatalogue = inRealm(function () {
    return pepSettings.catalogue();
  });
  const refusedIn = function (cat) {
    return cat.settings.filter(function (one) {
      return one.refusedInProduct;
    }).map(function (one) {
      return one.key;
    }).join(',');
  };
  t.check(refusedIn(productCatalogue) ===
            'proxyUpstreamInsecure,proxyRpAllowInsecure' &&
          refusedIn(devCatalogue) === '' &&
          devCatalogue.settings.length === 23 &&
          devCatalogue.bootstrap.map(function (one) {
            return one.env;
          }).indexOf('PEP_PDP_URL') >= 0 &&
          devCatalogue.precedence.join(',') === 'service,environment,default',
          'S10. the catalogue names the 23 settings, the bootstrap ' +
          'environment and the precedence; refusedInProduct follows the mode',
          refusedIn(productCatalogue) + ' / ' + refusedIn(devCatalogue));
  // Kept across a registration and a heartbeat; the report held to its
  // members, kept by a heartbeat without it, cleared by null, dropped by a
  // registration.
  r = await request(port, 'POST', PREFIX + '/xacml/pep/register', pepCred,
                    { version: 'settings' });
  const tokenNow = (await request(port, 'GET', SETTINGS_PULL, pepCred))
    .json.syncToken;
  const report = { token: tokenNow, at: '1999-01-01T00:00:00Z',
    values: {
      bias: { value: 'deny-biased', source: 'environment' },
      pollIntervalMs: { value: 8000, source: 'service' },
      timeoutMs: { value: -5, source: 'default' },
      logLevel: { value: 'loud', source: 'default' },
      pip: { value: true, source: 'invented' },
      description: { value: 'two\nlines', source: 'environment' },
      aNewerSetting: { value: 1, source: 'service' }
    }, secret: 'nope' };
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                    { decisions: 1, settings: report });
  let row2 = inRealm(function () {
    return peps.read(NAME);
  });
  const inUse = row2 && row2.settingsInUse;
  t.check(r.status === 200 && row2 && row2.settings &&
          JSON.parse(row2.settings).pollIntervalMs === 8000 && inUse &&
          Object.keys(inUse.values).sort().join(',') ===
            'bias,pollIntervalMs' &&
          inUse.token === tokenNow && !('secret' in inUse) &&
          Math.abs(Date.parse(inUse.at) - Date.now()) < 60000,
          'S11. a registration keeps the settings; the report keeps only ' +
          'known settings of their type and closed source, stamped on ' +
          'arrival', JSON.stringify(row2 && row2.settingsInUse));
  const viewed = inRealm(function () {
    return require(ROOT + '/xacml/xacml_admin').pepsJson(NAME);
  });
  const vrow = viewed.peps && viewed.peps[0];
  t.check(viewed.found === true && viewed.pep === NAME &&
          viewed.peps.length === 1 && vrow.settings &&
          vrow.settings.pollIntervalMs === 8000 &&
          vrow.settingsProblem === null && vrow.settingsCurrent === true &&
          vrow.settingsInUse && viewed.settingsCatalogue &&
          vrow.effectiveNotifyUrl === (vrow.notifyUrl || ''),
          'S12. GET /admin-api/xacml/peps?pep= is that row alone, found, ' +
          'its settings, current, and the catalogue',
          JSON.stringify(vrow).slice(0, 400));
  const pepPageProblem = answerProblem('GET', '/admin-api/xacml/peps', 200,
                                       viewed);
  const pepListProblem = answerProblem('GET', '/admin-api/xacml/peps', 200,
    inRealm(function () {
      return require(ROOT + '/xacml/xacml_admin').pepsJson();
    }));
  t.check(pepPageProblem === null && pepListProblem === null,
          'S12b. the PEP page\'s answer (settings, report, catalogue) and ' +
          'the list\'s meet the getXacmlPeps model',
          JSON.stringify([pepPageProblem, pepListProblem]));
  const missing = inRealm(function () {
    return require(ROOT + '/xacml/xacml_admin').pepsJson('nobody-here');
  });
  t.check(missing.found === false && missing.peps.length === 0,
          'S13. a name with no row is found: false', JSON.stringify(missing)
            .slice(0, 200));
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                    { decisions: 2 });
  row2 = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(row2 && row2.settingsInUse &&
          row2.settingsInUse.values.pollIntervalMs.value === 8000,
          'S14. a heartbeat without settings (an older PEP) keeps the report',
          JSON.stringify(row2 && row2.settingsInUse));
  // A settings change moves the pull's token, so the report goes stale.
  inRealm(function () {
    adminActions.xacmlAction({ action: 'set-pep-settings', name: NAME,
      settings: { pollIntervalMs: 9000,
                  notifyUrl: 'https://managed.example/notify' } });
  });
  const stale = inRealm(function () {
    return require(ROOT + '/xacml/xacml_admin').pepsJson(NAME);
  }).peps[0];
  const nudged = inRealm(function () {
    return peps.notifiable().filter(function (one) {
      return one.name === NAME;
    })[0];
  });
  t.check(stale && stale.settingsCurrent === false &&
          stale.effectiveNotifyUrl === 'https://managed.example/notify' &&
          nudged && nudged.notifyUrl === 'https://managed.example/notify',
          'S15. a change leaves the PEP not current, and the nudge dials the ' +
          'managed notify URL', JSON.stringify([stale && stale.settingsCurrent,
                                                nudged && nudged.notifyUrl]));
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                    { settings: null });
  row2 = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(row2 && row2.settingsInUse === null && row2.settings,
          'S16. settings: null clears the report and keeps the settings',
          JSON.stringify(row2 && row2.settingsInUse));
  await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
                { settings: report });
  r = await request(port, 'POST', PREFIX + '/xacml/pep/register', pepCred,
                    { version: 'restarted' });
  row2 = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(row2 && row2.settingsInUse === null && row2.settings,
          'S17. a re-registration drops the report and keeps the settings',
          JSON.stringify(row2 && row2.settingsInUse));
  // A stored value an ldapmodify wrote that does not validate.
  inRealm(function () {
    peps.setSettings(NAME, '{"pollIntervalMs":1}');
  });
  sp = await request(port, 'GET', SETTINGS_PULL, pepCred);
  const badView = inRealm(function () {
    return require(ROOT + '/xacml/xacml_admin').pepsJson(NAME);
  }).peps[0];
  t.check(sp.json && sp.json.configured === false && !sp.json.settings &&
          badView && badView.settings === null &&
          /pollIntervalMs/.test(String(badView.settingsProblem)),
          'S18. a stored document that does not validate is pulled as ' +
          'configured: false and named on the page', brief(sp));
  const clearedS = inRealm(function () {
    return adminActions.xacmlAction({ action: 'clear-pep-settings',
                                      name: NAME });
  });
  sp = await request(port, 'GET', SETTINGS_PULL, pepCred);
  row2 = inRealm(function () {
    return peps.read(NAME);
  });
  const actProblems = [
    answerProblem('POST', '/admin-api/xacml/set-pep-settings', 200, setS),
    answerProblem('POST', '/admin-api/xacml/set-pep-settings', 400,
      inRealm(function () {
        return adminActions.xacmlAction({ action: 'set-pep-settings',
          name: NAME, settings: { pollIntervalMs: 1 } });
      })),
    answerProblem('POST', '/admin-api/xacml/clear-pep-settings', 200,
                  clearedS)
  ];
  t.check(actProblems.every(function (one) {
    return one === null;
  }), 'S19b. set-pep-settings\' and clear-pep-settings\' answers, saved ' +
      'and refused, meet their models', JSON.stringify(actProblems));
  t.check(clearedS && clearedS.ok && clearedS.settings === null &&
          sp.json && sp.json.configured === false && row2 &&
          row2.settings === '',
          'S19. clear-pep-settings removes them; the pull is configured: ' +
          'false', JSON.stringify(clearedS));
  const nobodyS = inRealm(function () {
    return adminActions.xacmlAction({ action: 'set-pep-settings',
                                      name: 'not-registered',
                                      settings: { pip: true } });
  });
  t.check(nobodyS && !nobodyS.ok && errorCodes.codeOf(nobodyS),
          'S20. set-pep-settings for a PEP not registered is refused',
          JSON.stringify(nobodyS));
  const unknownS = inRealm(function () {
    return adminActions.xacmlAction({ action: 'nope' });
  });
  t.check(/set-pep-settings/.test(JSON.stringify(unknownS)) &&
          /clear-pep-settings/.test(JSON.stringify(unknownS)),
          'S21. the unknown-action sentence names the two settings actions',
          JSON.stringify(unknownS).slice(0, 300));

  // -------------------------------------------------------------------------
  // L. THE LISTENERS (#1760): defined on the PEP's page, validated whole
  // against the environment's as the PEP reported them, pulled beside the
  // settings, reported back held to closed sets, and an HTTPS listener's
  // certificate issued over the key the PEP generated.
  // -------------------------------------------------------------------------
  const xacmlAdminL = require(ROOT + '/xacml/xacml_admin');
  const keyMaterialL = require(ROOT + '/common/crypto_impl/key_material');
  const x509L = require(ROOT + '/common/crypto_impl/x509');
  const listenerAct = function (body) {
    return inRealm(function () {
      return adminActions.xacmlAction(Object.assign({ name: NAME }, body));
    });
  };
  const setL = listenerAct({ action: 'set-pep-listener', id: 'pub',
                             protocol: 'https', purpose: 'proxy',
                             port: '8443', dnsNames: 'a.example, b.example' });
  t.check(setL && setL.ok && setL.listeners.length === 1 &&
          setL.listeners[0].port === 8443 &&
          setL.listeners[0].address === '0.0.0.0' &&
          setL.listeners[0].keyAlg === 'ec-p256' &&
          setL.listeners[0].dnsNames.join(',') === 'a.example,b.example' &&
          setL.listeners[0].renew === 0,
          'L1. set-pep-listener defines one from the form, normalised',
          JSON.stringify(setL));
  sp = await request(port, 'GET', SETTINGS_PULL, pepCred);
  t.check(sp.status === 200 && Array.isArray(sp.json.listeners) &&
          sp.json.listeners.length === 1 && sp.json.listeners[0].id === 'pub' &&
          !/privateKey/.test(sp.text),
          'L2. the settings pull carries the definition, and no key',
          brief(sp));
  const refusedL = [
    [{ id: 'api-http', protocol: 'http', purpose: 'api', port: 9999 },
     'STS-XACML-0244'],
    [{ id: 'x', protocol: 'ftp', purpose: 'api', port: 9999 },
     'STS-XACML-0245'],
    [{ id: 'x', protocol: 'http', purpose: 'edge', port: 9999 },
     'STS-XACML-0245'],
    [{ id: 'x', protocol: 'http', purpose: 'api', port: 70000 },
     'STS-XACML-0246'],
    [{ id: 'x', protocol: 'http', purpose: 'api', address: 'host',
       port: 9999 }, 'STS-XACML-0246'],
    [{ id: 'x', protocol: 'http', purpose: 'api', port: 9090 },
     'STS-XACML-0247'],
    [{ id: 'x', protocol: 'https', purpose: 'api', address: '::',
       port: 8443 }, 'STS-XACML-0247'],
    [{ id: 'x', protocol: 'http', purpose: 'api', port: 9999,
       dnsNames: ['a.example'] }, 'STS-XACML-0248'],
    [{ id: 'x', protocol: 'https', purpose: 'api', port: 9999,
       keyAlg: 'dsa-1024' }, 'STS-XACML-0248'],
    [{ id: 'x', protocol: 'https', purpose: 'api', port: 9999,
       dnsNames: ['bad name'] }, 'STS-XACML-0248'],
    [{ id: 'x', protocol: 'http', purpose: 'api', port: 9999, extra: 1 },
     'STS-XACML-0243']
  ];
  refusedL.forEach(function (one, i) {
    const got = listenerAct({ action: 'set-pep-listener', listener: one[0] });
    t.check(got && !got.ok && errorCodes.codeOf(got) === one[1],
            'L3.' + i + '. set-pep-listener refuses ' +
            JSON.stringify(one[0]) + ' with ' + one[1],
            JSON.stringify(got) + ' ' + errorCodes.codeOf(got));
  });
  inRealm(function () {
    config.setOverride('global.mode', 'product');
  });
  const plainProduct = listenerAct({ action: 'set-pep-listener',
    listener: { id: 'plain', protocol: 'http', purpose: 'proxy',
                port: 8080 } });
  inRealm(function () {
    config.setOverride('xacml.pepPlainHttpProxyListeners', true);
  });
  const plainAllowed = listenerAct({ action: 'set-pep-listener',
    listener: { id: 'plain', protocol: 'http', purpose: 'proxy',
                port: 8080 } });
  inRealm(function () {
    config.clearOverride('xacml.pepPlainHttpProxyListeners');
    config.clearOverride('global.mode');
  });
  t.check(plainProduct && !plainProduct.ok &&
          errorCodes.codeOf(plainProduct) === 'STS-XACML-0249' &&
          plainAllowed && plainAllowed.ok &&
          plainAllowed.listeners.length === 2,
          'L4. product refuses a plain-HTTP proxy listener unless ' +
          'xacml.pepPlainHttpProxyListeners is on',
          JSON.stringify([plainProduct, plainAllowed]).slice(0, 400));
  const renewL = listenerAct({ action: 'renew-pep-listener-certificate',
                               listener: 'pub' });
  const renewPlain = listenerAct({ action: 'renew-pep-listener-certificate',
                                   listener: 'plain' });
  const removeEnv = listenerAct({ action: 'remove-pep-listener',
                                  listener: 'api-https' });
  const removeL = listenerAct({ action: 'remove-pep-listener',
                                listener: 'plain' });
  t.check(renewL && renewL.ok && renewL.listeners[0].renew === 1 &&
          errorCodes.codeOf(renewPlain) === 'STS-XACML-0250' &&
          errorCodes.codeOf(removeEnv) === 'STS-XACML-0250' &&
          removeL && removeL.ok && removeL.listeners.length === 1,
          'L5. renew moves an HTTPS listener\'s counter; plain HTTP and the ' +
          'environment\'s are refused; remove removes',
          JSON.stringify([renewL, renewPlain, removeEnv, removeL])
            .slice(0, 400));
  // What the PEP reports, held to its members.
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
    { listeners: { listeners: [
      { id: 'api-http', source: 'environment', protocol: 'http',
        purpose: 'api', address: '0.0.0.0', port: 9091,
        state: 'listening', reason: 'none', renew: 0, certificate: null },
      { id: 'pub', source: 'service', protocol: 'https', purpose: 'proxy',
        address: '0.0.0.0', port: 8443, state: 'failed',
        reason: 'Address in use (os error 98) <b>', renew: 0,
        certificate: { subject: 'CN=ppxpep', issuer: 'CN=x\u0007',
                       serialHex: '0a', evil: 'drop me' } },
      { id: 'bad id', state: 'listening' }
    ], secret: 'nope' } });
  row2 = inRealm(function () {
    return peps.read(NAME);
  });
  const lu = row2 && row2.listenersInUse;
  t.check(r.status === 200 && lu && lu.listeners.length === 2 &&
          lu.listeners[1].reason === 'other' &&
          lu.listeners[1].certificate.subject === 'CN=ppxpep' &&
          lu.listeners[1].certificate.issuer === '' &&
          !('evil' in lu.listeners[1].certificate) && !('secret' in lu) &&
          Math.abs(Date.parse(lu.at) - Date.now()) < 60000,
          'L6. the heartbeat\'s listeners are kept to their closed sets, a ' +
          'reason that is not one is "other", control text is dropped',
          JSON.stringify(lu));
  // The environment as reported is what a definition must not clash with.
  const clashReported = listenerAct({ action: 'set-pep-listener',
    listener: { id: 'x', protocol: 'http', purpose: 'api', port: 9091 } });
  const freedDefault = listenerAct({ action: 'set-pep-listener',
    listener: { id: 'x', protocol: 'http', purpose: 'api', port: 9090 } });
  t.check(errorCodes.codeOf(clashReported) === 'STS-XACML-0247' &&
          freedDefault && freedDefault.ok,
          'L7. the clash check reads the environment\'s ports as the PEP ' +
          'reported them', JSON.stringify([clashReported, freedDefault])
            .slice(0, 300));
  listenerAct({ action: 'remove-pep-listener', listener: 'x' });
  const lview = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME);
  });
  const lrow = lview.peps[0];
  t.check(lrow && Array.isArray(lrow.listeners) &&
          lrow.listeners.length === 1 && lrow.listenersProblem === null &&
          lrow.listenerRows.length === 5 &&
          lrow.listenerRows[0].id === 'api-http' &&
          lrow.listenerRows[0].reported.port === 9091 &&
          lrow.listenerRows[4].id === 'pub' &&
          lrow.listenerRows[4].definition.renew === 1 &&
          lrow.listenerRows[4].reported.state === 'failed' &&
          lview.listenersCatalogue.bootstrap.length === 4 &&
          Array.isArray(lview.applicationChoices) &&
          lview.applicationChoices.length >= 1 &&
          lview.applicationChoices.every(function (one) {
            return typeof one.identifier === 'string' && one.identifier &&
              typeof one.name === 'string';
          }),
          'L8. the page answers every listener joined to the report, the ' +
          'catalogue and the application chooser',
          JSON.stringify([lrow && lrow.listeners,
                          lrow && lrow.listenerRows.map(function (one) {
                            return one.id;
                          }),
                          lview.applicationChoices]));
  // PLAIN HTTP OFF BY DEFAULT (#1760): a PEP reports api-http `off` with
  // the reason `http-off`, which is kept rather than folded into `other`;
  // that row holds no port, so a listener defined here may take 9090; and
  // every environment row names the switch that binds it.
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
    { listeners: { listeners: [
      { id: 'api-http', source: 'environment', protocol: 'http',
        purpose: 'api', address: '0.0.0.0', port: 9090,
        state: 'off', reason: 'http-off', renew: 0, certificate: null },
      { id: 'proxy-http', source: 'environment', protocol: 'http',
        purpose: 'proxy', address: '0.0.0.0', port: 9180,
        state: 'listening', reason: 'none', renew: 0, certificate: null }
    ] } });
  const offRow = inRealm(function () {
    return peps.read(NAME);
  });
  const onOff = listenerAct({ action: 'set-pep-listener',
    listener: { id: 'plain9090', protocol: 'http', purpose: 'api',
                port: 9090 } });
  const onListening = listenerAct({ action: 'set-pep-listener',
    listener: { id: 'plain9180', protocol: 'http', purpose: 'api',
                port: 9180 } });
  listenerAct({ action: 'remove-pep-listener', listener: 'plain9090' });
  const offView = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME);
  });
  const enables = offView.peps[0].listenerRows.slice(0, 4)
    .map(function (one) {
      return one.id + '=' + one.enable;
    }).join(',');
  t.check(r.status === 200 && offRow.listenersInUse &&
          offRow.listenersInUse.listeners[0].reason === 'http-off' &&
          offRow.listenersInUse.listeners[0].state === 'off' &&
          onOff && onOff.ok &&
          errorCodes.codeOf(onListening) === 'STS-XACML-0247' &&
          enables === 'api-http=PEP_HTTP,api-https=,' +
                      'proxy-http=PEP_PROXY_HTTP,proxy-https=' &&
          offView.listenersCatalogue.bootstrap[0].enable === 'PEP_HTTP' &&
          offView.listenersCatalogue.bootstrap[1].enable === '',
          'L8b. a plain-HTTP listener reported off (http-off) is kept as ' +
          'that, holds no port, and every environment row names its switch',
          JSON.stringify([offRow.listenersInUse, onOff && onOff.ok,
                          errorCodes.codeOf(onListening), enables]));
  // The certificate, over a key the PEP holds.
  const pepKey = await keyMaterialL.generateKeyPair('ec-p256');
  const csr = await x509L.certificationRequest({ subject: 'CN=ppxpep',
    publicKeyPem: pepKey.publicPem, privateKeyPem: pepKey.privatePem,
    subjectAltName: [{ kind: 'dns', value: 'evil.example' }] });
  const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\n' +
    Buffer.from(csr.der).toString('base64') +
    '\n-----END CERTIFICATE REQUEST-----\n';
  const CERT = PREFIX + '/xacml/pep/listener-certificate';
  const issuedL = await request(port, 'POST', CERT, pepCred,
                                { listener: 'pub', csr: csrPem });
  const leaf = issuedL.json && issuedL.json.certificatePem
    ? new nodeCrypto.X509Certificate(issuedL.json.certificatePem) : null;
  t.check(issuedL.status === 200 && issuedL.json.issued === true &&
          issuedL.headers['cache-control'] === 'no-store' &&
          !/PRIVATE KEY/.test(issuedL.text) && leaf &&
          leaf.publicKey.export({ type: 'spki', format: 'pem' }) ===
            nodeCrypto.createPublicKey(pepKey.publicPem)
              .export({ type: 'spki', format: 'pem' }) &&
          /a\.example/.test(leaf.subjectAltName) &&
          !/evil\.example/.test(leaf.subjectAltName) &&
          /BEGIN CERTIFICATE[\s\S]*BEGIN CERTIFICATE/
            .test(issuedL.json.fullChainPem),
          'L9. the listener\'s certificate certifies the PEP\'s own key, ' +
          'names the definition\'s names and not the request\'s, with its ' +
          'chain, no-store and no key', brief(issuedL));
  const againL = await request(port, 'POST', CERT, pepCred,
                               { listener: 'pub', csr: csrPem });
  t.check(againL.status === 200 && againL.json.issued === false &&
          againL.json.serialHex === issuedL.json.serialHex,
          'L10. the same key again is answered the certificate held',
          brief(againL));
  const noSuchL = await request(port, 'POST', CERT, pepCred,
                                { listener: 'nope', csr: csrPem });
  const badCsrL = await request(port, 'POST', CERT, pepCred,
                                { listener: 'pub', csr: 'not a request' });
  const anonL = await request(port, 'POST', CERT, null,
                              { listener: 'pub', csr: csrPem });
  t.check(noSuchL.status === 400 && badCsrL.status === 400 &&
          (anonL.status === 401 || anonL.status === 403),
          'L11. an unknown listener and an unreadable request are 400, and ' +
          'the door is behind the PEP gate',
          JSON.stringify([noSuchL.status, badCsrL.status, anonL.status]));
  const withIssued = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME);
  }).peps[0].listenerRows[4];
  t.check(withIssued && withIssued.issued &&
          withIssued.issued.serialHex === issuedL.json.serialHex,
          'L12. the page shows the certificate this realm issued the ' +
          'listener', JSON.stringify(withIssued && withIssued.issued));
  r = await request(port, 'POST', PREFIX + '/xacml/pep/register', pepCred,
                    { version: 'restarted-again' });
  row2 = inRealm(function () {
    return peps.read(NAME);
  });
  t.check(row2 && row2.listeners && row2.listenersInUse === null,
          'L13. a re-registration keeps the definitions and drops the report',
          JSON.stringify(row2 && row2.listenersInUse));
  inRealm(function () {
    peps.setListeners(NAME, '[{"id":"q","protocol":"gopher"}]');
  });
  sp = await request(port, 'GET', SETTINGS_PULL, pepCred);
  const badL = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME);
  }).peps[0];
  t.check(sp.json && sp.json.listeners === undefined && badL &&
          badL.listeners === null && /protocol/.test(badL.listenersProblem),
          'L14. stored definitions that do not validate are not pulled and ' +
          'are named on the page', brief(sp));
  const answersL = [
    answerProblem('GET', '/admin-api/xacml/peps', 200, lview),
    answerProblem('GET', '/admin-api/xacml/peps', 200, offView),
    answerProblem('GET', '/admin-api/xacml/peps', 200, inRealm(function () {
      return xacmlAdminL.pepsJson(NAME);
    })),
    answerProblem('POST', '/admin-api/xacml/set-pep-listener', 200, setL),
    answerProblem('POST', '/admin-api/xacml/set-pep-listener', 400,
                  plainProduct),
    answerProblem('POST', '/admin-api/xacml/remove-pep-listener', 200,
                  removeL),
    answerProblem('POST', '/admin-api/xacml/renew-pep-listener-certificate',
                  200, renewL),
    answerProblem('POST', '/admin-api/xacml/renew-pep-listener-certificate',
                  400, renewPlain)
  ];
  t.check(answersL.every(function (one) {
    return one === null;
  }), 'L15. the page and the three listener actions\' answers meet their ' +
      'models', JSON.stringify(answersL));
  inRealm(function () {
    peps.setListeners(NAME, null);
  });

  // -------------------------------------------------------------------------
  // R. THE ROUTES ONE AT A TIME (#1760): each action builds the whole
  // document and saves it through set-pep-proxy's own validator.
  // -------------------------------------------------------------------------
  const routeAct = function (body) {
    return inRealm(function () {
      return adminActions.xacmlAction(Object.assign({ name: NAME }, body));
    });
  };
  const routesBefore = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME);
  }).peps[0].proxy;
  const guarded = routesBefore.routes.filter(function (one) {
    return !one.public;
  })[0];
  const addR = routeAct({ action: 'set-pep-route', id: 'health',
                          path: '/health', match: 'exact', methods: 'GET',
                          public: 'true', position: '0' });
  t.check(addR && addR.ok && addR.proxy.routes[0].id === 'health' &&
          addR.proxy.routes[0].public === true &&
          addR.proxy.routes[0].methods.join(',') === 'GET' &&
          addR.proxy.routes.length === routesBefore.routes.length + 1,
          'R1. set-pep-route adds a route from the form where it is asked',
          JSON.stringify(addR).slice(0, 300));
  const editR = routeAct({ action: 'set-pep-route', id: guarded.id,
    path: guarded.path, match: guarded.match, methods: ['GET', 'HEAD'],
    public: 'false', mechanisms: guarded.mechanisms,
    application: guarded.application, resource: 'edited' });
  const edited = editR && editR.proxy && editR.proxy.routes.filter(
    function (one) {
      return one.id === guarded.id;
    })[0];
  t.check(editR && editR.ok && edited &&
          edited.methods.join(',') === 'GET,HEAD' &&
          edited.resource === 'edited' &&
          JSON.stringify(edited.identity) ===
            JSON.stringify(guarded.identity) &&
          editR.proxy.routes.indexOf(edited) ===
            addR.proxy.routes.map(function (one) {
              return one.id;
            }).indexOf(guarded.id),
          'R2. an edit replaces the route where it stands and keeps its ' +
          'identity', JSON.stringify(edited));
  const badPath = routeAct({ action: 'set-pep-route', id: 'bad',
                             path: 'no-slash', public: 'true' });
  const badPos = routeAct({ action: 'set-pep-route', id: 'bad', path: '/b',
                            public: 'true', position: '99' });
  const noApp = routeAct({ action: 'set-pep-route', id: 'bad', path: '/b',
                           mechanisms: ['oauth2'] });
  t.check(errorCodes.codeOf(badPath) === 'STS-XACML-0193' &&
          errorCodes.codeOf(badPos) === 'STS-XACML-0256' &&
          errorCodes.codeOf(noApp) === 'STS-XACML-0197',
          'R3. a route the document editor would refuse is refused by the ' +
          'same codes; a position past the list is STS-XACML-0256',
          JSON.stringify([badPath, badPos, noApp].map(function (one) {
            return errorCodes.codeOf(one);
          })));
  const mapUnknown = routeAct({ action: 'set-pep-route-application',
                                route: guarded.id,
                                application: 'no-such-app' });
  const mapPublic = routeAct({ action: 'set-pep-route-application',
                               route: 'health',
                               application: guarded.application });
  const mapNone = routeAct({ action: 'set-pep-route-application',
                             route: guarded.id });
  const mapOk = routeAct({ action: 'set-pep-route-application',
                           route: guarded.id,
                           application: guarded.application });
  t.check(mapUnknown && !mapUnknown.ok && errorCodes.codeOf(mapUnknown) &&
          errorCodes.codeOf(mapPublic) === 'STS-XACML-0197' &&
          errorCodes.codeOf(mapNone) === 'STS-XACML-0256' &&
          mapOk && mapOk.ok,
          'R4. set-pep-route-application resolves the application like a ' +
          'save; a public route takes none',
          JSON.stringify([mapUnknown, mapPublic, mapNone].map(function (o) {
            return errorCodes.codeOf(o);
          })));
  const removeUnknownR = routeAct({ action: 'remove-pep-route',
                                    route: 'nope' });
  const removeR = routeAct({ action: 'remove-pep-route', route: 'health' });
  t.check(errorCodes.codeOf(removeUnknownR) === 'STS-XACML-0230' &&
          removeR && removeR.ok &&
          removeR.proxy.routes.length === routesBefore.routes.length,
          'R5. remove-pep-route removes; an unknown one is STS-XACML-0230',
          JSON.stringify(removeR).slice(0, 200));
  const answersR = [
    answerProblem('POST', '/admin-api/xacml/set-pep-route', 200, addR),
    answerProblem('POST', '/admin-api/xacml/set-pep-route', 400, badPath),
    answerProblem('POST', '/admin-api/xacml/remove-pep-route', 200, removeR),
    answerProblem('POST', '/admin-api/xacml/set-pep-route-application', 200,
                  mapOk),
    answerProblem('POST', '/admin-api/xacml/set-pep-route-application', 400,
                  mapNone)
  ];
  t.check(answersR.every(function (one) {
    return one === null;
  }), 'R6. the three route actions\' answers meet their models',
      JSON.stringify(answersR));
  const unknownR = inRealm(function () {
    return adminActions.xacmlAction({ action: 'nope' });
  });
  t.check(['set-pep-listener', 'remove-pep-listener',
           'renew-pep-listener-certificate', 'set-pep-route',
           'remove-pep-route', 'set-pep-route-application']
    .every(function (one) {
      return JSON.stringify(unknownR).indexOf(one) >= 0;
    }), 'R7. the unknown-action sentence names the six new actions',
          JSON.stringify(unknownR).slice(0, 200));

  // -------------------------------------------------------------------------
  // P. A ROUTE'S OWN PAGE (#1760): `?pep=&route=` answers the route where
  // it stands, its resolution and the proxy listeners; its save is
  // set-pep-route with `from` (a rename) and the identity's form members,
  // through the one validator.
  // -------------------------------------------------------------------------
  const pageView = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME, guarded.id);
  });
  const rd = pageView.routeDetail;
  const atBefore = pageView.peps[0].proxy.routes.map(function (one) {
    return one.id;
  }).indexOf(guarded.id);
  t.check(pageView.route === guarded.id && rd && rd.found === true &&
          rd.route.id === guarded.id && rd.position === atBefore &&
          rd.count === pageView.peps[0].proxy.routes.length &&
          typeof rd.usable === 'boolean' &&
          rd.application.identifier === guarded.application &&
          rd.application.found === true &&
          rd.servedBy.length >= 2 && rd.servedBy.every(function (one) {
            return /^proxy-/.test(one.id) || one.source === 'service';
          }),
          'P1. ?route= answers the route where it stands, whether it resolves, ' +
          'its application and the proxy listeners serving it',
          JSON.stringify(rd));
  const missingView = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME, 'no-such-route');
  });
  t.check(missingView.routeDetail && missingView.routeDetail.found === false &&
          missingView.routeDetail.route === null,
          'P2. a route the PEP does not hold is found: false',
          JSON.stringify(missingView.routeDetail));
  const newId = guarded.id + '-renamed';
  const renamedR = routeAct({ action: 'set-pep-route', from: guarded.id,
    id: newId, path: guarded.path, match: guarded.match,
    methods: guarded.methods, public: 'false',
    mechanisms: guarded.mechanisms, application: guarded.application,
    resource: guarded.resource, routeAction: guarded.action,
    forwardCredentials: 'false', signals: 'true',
    mode: 'headers', headerName: ['X-Page-User', ''],
    headerClaim: ['username', ''], separator: ';' });
  const afterIds = renamedR && renamedR.proxy
    ? renamedR.proxy.routes.map(function (one) {
        return one.id;
      }) : [];
  const renamedRoute = renamedR && renamedR.proxy
    ? renamedR.proxy.routes[afterIds.indexOf(newId)] : null;
  t.check(renamedR && renamedR.ok && afterIds.indexOf(guarded.id) < 0 &&
          afterIds.indexOf(newId) === atBefore && renamedRoute &&
          renamedRoute.identity.mode === 'headers' &&
          renamedRoute.identity.headers.length === 1 &&
          renamedRoute.identity.headers[0].name === 'X-Page-User' &&
          renamedRoute.identity.separator === ';',
          'P3. the page\'s save renames the route where it stands and sets ' +
          'its identity from the form', JSON.stringify(renamedRoute));
  const other = renamedR.proxy.routes.filter(function (one) {
    return one.id !== newId;
  })[0];
  const clash = routeAct({ action: 'set-pep-route', from: newId,
    id: other.id, path: guarded.path, mechanisms: guarded.mechanisms,
    application: guarded.application });
  const noFrom = routeAct({ action: 'set-pep-route', from: 'no-such-route',
    id: 'x', path: '/x', public: 'true' });
  const badIdentity = routeAct({ action: 'set-pep-route', from: newId,
    id: newId, path: guarded.path, mechanisms: guarded.mechanisms,
    application: guarded.application, mode: 'headers',
    headerName: ['Authorization'], headerClaim: ['sub'] });
  t.check(errorCodes.codeOf(clash) === 'STS-XACML-0192' &&
          errorCodes.codeOf(noFrom) === 'STS-XACML-0230' &&
          badIdentity && !badIdentity.ok && errorCodes.codeOf(badIdentity),
          'P4. a rename to an id another route holds is STS-XACML-0192, an ' +
          'unknown `from` STS-XACML-0230, and a refused identity is refused',
          JSON.stringify([clash, noFrom, badIdentity].map(function (o) {
            return errorCodes.codeOf(o);
          })));
  const restored = routeAct({ action: 'set-pep-route', from: newId,
                              route: guarded });
  t.check(restored && restored.ok &&
          JSON.stringify(restored.proxy.routes[atBefore]) ===
            JSON.stringify(guarded),
          'P5. the route object with `from` puts the route back whole',
          JSON.stringify(restored && restored.proxy.routes[atBefore]));
  const answersP = [
    answerProblem('GET', '/admin-api/xacml/peps', 200, pageView),
    answerProblem('GET', '/admin-api/xacml/peps', 200, missingView),
    answerProblem('POST', '/admin-api/xacml/set-pep-route', 200, renamedR),
    answerProblem('POST', '/admin-api/xacml/set-pep-route', 400, clash)
  ];
  t.check(answersP.every(function (one) {
    return one === null;
  }), 'P6. the route page\'s answer and its save meet their models',
      JSON.stringify(answersP));

  // -------------------------------------------------------------------------
  // T. THE SIGNAL STREAMS, ONE ROW EACH (#1760): ages turned into times on
  // arrival, a PEP's own times never believed, a client this PEP's routes
  // do not name answered empty, and the answer meeting its model.
  // -------------------------------------------------------------------------
  const sessionRoute = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME);
  }).peps[0].proxyRoutes;
  r = await request(port, 'POST', PREFIX + '/xacml/pep/heartbeat', pepCred,
    { signals: { receivers: 2, healthy: 1, stale: 1, streams: [
      { clientId: 'ppx-web', streamId: 'stream-1', running: true,
        healthy: true, startedAgeMs: 60000, lastPollAgeMs: 1000,
        lastSuccessAgeMs: 1000, startedAt: '2001-01-01T00:00:00.000Z',
        consecutiveFailures: 0, polls: 7, failedPolls: 1, setsAccepted: 2,
        setsRefused: 0, sessionsEnded: 1, url: 'https://leak' },
      { clientId: 'not <in> config', streamId: 'x y', running: false,
        healthy: false, lastPollAgeMs: null, consecutiveFailures: 3 }
    ] } });
  const sview = inRealm(function () {
    return xacmlAdminL.pepsJson(NAME);
  });
  const streams = sview.peps[0].signals && sview.peps[0].signals.streams;
  const startedAgo = streams && Date.now() - Date.parse(streams[0].startedAt);
  t.check(r.status === 200 && streams && streams.length === 2 &&
          startedAgo > 55000 && startedAgo < 120000 &&
          streams[0].polls === 7 && !('url' in streams[0]) &&
          streams[1].clientId === '' && streams[1].streamId === '' &&
          streams[1].lastPollAt === null &&
          streams[1].consecutiveFailures === 3,
          'T1. each stream is a row: times from the ages on arrival, never ' +
          'the PEP\'s own, identifiers held to a charset',
          JSON.stringify(streams) + ' ' + JSON.stringify(sessionRoute));
  t.check(streams && (streams[0].clientId === '' ||
                      streams[0].applications.indexOf('ppx-web') >= 0),
          'T2. a stream of a client this PEP\'s routes resolve to names the ' +
          'application it serves', JSON.stringify(streams && streams[0]));
  t.check(answerProblem('GET', '/admin-api/xacml/peps', 200, sview) === null,
          'T3. the page answer with streams meets its model',
          String(answerProblem('GET', '/admin-api/xacml/peps', 200, sview)));

  // -------------------------------------------------------------------------
  // G. BASIC IN PRODUCT: a password is verified, a second factor is owed by
  // everybody so the person's own password is refused, an app password
  // scoped to `xacml-pep` is accepted, and failures meet the door's limit.
  // -------------------------------------------------------------------------
  const PASSWORD = 'Ppx-' + nodeCrypto.randomBytes(4).toString('hex') +
    '-Correct.Horse.Battery.Staple.42';
  const credentials = require(ROOT + '/common/credentials');
  const prepared = inRealm(function () {
    // The person first: product creates nobody a reference names.
    ldap.createUser('ppxbob', { invent: false });
    config.setOverride('global.mode', 'product');
    const set = credentials.setPassword('ppxbob', PASSWORD);
    const app = credentials.createAppPassword('ppxbob',
      { name: 'proxy', doors: ['xacml-pep'], createdBy: 'test' });
    return { set: set, app: app };
  });
  t.check(prepared.set && prepared.set.ok !== false && prepared.app &&
          prepared.app.ok && prepared.app.password,
          'G0. product: ppxbob has a password and an app password for ' +
          'xacml-pep', JSON.stringify(prepared).slice(0, 300));
  since = marks.length;
  r = await request(port, 'POST', BASIC, pepCred,
                    { username: 'ppxbob', password: PASSWORD });
  t.check(r.status === 200 && JSON.stringify(r.json) === '{"valid":false}',
          'G1. product: the person\'s own password is { valid: false } at ' +
          'a door that cannot ask for the second factor everybody owes',
          brief(r));
  r = await request(port, 'POST', BASIC, pepCred,
    { username: 'ppxbob', password: String(prepared.app.password || '') });
  t.check(r.status === 200 && r.json && r.json.valid === true &&
          r.json.username === 'ppxbob',
          'G2. product: an app password scoped to xacml-pep is valid',
          brief(r));
  let blocked = null;
  for (let i = 0; i < 200 && !blocked; i++) {
    const one = await request(port, 'POST', BASIC, pepCred,
                              { username: 'ppxbob', password: 'wrong-' + i });
    if (one.status === 429) {
      blocked = one;
    } else if (JSON.stringify(one.json) !== '{"valid":false}') {
      blocked = { status: -1, text: one.text, json: null, headers: {} };
    }
  }
  t.check(blocked && blocked.status === 429 && blocked.json &&
          blocked.json.valid === false && blocked.json.retryAfterS > 0 &&
          closedTo(blocked.json, 'basic') &&
          Number(blocked.headers['retry-after']) > 0,
          'G3. product: past the sign-in door\'s limit it is 429 with ' +
          'retryAfterS', blocked ? brief(blocked) : 'never blocked');
  r = await request(port, 'POST', BASIC, pepCred,
    { username: 'ppxbob', password: String(prepared.app.password || '') });
  t.check(r.status === 429,
          'G4. product: a right app password is still blocked while the ' +
          'door is', brief(r));
  inRealm(function () {
    config.clearOverride('global.mode');
  });

  await new Promise(function (ok) {
    listener.close(ok);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the remote PEP as a reverse proxy (#1760) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'xacml_pep_proxy',
  describe: 'the remote PEP as a reverse proxy (#1760): the configuration ' +
            'grammar, the register, GET /xacml/pep/proxy, the four ' +
            'validation doors, the session client and the actions',
  run: run
};
