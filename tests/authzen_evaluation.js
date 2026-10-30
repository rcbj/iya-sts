// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authzen_evaluation.js
//
// ---------------------------------------------------------------------------
// POST /access/v1/evaluation, IN PROCESS, OVER REAL HANDSHAKES (#563 phase 2,
// #1161).
//
// The whole stack in a child process (`stored_certificates.js`'s reason: it
// builds a certificate authority and registers every route), a listener with
// the main port's posture over the client truststore, and a throwaway realm
// whose root policy this file wrote. What it holds:
//
//   M. THE CERTIFICATE DOOR, the default: none (401, and no Bearer
//      challenge on a door of certificates alone), one stored nowhere (401),
//      a stored one whose entry lacks AUTHZEN_PEPS (403 on the policy), one
//      admitted and scoped to no application (403), and one admitted and
//      scoped.
//   D. THE RESULT MAPPING through the realm's root policy: Permit true,
//      Deny false, NotApplicable false, X-Request-ID echoed, an undeclared
//      property 400, an application out of scope 403, a PIP-resolved
//      subject type deciding on the person's directory entry and another
//      type with the same id not, the reasons only when asked for, and a
//      root policy that will not load answered 500 rather than false.
//   B. THE TOKEN DOOR: a client_credentials token for /access/v1 carrying
//      authzen:evaluate, from a client in the AUTHZEN_PEPS group (true); no
//      token (401 with WWW-Authenticate: Bearer realm=...); the same client
//      out of the group (403).
//   W. THE METADATA (#1163): both forms, the identifier the URL was built
//      from, every advertised URL a registered route, nothing unimplemented
//      advertised, 404 for a path naming no realm, 501 while off.
//   E. THE BATCH (#1164): every semantic, an item's failure in its own
//      context.error, the defaults overridden per item, no items as one
//      evaluation, both bounds, the switch, and the batch id on each row.
//   O. OFF: authzen.enabled off answers 501.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const https = require('https');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_AUTHZEN_EVALUATION_CHILD';
const MARK = 'AUTHZEN-EVALUATION-CHILD ';
const REALM = 'azeval';
const PREFIX = '/realm/' + REALM;
const CLIENT = 'azeval-pep-client';
const SECRET = 'azeval-secret-0123456789abcdef';

const CA_PEM = { value: '' };

const log = require('bunyan').createLogger({ name: 'authzen_evaluation',
  level: process.env.LOG_LEVEL || 'info' });

// THE ROOT POLICY: readers of an internal document, staff writers (read off
// the subject's own directory entry), no deletes — and an `explode` whose
// condition is a PROCESSING ERROR when `tags` carries two values, which is
// how a fault the PDP reaches is made without breaking the repository.
const POLICY = [
  'namespace azeval {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute protocol { category = environmentCat',
  '        id = "urn:sts:xacml:protocol" type = string }',
  '    attribute classification { category = resourceCat',
  '        id = "urn:example:classification" type = string }',
  '    attribute staff { category = subjectCat id = "employeeType"',
  '        type = string }',
  '    attribute tags { category = resourceCat id = "urn:example:tags"',
  '        type = string }',
  '    attribute rtype { category = resourceCat',
  '        id = "urn:sts:xacml:authzen:resource-type" type = string }',
  '    policy azevalRoot {',
  '        id = "urn:test:azeval-root"',
  '        apply firstApplicable',
  '        target clause protocol == "authzen"',
  '        rule readInternal {',
  '            permit',
  '            target clause act == "read"',
  '            target clause classification == "internal"',
  '        }',
  '        rule staffWrite {',
  '            permit',
  '            target clause act == "write"',
  '            target clause staff == "staff"',
  '        }',
  '        rule noDelete {',
  '            deny',
  '            target clause act == "delete"',
  '        }',
  '        rule inspectApplications {',
  '            permit',
  '            target clause act == "inspect"',
  '            target clause rtype == "application" or rtype == "api"',
  '        }',
  '        rule followDelegation {',
  '            permit',
  '            target clause act == "follow"',
  '            target clause rtype == "delegation"',
  '        }',
  '        rule approve {',
  '            permit',
  '            target clause act == "approve"',
  '            on permit {',
  '                obligation "urn:sts:xacml:authzen:obligation:step-up" {',
  '                    "acr_value" = "phr"',
  '                }',
  '            }',
  '        }',
  '        rule explode {',
  '            permit',
  '            target clause act == "explode"',
  '            condition stringEqual(stringOneAndOnly(tags), "x")',
  '        }',
  '    }',
  '}'
].join('\n');


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

// One evaluation request, and whatever `extra` adds to its members.
function evaluation(extra) {
  log.debug("Entering evaluation().");
  const out = {
    subject: { type: 'user', id: 'azalice' },
    action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1',
                properties: { classification: 'internal' } }
  };
  Object.keys(extra || {}).forEach(function (key) {
    out[key] = Object.assign({}, out[key] || {}, extra[key]);
  });
  log.debug("Leaving evaluation().");
  return out;
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
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const store = require(ROOT + '/xacml/xacml_store');
  const xml = require(ROOT + '/xacml/xacml_xml');
  const alfa = require(ROOT + '/xacml/xacml_alfa');
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

  // THE PEOPLE AND THE CALLERS, in the realm. `azalice` is the subject a
  // question is about (staff, on her own entry); `azpep` and `azother` are
  // callers, each storing an outside authority's certificate; only `azpep`
  // is in authzen-peps.
  const mint = function (subject) {
    log.debug("Entering mint().");
    log.debug("Leaving mint().");
    return outsideCa.mint({ subject: subject, crlBase: '' });
  };
  const pepCred = await mint('CN=azpep,O=Outside');
  const otherCred = await mint('CN=azother,O=Outside');
  const strayCred = await mint('CN=azstray,O=Outside');
  const added = tls.addAnchors([pepCred, otherCred, strayCred]
    .map(function (one) {
      return one.anchorPem;
    }).join(''));
  t.check(added && added.added === 3,
          'setup: the outside Root CAs are in the client truststore',
          JSON.stringify(added));
  const derOf = function (minted) {
    log.debug("Entering derOf().");
    log.debug("Leaving derOf().");
    return new nodeCrypto.X509Certificate(minted.leaf.pem).raw;
  };
  const group = String(config.value('roles.authzenPepGroup'));
  let catalogued = null;
  let client = null;
  inRealm(function () {
    ['azalice', 'azpep', 'azother'].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    ldap.locateEntry('azalice').stored.attributes.employeetype = ['staff'];
    ldap.changeStoredCertificate('person', 'azpep', { add: derOf(pepCred) });
    ldap.changeStoredCertificate('person', 'azother',
                                 { add: derOf(otherCred) });
    adminActions.groupsAction({ action: 'add-member', group: group,
                                member: 'azpep' });
    catalogued = applications.updateApplication('sts-authzen-api', {
      mode: 'add', attribute: 'authzenAttribute',
      value: JSON.stringify({ object: 'resource',
        property: 'classification',
        attributeId: 'urn:example:classification' }) });
    applications.updateApplication('sts-authzen-api', {
      mode: 'add', attribute: 'authzenAttribute',
      value: JSON.stringify({ object: 'resource', property: 'tags',
        multiplicity: 'bag', attributeId: 'urn:example:tags' }) });
    const policy = alfa.parse(POLICY);
    store.write('azeval-root', xml.writePolicy(policy),
                { enabled: true, isRoot: true });
    client = applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthGrantType: ['client_credentials'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic',
                oauthDelegatedPermission:
                  ['urn:sts:authzen-api:authzen:evaluate'],
                appAuthzenApplication: ['todo-app'] } });
  });
  t.check(catalogued && catalogued.ok,
          'setup: a catalogue row is written onto sts-authzen-api',
          JSON.stringify(catalogued));
  t.check(client && client.ok !== false,
          'setup: the OAuth caller is created', JSON.stringify(client));
  const reserved = inRealm(function () {
    return applications.updateApplication('sts-authzen-api', {
      mode: 'add', attribute: 'authzenAttribute',
      value: JSON.stringify({ object: 'subject', property: 'roles',
                              attributeId: 'urn:sts:xacml:role' }) });
  });
  t.check(reserved && !reserved.ok &&
          errorCodes.codeOf(reserved) === 'STS-AUTHZEN-0011',
          'C1. a catalogue row onto urn:sts:xacml:role is refused at the ' +
          'write (STS-AUTHZEN-0011)', JSON.stringify(reserved));

  // THE LISTENER, with the main port's posture over the client truststore.
  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  CA_PEM.value = serverCa.certPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  tls.trustClientCertificatesOn(listener,
    'the authzen_evaluation listener', function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;
  const URL = PREFIX + '/access/v1/evaluation';
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 300);
  };

  // -------------------------------------------------------------------------
  // M. THE CERTIFICATE DOOR
  // -------------------------------------------------------------------------
  let since = marks.length;
  let r = await request(port, 'POST', URL, null, evaluation());
  t.check(r.status === 401 && markedSince(since, 'STS-AUTHZEN-0015') &&
          !r.headers['www-authenticate'] && r.json && r.json.error &&
          r.json.error.status === 401,
          'M1. no certificate is 401 (STS-AUTHZEN-0015), with no Bearer ' +
          'challenge on a door of certificates alone', brief(r));
  since = marks.length;
  r = await request(port, 'POST', URL, strayCred, evaluation());
  t.check(r.status === 401 && markedSince(since, 'STS-AUTHZEN-0017'),
          'M2. a verified certificate stored on no entry is 401 ' +
          '(STS-AUTHZEN-0017)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', URL, otherCred, evaluation());
  t.check(r.status === 403 && markedSince(since, 'STS-AUTHZEN-0024') &&
          /AUTHZEN_PEPS/.test(r.text),
          'M3. a stored certificate whose entry lacks AUTHZEN_PEPS is 403 ' +
          'on the policy (STS-AUTHZEN-0024)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', URL, pepCred, evaluation());
  t.check(r.status === 403 && markedSince(since, 'STS-AUTHZEN-0026'),
          'M4. admitted and scoped to no application is 403 ' +
          '(STS-AUTHZEN-0026)', brief(r));
  // The scope an administrator sets (#1162 gives it a door; the attribute
  // is what is read).
  inRealm(function () {
    ldap.locateEntry('azpep').stored.attributes.stsauthzenapplication =
      ['todo-app', 'wiki'];
  });
  since = marks.length;
  r = await request(port, 'POST', URL, pepCred, evaluation());
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0027'),
          'M5. scoped to two and naming neither is 400 (STS-AUTHZEN-0027)',
          brief(r));

  // -------------------------------------------------------------------------
  // D. THE RESULT MAPPING
  // -------------------------------------------------------------------------
  const asked = function (extra) {
    log.debug("Entering asked().");
    log.debug("Leaving asked().");
    return evaluation(Object.assign({ context: { application: 'todo-app' } },
                                    extra || {}));
  };
  r = await request(port, 'POST', URL, pepCred, asked(),
                    { 'x-request-id': 'az-req-1' });
  t.check(r.status === 200 && r.json && r.json.decision === true &&
          r.headers['x-request-id'] === 'az-req-1' && !r.json.context,
          'D1. a Permit is 200 decision true, X-Request-ID is echoed, and ' +
          'no context is sent while authzen.returnReasons is off', brief(r));
  r = await request(port, 'POST', URL, pepCred,
                    asked({ action: { name: 'delete' } }));
  t.check(r.status === 200 && r.json && r.json.decision === false,
          'D2. a Deny is 200 decision false', brief(r));
  r = await request(port, 'POST', URL, pepCred,
                    asked({ action: { name: 'archive' } }));
  t.check(r.status === 200 && r.json && r.json.decision === false,
          'D3. NotApplicable is 200 decision false', brief(r));
  since = marks.length;
  r = await request(port, 'POST', URL, pepCred,
    asked({ resource: { properties: { classification: 'internal',
                                      colour: 'red' } } }));
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0004'),
          'D4. an undeclared property is 400 (STS-AUTHZEN-0004)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', URL, pepCred,
                    evaluation({ context: { application: 'payroll' } }));
  t.check(r.status === 403 && markedSince(since, 'STS-AUTHZEN-0025'),
          'D5. an application out of the caller\'s scope is 403 ' +
          '(STS-AUTHZEN-0025)', brief(r));
  r = await request(port, 'POST', URL, pepCred,
                    asked({ action: { name: 'write' } }));
  const resolved = r;
  r = await request(port, 'POST', URL, pepCred,
                    asked({ action: { name: 'write' },
                            subject: { type: 'service' } }));
  t.check(resolved.json && resolved.json.decision === true &&
          r.json && r.json.decision === false,
          'D6. a user subject is decided on the person\'s directory entry ' +
          '(staff), and a service subject with the same id is not that ' +
          'person', brief(resolved) + ' / ' + brief(r));
  inRealm(function () {
    config.setOverride('authzen.returnReasons', true);
  });
  r = await request(port, 'POST', URL, pepCred,
                    asked({ action: { name: 'delete' } }));
  inRealm(function () {
    config.setOverride('authzen.returnReasons', false);
  });
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          r.json.context && r.json.context.xacml_decision === 'Deny',
          'D7. with authzen.returnReasons on, the context names the XACML ' +
          'decision', brief(r));
  since = marks.length;
  r = await request(port, 'POST', URL, pepCred,
    asked({ action: { name: 'explode' },
            resource: { properties: { classification: 'internal',
                                      tags: ['a', 'b'] } } }));
  t.check(r.status === 500 && markedSince(since, 'STS-AUTHZEN-0028') &&
          !(r.json && r.json.decision === false),
          'D8. a processing error the PDP reaches is 500 ' +
          '(STS-AUTHZEN-0028), never decision false', brief(r));

  // -------------------------------------------------------------------------
  // B. THE TOKEN DOOR
  // -------------------------------------------------------------------------
  inRealm(function () {
    config.setOverride('authzen.callerAuthentication', 'bearer');
  });
  since = marks.length;
  r = await request(port, 'POST', URL, null, asked());
  t.check(r.status === 401 && markedSince(since, 'STS-AUTHZEN-0018') &&
          /^Bearer realm="[^"]+"/.test(String(r.headers['www-authenticate'])),
          'B1. no token is 401 (STS-AUTHZEN-0018) with WWW-Authenticate: ' +
          'Bearer realm="<issuer>" (section 11.3)', brief(r) + ' ' +
          r.headers['www-authenticate']);
  const base = 'https://127.0.0.1:' + port + PREFIX;
  const tokenResponse = await request(port, 'POST', PREFIX + '/oauth2/token',
    null, 'grant_type=client_credentials&scope=authzen%3Aevaluate' +
          '&resource=' + encodeURIComponent(base + '/access/v1'),
    { 'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' + Buffer.from(CLIENT + ':' + SECRET)
        .toString('base64') });
  const token = tokenResponse.json && tokenResponse.json.access_token;
  t.check(!!token, 'setup: a client_credentials token for /access/v1 ' +
          'carrying authzen:evaluate is issued', brief(tokenResponse));
  since = marks.length;
  r = await request(port, 'POST', URL, null, asked(),
                    { authorization: 'Bearer ' + token });
  t.check(r.status === 403 && markedSince(since, 'STS-AUTHZEN-0024'),
          'B2. the client out of authzen-peps is refused on the policy',
          brief(r));
  const entry = inRealm(function () {
    return applications.get(CLIENT);
  });
  inRealm(function () {
    adminActions.groupsAction({ action: 'add-member', group: group,
                                member: entry.dn });
  });
  r = await request(port, 'POST', URL, null, asked(),
                    { authorization: 'Bearer ' + token });
  t.check(r.status === 200 && r.json && r.json.decision === true,
          'B3. its own token, with its entry in authzen-peps and scoped to ' +
          'todo-app, is decided: true', brief(r));
  r = await request(port, 'POST', URL, null,
                    evaluation({ context: { application: CLIENT } }),
                    { authorization: 'Bearer ' + token });
  t.check(r.status === 200,
          'B4. a client\'s own application is always in its scope',
          brief(r));
  inRealm(function () {
    config.setOverride('authzen.callerAuthentication', 'mtls');
  });

  // -------------------------------------------------------------------------
  // B2. THE OBLIGATIONS PROFILE (#1177)
  // -------------------------------------------------------------------------
  r = await request(port, 'POST', URL, pepCred,
                    asked({ action: { name: 'approve' } }));
  t.check(r.status === 200 && r.json && r.json.decision === false &&
          !r.json.context,
          'G1. a Permit with a step-up obligation, asked by a PEP that ' +
          'declared none, is false', brief(r));
  r = await request(port, 'POST', URL, pepCred,
    asked({ action: { name: 'approve' },
            context: { application: 'todo-app',
                       supported_obligations: ['step-up'] } }));
  const handed = (r.json && r.json.context &&
                  r.json.context.obligations) || [];
  t.check(r.status === 200 && r.json.decision === true &&
          handed.length === 1 && handed[0].type === 'step-up' &&
          handed[0].properties.acr_value === 'phr',
          'G2. declared, it is true with the step-up in context.obligations',
          brief(r));

  // -------------------------------------------------------------------------
  // S. THE THREE SEARCHES (#1175)
  // -------------------------------------------------------------------------
  inRealm(function () {
    applications.createApplication({ identifier: 'azeval-front',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'azeval-front',
                appAllowedToDelegateTo: ['azeval-back'] } });
  });
  const SEARCH = PREFIX + '/access/v1/search/';
  r = await request(port, 'POST', SEARCH + 'subject', pepCred, {
    subject: { type: 'user' }, action: { name: 'write' },
    resource: { type: 'document', id: 'doc-1' },
    context: { application: 'todo-app' } });
  let ids = ((r.json && r.json.results) || []).map(function (one) {
    return one.type + ':' + one.id;
  });
  t.check(r.status === 200 && ids.indexOf('user:azalice') >= 0 &&
          ids.indexOf('user:azpep') < 0 && r.json.page &&
          typeof r.json.page.next_token === 'string' &&
          Object.keys(r.json)[0] === 'page',
          'S1. Subject Search answers the directory people the policy ' +
          'permits (staff azalice, not azpep), the page first', brief(r));
  r = await request(port, 'POST', SEARCH + 'subject', pepCred, {
    subject: { type: 'service', id: 'ignored' }, action: { name: 'write' },
    resource: { type: 'document', id: 'doc-1' },
    context: { application: 'todo-app' } });
  t.check(r.status === 200 && r.json.results.length === 0,
          'S2. a subject type this realm does not resolve has no candidates, ' +
          'and an id sent is ignored', brief(r));
  r = await request(port, 'POST', SEARCH + 'resource', pepCred, {
    subject: { type: 'user', id: 'azalice' }, action: { name: 'inspect' },
    resource: { type: 'application' },
    context: { application: 'todo-app' } });
  ids = ((r.json && r.json.results) || []).map(function (one) {
    return one.id;
  });
  t.check(r.status === 200 && ids.indexOf('azeval-front') >= 0 &&
          ids.indexOf('sts-authzen-api') >= 0 &&
          r.json.results.every(function (one) {
            return one.type === 'application';
          }),
          'S3. Resource Search answers the realm\'s applications, all of the ' +
          'searched type', brief(r));
  r = await request(port, 'POST', SEARCH + 'resource', pepCred, {
    subject: { type: 'user', id: 'azalice' }, action: { name: 'inspect' },
    resource: { type: 'api' }, context: { application: 'todo-app' } });
  ids = ((r.json && r.json.results) || []).map(function (one) {
    return one.id;
  });
  t.check(r.status === 200 && ids.indexOf('sts-authzen-api') >= 0 &&
          ids.indexOf('azeval-front') < 0,
          'S4. the api type is the resource-server objects alone', brief(r));
  r = await request(port, 'POST', SEARCH + 'resource', pepCred, {
    subject: { type: 'user', id: 'azalice' }, action: { name: 'follow' },
    resource: { type: 'delegation' }, context: { application: 'todo-app' } });
  t.check(r.status === 200 && r.json.results.length === 1 &&
          r.json.results[0].id === 'azeval-front|azeval-back',
          'S5. the delegation type is each declared relationship, ' +
          '<source>|<target>', brief(r));
  r = await request(port, 'POST', SEARCH + 'action', pepCred, {
    subject: { type: 'user', id: 'azalice' },
    resource: { type: 'document', id: 'doc-1',
                properties: { classification: 'internal' } },
    context: { application: 'todo-app' } });
  const names = ((r.json && r.json.results) || []).map(function (one) {
    return one.name;
  });
  t.check(r.status === 200 && names.indexOf('read') >= 0 &&
          names.indexOf('write') >= 0 && names.indexOf('delete') < 0 &&
          names.indexOf('approve') < 0,
          'S6. Action Search answers the policy\'s actions the subject is ' +
          'permitted (read, write; not delete, nor approve whose ' +
          'obligation was not declared)', brief(r));
  since = marks.length;
  r = await request(port, 'POST', SEARCH + 'action', pepCred, {
    subject: { type: 'user', id: 'azalice' }, action: { name: 'read' },
    resource: { type: 'document', id: 'doc-1' },
    context: { application: 'todo-app' } });
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0009'),
          'S7. an Action Search carrying action is refused', brief(r));
  const paged = { subject: { type: 'user', id: 'azalice' },
                  action: { name: 'inspect' },
                  resource: { type: 'application' },
                  context: { application: 'todo-app' },
                  page: { limit: 1 } };
  const first = await request(port, 'POST', SEARCH + 'resource', pepCred,
                              paged);
  const pageToken = first.json && first.json.page &&
                    first.json.page.next_token;
  const second = await request(port, 'POST', SEARCH + 'resource', pepCred,
    Object.assign({}, paged, { page: { limit: 1, token: pageToken } }));
  t.check(first.status === 200 && first.json.results.length === 1 &&
          !!pageToken && second.status === 200 &&
          second.json.results.length === 1 &&
          second.json.results[0].id !== first.json.results[0].id &&
          first.json.page.total === second.json.page.total,
          'S8. page.limit pages, and next_token continues to the next page',
          brief(first) + ' / ' + brief(second));
  since = marks.length;
  r = await request(port, 'POST', SEARCH + 'resource', pepCred,
    Object.assign({}, paged, { action: { name: 'follow' },
                               page: { limit: 1, token: pageToken } }));
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0043'),
          'S9. a token continued with a changed request is refused ' +
          '(STS-AUTHZEN-0043)', brief(r));
  inRealm(function () {
    config.setOverride('authzen.searchMaxCandidates', 1);
  });
  r = await request(port, 'POST', SEARCH + 'resource', pepCred,
                    Object.assign({}, paged, { page: undefined }));
  inRealm(function () {
    config.setOverride('authzen.searchMaxCandidates', 1000);
    config.setOverride('authzen.searchEnabled', false);
  });
  t.check(r.status === 200 && r.json.context &&
          r.json.context.incomplete === true,
          'S10. past authzen.searchMaxCandidates the answer says it is ' +
          'incomplete', brief(r));
  since = marks.length;
  r = await request(port, 'POST', SEARCH + 'subject', pepCred, {
    subject: { type: 'user' }, action: { name: 'write' },
    resource: { type: 'document', id: 'doc-1' },
    context: { application: 'todo-app' } });
  inRealm(function () {
    config.setOverride('authzen.searchEnabled', true);
  });
  t.check(r.status === 501 && markedSince(since, 'STS-AUTHZEN-0044'),
          'S11. authzen.searchEnabled off answers 501', brief(r));

  // -------------------------------------------------------------------------
  // W. THE METADATA (#1163)
  // -------------------------------------------------------------------------
  const fromRoot = await request(port, 'GET',
    '/.well-known/authzen-configuration' + PREFIX, null);
  const appended = await request(port, 'GET',
    PREFIX + '/.well-known/authzen-configuration', null);
  const own = 'https://127.0.0.1:' + port + PREFIX;
  const doc = fromRoot.json || {};
  t.check(fromRoot.status === 200 && doc.policy_decision_point === own &&
          doc.access_evaluation_endpoint === own + '/access/v1/evaluation' &&
          /no-store/.test(String(fromRoot.headers['cache-control'])),
          'W1. the inserted form names the realm\'s PDP by the base it is ' +
          'fetched under (section 9.2.3)', brief(fromRoot));
  t.check(appended.status === 200 && appended.json &&
          appended.json.policy_decision_point === own,
          'W2. the appended form answers the same document', brief(appended));
  const advertised = Object.keys(doc).filter(function (key) {
    return /_endpoint$/.test(key);
  });
  t.check(Array.isArray(doc.supported_obligations) &&
          doc.supported_obligations.indexOf('step-up') >= 0,
          'W0. the metadata advertises supported_obligations (#1177)',
          JSON.stringify(doc));
  t.check(advertised.every(function (key) {
    return ['access_evaluation_endpoint', 'access_evaluations_endpoint',
            'search_subject_endpoint', 'search_resource_endpoint',
            'search_action_endpoint'].indexOf(key) >= 0;
  }) && advertised.length === 5 && !doc.capabilities,
          'W3. every implemented endpoint is advertised, the three searches ' +
          'among them, and no capabilities', JSON.stringify(doc));
  for (let i = 0; i < advertised.length; i += 1) {
    const at = String(doc[advertised[i]]).replace(/^https?:\/\/[^/]+/, '');
    const answered = await request(port, 'POST', at, null, {});
    t.check(answered.status !== 404 && answered.status !== 0,
            'W4. ' + advertised[i] + ' is a registered route (' + at + ')',
            brief(answered));
  }
  let signedClaims = null;
  try {
    signedClaims = inRealm(function () {
      return helpers.verifyOwnJws(String(doc.signed_metadata || ''));
    });
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.message) || e));
    signedClaims = null;
  }
  t.check(!!signedClaims && signedClaims.iss === own &&
          signedClaims.policy_decision_point === own &&
          signedClaims.access_evaluation_endpoint ===
            doc.access_evaluation_endpoint &&
          signedClaims.signed_metadata === undefined,
          'W7. signed_metadata verifies with the realm\'s key, iss is the ' +
          'PDP identifier, and its claims are the plain members (#1178)',
          JSON.stringify(signedClaims));
  inRealm(function () {
    config.setOverride('authzen.signedMetadata', false);
  });
  r = await request(port, 'GET', '/.well-known/authzen-configuration' +
                    PREFIX, null);
  inRealm(function () {
    config.setOverride('authzen.signedMetadata', true);
  });
  t.check(r.json && r.json.signed_metadata === undefined,
          'W8. authzen.signedMetadata off leaves it out', brief(r));
  r = await request(port, 'GET',
                    '/.well-known/authzen-configuration/realm/nowhere', null);
  t.check(r.status === 404, 'W5. a path naming no realm is a 404', brief(r));
  inRealm(function () {
    config.setOverride('authzen.enabled', false);
  });
  r = await request(port, 'GET', '/.well-known/authzen-configuration' +
                    PREFIX, null);
  inRealm(function () {
    config.setOverride('authzen.enabled', true);
  });
  t.check(r.status === 501, 'W6. with the API off the document answers ' +
          '501 rather than advertising an endpoint that does not', brief(r));

  // -------------------------------------------------------------------------
  // E. THE BATCH (#1164)
  // -------------------------------------------------------------------------
  const BATCH = PREFIX + '/access/v1/evaluations';
  const audit = require(ROOT + '/common/audit');
  const top = { subject: { type: 'user', id: 'azalice' },
                resource: { type: 'document', id: 'doc-1',
                            properties: { classification: 'internal' } },
                context: { application: 'todo-app' } };
  const items = function (names) {
    log.debug("Entering items().");
    log.debug("Leaving items().");
    return names.map(function (name) {
      return name === 'bad'
        ? { action: { name: 'read' },
            resource: { type: 'document', id: 'doc-2',
                        properties: { colour: 'red' } } }
        : { action: { name: name } };
    });
  };
  r = await request(port, 'POST', BATCH, pepCred,
    Object.assign({ evaluations: items(['read', 'delete', 'bad']) }, top),
    { 'x-request-id': 'az-batch-1' });
  const all = (r.json && r.json.evaluations) || [];
  t.check(r.status === 200 && all.length === 3 && all[0].decision === true &&
          all[1].decision === false && all[2].decision === false &&
          all[2].context && all[2].context.error &&
          all[2].context.error.status === 400 &&
          r.headers['x-request-id'] === 'az-batch-1',
          'E1. execute_all answers every item in order, an item\'s own ' +
          'failure in its context.error and never hidden by the 200',
          brief(r));
  const rows = inRealm(function () {
    return audit.list();
  }).filter(function (row) {
    return row && row.action === 'authzen.decision' &&
           /request az-batch-1#\d/.test(String(row.summary || ''));
  });
  t.check(rows.length === 2,
          'E2. each item decided is its own audit row carrying the batch id',
          rows.length + ' row(s)');
  r = await request(port, 'POST', BATCH, pepCred, Object.assign({
    evaluations: items(['read', 'delete', 'read']),
    options: { evaluations_semantic: 'deny_on_first_deny' } }, top));
  t.check(r.status === 200 && r.json && r.json.evaluations.length === 2 &&
          r.json.evaluations[1].decision === false,
          'E3. deny_on_first_deny stops at the first false', brief(r));
  r = await request(port, 'POST', BATCH, pepCred, Object.assign({
    evaluations: items(['delete', 'read', 'delete']),
    options: { evaluations_semantic: 'permit_on_first_permit' } }, top));
  t.check(r.status === 200 && r.json && r.json.evaluations.length === 2 &&
          r.json.evaluations[1].decision === true,
          'E4. permit_on_first_permit stops at the first true', brief(r));
  r = await request(port, 'POST', BATCH, pepCred,
                    Object.assign({ action: { name: 'read' } }, top));
  t.check(r.status === 200 && r.json && r.json.decision === true &&
          !r.json.evaluations,
          'E5. no evaluations is one evaluation, answered as the single ' +
          'endpoint answers it', brief(r));
  since = marks.length;
  r = await request(port, 'POST', BATCH, pepCred, Object.assign({
    evaluations: items(['read']),
    options: { evaluations_semantic: 'sometimes' } }, top));
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0036'),
          'E6. an unknown semantic is 400 (STS-AUTHZEN-0036)', brief(r));
  inRealm(function () {
    config.setOverride('authzen.maxEvaluations', 2);
  });
  since = marks.length;
  r = await request(port, 'POST', BATCH, pepCred, Object.assign({
    evaluations: items(['read', 'read', 'read']) }, top));
  inRealm(function () {
    config.setOverride('authzen.maxEvaluations', 64);
    config.setOverride('authzen.maxBodyBytes', 1024);
  });
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0038'),
          'E7. a batch over authzen.maxEvaluations is 400 for the whole ' +
          'batch (STS-AUTHZEN-0038)', brief(r));
  since = marks.length;
  const padded = items(['read']);
  r = await request(port, 'POST', BATCH, pepCred, Object.assign({}, top, {
    evaluations: padded, context: { application: 'todo-app',
                                    padding: 'x'.repeat(2048) } }));
  inRealm(function () {
    config.setOverride('authzen.maxBodyBytes', 262144);
  });
  t.check(r.status === 400 && markedSince(since, 'STS-AUTHZEN-0037'),
          'E8. a body over authzen.maxBodyBytes is 400 unread ' +
          '(STS-AUTHZEN-0037)', brief(r));
  r = await request(port, 'GET', '/.well-known/authzen-configuration' +
                    PREFIX, null);
  const withBatch = r.json || {};
  inRealm(function () {
    config.setOverride('authzen.batchEnabled', false);
  });
  since = marks.length;
  const off = await request(port, 'POST', BATCH, pepCred, Object.assign({
    evaluations: items(['read']) }, top));
  const without = await request(port, 'GET',
    '/.well-known/authzen-configuration' + PREFIX, null);
  inRealm(function () {
    config.setOverride('authzen.batchEnabled', true);
  });
  t.check(withBatch.access_evaluations_endpoint === own +
            '/access/v1/evaluations' &&
          off.status === 501 && markedSince(since, 'STS-AUTHZEN-0039') &&
          without.json && !without.json.access_evaluations_endpoint,
          'E9. the metadata names the batch endpoint while it is on, and ' +
          'with authzen.batchEnabled off the route answers 501 and the ' +
          'metadata leaves it out', JSON.stringify([withBatch, off.status,
                                                    without.json]));

  // -------------------------------------------------------------------------
  // O. OFF
  // -------------------------------------------------------------------------
  inRealm(function () {
    config.setOverride('authzen.enabled', false);
  });
  since = marks.length;
  r = await request(port, 'POST', URL, pepCred, asked());
  inRealm(function () {
    config.setOverride('authzen.enabled', true);
  });
  t.check(r.status === 501 && markedSince(since, 'STS-AUTHZEN-0013'),
          'O1. authzen.enabled off is 501 (STS-AUTHZEN-0013), the route ' +
          'still registered', brief(r));
  r = await request(port, 'POST', '/access/v1/evaluation', pepCred, asked());
  t.check(r.status === 401 || r.status === 403,
          'O2. the default realm\'s door is another realm\'s: azpep is ' +
          'nobody there', brief(r));

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
  t.log.info('=== POST /access/v1/evaluation (#563, #1161) ===');
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
  name: 'authzen_evaluation',
  describe: 'POST /access/v1/evaluation (#563): the certificate door, the ' +
            'AUTHZEN_PEPS policy, the application scope, the result ' +
            'mapping through a realm\'s root policy, the token door and the ' +
            'off switch, over real handshakes',
  run: run
};
