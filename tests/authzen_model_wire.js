// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authzen_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT THE AUTHZEN AUTHORIZATION API ANSWERS, HELD BYTE FOR BYTE (#1579
// item 6).
//
// The shapes of every AuthZEN request this service reads, of every answer
// and error it writes, and the metadata document's members come from
// `models/authzen/authzen.tsp` since #1579. Before the switch the readers
// were written by hand in `authzen/authzen_map.ts`, `authzen.ts`,
// `authzen_search.ts` and `authzen_access_request.ts`, and the switch was to
// change NOTHING a PEP sees: the model describes and validates the wire, it
// does not reshape it. So this records what the hand-written version
// answered, in `tests/authzen_model_wire.snapshot.json`, and holds every
// later build to it: a scripted conversation over real mutual-TLS
// handshakes — the metadata in both forms, a single evaluation's every
// success and refusal, the batch with each semantic and each bound, the
// three searches and their paging, and the Access Request and Approval
// Profile's submission, status, cancellation, re-evaluation and callback —
// in a development realm and a product realm, with each of the family's
// switches (`authzen.returnReasons`, `obligationsProfile`, `batchEnabled`,
// `searchEnabled`, `signedMetadata`, `accessRequests`, `tokenExchange`,
// `enabled`) turned the other way for the steps it changes.
//
// What is recorded of each answer: the status, every header but the ones
// that are about the connection, and the body — parsed when it is JSON. A
// JWT is DECODED, header and claims, and its signature dropped. The callback
// a finished access request sends is recorded too, as the outbound
// delivery's arguments.
//
// Values that differ from run to run are replaced by a placeholder: an
// instant, a port, a UUID, a key's material and id, a task's, an
// approval's and an evaluation's id, and any long random run. The comparison
// is of everything else, exactly.
//
// `AUTHZEN_WIRE_PRINT=1 node tests/authzen_model_wire.js` prints the
// snapshot instead of comparing it; that is how the file was written, from
// the image of the tree before the switch, and how it is rewritten when the
// wire is MEANT to change.
//
// A CHILD PROCESS, as tests/oauth_model_wire.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'authzen_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'authzen_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.AW_ROOT;
  const OUT = process.env.AW_OUT;
  const https = require('https');
  const nodeCrypto = require('crypto');
  const record = { wire: [], problems: [] };
  const ADVICE = 'urn:sts:xacml:advice:access-request';
  const CA = { pem: '' };

  const SKIPPED_HEADERS = ['date', 'connection', 'keep-alive',
                           'content-length', 'etag', 'transfer-encoding'];

  const POLICY = function (ns) {
    return [
      'namespace ' + ns + ' {',
      '    attribute act { category = actionCat',
      '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
      '        type = string }',
      '    attribute protocol { category = environmentCat',
      '        id = "urn:sts:xacml:protocol" type = string }',
      '    attribute classification { category = resourceCat',
      '        id = "urn:example:classification" type = string }',
      '    attribute tags { category = resourceCat id = "urn:example:tags"',
      '        type = string }',
      '    attribute rtype { category = resourceCat',
      '        id = "urn:sts:xacml:authzen:resource-type" type = string }',
      '    attribute approval { category = environmentCat',
      '        id = "urn:sts:xacml:authzen:approval-id" type = string }',
      '    policy ' + ns + 'Root {',
      '        id = "urn:test:' + ns + '-root"',
      '        apply firstApplicable',
      '        target clause protocol == "authzen"',
      '        rule approvedRead {',
      '            permit',
      '            target clause act == "read"',
      '            condition integerGreaterThan(stringBagSize(approval), 0)',
      '        }',
      '        rule readInternal {',
      '            permit',
      '            target clause act == "read"',
      '            target clause classification == "internal"',
      '        }',
      '        rule requestableRead {',
      '            deny',
      '            target clause act == "read"',
      '            on deny {',
      '                advice "' + ADVICE + '" {',
      '                    "' + ADVICE + ':approver-group" = "azwapprovers"',
      '                    "' + ADVICE + ':max-approval-seconds" = "3600"',
      '                    "' + ADVICE + ':emergency" = "true"',
      '                }',
      '            }',
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
  };

  function request(port, method, urlPath, cred, body, headers) {
    return new Promise(function (resolve) {
      const text = body === undefined ? ''
        : (typeof body === 'string' ? body : JSON.stringify(body));
      const sent = Object.assign({ 'content-type': 'application/json',
                                   'content-length': Buffer.byteLength(text) },
                                 headers || {});
      const req = https.request({ host: '127.0.0.1', port: port,
        path: urlPath, method: method, headers: sent, ca: CA.pem,
        cert: cred ? cred.certPem : undefined,
        key: cred ? cred.keyPem : undefined, agent: false },
      function (res) {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
          raw += chunk;
        });
        res.on('end', function () {
          let parsed = raw;
          if (/json/.test(String(res.headers['content-type'] || '')) && raw) {
            try {
              parsed = JSON.parse(raw);
            } catch (e) {
              parsed = { unparsed: raw };
            }
          }
          const kept = {};
          Object.keys(res.headers).sort().forEach(function (name) {
            if (SKIPPED_HEADERS.indexOf(name) < 0) {
              kept[name] = res.headers[name];
            }
          });
          resolve({ status: res.statusCode, headers: kept, body: parsed });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, headers: {}, body: String(e && e.message) });
      });
      req.end(text);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const keystore = require(ROOT + '/common/keystore');
    const pki = require(ROOT + '/common/pki');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const tls = require(ROOT + '/tls/tls_server');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const store = require(ROOT + '/xacml/xacml_store');
    const xml = require(ROOT + '/xacml/xacml_xml');
    const alfa = require(ROOT + '/xacml/xacml_alfa');
    const requests = require(ROOT + '/authzen/authzen_access_request');
    const authzenAdmin = require(ROOT + '/authzen/authzen_admin');
    const fedHttp = require(ROOT + '/federation/federation_http');
    const testCa = require(ROOT + '/tests/protocol/outbound_test_ca');
    const outsideCa = require(ROOT + '/tests/tools/pep-credential.js');

    // THE CALLBACK IS RECORDED, NOT SENT: its arguments are the wire.
    const delivered = [];
    fedHttp.deliverJson = function (target, attribute, payload, headers) {
      delivered.push({ attribute: attribute,
                       endpoint: target[attribute], payload: payload,
                       headers: headers });
      return Promise.resolve({ ok: true, status: 204 });
    };

    const MODES = [
      { name: 'development', id: 'azwire', product: false },
      { name: 'product', id: 'azwirep', product: true }
    ];
    await keystore.start();
    MODES.forEach(function (mode) {
      if (!realms.get(mode.id)) {
        const made = realms.create({ id: mode.id, name: mode.id,
                                     description: 'authzen_model_wire.js' });
        if (!made.ok) {
          record.problems.push(mode.name + ': ' + JSON.stringify(made));
        }
      }
    });
    await pki.start({ realmIds: [''].concat(MODES.map(function (m) {
      return m.id;
    })),
    keySetFor: function (id) {
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      return false;
    } });

    const mint = function (subject) {
      return outsideCa.mint({ subject: subject, crlBase: '' });
    };
    const creds = {};
    for (let m = 0; m < MODES.length; m++) {
      const id = MODES[m].id;
      creds[id] = { pep: await mint('CN=' + id + 'pep,O=Outside'),
                    other: await mint('CN=' + id + 'other,O=Outside'),
                    stray: await mint('CN=' + id + 'stray,O=Outside') };
    }
    const anchors = [];
    Object.keys(creds).forEach(function (id) {
      ['pep', 'other', 'stray'].forEach(function (k) {
        anchors.push(creds[id][k].anchorPem);
      });
    });
    tls.addAnchors(anchors.join(''));
    const derOf = function (minted) {
      return new nodeCrypto.X509Certificate(minted.leaf.pem).raw;
    };
    const group = String(config.value('roles.authzenPepGroup'));

    MODES.forEach(function (mode) {
      realms.run(realms.get(mode.id), function () {
        if (mode.product) {
          config.setOverride('global.mode', 'product');
        }
        ['azalice', 'azbob', 'azpep', 'azother'].forEach(function (name) {
          ldap.createUser(name, { invent: false });
        });
        ldap.changeStoredCertificate('person', 'azpep',
                                     { add: derOf(creds[mode.id].pep) });
        ldap.changeStoredCertificate('person', 'azother',
                                     { add: derOf(creds[mode.id].other) });
        adminActions.groupsAction({ action: 'add-member', group: group,
                                    member: 'azpep' });
        adminActions.groupsAction({ action: 'add-member', group: group,
                                    member: 'azother' });
        ldap.locateEntry('azpep').stored.attributes.stsauthzenapplication =
          ['todo-app'];
        ldap.locateEntry('azother').stored.attributes
          .stsauthzenapplication = ['todo-app', 'wiki'];
        ldap.createGroup('azwapprovers', { members: [] });
        adminActions.groupsAction({ action: 'add-member',
                                    group: 'azwapprovers', member: 'azbob' });
        [{ object: 'resource', property: 'classification',
           attributeId: 'urn:example:classification' },
         { object: 'resource', property: 'tags', multiplicity: 'bag',
           attributeId: 'urn:example:tags' },
         { object: 'resource', property: 'address.country',
           attributeId: 'urn:example:country' },
         { object: 'subject', property: 'level',
           dataType: 'http://www.w3.org/2001/XMLSchema#integer',
           attributeId: 'urn:example:level' },
         { object: 'context', property: 'ip',
           attributeId: 'urn:example:ip' }].forEach(function (row) {
          const done = applications.updateApplication('sts-authzen-api', {
            mode: 'add', attribute: 'authzenAttribute',
            value: JSON.stringify(row) });
          if (!done || !done.ok) {
            record.problems.push(mode.name + ': catalogue row ' +
                                 row.property + ': ' + JSON.stringify(done));
          }
        });
        store.write(mode.id + '-root',
                    xml.writePolicy(alfa.parse(POLICY(mode.id))),
                    { enabled: true, isRoot: true });
      });
    });

    const serverCa = await testCa.makeCa();
    const serverLeaf = await testCa.listenerCertificate(serverCa,
                                                        '127.0.0.1');
    CA.pem = serverCa.certPem;
    const listener = https.createServer(Object.assign({
      cert: serverLeaf.cert, key: serverLeaf.key,
      ca: tls.clientTruststoreOptions().ca,
      requestCert: true, rejectUnauthorized: false
    }, tls.protocolOptions()), app);
    tls.trustClientCertificatesOn(listener, 'the authzen_model_wire listener',
      function () {
        return { key: serverLeaf.key, cert: serverLeaf.cert };
      });
    await new Promise(function (ok) {
      listener.listen(0, '127.0.0.1', ok);
    });
    const port = listener.address().port;

    for (let m = 0; m < MODES.length; m++) {
      const mode = MODES[m];
      const P = '/realm/' + mode.id;
      const pep = creds[mode.id].pep;
      const other = creds[mode.id].other;
      const stray = creds[mode.id].stray;
      const inRealm = function (fn) {
        return realms.run(realms.get(mode.id), fn);
      };
      const set = function (key, value) {
        inRealm(function () {
          config.setOverride(key, value);
        });
      };
      const step = async function (name, method, p, cred, body, headers) {
        const r = await request(port, method, p, cred, body, headers);
        record.wire.push({ mode: mode.name, step: name, method: method,
                           path: p, status: r.status, headers: r.headers,
                           body: r.body });
        return r;
      };
      const EVAL = P + '/access/v1/evaluation';
      const BATCH = P + '/access/v1/evaluations';
      const SEARCH = P + '/access/v1/search/';
      const SUBMIT = P + '/access/v1/access-requests';
      const META = '/.well-known/authzen-configuration' + P;
      const ok = function (extra) {
        const out = {
          subject: { type: 'user', id: 'azalice' },
          action: { name: 'read' },
          resource: { type: 'document', id: 'doc-1',
                      properties: { classification: 'internal' } },
          context: { application: 'todo-app' }
        };
        Object.keys(extra || {}).forEach(function (key) {
          if (extra[key] === undefined) {
            delete out[key];
          } else {
            out[key] = extra[key];
          }
        });
        return out;
      };
      const pathOf = function (url) {
        return String(url || '').replace(/^https?:\/\/[^/]+/, '');
      };

      // --- THE METADATA -----------------------------------------------------
      await step('metadata inserted', 'GET', META, null);
      await step('metadata appended', 'GET',
                 P + '/.well-known/authzen-configuration', null);
      await step('metadata names no PDP', 'GET',
                 '/.well-known/authzen-configuration/realm', null);
      await step('metadata names no realm', 'GET',
                 '/.well-known/authzen-configuration/realm/azwire-none',
                 null);
      set('authzen.signedMetadata', false);
      set('authzen.obligationsProfile', false);
      set('authzen.batchEnabled', false);
      set('authzen.searchEnabled', false);
      set('authzen.accessRequests', false);
      await step('metadata, every switch off', 'GET', META, null);
      set('authzen.signedMetadata', true);
      set('authzen.obligationsProfile', true);
      set('authzen.batchEnabled', true);
      set('authzen.searchEnabled', true);
      set('authzen.accessRequests', true);
      set('authzen.tokenExchange', true);
      await step('metadata, token exchange on', 'GET', META, null);
      set('authzen.tokenExchange', false);

      // --- THE DOORS --------------------------------------------------------
      await step('no certificate', 'POST', EVAL, null, ok());
      await step('a certificate on no entry', 'POST', EVAL, stray, ok());
      await step('several applications, none named', 'POST', EVAL, other,
                 ok({ context: undefined }));
      await step('an application out of scope', 'POST', EVAL, pep,
                 ok({ context: { application: 'nope' } }));
      await step('the X-Request-ID echoed', 'POST', EVAL, pep, ok(),
                 { 'x-request-id': 'wire-req-1' });
      await step('an X-Request-ID not echoed', 'POST', EVAL, pep, ok(),
                 { 'x-request-id': 'has space' });

      // --- ONE EVALUATION ---------------------------------------------------
      await step('permit', 'POST', EVAL, pep, ok());
      await step('the one application implied', 'POST', EVAL, pep,
                 ok({ context: undefined }));
      await step('deny, no advice', 'POST', EVAL, pep,
                 ok({ action: { name: 'delete' } }));
      await step('not applicable', 'POST', EVAL, pep,
                 ok({ action: { name: 'paint' } }));
      await step('a requestable denial', 'POST', EVAL, pep,
                 ok({ resource: { type: 'document', id: 'doc-2' } }));
      await step('a fault', 'POST', EVAL, pep,
                 ok({ action: { name: 'explode' },
                      resource: { type: 'document', id: 'd',
                                  properties: { tags: ['x', 'y'] } } }));
      await step('a step-up obligation, undeclared', 'POST', EVAL, pep,
                 ok({ action: { name: 'approve' } }));
      await step('a step-up obligation, declared', 'POST', EVAL, pep,
                 ok({ action: { name: 'approve' },
                      context: { application: 'todo-app',
                                 supported_obligations: ['step-up'] } }));
      set('authzen.obligationsProfile', false);
      await step('a step-up obligation, profile off', 'POST', EVAL, pep,
                 ok({ action: { name: 'approve' },
                      context: { application: 'todo-app',
                                 supported_obligations: ['step-up'] } }));
      set('authzen.obligationsProfile', true);
      set('authzen.returnReasons', true);
      await step('reasons, permit', 'POST', EVAL, pep, ok());
      await step('reasons, deny', 'POST', EVAL, pep,
                 ok({ action: { name: 'delete' } }));
      set('authzen.returnReasons', false);
      await step('every catalogue row', 'POST', EVAL, pep,
                 ok({ subject: { type: 'user', id: 'azalice',
                                 properties: { level: '3' } },
                      resource: { type: 'document', id: 'doc-1',
                                  properties: { classification: 'internal',
                                                tags: [],
                                                address: { country: 'NZ' } } },
                      context: { application: 'todo-app',
                                 ip: '192.0.2.1' } }));

      // The shape refusals, in the order the reader meets them.
      const SHAPES = [
        ['not JSON', '{"subject":'],
        ['an array', '[1]'],
        ['null', 'null'],
        ['a string', '"x"'],
        ['a stray top member', ok({ extra: 1 })],
        ['a stray top member, long', ok({ ['m'.repeat(80)]: 1 })],
        ['no subject', ok({ subject: undefined })],
        ['no action', ok({ action: undefined })],
        ['no resource', ok({ resource: undefined })],
        ['subject an array', ok({ subject: [] })],
        ['subject a string', ok({ subject: 'x' })],
        ['subject null', ok({ subject: null })],
        ['a stray subject member', ok({ subject: { type: 'user',
                                                   id: 'a', name: 'x' } })],
        ['a stray action member', ok({ action: { name: 'read', id: 'x' } })],
        ['a stray resource member', ok({ resource: { type: 'd', id: 'x',
                                                     owner: 'y' } })],
        ['no subject.type', ok({ subject: { id: 'a' } })],
        ['no subject.id', ok({ subject: { type: 'user' } })],
        ['subject.type empty', ok({ subject: { type: '', id: 'a' } })],
        ['subject.type null', ok({ subject: { type: null, id: 'a' } })],
        ['subject.type a number', ok({ subject: { type: 7, id: 'a' } })],
        ['subject.id too long', ok({ subject: { type: 'user',
                                                id: 'i'.repeat(1025) } })],
        ['subject.id at the bound', ok({ subject: { type: 'user',
                                                    id: 'i'.repeat(1024) } })],
        ['no action.name', ok({ action: {} })],
        ['action.name a boolean', ok({ action: { name: true } })],
        ['resource.id an object', ok({ resource: { type: 'd',
                                                   id: { a: 1 } } })],
        ['subject.properties an array', ok({ subject: { type: 'user',
          id: 'a', properties: [] } })],
        ['action.properties a string', ok({ action: { name: 'read',
          properties: 'x' } })],
        ['resource.properties null', ok({ resource: { type: 'd', id: 'x',
          properties: null } })],
        ['subject bad, resource missing', ok({ subject: { type: 7, id: 'a' },
                                               resource: undefined })],
        ['context an array', ok({ context: [] })],
        ['context null', ok({ context: null })],
        ['supported_obligations a string', ok({ context: {
          application: 'todo-app', supported_obligations: 'step-up' } })],
        ['supported_obligations too many', ok({ context: {
          application: 'todo-app',
          supported_obligations: new Array(33).fill('a') } })],
        ['supported_obligations a long name', ok({ context: {
          application: 'todo-app',
          supported_obligations: ['o'.repeat(65)] } })],
        ['supported_obligations a number', ok({ context: {
          application: 'todo-app', supported_obligations: [1] } })],
        ['approval a string', ok({ context: { application: 'todo-app',
                                              approval: 'apr_x' } })],
        ['approval without id', ok({ context: { application: 'todo-app',
                                                approval: {} } })],
        ['approval id empty', ok({ context: { application: 'todo-app',
                                              approval: { id: '' } } })],
        ['approval id too long', ok({ context: { application: 'todo-app',
          approval: { id: 'a'.repeat(1025) } } })],
        ['application empty', ok({ context: { application: '' } })],
        ['application a number', ok({ context: { application: 5 } })],
        ['application too long', ok({ context: {
          application: 'a'.repeat(1025) } })],
        ['two bad context members', ok({ context: { application: 5,
          supported_obligations: 'x', approval: 'y' } })],
        ['an undeclared property', ok({ resource: { type: 'd', id: 'x',
          properties: { colour: 'red' } } })],
        ['an undeclared context member', ok({ context: {
          application: 'todo-app', colour: 'red' } })],
        ['a null value', ok({ resource: { type: 'd', id: 'x',
          properties: { classification: null } } })],
        ['a number for a string row', ok({ resource: { type: 'd', id: 'x',
          properties: { classification: 4 } } })],
        ['a fraction for an integer row', ok({ subject: { type: 'user',
          id: 'a', properties: { level: 1.5 } } })],
        ['an array for a single row', ok({ resource: { type: 'd', id: 'x',
          properties: { classification: ['a'] } } })],
        ['an object for a single row', ok({ resource: { type: 'd', id: 'x',
          properties: { classification: { a: 1 } } } })],
        ['an undeclared nested member', ok({ resource: { type: 'd', id: 'x',
          properties: { address: { city: 'W' } } } })],
        ['a binding context member', ok({ context: {
          application: 'todo-app', client_id: 'x' } })]
      ];
      for (let i = 0; i < SHAPES.length; i++) {
        await step('evaluation: ' + SHAPES[i][0], 'POST', EVAL, pep,
                   SHAPES[i][1]);
      }

      // --- THE BATCH --------------------------------------------------------
      const items = [
        { action: { name: 'read' } },
        { action: { name: 'delete' } },
        { action: { name: 'read' }, resource: { type: 'document',
          id: 'doc-3', properties: { classification: 'internal' } } },
        { action: { name: 'inspect' }, resource: { type: 'application',
                                                   id: 'x' } }
      ];
      const defaults = ok();
      await step('batch, execute_all by default', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: items }),
                 { 'x-request-id': 'wire-batch-1' });
      const SEMANTICS = ['execute_all', 'deny_on_first_deny',
                         'permit_on_first_permit'];
      for (let i = 0; i < SEMANTICS.length; i++) {
        await step('batch, ' + SEMANTICS[i], 'POST', BATCH, pep,
                   Object.assign({}, defaults, { evaluations: items.slice(1),
                     options: { evaluations_semantic: SEMANTICS[i] } }));
      }
      await step('batch, an item that fails', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: [
                   { action: { name: 'read' } }, 'x', { colour: 1 },
                   { subject: { type: 'user' } }, null, [] ],
                   options: { evaluations_semantic: 'execute_all' } }));
      await step('batch, an error is a deny', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: [ 'x',
                   { action: { name: 'read' } } ],
                   options: { evaluations_semantic: 'deny_on_first_deny' } }));
      await step('batch, no items', 'POST', BATCH, pep, defaults);
      await step('batch, empty items', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: [] }));
      await step('batch, no items and a refusal', 'POST', BATCH, pep,
                 { subject: { type: 'user', id: 'a' } });
      await step('batch, no items, reasons', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { action: { name: 'delete' } }));
      await step('batch, an unknown semantic', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: items,
                   options: { evaluations_semantic: 'first' } }));
      await step('batch, a numeric semantic', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: items,
                   options: { evaluations_semantic: 1 } }));
      await step('batch, other options', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: items.slice(0, 1),
                   options: { colour: 'red' } }));
      await step('batch, evaluations an object', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: {} }));
      await step('batch, options an array', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { options: [] }));
      await step('batch, options null', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { options: null }));
      await step('batch, a stray member', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { items: [] }));
      await step('batch, an array', 'POST', BATCH, pep, '[]');
      await step('batch, not JSON', 'POST', BATCH, pep, '{');
      set('authzen.maxEvaluations', 2);
      await step('batch, too many', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: items }));
      set('authzen.maxEvaluations', 64);
      set('authzen.maxBodyBytes', 1024);
      await step('batch, too large', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: items,
                   pad: 'p'.repeat(2000) }));
      set('authzen.maxBodyBytes', 1048576);
      set('authzen.batchEnabled', false);
      await step('batch, off', 'POST', BATCH, pep,
                 Object.assign({}, defaults, { evaluations: items }));
      set('authzen.batchEnabled', true);

      // --- THE SEARCHES -----------------------------------------------------
      inRealm(function () {
        ['wire-app-a', 'wire-app-b', 'wire-app-c'].forEach(function (id) {
          applications.createApplication({ identifier: id,
            protocols: ['oauth2'],
            fields: { oauthClientId: id,
                      oauthRedirectUri: ['https://rp.example/cb'] } });
        });
      });
      const searchBase = {
        subject: { type: 'user', id: 'azalice' },
        action: { name: 'inspect' },
        resource: { type: 'application' },
        context: { application: 'todo-app' }
      };
      let r = await step('search resource', 'POST', SEARCH + 'resource', pep,
                         Object.assign({}, searchBase, { page: { limit: 2 } }));
      const token = r.body && r.body.page ? r.body.page.next_token : '';
      await step('search resource, next page', 'POST', SEARCH + 'resource',
                 pep, Object.assign({}, searchBase,
                   { page: { limit: 2, token: token } }));
      await step('search resource, a changed request', 'POST',
                 SEARCH + 'resource', pep, Object.assign({}, searchBase,
                   { page: { limit: 3, token: token } }));
      await step('search resource, a foreign token', 'POST',
                 SEARCH + 'resource', pep, Object.assign({}, searchBase,
                   { page: { token: '5.abc' } }));
      await step('search resource, an unknown type', 'POST',
                 SEARCH + 'resource', pep, Object.assign({}, searchBase,
                   { resource: { type: 'widget' } }));
      await step('search resource, no type', 'POST', SEARCH + 'resource',
                 pep, Object.assign({}, searchBase, { resource: {} }));
      await step('search subject', 'POST', SEARCH + 'subject', pep,
                 { subject: { type: 'user' }, action: { name: 'read' },
                   resource: { type: 'document', id: 'doc-1',
                     properties: { classification: 'internal' } },
                   context: { application: 'todo-app' } });
      await step('search subject, no subject', 'POST', SEARCH + 'subject',
                 pep, { action: { name: 'read' },
                        resource: { type: 'document', id: 'doc-1' } });
      await step('search action', 'POST', SEARCH + 'action', pep,
                 { subject: { type: 'user', id: 'azalice' },
                   resource: { type: 'application', id: 'wire-app-a' },
                   context: { application: 'todo-app' } });
      await step('search action, an action sent', 'POST', SEARCH + 'action',
                 pep, searchBase);
      const PAGES = [
        ['page a string', 'x'],
        ['page a stray member', { size: 1 }],
        ['page limit negative', { limit: -1 }],
        ['page limit a fraction', { limit: 1.5 }],
        ['page token a number', { token: 5 }],
        ['page properties an array', { properties: [] }]
      ];
      for (let i = 0; i < PAGES.length; i++) {
        await step('search: ' + PAGES[i][0], 'POST', SEARCH + 'resource',
                   pep, Object.assign({}, searchBase, { page: PAGES[i][1] }));
      }
      await step('search, not an object', 'POST', SEARCH + 'resource', pep,
                 '[]');
      await step('search, a stray member', 'POST', SEARCH + 'resource', pep,
                 Object.assign({}, searchBase, { colour: 1 }));
      set('authzen.searchMaxCandidates', 1);
      await step('search, truncated', 'POST', SEARCH + 'resource', pep,
                 searchBase);
      set('authzen.searchMaxCandidates', 1000);
      set('authzen.searchEnabled', false);
      await step('search, off', 'POST', SEARCH + 'subject', pep, searchBase);
      set('authzen.searchEnabled', true);

      // --- ACCESS REQUESTS --------------------------------------------------
      const fresh = async function (name) {
        const got = await step(name || 'a fresh requestable denial', 'POST',
          EVAL, pep, ok({ resource: { type: 'document', id: 'doc-2' } }));
        return got.body;
      };
      const submission = function (denied, extra) {
        const ar = (denied && denied.context &&
                    denied.context.access_request) || {};
        const out = {
          subject: { type: 'user', id: 'azalice' },
          action: { name: 'read' },
          resource: { type: 'document', id: 'doc-2' },
          context: { application: 'todo-app' },
          denial: { expires_at: ar.expires_at,
                    binding_token: ar.binding_token,
                    evaluation_id: denied && denied.context
                      ? denied.context.evaluation_id : undefined,
                    reason: denied && denied.context
                      ? denied.context.reason : undefined }
        };
        Object.keys(extra || {}).forEach(function (key) {
          if (extra[key] === undefined) {
            delete out[key];
          } else {
            out[key] = extra[key];
          }
        });
        return out;
      };
      const denied = await fresh();
      const SUBMISSIONS = [
        ['not an object', '[]'],
        ['not JSON', '{'],
        ['bulk', { items: [] }],
        ['a stray member', submission(denied, { colour: 1 })],
        ['no subject', submission(denied, { subject: undefined })],
        ['resource a string', submission(denied, { resource: 'x' })],
        ['no denial', submission(denied, { denial: undefined })],
        ['denial a string', submission(denied, { denial: 'x' })],
        ['an evaluation_id alone', submission(denied, { denial: {
          evaluation_id: denied.context.evaluation_id } })],
        ['a binding token that does not verify', submission(denied, {
          denial: { binding_token: 'a.b.c',
                    expires_at: denied.context.access_request.expires_at } })],
        ['expires_at changed', submission(denied, { denial: {
          binding_token: denied.context.access_request.binding_token,
          expires_at: '2099-01-01T00:00:00Z' } })],
        ['another resource', submission(denied, { resource: {
          type: 'document', id: 'doc-9' } })],
        ['requested_access a string', submission(denied, {
          requested_access: 'x' })],
        ['requested_until past', submission(denied, { requested_access: {
          requested_until: '2001-01-01T00:00:00Z' } })],
        ['requested_until a number', submission(denied, {
          requested_access: { requested_until: 5 } })],
        ['emergency unjustified', submission(denied, { requested_access: {
          emergency: true } })],
        ['callback a string', submission(denied, { callback: 'x' })],
        ['callback unregistered', submission(denied, { callback: {
          endpoint: 'https://pep.example.com/cb' } })]
      ];
      for (let i = 0; i < SUBMISSIONS.length; i++) {
        await step('submission: ' + SUBMISSIONS[i][0], 'POST', SUBMIT, pep,
                   SUBMISSIONS[i][1]);
      }
      const CALLBACK = 'https://127.0.0.1:9/azwire-callback';
      inRealm(function () {
        authzenAdmin.act({ action: 'set-callbacks', caller: 'azpep',
                           callbacks: CALLBACK },
                         { actor: 'azbob', via: 'api' });
      });
      r = await step('submission: callback events a string', 'POST', SUBMIT,
                     pep, submission(denied, { callback: {
                       endpoint: CALLBACK, events: 'approved' } }));
      r = await step('submission accepted', 'POST', SUBMIT, pep,
                     submission(denied, { callback: { endpoint: CALLBACK,
                       state: 's-1', events: ['approved', 'cancelled',
                                              'nonsense'] } }),
                     { 'idempotency-key': 'wire-key-1' });
      const task = (r.body && r.body.task) || {};
      await step('submission again', 'POST', SUBMIT, pep, submission(denied, {
        callback: { endpoint: CALLBACK, state: 's-1',
                    events: ['approved', 'cancelled', 'nonsense'] } }),
                 { 'idempotency-key': 'wire-key-1' });
      await step('submission, the key reused', 'POST', SUBMIT, pep,
                 submission(denied), { 'idempotency-key': 'wire-key-1' });
      await step('status, pending', 'GET', pathOf(task.status_endpoint), pep);
      await step('status, another caller', 'GET',
                 pathOf(task.status_endpoint), other);
      await step('status, unknown', 'GET', SUBMIT + '/arq_none', pep);
      inRealm(function () {
        requests.decide(task.id, 'approve',
                        { username: 'azbob', door: 'portal' });
      });
      r = await step('status, approved', 'GET', pathOf(task.status_endpoint),
                     pep);
      const approval = (r.body && r.body.result &&
                        r.body.result.approval) || {};
      await step('re-evaluation with the approval', 'POST', EVAL, pep,
                 ok({ resource: { type: 'document', id: 'doc-2' },
                      context: { application: 'todo-app',
                                 approval: approval } }));
      await step('re-evaluation, out of scope', 'POST', EVAL, pep,
                 ok({ resource: { type: 'document', id: 'doc-9' },
                      context: { application: 'todo-app',
                                 approval: approval } }));
      await step('re-evaluation, a forged approval', 'POST', EVAL, pep,
                 ok({ resource: { type: 'document', id: 'doc-2' },
                      context: { application: 'todo-app',
                                 approval: { id: 'apr_forged' } } }));
      await step('cancel, finished', 'POST',
                 pathOf(task.status_endpoint) + '/cancel', pep, {});
      r = await step('a second submission', 'POST', SUBMIT, pep,
                     submission(await fresh('another requestable denial')));
      const second = (r.body && r.body.task) || {};
      await step('cancel (DELETE)', 'DELETE',
                 pathOf(second.status_endpoint) + '/cancel', pep);
      await step('status, cancelled', 'GET', pathOf(second.status_endpoint),
                 pep);
      await step('emergency, justified', 'POST', SUBMIT, pep,
                 submission(await fresh('a third requestable denial'), {
                   requested_access: { emergency: true },
                   context: { application: 'todo-app',
                              business_justification: 'on call' } }));
      // The callback the approval sent, as delivered.
      await new Promise(function (ok2) {
        setTimeout(ok2, 50);
      });
      delivered.splice(0).forEach(function (one) {
        record.wire.push({ mode: mode.name, step: 'the callback',
                           method: 'DELIVER', path: one.endpoint,
                           status: 0, headers: one.headers,
                           body: { attribute: one.attribute,
                                   payload: one.payload } });
      });
      set('authzen.accessRequests', false);
      await step('submission, off', 'POST', SUBMIT, pep, {});
      await step('status, off', 'GET', SUBMIT + '/arq_none', pep);
      await step('a denial while off', 'POST', EVAL, pep,
                 ok({ resource: { type: 'document', id: 'doc-2' } }));
      set('authzen.accessRequests', true);

      // --- THE TOKEN-EXCHANGE BINDING --------------------------------------
      set('authzen.tokenExchange', true);
      await step('a binding gate tuple', 'POST', EVAL, pep, {
        subject: { type: 'user', id: 'azalice' },
        action: { name: 'issue:access_token:token_exchange' },
        resource: { type: 'audience', id: 'https://api.wire.example' },
        context: { application: 'todo-app', client_id: 'nobody' } });
      await step('a binding member of the wrong type', 'POST', EVAL, pep, {
        subject: { type: 'user', id: 'azalice' },
        action: { name: 'issue:access_token:token_exchange' },
        resource: { type: 'audience', id: 'https://api.wire.example' },
        context: { application: 'todo-app', client_id: 5 } });
      set('authzen.tokenExchange', false);

      // --- OFF --------------------------------------------------------------
      set('authzen.enabled', false);
      await step('evaluation, off', 'POST', EVAL, pep, ok());
      await step('metadata, off', 'GET', META, null);
      set('authzen.enabled', true);
    }

    listener.close();
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push(String(e && e.stack));
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// The member names whose values this service draws at random, or that carry
// key material, each replaced by its name. A JWT among them is decoded
// rather than replaced.
const VOLATILE_MEMBERS = ['jti', 'kid', 'n', 'e', 'x', 'y', 'x5c', 'x5t',
  'x5t#S256', 'iat', 'exp', 'nbf', 'next_token'];

const JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;

// A compact JWS, decoded: its header and claims, its signature dropped.
function decodeJwt(text) {
  log.debug("Entering decodeJwt().");
  const parts = text.split('.');
  try {
    const out = { jwt: {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')),
      claims: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')),
      signed: parts[2].length > 0 } };
    log.debug("Leaving decodeJwt().");
    return out;
  } catch (e) {
    log.debug("Caught in decodeJwt(): " + ((e && e.message) || e));
    log.debug("Leaving decodeJwt(). Not a JWT.");
    return text;
  }
}

// Walks a value: a JWT anywhere is decoded, and a volatile member's value is
// replaced by its name.
function scrub(value, name) {
  log.debug("Entering scrub().");
  if (Array.isArray(value)) {
    const list = value.map(function (one) {
      return scrub(one, name);
    });
    log.debug("Leaving scrub().");
    return list;
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = scrub(value[key], key);
    });
    log.debug("Leaving scrub().");
    return out;
  }
  if (typeof value === 'string' && JWT.test(value)) {
    const decoded = decodeJwt(value);
    if (decoded !== value) {
      log.debug("Leaving scrub(). A JWT.");
      return scrub(decoded, name);
    }
  }
  if (typeof value === 'number' && value >= 1.7e9 && value < 2.2e9) {
    log.debug("Leaving scrub(). An instant.");
    return '<epoch>';
  }
  if (name && VOLATILE_MEMBERS.indexOf(name) >= 0 && value !== undefined &&
      value !== null && value !== '') {
    log.debug("Leaving scrub(). A volatile member.");
    return '<' + name + '>';
  }
  log.debug("Leaving scrub().");
  return value;
}

// The run-to-run values, each replaced by a placeholder, so that two runs
// of one tree record the same text.
function normalise(record) {
  log.debug("Entering normalise().");
  const PATTERNS = [
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    // A task's, an approval's and an evaluation's id.
    ['arq', /\barq_[A-Za-z0-9_-]+/g],
    ['apr', /\bapr_(?!forged)[A-Za-z0-9_-]+/g],
    ['eval', /\beval_[A-Za-z0-9_-]+/g],
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{32,}/g]
  ];
  const text = JSON.stringify(scrub(record), null, 1);
  let out = text;
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], '<' + pair[0] + '>');
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'authzen-model-wire-' + process.pid +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', AW_ROOT: ROOT, AW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024
    });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return normalise(record);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + '.' + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ': ' + JSON.stringify(b).slice(0, 300) + ' where ' +
    JSON.stringify(a).slice(0, 300) + ' was recorded';
}

function run(t) {
  log.debug("Entering run().");
  const now = capture();
  if (!t.check(!!now, 'the child process reported')) {
    log.debug("Leaving run().");
    return;
  }
  t.check(now.problems.length === 0, 'the child ran to the end',
          now.problems.join('\n'));
  let recorded = null;
  try {
    recorded = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    recorded = null;
  }
  if (!t.check(!!recorded, 'the recorded wire is in the tree', SNAPSHOT)) {
    log.debug("Leaving run().");
    return;
  }
  t.check(recorded.wire.length === now.wire.length,
          'the conversation has as many steps as recorded',
          now.wire.length + ' vs ' + recorded.wire.length);
  recorded.wire.forEach(function (one, i) {
    t.check(firstDifference(one, now.wire[i], 'wire') === null,
            one.mode + ', ' + one.step + ': ' + one.method +
            ' answers as recorded (' + one.status + ')',
            firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.AUTHZEN_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'authzen_model_wire',
  describe: 'what the AuthZEN Authorization API answers, byte for byte, ' +
            'against the record made before its request and answer shapes ' +
            'came from the model (#1579): the metadata, the evaluation, the ' +
            'batch, the searches and the access requests, every success ' +
            'and refusal, in development and product realms and with each ' +
            'switch turned',
  run: run
};
