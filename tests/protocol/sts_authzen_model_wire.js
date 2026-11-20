// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authzen_model_wire.js
//
// ===========================================================================
// WHAT THE AUTHZEN AUTHORIZATION API ANSWERS, HELD TO THE RECORDED WIRE,
// OVER THE WIRE (#1579 item 6; #444 D12, phase 8).
//
// `tests/authzen_model_wire.js` holds every answer of a scripted
// conversation over mutual-TLS handshakes — the metadata in both forms, a
// single evaluation's successes and refusals, the batch with each semantic
// and bound, the three searches and their paging, the Access Request and
// Approval Profile's submission, status, cancellation and re-evaluation,
// the token-exchange binding and the family switched off — to
// `tests/authzen_model_wire.snapshot.json`, from a child process with its
// own listener, in the realms `azwire` (development) and `azwirep`
// (product). This job has the same conversation, step for step, with a
// RUNNING service on its main port, in two realms of this run's own whose
// entries, certificates, catalogue rows, scopes and root policy are
// written through `/admin-api` (the in-process file wrote the directory),
// and holds every answer to the snapshot after putting back what only the
// place of the conversation changes:
//
//   * the realms: this run's ids are the recorded `azwire` and `azwirep`;
//   * the realms' domains: `<id>.example.net` (and its DN) are the
//     recorded `<id>.example.com`;
//   * the origin: `https://localhost:<port>` is the recorded
//     `https://127.0.0.1:<port>`;
//   * taken off both sides (`placeless()`): the subject search's people
//     other than the conversation's own `az*` (the realm's seeded ones), and
//     the signed metadata's `x5u` — seen absent on a realm's first metadata
//     request and present later, in the record and over the wire alike.
//
// The in-process file's placeholders (`VOLATILE_MEMBERS`, the JWT decoding,
// `scrub()`, `normalise()`) are its own, copied unchanged.
//
// (d), with the reason: the two `the callback` steps are the outbound
// delivery's ARGUMENTS, recorded in process by stubbing
// `federation_http.deliverJson`; over the wire the callback is dialled
// (to the recorded unreachable `https://127.0.0.1:9`), and what a listener
// would receive is a different record. The approval is made through
// `/admin-api/xacml/authzen/approve-access-request` where the in-process
// file called `decide()` as azbob at the portal's door.
//
// OWNED HERE (local: true). Posts six outside test Roots to the client
// truststore and removes them. Its realms are removed only on a private
// probe.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const https = require("https");
const path = require("path");
const K = require("./oauth_wire_kit.js").kit("sts_authzen_model_wire");
const credentials = require("../tools/pep-credential.js");
const serviceTrust = require("../tools/service_trust.js");

const log = K.log;
const SNAPSHOT = process.env.AUTHZEN_WIRE_SNAPSHOT ||
  path.join(__dirname, "..", "authzen_model_wire.snapshot.json");
const ADVICE = "urn:sts:xacml:advice:access-request";
const SKIPPED_HEADERS = ["date", "connection", "keep-alive",
                         "content-length", "etag", "transfer-encoding"];
const added = [];
const stored = [];
const REALMS = {};

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

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return K.send(url).then(function (r) {
    return { status: r.status, body: r.json, text: r.text };
  });
}

function post(url, payload) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return K.send(url, { json: payload || {} }).then(function (r) {
    return { status: r.status, body: r.json, text: r.text };
  });
}

// One request as the in-process file's `request()` makes it, on the main
// port: `{ status, headers (kept), body }`.
function request(method, urlPath, cred, body, headers) {
  log.debug("Entering request(). " + method + " " + urlPath);
  return new Promise(function (resolve) {
    const target = new URL(K.base);
    const text = body === undefined ? ""
      : (typeof body === "string" ? body : JSON.stringify(body));
    const sent = Object.assign({ "content-type": "application/json",
                                 "content-length": Buffer.byteLength(text) },
                               headers || {});
    const req = https.request({ host: target.hostname,
      port: target.port || 443, path: urlPath, method: method,
      headers: sent, ca: serviceTrust.trustedCa(),
      cert: cred ? cred.certPem : undefined,
      key: cred ? cred.keyPem : undefined, agent: false },
    function (res) {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        raw += chunk;
      });
      res.on("end", function () {
        let parsedBody = raw;
        if (/json/.test(String(res.headers["content-type"] || "")) && raw) {
          try {
            parsedBody = JSON.parse(raw);
          } catch (e) {
            log.debug("Caught in request(): " + ((e && e.message) || e));
            // Recorded as the in-process file records it.
            parsedBody = { unparsed: raw };
          }
        }
        const kept = {};
        Object.keys(res.headers).sort().forEach(function (name) {
          if (SKIPPED_HEADERS.indexOf(name) < 0) {
            kept[name] = res.headers[name];
          }
        });
        log.debug("Leaving request(). " + res.statusCode);
        resolve({ status: res.statusCode, headers: kept, body: parsedBody });
      });
    });
    req.on("error", function (e) {
      log.debug("Caught in request(): " + ((e && e.message) || e));
      // Recorded as the in-process file records a failed request.
      resolve({ status: 0, headers: {}, body: String(e && e.message) });
    });
    req.end(text);
  });
}

// A realm of this run's own, set up as the in-process file set up
// `recorded`: its people, certificates, scopes, approvers, catalogue rows
// and root policy, through /admin-api.
async function setUp(mode, recorded) {
  log.debug("Entering setUp(). " + mode.name);
  const id = await K.realm(recorded, mode.name);
  REALMS[recorded] = id;
  const prefix = "/realm/" + id;
  const realm = { id: id, prefix: prefix,
                  api: function (p) {
                    return K.base + prefix + "/admin-api" + p;
                  } };
  for (const name of ["azalice", "azbob", "azpep", "azother"]) {
    await K.ok(realm.api("/users/create"), { username: name, invent: false,
      attributes: { cn: name, sn: name, givenName: name,
                    mail: name + "@azwire.test" } }, "created " + name);
  }
  realm.creds = {};
  for (const k of ["pep", "other", "stray"]) {
    realm.creds[k] = await credentials.mint({ subject: "CN=" + recorded +
                                              k + ",O=Outside" });
    const posted = await credentials.trustRecorded(K.base,
      realm.creds[k].anchorPem, added);
    assert.ok(posted.ok, "the truststore took the test Root: " +
              posted.status);
  }
  const io = { get: get, post: post };
  stored.push(await credentials.storeOnEntry(io, K.base, prefix, "azpep",
                                             realm.creds.pep.leaf.pem));
  stored.push(await credentials.storeOnEntry(io, K.base, prefix, "azother",
                                             realm.creds.other.leaf.pem));
  for (const member of ["azpep", "azother"]) {
    await K.ok(realm.api("/groups/add-member"), { group: "authzen-peps",
      member: member }, member + " in authzen-peps");
  }
  await K.ok(realm.api("/xacml/authzen/set-scope"), { caller: "azpep",
    applications: ["todo-app"] }, "azpep's scope");
  await K.ok(realm.api("/xacml/authzen/set-scope"), { caller: "azother",
    applications: ["todo-app", "wiki"] }, "azother's scope");
  await K.ok(realm.api("/groups/create"), { group: "azwapprovers",
    members: ["azbob"] }, "the approvers");
  for (const row of [
    { object: "resource", property: "classification",
      attributeId: "urn:example:classification" },
    { object: "resource", property: "tags", multiplicity: "bag",
      attributeId: "urn:example:tags" },
    { object: "resource", property: "address.country",
      attributeId: "urn:example:country" },
    { object: "subject", property: "level",
      dataType: "http://www.w3.org/2001/XMLSchema#integer",
      attributeId: "urn:example:level" },
    { object: "context", property: "ip",
      attributeId: "urn:example:ip" }]) {
    await K.ok(realm.api("/xacml/authzen/set-attribute"), row,
               "the catalogue row " + row.property);
  }
  await K.ok(realm.api("/xacml/import-alfa"), { name: recorded + "-root",
    alfa: POLICY(recorded) }, "the root policy");
  log.debug("Leaving setUp().");
  return realm;
}

async function conversation(mode, realm) {
  log.debug("Entering conversation(). " + mode.name);
  const wire = [];
  const P = realm.prefix;
  const pep = realm.creds.pep;
  const other = realm.creds.other;
  const stray = realm.creds.stray;
  const set = function (key, value) {
    return K.set(realm.id, key, value);
  };
  const step = async function (name, method, p, cred, body, headers) {
    const r = await request(method, p, cred, body, headers);
    wire.push({ mode: mode.name, step: name, method: method, path: p,
                status: r.status, headers: r.headers, body: r.body });
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
  await set('authzen.signedMetadata', false);
  await set('authzen.obligationsProfile', false);
  await set('authzen.batchEnabled', false);
  await set('authzen.searchEnabled', false);
  await set('authzen.accessRequests', false);
  await step('metadata, every switch off', 'GET', META, null);
  await set('authzen.signedMetadata', true);
  await set('authzen.obligationsProfile', true);
  await set('authzen.batchEnabled', true);
  await set('authzen.searchEnabled', true);
  await set('authzen.accessRequests', true);
  await set('authzen.tokenExchange', true);
  await step('metadata, token exchange on', 'GET', META, null);
  await set('authzen.tokenExchange', false);

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
  await set('authzen.obligationsProfile', false);
  await step('a step-up obligation, profile off', 'POST', EVAL, pep,
             ok({ action: { name: 'approve' },
                  context: { application: 'todo-app',
                             supported_obligations: ['step-up'] } }));
  await set('authzen.obligationsProfile', true);
  await set('authzen.returnReasons', true);
  await step('reasons, permit', 'POST', EVAL, pep, ok());
  await step('reasons, deny', 'POST', EVAL, pep,
             ok({ action: { name: 'delete' } }));
  await set('authzen.returnReasons', false);
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
  await set('authzen.maxEvaluations', 2);
  await step('batch, too many', 'POST', BATCH, pep,
             Object.assign({}, defaults, { evaluations: items }));
  await set('authzen.maxEvaluations', 64);
  await set('authzen.maxBodyBytes', 1024);
  await step('batch, too large', 'POST', BATCH, pep,
             Object.assign({}, defaults, { evaluations: items,
               pad: 'p'.repeat(2000) }));
  await set('authzen.maxBodyBytes', 1048576);
  await set('authzen.batchEnabled', false);
  await step('batch, off', 'POST', BATCH, pep,
             Object.assign({}, defaults, { evaluations: items }));
  await set('authzen.batchEnabled', true);

  // --- THE SEARCHES -----------------------------------------------------
  for (const id of ['wire-app-a', 'wire-app-b', 'wire-app-c']) {
    await K.app(realm.id, id, { oauthClientId: [id],
      oauthRedirectUri: ['https://rp.example/cb'] },
      { protocols: ['oauth2'] });
  }
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
  // Ignored since #936 (AuthZEN 1.0 sections 8.6.1 and 10.1.1): the
  // answer is the one above.
  await step('search action, an action sent', 'POST', SEARCH + 'action',
             pep, { subject: { type: 'user', id: 'azalice' },
                    action: { name: 'read' },
                    resource: { type: 'application', id: 'wire-app-a' },
                    context: { application: 'todo-app' } });
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
  await set('authzen.searchMaxCandidates', 1);
  await step('search, truncated', 'POST', SEARCH + 'resource', pep,
             searchBase);
  await set('authzen.searchMaxCandidates', 1000);
  await set('authzen.searchEnabled', false);
  await step('search, off', 'POST', SEARCH + 'subject', pep, searchBase);
  await set('authzen.searchEnabled', true);

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
    // Ignored since #936 (AuthZEN 1.0 section 10.1.1), so the refusal
    // is the missing denial's: a stray member alone would be accepted
    // and spend the denial the steps below submit.
    ['a stray member beside no denial', submission(denied, {
      colour: 1, denial: undefined })],
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
  await K.ok(realm.api('/xacml/authzen/set-callbacks'), {
    caller: 'azpep', callbacks: CALLBACK }, 'registered the callback');
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
  await K.ok(realm.api('/xacml/authzen/approve-access-request'),
             { request: task.id }, 'approved the access request');
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
  // The callback the approval sent is the outbound delivery's ARGUMENTS
  // in process (its `deliverJson` stubbed), and is left out here: see the
  // header.
  await set('authzen.accessRequests', false);
  await step('submission, off', 'POST', SUBMIT, pep, {});
  await step('status, off', 'GET', SUBMIT + '/arq_none', pep);
  await step('a denial while off', 'POST', EVAL, pep,
             ok({ resource: { type: 'document', id: 'doc-2' } }));
  await set('authzen.accessRequests', true);

  // --- THE TOKEN-EXCHANGE BINDING --------------------------------------
  await set('authzen.tokenExchange', true);
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
  await set('authzen.tokenExchange', false);

  // --- OFF --------------------------------------------------------------
  await set('authzen.enabled', false);
  await step('evaluation, off', 'POST', EVAL, pep, ok());
  await step('metadata, off', 'GET', META, null);
  log.debug("Leaving conversation(). " + wire.length);
  return wire;
}

// WHAT ONLY THE PLACE CHANGES, put back before the placeholders.
function placed(one) {
  log.debug("Entering placed().");
  // A JWT is decoded first (as `scrub()` would), so the place inside its
  // header and claims is put back too.
  const decodedAll = function (value) {
    if (Array.isArray(value)) {
      return value.map(decodedAll);
    }
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value).forEach(function (key) {
        out[key] = decodedAll(value[key]);
      });
      return out;
    }
    if (typeof value === "string" && JWT.test(value)) {
      const decoded = decodeJwt(value);
      return decoded === value ? value : decodedAll(decoded);
    }
    return value;
  };
  let text = JSON.stringify(decodedAll(one));
  const origin = new URL(K.base);
  const swaps = [[K.base, "https://127.0.0.1:1"],
    [encodeURIComponent(K.base), encodeURIComponent("https://127.0.0.1:1")],
    [origin.host, "127.0.0.1:1"]];
  Object.keys(REALMS).sort(function (a, b) {
    return REALMS[b].length - REALMS[a].length;
  }).forEach(function (recorded) {
    swaps.push(["dc=" + REALMS[recorded] + ",dc=example,dc=net",
                "dc=" + recorded + ",dc=example,dc=com"]);
    swaps.push([REALMS[recorded] + ".example.net",
                recorded + ".example.com"]);
    swaps.push([REALMS[recorded], recorded]);
  });
  swaps.forEach(function (pair) {
    text = text.split(JSON.stringify(pair[0]).slice(1, -1))
      .join(JSON.stringify(pair[1]).slice(1, -1));
  });
  log.debug("Leaving placed().");
  return JSON.parse(text);
}

// WHAT BOTH SIDES SAY OF THE PLACE, taken off both: the subject search's
// other people (the realm's seeded ones — development's demonstration
// people, and in a product realm made through /admin-api none — besides
// the conversation's own `az*`), and whether the signed metadata's header
// names its chain (`x5u`): seen absent on a realm's first metadata request
// and present on later ones, in the record and over the wire alike.
function placeless(one) {
  log.debug("Entering placeless().");
  const out = JSON.parse(JSON.stringify(one));
  const body = out.body;
  if (out.step === "search subject" && body && body.page &&
      Array.isArray(body.results)) {
    body.results = body.results.filter(function (r) {
      return /^az/.test(String(r.id));
    });
    body.page.count = "<count>";
    body.page.total = "<count>";
  }
  const header = body && body.signed_metadata && body.signed_metadata.jwt &&
    body.signed_metadata.jwt.header;
  if (header) {
    delete header.x5u;
  }
  log.debug("Leaving placeless().");
  return out;
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + "." + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ": " + String(JSON.stringify(b)).slice(0, 300) +
    " where " + String(JSON.stringify(a)).slice(0, 300) + " was recorded";
}

async function test() {
  log.debug("Entering test().");
  const recorded = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
  const MODES = [{ name: "development", id: "azwire" },
                 { name: "product", id: "azwirep" }];
  let wire = [];
  try {
    for (const mode of MODES) {
      const realm = await setUp(mode, mode.id);
      wire = wire.concat(await conversation(mode, realm));
    }
  } finally {
    await credentials.forgetStored({ get: get, post: post }, K.base, stored);
    await credentials.settleAnchors(K.base, added, null);
  }
  const now = normalise({ wire: wire.map(placed), problems: [] }).wire
    .map(placeless);
  const expected = recorded.wire.filter(function (one) {
    return one.step !== "the callback";
  }).map(placeless);
  K.check("the conversation has as many steps as recorded, less the " +
          "callbacks (" + expected.length + ")", function () {
    assert.strictEqual(now.length, expected.length);
  });
  const differing = [];
  expected.forEach(function (one, i) {
    const why = firstDifference(one, now[i], "wire");
    if (why) {
      differing.push(one.mode + ", " + one.step + ": " + why);
    } else {
      K.check(one.mode + ", " + one.step + ": " + one.method +
              " answers as recorded (" + one.status + ")", function () {
        assert.ok(true);
      });
    }
  });
  differing.forEach(function (one) {
    log.error("DIFFERS: " + one.slice(0, 1500));
  });
  K.check("every step answers as recorded", function () {
    assert.strictEqual(differing.length, 0, differing.length +
                       " step(s) differ; the first: " +
                       String(differing[0]).slice(0, 600));
  });
  log.debug("Leaving test().");
}

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
    // A certificate's digest, which names its chain in an x5u.
    ['digest', /\b[0-9a-f]{64}\b/g],
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

K.main(test, 326);
