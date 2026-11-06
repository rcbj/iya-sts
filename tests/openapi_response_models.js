// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi_response_models.js
//
// ===========================================================================
// EVERY OPERATION HAS A CLOSED RESPONSE MODEL, AND EVERY ANSWER MEETS IT (#1353).
//
// rcbj's decision, 2026-11-05. Two halves, both in process because they read
// what no request can show:
//
//   * THE RULE OVER THE DOCUMENTS: all four APIs' documents, every operation,
//     every status. A new operation with no model, or a model left open at any
//     depth, fails here, so the rule cannot erode one operation at a time.
//   * THE VALIDATOR, against documents written here: an extra member, a wrong
//     type, an undeclared status or media type are each not sent, and nothing
//     about the shape reaches the caller.
//
// That a RUNNING service's answers meet the real models is not asserted here:
// every protocol job drives those answers, and one that does not match answers
// 500 and fails that job.
// ===========================================================================

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');

const log = require('bunyan').createLogger({
  name: 'openapi_response_models',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.resolve(__dirname, '..');
const { rowsOf } = require('./tools/openapi_inventory');

function fakeApp() {
  log.debug("Entering fakeApp().");
  const app = {
    middleware: null,
    use: function (prefix, fn) {
      app.middleware = fn;
    }
  };
  log.debug("Leaving fakeApp().");
  return app;
}

// A response with the parts of express's the validator reads. Its `send` stands
// for the real one: an object goes round through `json()` as a string.
function fakeResponse(media) {
  log.debug("Entering fakeResponse().");
  const headers = { 'content-type': media };
  const res = {
    statusCode: 200,
    sent: null,
    get: function (name) {
      return headers[String(name).toLowerCase()];
    },
    set: function (name, value) {
      headers[String(name).toLowerCase()] = value;
      return res;
    },
    type: function (value) {
      headers['content-type'] = value;
      return res;
    },
    status: function (code) {
      res.statusCode = code;
      return res;
    },
    removeHeader: function (name) {
      delete headers[String(name).toLowerCase()];
    },
    locals: {},
    send: function (body) {
      if (body !== null && typeof body === 'object' &&
          !Buffer.isBuffer(body)) {
        return res.send(JSON.stringify(body));
      }
      res.sent = body;
      return res;
    }
  };
  log.debug("Leaving fakeResponse().");
  return res;
}

// A member NAMED like a keyword is a member. A walk that was not schema-aware
// moved such a model's whole `properties` map to `components`, and the first
// live run refused every answer carrying one.
function sharingKeepsWhatModelsSay(t) {
  log.debug("Entering sharingKeepsWhatModelsSay().");
  const Kit = require('../common/response_model_kit');
  const Ajv = require('ajv');
  const row = Kit.closed({
    type: Kit.str('a long enough description to be worth sharing, on a member ' +
                  'whose NAME is the word type, as a setting row has'),
    items: Kit.listOf(Kit.closed({ properties: Kit.str(), anyOf: Kit.int() })),
    required: Kit.bool('another member named like a keyword, for the same ' +
                       'reason as the one above and long enough to count')
  });
  const json = function (schema) {
    return { description: 'd', content: {
      'application/json': { schema: schema } } };
  };
  const doc = Kit.shareRepeated({
    components: { schemas: {} },
    paths: {
      '/a': { get: { responses: { 200: json(Kit.closed({ one: row })) } } },
      '/b': { get: { responses: { 200: json(Kit.closed({ two: row })) } } }
    }
  });
  const shared = Object.keys(doc.components.schemas);
  t.check(shared.length >= 1, 'a repeated model moves to components: ' +
          shared.join(','));
  const schema = doc.paths['/a'].get.responses[200]
    .content['application/json'].schema;
  const validate = new Ajv({ strict: false }).compile({
    allOf: [schema], components: doc.components });
  t.check(validate({ one: { type: 'x', required: true,
                            items: [{ properties: 'y', anyOf: 1 }] } }),
          'and an answer with members named like keywords still meets it');
  t.check(!validate({ one: { type: 'x', stray: 1 } }),
          'and it is still closed');
  t.check(typeof schema.properties.one.$ref === 'string' &&
          !schema.properties.$ref, 'the model moved, never its properties map');
  log.debug("Leaving sharingKeepsWhatModelsSay().");
}

function validatorCases(t) {
  log.debug("Entering validatorCases().");
  const { ResponseModels, CODE } = require('../common/response_models');
  const logged = [];
  const marked = [];
  const models = new ResponseModels({
    log: { debug: function () {},
           error: function (line) {
             logged.push(line);
           } },
    mark: function (res, code) {
      marked.push(code);
    },
    tag: function (code) {
      return '[' + code + '] ';
    }
  });
  const THING = { type: 'object', additionalProperties: false,
                  properties: { name: { type: 'string' },
                                count: { type: 'integer' } } };
  const refusal = { type: 'object', additionalProperties: false,
                    properties: { error: { type: 'string' } } };
  const json = function (schema) {
    return { description: 'd', content: {
      'application/json': { schema: schema } } };
  };
  const doc = {
    components: { schemas: { Thing: THING } },
    paths: {
      '/api/thing': { get: { operationId: 'getThing', responses: {
        200: json({ $ref: '#/components/schemas/Thing' }),
        default: json(refusal)
      } } },
      '/api/thing/{id}': { get: { operationId: 'getOne', responses: {
        200: json(THING)
      } } },
      '/api/picture': { get: { operationId: 'getPicture', responses: {
        200: { description: 'd', content: {
          'image/svg+xml': { schema: { type: 'string' } } } }
      } } },
      // A model ajv refuses to compile: this answer's problem, said to nobody.
      '/api/broken': { get: { operationId: 'getBroken', responses: {
        200: json({ type: 'string', enum: ['a', 'a'] })
      } } },
      '/api/free': { get: { operationId: 'getFree', responses: {
        200: json({ 'x-free-form': 'a relayed document' })
      } } }
    }
  };
  const app = fakeApp();
  models.install(app, '/api', function () {
    return doc;
  }, refusal);
  const answer = function (method, url, media, status, body) {
    const res = fakeResponse(media);
    const req = { method: method, baseUrl: '/api', path: url };
    app.middleware(req, res, function () {});
    res.status(status);
    res.send(body);
    return res;
  };
  const good = answer('GET', '/thing', 'application/json', 200,
                      { name: 'a', count: 1 });
  t.equal(good.statusCode, 200, 'a matching answer is sent as it was');
  t.equal(good.sent, JSON.stringify({ name: 'a', count: 1 }),
          'and its bytes are untouched');
  t.equal(answer('HEAD', '/thing', 'application/json', 200, '{}').statusCode,
          200, 'a HEAD is held to the GET');
  t.equal(answer('GET', '/thing/7/', 'application/json', 200,
                 { count: 2 }).statusCode, 200,
          'a templated path finds its operation, trailing slash and all');
  t.equal(answer('GET', '/thing', 'application/json', 403,
                 { error: 'forbidden' }).statusCode, 403,
          'a status with no model of its own meets `default`');
  t.equal(answer('GET', '/picture', 'image/svg+xml', 200, '<svg/>').statusCode,
          200, 'a declared media type passes without a JSON model');
  t.equal(answer('GET', '/free', 'application/json', 200,
                 { anything: { at: 'all' } }).statusCode, 200,
          'a free-form model takes anything, and is the only one that does');
  t.equal(answer('GET', '/thing', 'application/json', 200, '').statusCode, 200,
          'an empty body has nothing to check');
  const nothingYet = marked.length;
  t.equal(nothingYet, 0, 'none of those was reported');

  const SECRET = 'do-not-repeat-me';
  const extra = answer('GET', '/thing', 'application/json', 200,
                       { name: 'a', stray: SECRET });
  t.equal(extra.statusCode, 500, 'an undeclared member is not sent');
  t.check(extra.sent.indexOf(SECRET) < 0 && extra.sent.indexOf('stray') < 0,
          'and the caller learns neither the value nor the member');
  t.equal(JSON.parse(extra.sent).error, 'server_error',
          'the caller is told only server_error');
  t.check(marked.indexOf(CODE) >= 0, 'the failure carries its error code');
  t.check(logged.length === 1 && logged[0].indexOf('stray') >= 0 &&
          logged[0].indexOf('getThing') >= 0,
          'the operator is told the operation and the member');
  t.check(logged[0].indexOf(SECRET) < 0, 'and never a value');
  t.equal(answer('GET', '/thing', 'application/json', 200,
                 { name: 'a', stray: 'again' }).statusCode, 500,
          'the same failure is refused again');
  t.equal(logged.length, 1, 'but logged once, not per request');
  t.equal(answer('GET', '/thing', 'application/json', 200,
                 { count: 'one' }).statusCode, 500,
          'a value of the wrong type is not sent');
  t.equal(answer('GET', '/thing/7', 'application/json', 418,
                 { name: 'a' }).statusCode, 500,
          'a status an operation does not declare, with no default, is not');
  t.equal(answer('GET', '/picture', 'text/html', 200, '<p>').statusCode, 500,
          'a media type the status does not declare is not sent');
  t.equal(answer('GET', '/absent', 'application/json', 200, '{}').statusCode,
          500, 'JSON from an operation the document lacks is not sent');
  t.equal(answer('POST', '/thing/nonsense', 'application/json', 400,
                 { error: 'no such action' }).statusCode, 400,
          'an undocumented path may answer the API\'s refusal');
  t.equal(answer('POST', '/thing/nonsense', 'application/json', 400,
                 { error: 'x', stray: 1 }).statusCode, 500,
          'and that refusal is held to its model too');
  t.equal(answer('GET', '/absent', 'text/html', 404,
                 'Cannot GET /absent').statusCode, 404,
          'a body that is not JSON on an unrouted path is left alone');
  t.equal(answer('GET', '/thing', 'application/json', 200,
                 '{broken').statusCode, 500, 'unparsable JSON is not sent');
  const uncompilable = answer('GET', '/broken', 'application/json', 200, '"a"');
  t.equal(uncompilable.statusCode, 500, 'a model that will not compile is not ' +
          'answered through');
  t.check(uncompilable.sent.indexOf('enum') < 0 &&
          JSON.parse(uncompilable.sent).error === 'server_error',
          'and the caller hears nothing about the schema');
  t.check(logged.some(function (line) {
    return line.indexOf('getBroken') >= 0 &&
      line.indexOf('does not compile') >= 0;
  }), 'while the operator is told which model it was');
  const count = models.failureCount();
  t.check(count >= 7, 'every refusal is counted: ' + count);
  log.debug("Leaving validatorCases().");
}

// THE LOG LINE SAYS THE MEMBER THAT WAS WRONG, whichever branch of a union it
// is in (#1353: `getUsers` said dozens of the other branch's members), and an
// exception no handler caught answers as the API answers, never an HTML page.
function unionsAndExceptions(t) {
  log.debug("Entering unionsAndExceptions().");
  const { ResponseModels } = require('../common/response_models');
  const logged = [];
  const marked = [];
  const models = new ResponseModels({
    log: { debug: function () {},
           error: function (line) {
             logged.push(line);
           } },
    mark: function (res, code) {
      marked.push(code);
    },
    tag: function (code) {
      return '[' + code + '] ';
    }
  });
  const closed = function (properties) {
    return { type: 'object', additionalProperties: false,
             properties: properties };
  };
  const LIST = closed({ a: { type: 'string' }, b: { type: 'string' },
                        c: { type: 'string' } });
  const DETAIL = closed({ who: closed({ dn: { type: 'string' } }) });
  const doc = { components: { schemas: {} }, paths: { '/api/u': { get: {
    operationId: 'getU', responses: { 200: { description: 'd', content: {
      'application/json': { schema: { anyOf: [LIST, DETAIL] } } } } }
  } } } };
  const installed = models.installed(function () {
    return doc;
  });
  const problem = models.problemOf(installed,
    { method: 'GET', baseUrl: '/api', path: '/u' },
    { statusCode: 200, get: function () {
      return 'application/json';
    } }, JSON.stringify({ who: { dn: 'x', rogue: 1 } }));
  t.check(problem && problem.where.indexOf('/who additionalProperties ' +
          '"rogue"') === 0, 'the member that was wrong is said first: ' +
          (problem && problem.where));
  const uses = [];
  models.install({ use: function () {} }, '/api', function () {
    return doc;
  });
  models.answerExceptions({ use: function (prefix, fn) {
    uses.push([prefix, fn]);
  } });
  t.equal(uses.length, 1, 'one handler per published API');
  t.equal(uses[0][1].length, 4, 'and express reads four arguments as an ' +
          'error handler');
  const response = fakeResponse('text/html');
  response.statusCode = 200;
  uses[0][1](new RangeError('Invalid time value'),
             { method: 'GET', baseUrl: '/api', path: '/u' }, response,
             function () {
               t.check(false, 'a thrown exception does not pass on');
             });
  t.equal(response.statusCode, 500, 'a throw is a 500');
  t.equal(JSON.parse(response.sent).error, 'server_error', 'in JSON');
  t.check(marked.indexOf('STS-API-0140') >= 0 && logged.some(function (line) {
    return line.indexOf('Invalid time value') >= 0;
  }), 'with its code, and the operator told what it was');
  let passed = null;
  models.answerExceptions({ use: function (prefix, fn) {
    fn({ status: 400 }, {}, fakeResponse('text/html'), function (err) {
      passed = err;
    });
  } });
  t.check(passed && passed.status === 400,
          'a status below 500 is somebody else\'s');
  log.debug("Leaving unionsAndExceptions().");
}

// IN A CHILD: the operation tables are complete only with the whole stack loaded,
// which runs load-time effects this runner's other files must not inherit.
function buildDocuments(out) {
  log.debug("Entering buildDocuments().");
  require(ROOT + '/common/protocol_stack');
  const spec = require('../mgmt-api/admin_api_spec');
  const adminApi = require('../mgmt-api/admin_api');
  const accountApi = require('../account-api/account_api');
  const AccountApiSpec = require('../account-api/account_api_spec');
  const authnApi = require('../authn/authn_api');
  const OpenApi = require('../report/openapi');
  const Catalog = require('../report/catalog');
  // What a finished GNAP grant really holds, from the code that writes it, so
  // that the check below cannot agree with a model by way of a hand-typed copy.
  const { GnapGrants } = require('../gnap/gnap_grants');
  const finalized = { id: 'g', delivered: true, client: { identifier: 'c' } };
  GnapGrants.prototype.finalize.call({ deps: {
    log: log,
    nowSec: function () {
      return 1;
    },
    audit: { audit: function () {} },
    store: { dropContinuation: function () {},
             saveGrant: function () {} }
  } }, finalized, 'a note', 'issued');
  fs.writeFileSync(out, JSON.stringify({
    finalization: finalized.finalization,
    admin: spec.buildSpec(adminApi.ROUTES, { authRequired: true }),
    // The two as `/admin-api/openapi.json` and its console twin serve them, for
    // the published pages (`tests/tools/openapi_pages.js`).
    management: spec.buildSpec(adminApi.ROUTES.filter(function (route) {
      return (route.kind || 'management') === 'management';
    }), { authRequired: true }),
    console: spec.buildSpec(adminApi.ROUTES.filter(function (route) {
      return route.kind === 'console';
    }), { authRequired: true, console: true }),
    account: AccountApiSpec.document(accountApi.operations(), {}),
    authn: authnApi.document({}),
    report: OpenApi.document(new Catalog())
  }));
  log.debug("Leaving buildDocuments().");
}

function documents() {
  log.debug("Entering documents().");
  const out = path.join(os.tmpdir(), 'openapi-documents-' + process.pid +
                        '.json');
  const child = spawnSync(process.execPath, [__filename, '--build', out], {
    cwd: ROOT, stdio: ['ignore', 'ignore', 'pipe'], timeout: 180000,
    env: Object.assign({}, process.env, { LOG_LEVEL: 'fatal',
                                          STS_LOG_LEVEL: 'fatal' })
  });
  if (child.status !== 0) {
    log.debug("Leaving documents(). The child failed.");
    throw new Error('building the documents failed: ' +
                    String(child.stderr || '').slice(-2000));
  }
  const docs = JSON.parse(fs.readFileSync(out, 'utf8'));
  fs.unlinkSync(out);
  log.debug("Leaving documents().");
  return docs;
}

// The portal's `finalization` was modelled as a string, while every grant that
// has one holds an object: a person with a finished grant got a 500 on their
// grants page. Each model of a grant holds what `finalize()` writes, and null.
function aFinishedGrantMeetsEveryModel(t, docs) {
  log.debug("Entering aFinishedGrantMeetsEveryModel().");
  const Ajv = require('ajv');
  const ajv = new Ajv({ strict: false, allErrors: true });
  const sites = [];
  const walk = function (node, seen) {
    if (!node || typeof node !== 'object' || seen.has(node)) {
      return;
    }
    seen.add(node);
    if (node.properties && node.properties.finalization) {
      sites.push(node.properties.finalization);
    }
    Object.keys(node).forEach(function (k) {
      walk(node[k], seen);
    });
  };
  ['admin', 'account'].forEach(function (api) {
    const before = sites.length;
    const doc = docs[api];
    walk({ paths: doc.paths, components: doc.components }, new Set());
    t.check(sites.length > before, api + ' models a grant\'s finalization');
    sites.slice(before).forEach(function (schema) {
      const validate = ajv.compile({ allOf: [schema],
                                     components: doc.components });
      t.check(validate(docs.finalization),
              api + ': a finalized grant\'s record meets its model');
      t.check(validate(null), api + ': so does a grant not yet final');
      t.check(!validate('issued'), api + ': a bare string does not');
    });
  });
  log.debug("Leaving aFinishedGrantMeetsEveryModel().");
}

// AN ERROR CODE IS AN OPERATOR'S NAME, RECORDED AND NEVER SENT, with the one
// exception rcbj allowed on 2026-11-06 (#1355): an administrator's console page
// that draws it for someone diagnosing a recorded failure. Nothing here is a
// list of what MAY be added; each row names the page that draws the member.
const DRAWN_CODE_OPERATIONS = {
  getAudit: 'admin-ui/web_audit.ts: the audit log',
  getUsers: 'admin-ui/web_users.ts: a person\'s attempts, as audit rows',
  getApplications: 'admin-ui/web_applications.ts: an application\'s attempts',
  getScheduler: 'admin-ui/web_scheduler.ts: a run that failed',
  getRisk: 'admin-ui/web_risk.ts: the failure history',
  getMailOutbox: 'admin-ui/web_mail_outbox.ts: a message that failed',
  getLiveSessions: 'logout/web_logout.ts: a dead back-channel delivery',
  getProviderCommands: 'oauth-oidc/web_provider_commands.ts: a delivery',
  getOutboundDeliveries: 'oauth-oidc/web_provider_commands.ts: every kind',
  getSsf: 'ssf/web_ssf.ts: a stream\'s dead letters',
  getSsfDeadLetters: 'ssf/web_ssf_dead_letters.ts: why letters are held',
  getScim: 'scim/web_scim_clients.ts: the Clients tab\'s dead deliveries',
  getScimClients: 'scim/web_scim_clients.ts: a client\'s dead deliveries',
  getAttributeSources: 'attribute-sources/web_attribute_sources.ts: last error',
  getAcmeMonitor: 'acme/web_acme.ts: refused requests',
  getEstMonitor: 'est/web_est.ts: refused requests',
  getScepMonitor: 'scep/web_scep.ts: refused requests'
};

// `code` is too common a word to catch by name, so these are the ones kept,
// each checked to be still there.
const DRAWN_PLAIN_CODES = {
  'getErrorCodes codes.code': 'admin-ui/web_error_codes.ts: the catalogue',
  'getErrorCodes unregisteredSeen.code': 'admin-ui/web_error_codes.ts: the ' +
    'audit codes the catalogue does not hold',
  'getAudit filter.code': 'admin-ui/web_audit.ts: the filter, as asked',
  'getListeners problem.code': 'admin-ui/web_listeners.ts: a bad setting',
  'getSsfDeadLetters causes.code': 'ssf/web_ssf_dead_letters.ts: each cause',
  'getUma whatIf.code': 'uma/web_uma.ts: the dry run\'s verdict'
};

const CODE_MEMBER = /^(errorCode|errorCodes|lastCode|byCode)$/;

// Every member path in one operation's answers, following `$ref`.
function memberPaths(doc, schema, prefix, seen, out) {
  log.debug("Entering memberPaths().");
  let node = schema;
  while (node && node.$ref) {
    node = doc.components.schemas[String(node.$ref).split('/').pop()];
  }
  if (!node || typeof node !== 'object' || seen.indexOf(node) >= 0) {
    log.debug("Leaving memberPaths(). Nothing further.");
    return out;
  }
  const below = seen.concat([node]);
  Object.keys(node.properties || {}).forEach(function (name) {
    const at = prefix ? prefix + '.' + name : name;
    out.push(at);
    memberPaths(doc, node.properties[name], at, below, out);
  });
  ['items', 'additionalProperties'].forEach(function (key) {
    memberPaths(doc, node[key], prefix, below, out);
  });
  ['oneOf', 'anyOf', 'allOf'].forEach(function (key) {
    (node[key] || []).forEach(function (one) {
      memberPaths(doc, one, prefix, below, out);
    });
  });
  log.debug("Leaving memberPaths().");
  return out;
}

function codesOnlyWhereDrawn(t, docs) {
  log.debug("Entering codesOnlyWhereDrawn().");
  const Kit = require('../common/response_model_kit');
  const body = { ok: true, errorCode: 'x', rows: [{ errorCode: 'y', id: 1 }] };
  t.equal(JSON.stringify(Kit.stripCodes(body)),
          JSON.stringify({ ok: true, rows: [{ id: 1 }] }),
          'an act\'s answer loses a code at any depth');
  const found = {};
  ['admin', 'account', 'authn', 'report'].forEach(function (api) {
    const doc = docs[api];
    Object.keys(doc.paths).forEach(function (p) {
      Object.keys(doc.paths[p]).forEach(function (m) {
        const op = doc.paths[p][m] || {};
        Object.keys(op.responses || {}).forEach(function (status) {
          const content = op.responses[status].content || {};
          Object.keys(content).forEach(function (type) {
            memberPaths(doc, content[type].schema, '', [], []).forEach(
              function (at) {
                const key = api + ' ' + op.operationId;
                found[key] = found[key] || new Set();
                found[key].add(at);
              });
          });
        });
      });
    });
  });
  const wrong = [];
  Object.keys(found).forEach(function (key) {
    const [api, id] = key.split(' ');
    found[key].forEach(function (at) {
      const named = CODE_MEMBER.test(at.split('.').pop());
      if (named && (api !== 'admin' || !DRAWN_CODE_OPERATIONS[id])) {
        wrong.push(key + ' ' + at);
      }
    });
  });
  t.check(wrong.length === 0, 'a code is a member only where a console page ' +
          'draws it; these are not listed:\n  ' + wrong.join('\n  '));
  Object.keys(DRAWN_CODE_OPERATIONS).forEach(function (id) {
    const members = Array.from(found['admin ' + id] || []);
    t.check(members.some(function (at) {
      return CODE_MEMBER.test(at.split('.').pop());
    }), id + ' is listed and still carries a code: ' +
        DRAWN_CODE_OPERATIONS[id]);
  });
  Object.keys(DRAWN_PLAIN_CODES).forEach(function (key) {
    const [id, at] = key.split(' ');
    t.check((found['admin ' + id] || new Set()).has(at), key + ' is still ' +
            'there: ' + DRAWN_PLAIN_CODES[key]);
  });
  log.debug("Leaving codesOnlyWhereDrawn().");
}

function ruleOverDocuments(t) {
  log.debug("Entering ruleOverDocuments().");
  const docs = documents();
  aFinishedGrantMeetsEveryModel(t, docs);
  codesOnlyWhereDrawn(t, docs);
  delete docs.finalization;
  let total = 0;
  Object.keys(docs).forEach(function (api) {
    const rows = rowsOf(api, docs[api]);
    total += rows.length;
    const wrong = rows.filter(function (r) {
      const successWithNoBody = r.state === 'none' &&
        /^(204|3..)$/.test(r.status);
      return ['closed', 'free-form', 'not-json'].indexOf(r.state) < 0 &&
        !successWithNoBody;
    }).map(function (r) {
      return r.method + ' ' + r.path + ' ' + r.status + ' ' + r.state;
    });
    t.check(wrong.length === 0, api + ': every status has a closed model; ' +
            wrong.length + ' do not: ' + wrong.slice(0, 40).join(', '));
    const operations = [];
    Object.keys(docs[api].paths).forEach(function (p) {
      Object.keys(docs[api].paths[p]).forEach(function (m) {
        const op = docs[api].paths[p][m];
        if (op && op.responses) {
          operations.push(p + ' ' + m + ' ' + (op.responses.default ? '' : 'x'));
        }
      });
    });
    const noDefault = operations.filter(function (o) {
      return / x$/.test(o);
    });
    t.check(noDefault.length === 0, api + ': every operation declares what ' +
            'a refusal looks like: ' + noDefault.slice(0, 20).join(', '));
  });
  t.check(total >= 1500, 'the walk reached the documents: ' + total + ' rows');
  // EVERY MODEL COMPILES, with the validator's own options: ajv refuses a model
  // for what it IS (a duplicate in an enum), and that shows only when an answer
  // reaches it, which for the wallet's wait page was a sign-in.
  const Ajv = require('ajv');
  const addFormats = require('ajv-formats');
  const ajv = new Ajv({ strict: false, allErrors: true, coerceTypes: false,
                        useDefaults: false });
  addFormats(ajv);
  const broken = [];
  let compiled = 0;
  Object.keys(docs).forEach(function (api) {
    const doc = docs[api];
    Object.keys(doc.paths).forEach(function (p) {
      Object.keys(doc.paths[p]).forEach(function (m) {
        const responses = (doc.paths[p][m] || {}).responses || {};
        Object.keys(responses).forEach(function (status) {
          const content = responses[status].content || {};
          Object.keys(content).filter(function (type) {
            return /json/.test(type);
          }).forEach(function (type) {
            try {
              ajv.compile({ allOf: [content[type].schema],
                            components: doc.components });
              compiled += 1;
            } catch (e) {
              log.debug("Caught in ruleOverDocuments(): " +
                        ((e && e.message) || e));
              broken.push(api + ' ' + m + ' ' + p + ' ' + status + ': ' +
                          ((e && e.message) || e));
            }
          });
        });
      });
    });
  });
  t.check(broken.length === 0 && compiled > 1000, 'every model compiles (' +
          compiled + '): ' + broken.slice(0, 20).join('; '));
  // A free-form model carries its reason, or it is an open model by another
  // name; the list is printed, because the exception is meant to be read.
  const reasons = new Set();
  const walk = function (node, seen) {
    if (!node || typeof node !== 'object' || seen.has(node)) {
      return;
    }
    seen.add(node);
    if (Object.prototype.hasOwnProperty.call(node, 'x-free-form')) {
      t.check(typeof node['x-free-form'] === 'string' &&
              node['x-free-form'].length > 10,
              'a free-form model says why: ' + node['x-free-form']);
      reasons.add(node['x-free-form']);
    }
    Object.keys(node).forEach(function (k) {
      walk(node[k], seen);
    });
  };
  Object.keys(docs).forEach(function (api) {
    walk(docs[api].paths, new Set());
    walk(docs[api].components, new Set());
  });
  log.info('free-form models: ' + reasons.size + '\n  ' +
           Array.from(reasons).sort().join('\n  '));
  log.debug("Leaving ruleOverDocuments().");
}

// `res.send` is the door. A JSON answer through `res.end()` would pass nothing.
// (A report job's file is streamed: `report_api.ts`'s `reportStreamPieces()`,
// bytes with a declared media type and no model to hold them to.)
function nothingAnswersRoundTheDoor(t) {
  log.debug("Entering nothingAnswersRoundTheDoor().");
  ['mgmt-api', 'account-api', 'authn'].forEach(function (dir) {
    fs.readdirSync(path.join(ROOT, dir)).filter(function (f) {
      return /_api\.(ts|js)$/.test(f);
    }).forEach(function (f) {
      const text = fs.readFileSync(path.join(ROOT, dir, f), 'utf8');
      t.check(!/res\.(end|write)\(|\.pipe\(res\)/.test(text),
              dir + '/' + f + ' answers only through res.send');
    });
  });
  log.debug("Leaving nothingAnswersRoundTheDoor().");
}

async function run(t) {
  log.debug("Entering run().");
  validatorCases(t);
  unionsAndExceptions(t);
  sharingKeepsWhatModelsSay(t);
  nothingAnswersRoundTheDoor(t);
  ruleOverDocuments(t);
  log.debug("Leaving run().");
}

if (require.main === module && process.argv[2] === '--build') {
  buildDocuments(process.argv[3]);
  process.exit(0);
}

module.exports = {
  name: 'openapi_response_models',
  describe: 'Every OpenAPI operation has a closed response model, and every ' +
    'answer is held to it (#1353)',
  run: run,
  documents: documents
};
