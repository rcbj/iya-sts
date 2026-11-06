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
  const count = models.failureCount();
  t.check(count >= 7, 'every refusal is counted: ' + count);
  log.debug("Leaving validatorCases().");
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
  fs.writeFileSync(out, JSON.stringify({
    admin: spec.buildSpec(adminApi.ROUTES, { authRequired: true }),
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

function ruleOverDocuments(t) {
  log.debug("Entering ruleOverDocuments().");
  const docs = documents();
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
  run: run
};
