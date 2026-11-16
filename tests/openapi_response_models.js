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
// 500 and fails that job. The exceptions are records built here from the code
// that writes them (a finished GNAP grant, the read barrier's counters), held
// to every model of them, because a member added there reached a stack first.
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

// A COMPILE THAT FAILS IS CONTAINED TO ITS MODEL (2026-11-12). In the fuzz
// stage of a full run one model would not compile, and from then on every
// answer of every operation was refused. Here a model fails to compile once
// (the first schema it hands out throws the RangeError the service saw, from
// inside ajv), and: another operation's validator, compiled before, still passes a
// good answer and refuses a bad one; one compiled after the failure does the
// same; the failed model is answered from the memory of its failure inside
// the window, without compiling again; and after the window one request
// compiles it, and its answers pass.
function compileFailureContained(t) {
  log.debug("Entering compileFailureContained().");
  const { ResponseModels, CODE, RETRY_MS } =
    require('../common/response_models');
  const logged = [];
  const marked = [];
  let clock = 1000000;
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
    },
    now: function () {
      return clock;
    }
  });
  const closed = function (properties) {
    return { type: 'object', additionalProperties: false,
             properties: properties };
  };
  // The first schema it hands out throws from INSIDE ajv's compile, a member
  // deep in it failing as it is read, so whatever ajv had half-built when it
  // threw is left behind exactly as a real overflow leaves it.
  let reads = 0;
  const trap = {};
  Object.defineProperty(trap, 'type', { enumerable: true, get: function () {
    throw new RangeError('Maximum call stack size exceeded');
  } });
  const flaky = {
    get schema() {
      reads += 1;
      if (reads === 1) {
        return { type: 'object', additionalProperties: false,
                 properties: { ok: { $ref: '#/components/schemas/Ok' },
                               deep: closed({ trap: trap }) } };
      }
      return { $ref: '#/components/schemas/Ok' };
    }
  };
  const json = function (schema) {
    return { description: 'd', content: {
      'application/json': { schema: schema } } };
  };
  const doc = {
    components: { schemas: {
      Ok: closed({ ok: { type: 'boolean' }, message: { type: 'string' } }),
      Thing: closed({ name: { type: 'string' } })
    } },
    paths: {
      '/api/before': { get: { operationId: 'getBefore', responses: {
        200: json({ $ref: '#/components/schemas/Thing' }) } } },
      '/api/after': { get: { operationId: 'getAfter', responses: {
        200: json({ $ref: '#/components/schemas/Thing' }) } } },
      '/api/flaky': { post: { operationId: 'addFlaky', responses: {
        200: { description: 'd', content: { 'application/json': flaky } }
      } } }
    }
  };
  const app = fakeApp();
  models.install(app, '/api', function () {
    return doc;
  }, null);
  const answer = function (method, url, body) {
    const res = fakeResponse('application/json');
    app.middleware({ method: method, baseUrl: '/api', path: url }, res,
                   function () {});
    res.status(200);
    res.send(body);
    return res.statusCode;
  };
  t.equal(answer('GET', '/before', { name: 'a' }), 200,
          'an operation compiled before the failure passes a good answer');
  t.equal(answer('POST', '/flaky', { ok: true }), 500,
          'the answer whose model would not compile is not sent');
  t.check(logged.some(function (line) {
    return line.indexOf('addFlaky') >= 0 &&
      line.indexOf('does not compile: Maximum call stack') >= 0;
  }), 'and the operator is told which model and why');
  t.equal(answer('GET', '/before', { name: 'b' }), 200,
          'the operation compiled before still passes a good answer');
  t.equal(answer('GET', '/before', { name: 'b', rules: [] }), 500,
          'and still refuses a bad one');
  t.equal(answer('GET', '/after', { name: 'c' }), 200,
          'an operation first compiled after the failure passes a good answer');
  t.equal(answer('GET', '/after', { name: 'c', stray: 1 }), 500,
          'and refuses a bad one');
  const linesBefore = logged.length;
  t.equal(answer('POST', '/flaky', { ok: true }), 500,
          'inside the window the failed model is still refused');
  t.equal(reads, 1, 'from the memory of its failure, without compiling again');
  t.equal(logged.length, linesBefore, 'and the failure is not logged again');
  clock += RETRY_MS;
  t.equal(answer('POST', '/flaky', { ok: true }), 200,
          'after the window one request compiles it, and a good answer passes');
  t.equal(answer('POST', '/flaky', { ok: true, stray: 1 }), 500,
          'and its model refuses a bad one');
  t.equal(reads, 2, 'it was compiled once more, and kept');
  t.check(marked.every(function (code) {
    return code === CODE;
  }), 'every refusal carried ' + CODE);
  log.debug("Leaving compileFailureContained().");
}

// A POLLUTED PROTOTYPE IS NAMED (2026-11-12). An enumerable member on
// `Object.prototype` is a member of every answer as ajv reads one, so every
// closed model refuses every answer; the first refusal says which member, once.
// The prototype is restored before anything else runs.
function pollutionNamed(t) {
  log.debug("Entering pollutionNamed().");
  const { ResponseModels, POLLUTED } = require('../common/response_models');
  const logged = [];
  const models = new ResponseModels({
    log: { debug: function () {},
           error: function (line) {
             logged.push(line);
           } },
    mark: function () {},
    tag: function (code) {
      return '[' + code + '] ';
    }
  });
  const doc = { components: { schemas: {} }, paths: { '/api/x': { get: {
    operationId: 'getX', responses: { 200: { description: 'd', content: {
      'application/json': { schema: { type: 'object',
        additionalProperties: false,
        properties: { name: { type: 'string' } } } } } } }
  } } } };
  const app = fakeApp();
  models.install(app, '/api', function () {
    return doc;
  }, null);
  const answer = function (body) {
    const res = fakeResponse('application/json');
    app.middleware({ method: 'GET', baseUrl: '/api', path: '/x' }, res,
                   function () {});
    res.status(200);
    res.send(body);
    return res.statusCode;
  };
  t.equal(answer({ name: 'a' }), 200, 'before: a good answer passes');
  t.equal(ResponseModels.inheritedMembers().length, 0,
          'and this process inherits nothing enumerable');
  let during = 0;
  let duringAgain = 0;
  let named = [];
  // eslint-disable-next-line no-extend-native
  Object.prototype.rules = [{ id: 'urn:policy:rule:1' }];
  try {
    named = ResponseModels.inheritedMembers();
    during = answer({ name: 'a' });
    duringAgain = answer({ name: 'b' });
  } finally {
    delete Object.prototype.rules;
  }
  t.equal(during, 500, 'polluted: the same good answer is refused');
  t.equal(duringAgain, 500, 'and so is the next');
  t.equal(named.join(','), 'rules', 'the inherited member is found by name');
  const said = logged.filter(function (line) {
    return line.indexOf('[' + POLLUTED + ']') === 0;
  });
  t.check(said.length === 1 && said[0].indexOf('"rules"') >= 0,
          'the operator is told, once, which member every object inherits');
  t.equal(answer({ name: 'a' }), 200,
          'restored: the validator compiled before passes it again');
  log.debug("Leaving pollutionNamed().");
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
  // The answer is to what was asked, whatever the request says by the send.
  const app = fakeApp();
  models.install(app, '/api', function () {
    return doc;
  });
  const forged = { method: 'GET', baseUrl: '/api', path: '/u' };
  const asked = fakeResponse('application/json');
  app.middleware(forged, asked, function () {});
  forged.baseUrl = '';
  forged.path = '/.well-known/openid-federation';
  asked.send(JSON.stringify({ a: 'x' }));
  t.equal(asked.statusCode, 200, 'an answer is judged by the path it was ' +
          'asked on, not by one the request was changed to: ' + asked.sent);
  log.debug("Leaving unionsAndExceptions().");
}

// The `/admin/ldap/*` pages `/admin-api/ldap/*` answers, each built by the
// view `ldap/ldap_server.js` hands `admin.setDirectoryPages()`, against the
// directory this child loaded. A view that answers a promise is awaited; one
// that throws is recorded as the failure, so the check names it.
async function directoryPages() {
  log.debug("Entering directoryPages().");
  const adminViews = require('../admin-core/admin_views');
  const out = {};
  const names = ['service', 'directory', 'applications', 'federations',
    'spiffe', 'roles', 'policies', 'peps', 'devices'];
  for (const name of names) {
    const req = { query: {}, headers: {}, cookies: {},
      get: function () {
        return undefined;
      } };
    try {
      out[name] = { json: await Promise.resolve(
        adminViews.directoryPageJson(name, req)) };
    } catch (e) {
      log.debug("Caught in directoryPages(): " + ((e && e.message) || e));
      out[name] = { error: String((e && e.stack) || e).slice(0, 600) };
    }
  }
  log.debug("Leaving directoryPages().");
  return out;
}

// ---------------------------------------------------------------------------
// A PERSON'S ANSWER, AS `GET /admin-api/users` SENDS IT (2026-11-16).
//
// #1845 added `authenticationHistory` and `authenticationHistoryPaging` to
// the `?user=` answer and declared them only in `models/api/console.tsp`,
// whose `UserDetail` no operation uses. `getUsers` is held to
// `management.tsp`'s, closed, so every person's page answered 500
// (STS-API-0139) on the testbed until #1846 declared them there too. No test
// in process built a person's answer, and the stack job that walks every read
// did not run, because the unit job failed first. So the child below signs a
// person in over a loopback listener of the whole stack, gives them tokens on
// and off a session and a key pair, makes a service account, and asks the
// operation's own handler for the list, each of those, and a name never
// seen, through the API's own response check (`common/response_models.ts`)
// holding the document the API holds it to. The parent holds each body to
// the Management API OpenAPI document's model besides.
// ---------------------------------------------------------------------------

// A browser's User-Agent: risk scoring takes a tool's name for a robot.
const BROWSER = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
                '(KHTML, like Gecko) Chrome/130.0 Safari/537.36';

// One request to the child's loopback listener, the cookies kept in `jar`.
function loopback(port, jar, method, at, options) {
  log.debug("Entering loopback(). " + method + ' ' + at);
  const http = require('http');
  const o = options || {};
  const body = o.form ? new URLSearchParams(o.form).toString() : '';
  const headers = Object.assign({ 'user-agent': BROWSER }, o.headers || {});
  const names = Object.keys(jar).filter(function (k) {
    return jar[k];
  });
  if (names.length) {
    headers.cookie = names.map(function (k) {
      return k + '=' + jar[k];
    }).join('; ');
  }
  if (method !== 'GET') {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    headers['content-length'] = Buffer.byteLength(body);
  }
  log.debug("Leaving loopback().");
  return new Promise(function (resolve) {
    const req = http.request({ host: '127.0.0.1', port: port,
      path: String(at).replace(/^https?:\/\/[^/]+/, ''), method: method,
      headers: headers }, function (res) {
      (res.headers['set-cookie'] || []).forEach(function (line) {
        const pair = line.split(';')[0];
        const eq = pair.indexOf('=');
        jar[pair.slice(0, eq)] = /Max-Age=0/.test(line) ? ''
          : pair.slice(eq + 1);
      });
      let text = '';
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          // Not JSON: a redirect or a page. The status and text say enough.
          log.debug("Caught in loopback(): " + ((e && e.message) || e));
        }
        resolve({ status: res.statusCode, headers: res.headers, text: text,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in loopback(): " + ((e && e.message) || e));
      resolve({ status: 0, headers: {}, text: String(e.message),
                json: null });
    });
    req.end(method === 'GET' ? undefined : body);
  });
}

// An OpenID Connect code flow through the sign-in screen as `who`, the
// offered set-up ignored, and the code redeemed: a sign-on session with
// tokens on it. Answers the token response, or `{ error }`.
async function codeFlow(port, client, who) {
  log.debug("Entering codeFlow(). " + who);
  const screen = require('./tools/authn_screen');
  const jar = {};
  let r = await loopback(port, jar, 'GET', '/oauth2/authorize?' +
    new URLSearchParams({ client_id: client.id, response_type: 'code',
      redirect_uri: client.redirect, scope: 'openid offline_access',
      state: 's', nonce: 'n-' + Date.now() }).toString());
  for (let hop = 0; hop < 12; hop += 1) {
    const to = String((r.headers && r.headers.location) || '');
    if (r.status >= 300 && r.status < 400 && /\/authn\/login/.test(to)) {
      const posted = await screen.submit({ port: port, jar: jar,
        userAgent: BROWSER, at: to,
        fields: { action: 'login', username: who, password: 'x' } });
      const next = await screen.ignoreOffer({ port: port, jar: jar,
                                              userAgent: BROWSER }, posted);
      r = { status: next.status, headers: next.headers || {} };
      continue;
    }
    if (r.status >= 300 && r.status < 400 && to &&
        to.indexOf(client.redirect) !== 0) {
      r = await loopback(port, jar, 'GET', to);
      continue;
    }
    break;
  }
  const to = String((r.headers && r.headers.location) || '');
  const at = to.indexOf('?');
  const code = to.indexOf(client.redirect) === 0 && at > 0
    ? new URLSearchParams(to.slice(at + 1)).get('code') : '';
  if (!code) {
    log.debug("Leaving codeFlow(). No code.");
    return { error: r.status + ' ' + to };
  }
  const token = await loopback(port, {}, 'POST', '/oauth2/token', {
    headers: { authorization: client.basic },
    form: { grant_type: 'authorization_code', code: code,
            redirect_uri: client.redirect } });
  log.debug("Leaving codeFlow(). " + token.status);
  return token.status === 200 && token.json ? token.json
    : { error: token.status + ' ' + String(token.text).slice(0, 200) };
}

// A response with the parts of express's the handler and the check use. Its
// `send` resolves `answered` with what was finally sent.
function doorResponse(req, answered) {
  log.debug("Entering doorResponse().");
  const headers = { 'content-type': 'application/json' };
  const res = {
    statusCode: 200, req: req, locals: {},
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
    send: function (body) {
      answered({ status: res.statusCode, sent: String(body) });
      return res;
    }
  };
  log.debug("Leaving doorResponse().");
  return res;
}

// Asks a GET operation with `query` of its own handler (`row`, its route
// table row), its answer through the API's own response check, which holds it
// to the document the API holds it to: `{ status, codes, json }`, `json` being
// the body the handler handed the check, kept before the check could replace
// it, and `codes` what was marked on the way. A handler that throws, calls
// `next()` or has not answered in `ASK_MS` is answered as that.
const ASK_MS = 15000;
async function askTheDoor(door, row, at, query) {
  log.debug("Entering askTheDoor(). " + at + ' ' + JSON.stringify(query));
  const req = { method: 'GET', baseUrl: '', path: at, url: at,
    originalUrl: at, query: query, headers: {}, cookies: {}, params: {},
    get: function () {
      return undefined;
    } };
  let answered = null;
  const done = new Promise(function (resolve) {
    answered = resolve;
  });
  const res = doorResponse(req, answered);
  // What the route's registration sets before it calls the handler
  // (`admin_api.ts`, the GET loop): a console twin's members to drop (#454),
  // and a mirrored Protocols page's endpoints to add.
  if (row.consoleMembers) {
    res.locals.consoleMembers = row.consoleMembers;
  }
  const protocolEndpoints = require('../admin-core/protocol_endpoints');
  const mirrored = /^GET (\/admin\S*)$/.exec(String(row.mirrors || ''));
  if (mirrored && protocolEndpoints.pages().indexOf(mirrored[1]) >= 0) {
    res.locals.protocolEndpoints = protocolEndpoints.forPage(req,
                                                             mirrored[1]);
  }
  door.middleware(req, res, function () {});
  const checked = res.send;
  let handed = null;
  res.send = function (body) {
    if (typeof body === 'string') {
      handed = body;
    }
    return checked.call(this, body);
  };
  const codes = [];
  door.marks = codes;
  const timer = setTimeout(function () {
    answered({ status: 'timeout', sent: '' });
  }, ASK_MS);
  try {
    row.handler(req, res, function (e) {
      answered({ status: 'next', sent: String((e && e.stack) || e) });
    });
  } catch (e) {
    log.debug("Caught in askTheDoor(): " + ((e && e.message) || e));
    answered({ status: 'threw', sent: String((e && e.stack) || e) });
  }
  const out = await done;
  clearTimeout(timer);
  door.marks = null;
  let json = null;
  try {
    json = JSON.parse(handed);
  } catch (e) {
    log.debug("Caught in askTheDoor(): " + ((e && e.message) || e));
  }
  log.debug("Leaving askTheDoor(). " + out.status);
  return { status: out.status, codes: codes, json: json,
           sent: json ? '' : out.sent.slice(0, 600) };
}

// The API's own response check, installed as `/admin-api` installs it, over
// the document the API holds every answer to. One for every ask, so the
// document is built once.
function theDoor() {
  log.debug("Entering theDoor().");
  const spec = require('../mgmt-api/admin_api_spec');
  const adminApi = require('../mgmt-api/admin_api');
  const { ResponseModels } = require('../common/response_models');
  const door = { middleware: null, marks: null };
  const checks = new ResponseModels({ log: log,
    mark: function (res, code) {
      if (door.marks) {
        door.marks.push(code);
      }
    },
    tag: function (code) {
      return code + ' ';
    } });
  checks.install({ use: function (prefix, fn) {
    door.middleware = fn;
  } }, '/admin-api', function () {
    return spec.buildSpec(adminApi.ROUTES, { authRequired: true });
  }, spec.refusalSchema());
  log.debug("Leaving theDoor().");
  return door;
}

// The route-table row of `operationId`.
function rowOf(operationId) {
  log.debug("Entering rowOf(). " + operationId);
  const adminApi = require('../mgmt-api/admin_api');
  log.debug("Leaving rowOf().");
  return adminApi.ROUTES.filter(function (route) {
    return route.operationId === operationId;
  })[0];
}

// What a person needs to have done for every part of their answer to be
// drawn: signed in through the screen, a refresh on that session, a
// password grant with none, and a key pair of their own (RFC 7523); and a
// service account they own. Answers the names and how each seed went.
async function seedPeople() {
  log.debug("Entering seedPeople().");
  const http = require('http');
  const crypto = require('crypto');
  const app = require('../common/app');
  const config = require('../common/config');
  const keystore = require('../common/keystore');
  const helpers = require('../common/helpers');
  const pki = require('../common/pki');
  const applications = require('../common/applications');
  const ldap = require('../ldap/ldap_server');
  const pkiAdmin = require('../admin-ui/pki_admin');
  const serviceAccounts = require('../common/service_accounts');
  await keystore.start();
  await pki.start({ realmIds: [''],
    keySetFor: function (id) {
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      return false;
    } });
  config.setOverride('oauth2.consentRequired', false);
  const server = http.createServer(app);
  await new Promise(function (ok) {
    server.listen(0, '127.0.0.1', ok);
  });
  const port = server.address().port;
  const suffix = crypto.randomBytes(3).toString('hex');
  const client = { id: 'orm-rp-' + suffix,
                   redirect: 'https://rp.orm.example/cb',
                   secret: 'orm-secret-0123456789abcdef0123456789' };
  client.basic = 'Basic ' + Buffer.from(client.id + ':' + client.secret)
    .toString('base64');
  applications.createApplication({ identifier: client.id,
    protocols: ['oauth2', 'oidc'],
    fields: { oauthClientId: client.id, oauthClientSecret: client.secret,
              oauthRedirectUri: [client.redirect],
              oauthGrantType: ['authorization_code', 'refresh_token',
                'password'],
              oauthAllowedScope: ['openid', 'offline_access', 'profile'],
              oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
  const seeds = {};
  const person = 'orm-person-' + suffix;
  ldap.createUser(person, { invent: false });
  const flow = await codeFlow(port, client, person);
  seeds.codeFlow = flow.error || 'ok';
  const refreshed = await loopback(port, {}, 'POST', '/oauth2/token', {
    headers: { authorization: client.basic },
    form: { grant_type: 'refresh_token',
            refresh_token: String(flow.refresh_token || '') } });
  seeds.refresh = refreshed.status;
  const ropc = await loopback(port, {}, 'POST', '/oauth2/token', {
    headers: { authorization: client.basic },
    form: { grant_type: 'password', username: person, password: 'x',
            scope: 'openid' } });
  seeds.passwordGrant = ropc.status;
  const keyPair = await pkiAdmin.pkiAction({ action: 'issue',
    target: 'person', purpose: 'jwt', identifier: person,
    leafKeyAlg: 'rsa-2048' });
  seeds.keyPair = keyPair && keyPair.ok ? 'ok'
    : JSON.stringify(keyPair && (keyPair.why || keyPair.errors));
  const service = 'orm-service-' + suffix;
  ldap.createUser(service, { invent: false });
  const made = serviceAccounts.set(service, { serviceAccount: true,
                                              owners: [person] });
  seeds.serviceAccount = made && made.ok ? 'ok' : JSON.stringify(made);
  // Not waited for: what it still holds is the child's, which exits.
  server.close();
  log.debug("Leaving seedPeople().");
  return { seeds: seeds, person: person, service: service,
           application: client.id, unknown: 'orm-never-seen-' + suffix };
}

// IN THE CHILD, with the whole stack loaded: the seeds, then each answer.
async function usersAnswers() {
  log.debug("Entering usersAnswers().");
  const seeded = await seedPeople();
  const door = theDoor();
  const row = rowOf('getUsers');
  const asks = {
    list: {},
    services: { kind: 'service' },
    person: { user: seeded.person },
    personSecondPage: { user: seeded.person,
                        authenticationHistoryPage: '2', per: '1' },
    serviceAccount: { user: seeded.service },
    unknown: { user: seeded.unknown }
  };
  const answers = {};
  for (const name of Object.keys(asks)) {
    answers[name] = await askTheDoor(door, row, '/admin-api/users',
                                     asks[name]);
  }
  log.debug("Leaving usersAnswers().");
  return Object.assign(seeded, { answers: answers });
}

// THE DRILL-DOWNS OF WHAT WAS SEEDED: the reads that answer one object
// rather than a list, asked for the person, the service account and the
// application the seeds made. Answers each ask's `{ status, codes, sent }`.
async function seededDrillDowns(seeded) {
  log.debug("Entering seededDrillDowns().");
  const door = theDoor();
  const asks = [
    ['getApplications', { application: seeded.application }],
    ['getApplications', { claimsUser: seeded.person }],
    ['getServiceAccounts', { account: seeded.service }],
    ['getLiveSessions', { user: seeded.person }],
    ['getUserInfoClaims', { user: seeded.person }],
    ['getSamlAttributes', { user: seeded.person }],
    ['getIssued', { state: 'valid' }],
    ['getAudit', { actor: seeded.person }]
  ];
  const out = [];
  for (const ask of asks) {
    const row = rowOf(ask[0]);
    const one = await askTheDoor(door, row, row.path, ask[1]);
    out.push({ operationId: ask[0], query: ask[1], status: one.status,
               codes: one.codes, sent: one.sent,
               members: Object.keys(one.json || {}) });
  }
  log.debug("Leaving seededDrillDowns().");
  return out;
}

// EVERY PLAIN READ, ASKED (2026-11-16): each management GET whose path names
// nothing, asked of its own handler with no query, through the API's own
// check, after the seeds above. What `sts_admin_api_operations.js` does to a
// stack, done here so that a member a view adds and its model lacks is caught
// by the unit job — which runs first, and on whose failure that stack job
// never runs. Answers each operation's `{ status, codes, sent }`.
async function everyPlainRead() {
  log.debug("Entering everyPlainRead().");
  const adminApi = require('../mgmt-api/admin_api');
  const door = theDoor();
  const rows = adminApi.ROUTES.filter(function (route) {
    return route.method === 'GET' && route.operationId && !route.actions &&
      (route.kind || 'management') === 'management' &&
      typeof route.path === 'string' && route.path.indexOf(':') < 0;
  });
  const out = {};
  for (const row of rows) {
    const one = await askTheDoor(door, row, row.path, {});
    out[row.operationId] = { path: row.path, status: one.status,
                             codes: one.codes, sent: one.sent };
  }
  log.debug("Leaving everyPlainRead(). " + rows.length);
  return out;
}

// IN A CHILD: the operation tables are complete only with the whole stack loaded,
// which runs load-time effects this runner's other files must not inherit.
async function buildDocuments(out) {
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
  const users = await usersAnswers();
  fs.writeFileSync(out, JSON.stringify({
    finalization: finalized.finalization,
    // What the read barrier reports on `/admin-api/cluster` and
    // `/admin-api/persistence`, from the module itself (run 22: a counter
    // added there and not to the model answered both 500).
    barrier: require('../cluster/cluster_barrier').report(),
    // What each `/admin-api/ldap/*` operation answers, from its own view
    // (#1760: `jsonBlob` on the PEP schema's rows answered 500).
    directoryPages: await directoryPages(),
    // What `GET /admin-api/users` answers for the list, a person, a
    // service account and a stranger, from its own handler (#1845).
    users: users,
    // The one-object reads of what the seeds made.
    drillDowns: await seededDrillDowns(users),
    // And every management GET whose path names nothing, after them.
    plainReads: await everyPlainRead(),
    // Each management operation whose console twin answers more (#454):
    // the twin's operation and the members the management answer drops.
    consoleTwins: adminApi.ROUTES.filter(function (route) {
      return route.consoleMembers;
    }).map(function (route) {
      return { operationId: route.operationId, twin: route.consoleTwin,
               members: route.consoleMembers };
    }),
    admin: spec.buildSpec(adminApi.ROUTES, { authRequired: true }),
    // The two as `/admin-api/openapi.json` and its console twin serve them, for
    // the published pages (`tests/tools/openapi_pages.js`).
    management: spec.buildSpec(adminApi.ROUTES.filter(function (route) {
      return (route.kind || 'management') === 'management';
    }), { authRequired: true }),
    console: spec.buildSpec(adminApi.ROUTES.filter(function (route) {
      return route.kind === 'console';
    }), { authRequired: true, console: true }),
    account: AccountApiSpec.document({}),
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

// THE READ BARRIER'S COUNTERS MEET EVERY MODEL OF THEM. Run 22 (2026-11-13):
// #884's review added `checkRefusals` to `cluster_barrier.js`'s report and not
// to the model, so `GET /admin-api/cluster` answered 500 (STS-API-0139) and
// nothing in process asked. The report is the module's own, every member
// present, so a member the model lacks is caught here rather than by a stack.
function theBarrierReportMeetsEveryModel(t, docs) {
  log.debug("Entering theBarrierReportMeetsEveryModel().");
  const Ajv = require('ajv');
  const ajv = new Ajv({ strict: false, allErrors: true });
  const sites = [];
  const walk = function (node, seen) {
    if (!node || typeof node !== 'object' || seen.has(node)) {
      return;
    }
    seen.add(node);
    if (node.properties && node.properties.barrier &&
        node.properties.barrier.properties &&
        node.properties.barrier.properties.heldForCommit) {
      sites.push(node.properties.barrier);
    }
    Object.keys(node).forEach(function (k) {
      walk(node[k], seen);
    });
  };
  const doc = docs.admin;
  walk({ paths: doc.paths, components: doc.components }, new Set());
  t.check(sites.length > 0, 'admin models the read barrier\'s counters', '');
  t.check(Object.keys(docs.barrier).length > 10,
          'the barrier reports its counters (' +
          Object.keys(docs.barrier).join(', ') + ')', '');
  sites.forEach(function (schema) {
    const validate = ajv.compile({ allOf: [schema],
                                   components: doc.components });
    t.check(validate(docs.barrier),
            'the barrier\'s report meets its model',
            JSON.stringify(validate.errors || []));
    t.check(!validate(Object.assign({ notAMember: 1 }, docs.barrier)),
            'and the model is closed', '');
  });
  log.debug("Leaving theBarrierReportMeetsEveryModel().");
}

// The 200 model of the management API operation at `GET <path>`, or null.
function okModelOf(doc, at) {
  log.debug("Entering okModelOf().");
  const op = (doc.paths[at] || {}).get;
  const content = op && op.responses && op.responses['200'] &&
    op.responses['200'].content;
  const model = content && content['application/json'] &&
    content['application/json'].schema;
  log.debug("Leaving okModelOf().");
  return model || null;
}

// EVERY `/admin-api/ldap/*` ANSWER, BUILT BY ITS OWN VIEW, MEETS ITS MODEL.
// 2026-11-16: #1760 marked six `xacmlPep*` attributes `jsonBlob: true` in
// `models/directory/xacml_pep.tsp`, the generator copies that onto each row
// of the SCHEMA table, and `GET /admin-api/ldap/peps` publishes the table
// whole, so the answer carried a member its model did not declare and was a
// 500 (STS-API-0139) on every call. Nothing in process built the answer, and
// the stack job that walks every read (`sts_admin_api_operations.js`) never
// ran on develop after it: the mode jobs are skipped when the unit job
// fails. The pages' answers come from the views themselves, against the
// directory the child loaded, so a member the model lacks is caught here.
function everyDirectoryPageMeetsItsModel(t, docs) {
  log.debug("Entering everyDirectoryPageMeetsItsModel().");
  const Ajv = require('ajv');
  const addFormats = require('ajv-formats');
  const ajv = new Ajv({ strict: false, allErrors: true, coerceTypes: false,
                        useDefaults: false });
  addFormats(ajv);
  const doc = docs.admin;
  const pages = docs.directoryPages || {};
  // The pages that publish an owning module's SCHEMA table, which must each
  // be built with it, or this check would pass by building nothing.
  const withSchema = ['applications', 'federations', 'spiffe', 'roles',
    'policies', 'peps', 'devices'];
  Object.keys(pages).forEach(function (name) {
    const at = '/admin-api/ldap/' + name;
    const model = okModelOf(doc, at);
    t.check(!!model, 'GET ' + at + ' has a 200 model', '');
    const page = pages[name];
    t.check(!page.error && page.json && typeof page.json === 'object',
            'GET ' + at + ': its view builds an answer',
            String(page.error || ''));
    if (!model || !page.json || typeof page.json !== 'object') {
      return;
    }
    if (withSchema.indexOf(name) >= 0) {
      t.check(page.json.schema &&
              Array.isArray(page.json.schema.attributes) &&
              page.json.schema.attributes.length > 0,
              'GET ' + at + ' publishes its SCHEMA table',
              JSON.stringify(Object.keys(page.json)));
    }
    const validate = ajv.compile({ allOf: [model],
                                   components: doc.components });
    t.check(validate(page.json), 'GET ' + at + '\'s answer meets its model',
            JSON.stringify((validate.errors || []).slice(0, 5)));
  });
  t.check(Object.keys(pages).length === 9,
          'all nine directory pages were built: ' +
          Object.keys(pages).join(', '), '');
  log.debug("Leaving everyDirectoryPageMeetsItsModel().");
}

// EVERY ANSWER OF `GET /admin-api/users` MEETS ITS MODEL (#1845, #1846). The
// child asked the operation's own handler, behind the API's own check, for
// the list, the service accounts, a person who signed in (on page one of
// their history and on page two), a service account and a stranger. Each is
// held twice: the check must have let it through as a 200, and the body must
// meet `getUsers`' 200 model in the Management API OpenAPI document. And each
// seed must have taken, or the person's answer would have empty lists and
// the check would pass by building nothing.
function everyUsersAnswerMeetsItsModel(t, docs) {
  log.debug("Entering everyUsersAnswerMeetsItsModel().");
  const Ajv = require('ajv');
  const addFormats = require('ajv-formats');
  const ajv = new Ajv({ strict: false, allErrors: true, coerceTypes: false,
                        useDefaults: false });
  addFormats(ajv);
  const users = docs.users || { seeds: {}, answers: {} };
  const seeds = users.seeds || {};
  t.check(seeds.codeFlow === 'ok' && seeds.refresh === 200 &&
          seeds.passwordGrant === 200 && seeds.keyPair === 'ok' &&
          seeds.serviceAccount === 'ok',
          'users: the person signed in, was issued tokens on a session and ' +
          'off one and a key pair, and owns a service account',
          JSON.stringify(seeds));
  const doc = docs.management;
  const model = okModelOf(doc, '/admin-api/users');
  t.check(!!model, 'GET /admin-api/users has a 200 model in the ' +
          'Management API OpenAPI document', '');
  const validate = model ? ajv.compile({ allOf: [model],
                                         components: doc.components })
    : function () {
      return false;
    };
  const answers = users.answers || {};
  const asked = ['list', 'services', 'person', 'personSecondPage',
    'serviceAccount', 'unknown'];
  asked.forEach(function (name) {
    const one = answers[name] || {};
    t.check(one.status === 200 && (one.codes || []).length === 0,
            'GET /admin-api/users (' + name + '): the API\'s own check ' +
            'lets the answer through',
            JSON.stringify({ status: one.status, codes: one.codes,
                             sent: one.sent }));
    const met = !!one.json && validate(one.json);
    // `anyOf` reports every branch; a person's answer is `UserDetail`'s.
    const errors = validate.errors || [];
    const detail = errors.filter(function (e) {
      return /UserDetail/.test(String(e.schemaPath));
    });
    t.check(met, 'GET /admin-api/users (' + name + '): the answer meets ' +
            'the Management API OpenAPI document\'s model',
            JSON.stringify((detail.length ? detail : errors).slice(0, 5)));
  });
  // WHAT EACH ANSWER HAD TO CARRY for the check to mean anything.
  const p = (answers.person || {}).json || {};
  const sessions = [].concat(p.sessions || []);
  const onSessions = sessions.reduce(function (n, s) {
    return n + [].concat(s.tokens || []).length;
  }, 0);
  t.check(p.known === true && [].concat((p.user || {}).events || [])
    .length >= 1 && [].concat(p.authenticationHistory || []).length >= 1 &&
          !!p.authenticationHistoryPaging && sessions.length >= 1 &&
          onSessions >= 1 &&
          [].concat(p.tokensWithNoSession || []).length >= 1 &&
          [].concat(p.authenticationEvents || []).length >= 1,
          'users: the person\'s answer carries their history and its ' +
          'paging, a session with tokens on it, a token on none, and ' +
          'their attempts',
          JSON.stringify({ known: p.known, members: Object.keys(p),
                           sessions: sessions.length,
                           onSessions: onSessions }));
  const second = (answers.personSecondPage || {}).json || {};
  t.check(((second.authenticationHistoryPaging || {}).page) === 2,
          'users: and page two of their history is page two',
          JSON.stringify(second.authenticationHistoryPaging));
  const s = (answers.serviceAccount || {}).json || {};
  t.check(s.known === true && !!s.serviceAccount,
          'users: the service account\'s answer says it is one',
          JSON.stringify({ known: s.known,
                           serviceAccount: s.serviceAccount }));
  const u = (answers.unknown || {}).json || {};
  t.check(u.known === false, 'users: a name never seen is known: false',
          JSON.stringify(u));
  const list = (answers.list || {}).json || {};
  const listed = [].concat(list.users || []).map(function (row) {
    return row.key || row.name;
  });
  t.check(listed.indexOf(users.person) >= 0,
          'users: the list carries the person', JSON.stringify(listed));
  log.debug("Leaving everyUsersAnswerMeetsItsModel().");
}

// EVERY PLAIN READ MEETS ITS MODEL: no management GET whose path names
// nothing, asked with no query after the seeds, was refused by the API's own
// check (STS-API-0139) or threw past its handler (STS-API-0140). A handler
// that did not answer here (one that needs what this child has not got) is
// listed, not failed: what it would have sent is not known.
function everyPlainReadMeetsItsModel(t, docs) {
  log.debug("Entering everyPlainReadMeetsItsModel().");
  const reads = docs.plainReads || {};
  const ids = Object.keys(reads);
  const refused = ids.filter(function (id) {
    const codes = reads[id].codes || [];
    return codes.indexOf('STS-API-0139') >= 0 ||
      codes.indexOf('STS-API-0140') >= 0;
  }).map(function (id) {
    return id + ' ' + reads[id].path + ' ' + reads[id].status + ' ' +
      (reads[id].codes || []).join(',');
  });
  const unanswered = ids.filter(function (id) {
    return typeof reads[id].status !== 'number';
  }).map(function (id) {
    return id + ' (' + reads[id].status + ': ' +
      String(reads[id].sent || '').split('\n')[0].slice(0, 160) + ')';
  });
  const byStatus = {};
  ids.forEach(function (id) {
    const key = String(reads[id].status);
    byStatus[key] = (byStatus[key] || 0) + 1;
  });
  t.check(ids.length >= 100 && refused.length === 0,
          'every plain management read meets its model (' + ids.length +
          ' asked, ' + JSON.stringify(byStatus) + '): ' +
          refused.join('; '), '');
  log.info('plain reads not answered here: ' + unanswered.length +
           (unanswered.length ? '\n  ' + unanswered.join('\n  ') : ''));
  log.debug("Leaving everyPlainReadMeetsItsModel().");
}

// THE DRILL-DOWNS OF WHAT WAS SEEDED MEET THEIR MODELS: each one-object
// read the child asked answered 200, through the API's own check.
function everySeededDrillDownMeetsItsModel(t, docs) {
  log.debug("Entering everySeededDrillDownMeetsItsModel().");
  const asked = docs.drillDowns || [];
  t.check(asked.length >= 8, 'the seeded drill-downs were asked (' +
          asked.length + ')', '');
  asked.forEach(function (one) {
    t.check(one.status === 200 && (one.codes || []).length === 0,
            'GET ' + one.operationId + ' ' + JSON.stringify(one.query) +
            ': answered 200 through the API\'s own check',
            JSON.stringify({ status: one.status, codes: one.codes,
                             sent: one.sent,
                             members: (one.members || []).slice(0, 12) }));
  });
  log.debug("Leaving everySeededDrillDownMeetsItsModel().");
}

// The members a model declares, `$ref`s and `allOf`/`anyOf`/`oneOf`
// followed, at its top level.
function topMembers(doc, schema, seen) {
  log.debug("Entering topMembers().");
  const out = new Set();
  let node = schema;
  const been = seen || new Set();
  while (node && node.$ref) {
    if (been.has(node.$ref)) {
      log.debug("Leaving topMembers(). A cycle.");
      return out;
    }
    been.add(node.$ref);
    node = doc.components.schemas[node.$ref.split('/').pop()];
  }
  if (!node) {
    log.debug("Leaving topMembers(). Nothing.");
    return out;
  }
  Object.keys(node.properties || {}).forEach(function (name) {
    out.add(name);
  });
  ['allOf', 'anyOf', 'oneOf'].forEach(function (key) {
    (node[key] || []).forEach(function (one) {
      topMembers(doc, one, been).forEach(function (name) {
        out.add(name);
      });
    });
  });
  log.debug("Leaving topMembers().");
  return out;
}

// ONE ANSWER, ONE MODEL (2026-11-16). #1845 was a member added to a copy:
// `models/api/console.tsp` carried 74 models under the names the Management
// API OpenAPI document gives them — `UserDetail` among them — and no console
// operation used any of them, so a member added there was read by nothing,
// and the answer it was meant for still failed its real model. The copies
// are deleted, and the models the two documents really share live once, in
// `common.tsp` (models/CLAUDE.md, *One model, one place*). Three halves:
//
//   * A MODEL THE TWO DOCUMENTS BOTH NAME IS A `common.tsp` COMPONENT, and
//     so the same model, whole: neither document's own namespace may declare
//     it (the build refuses that too, `lib/api_lib.mjs`).
//   * EVERY COMPONENT OF THE ADMIN CONSOLE API OPENAPI DOCUMENT IS REACHED
//     FROM ONE OF ITS OPERATIONS, so no copy no operation reads can come
//     back. `tests/model_typespec.js` holds the same of every declaration in
//     `console.tsp`, the hoisted ones included.
//   * A CONSOLE TWIN (#454) answers what its management operation answers
//     and the members `sendJson()` drops from that one: the management
//     model's members are the twin's, and the twin's are the management
//     model's and the dropped ones. No path is in both documents (each twin
//     is under `/admin-api/console`), so the pairs are the route table's.
function consoleAndManagementAgree(t, docs) {
  log.debug("Entering consoleAndManagementAgree().");
  const management = docs.management;
  const consoleDoc = docs.console;
  const ms = management.components.schemas;
  const cs = consoleDoc.components.schemas;
  const common = [];
  const declared = /@component\s+model\s+`?(\w+)`?/g;
  const source = fs.readFileSync(path.join(ROOT, 'models', 'api',
    'common.tsp'), 'utf8');
  let found = declared.exec(source);
  while (found) {
    common.push(found[1]);
    found = declared.exec(source);
  }
  const shared = Object.keys(cs).filter(function (name) {
    return Object.prototype.hasOwnProperty.call(ms, name);
  });
  const notCommon = shared.filter(function (name) {
    return common.indexOf(name) < 0 ||
      JSON.stringify(cs[name]) !== JSON.stringify(ms[name]);
  });
  t.check(common.length > 0 && notCommon.length === 0,
          'a model both documents name is one model, a common.tsp ' +
          'component (' + shared.length + ' shared, ' + common.length +
          ' in common.tsp): ' + notCommon.join(', '), '');
  const reached = new Set();
  const pending = [consoleDoc.paths];
  while (pending.length > 0) {
    const node = pending.pop();
    if (!node || typeof node !== 'object') {
      continue;
    }
    if (typeof node.$ref === 'string') {
      const name = node.$ref.split('/').pop();
      if (!reached.has(name)) {
        reached.add(name);
        pending.push(cs[name]);
      }
    }
    Object.keys(node).forEach(function (key) {
      pending.push(node[key]);
    });
  }
  const unread = Object.keys(cs).filter(function (name) {
    return !reached.has(name);
  });
  t.check(Object.keys(cs).length > 0 && unread.length === 0,
          'every component of the Admin Console API OpenAPI document is ' +
          'reached from one of its operations (' + Object.keys(cs).length +
          '): ' + unread.join(', '), '');
  const samePath = Object.keys(consoleDoc.paths).filter(function (at) {
    return Object.prototype.hasOwnProperty.call(management.paths, at);
  });
  t.check(samePath.length === 0, 'no path is in both documents, so a ' +
          'twin is paired by the route table: ' + samePath.join(', '), '');
  const twins = docs.consoleTwins || [];
  t.check(twins.length >= 4, 'the route table names the console twins: ' +
          twins.map(function (one) {
            return one.operationId;
          }).join(', '), '');
  twins.forEach(function (twin) {
    let managed = null;
    Object.keys(management.paths).forEach(function (at) {
      const op = management.paths[at].get;
      if (op && op.operationId === twin.operationId) {
        managed = at;
      }
    });
    const mModel = managed && okModelOf(management, managed);
    const cModel = okModelOf(consoleDoc, twin.twin);
    t.check(!!mModel && !!cModel, twin.operationId + ' and its twin ' +
            twin.twin + ' each have a 200 model', '');
    if (!mModel || !cModel) {
      return;
    }
    const m = Array.from(topMembers(management, mModel));
    const c = Array.from(topMembers(consoleDoc, cModel));
    const missing = m.filter(function (k) {
      return c.indexOf(k) < 0;
    });
    const extra = c.filter(function (k) {
      return m.indexOf(k) < 0 && twin.members.indexOf(k) < 0;
    });
    t.check(missing.length === 0 && extra.length === 0,
            twin.operationId + ' and ' + twin.twin + ' declare the same ' +
            'members, but for the console\'s own (' +
            twin.members.join(', ') + ')',
            JSON.stringify({ notInTheTwin: missing,
                             notInTheManagementModel: extra }));
  });
  log.debug("Leaving consoleAndManagementAgree().");
}

// EVERY ROW THE MODEL'S GENERATOR WRITES INTO A SCHEMA TABLE MEETS THE
// PUBLISHED ROW MODEL. Each directory object's table is read from
// `models/generated/<id>.schema.json` and the `/admin-api/ldap/*` pages
// publish a module's table whole as `schema` (`WithObjectClassesAttributes`),
// so a key `models/lib/model_lib.mjs`'s `ROW_KEYS` passes through and the row
// model does not declare is a 500 on the first page that publishes that
// object, as `jsonBlob` was. Every table is held, published today or not.
function everySchemaRowMeetsTheRowModel(t, docs) {
  log.debug("Entering everySchemaRowMeetsTheRowModel().");
  const Ajv = require('ajv');
  const ajv = new Ajv({ strict: false, allErrors: true });
  const doc = docs.admin;
  let model = okModelOf(doc, '/admin-api/ldap/peps') || {};
  if (model.$ref) {
    model = doc.components.schemas[model.$ref.split('/').pop()] || {};
  }
  const schemaModel = (model.properties || {}).schema;
  t.check(!!schemaModel, 'the PEP page models its SCHEMA table', '');
  if (!schemaModel) {
    log.debug("Leaving everySchemaRowMeetsTheRowModel(). No model.");
    return;
  }
  const validate = ajv.compile({ allOf: [schemaModel],
                                 components: doc.components });
  const dir = path.join(ROOT, 'models', 'generated');
  const tables = fs.readdirSync(dir).filter(function (f) {
    return /\.schema\.json$/.test(f);
  });
  t.check(tables.length > 10, 'the generated tables were found: ' +
          tables.length, '');
  const wrong = [];
  tables.forEach(function (f) {
    const table = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    const shown = { objectClasses: table.objectClasses || [],
                    attributes: table.attributes || [] };
    if (!validate(shown)) {
      wrong.push(f + ': ' + JSON.stringify((validate.errors || [])
        .slice(0, 3)));
    }
  });
  t.check(wrong.length === 0, 'every generated SCHEMA table\'s rows meet ' +
          'the published row model: ' + wrong.join('; '), '');
  log.debug("Leaving everySchemaRowMeetsTheRowModel().");
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

// What compiling one model says: null when it compiles, ajv's sentence when
// it will not — the validator's own form, `allOf` beside the document's
// components (`common/response_models.ts`, `validatorFor()`).
function compileProblem(ajv, schema, components) {
  log.debug("Entering compileProblem().");
  try {
    ajv.compile({ allOf: [schema], components: components });
  } catch (e) {
    log.debug("Caught in compileProblem(): " + ((e && e.message) || e));
    log.debug("Leaving compileProblem(). It will not compile.");
    return String((e && e.message) || e);
  }
  log.debug("Leaving compileProblem().");
  return null;
}

function ruleOverDocuments(t) {
  log.debug("Entering ruleOverDocuments().");
  const docs = documents();
  aFinishedGrantMeetsEveryModel(t, docs);
  theBarrierReportMeetsEveryModel(t, docs);
  everyDirectoryPageMeetsItsModel(t, docs);
  everyUsersAnswerMeetsItsModel(t, docs);
  everyPlainReadMeetsItsModel(t, docs);
  everySeededDrillDownMeetsItsModel(t, docs);
  consoleAndManagementAgree(t, docs);
  everySchemaRowMeetsTheRowModel(t, docs);
  codesOnlyWhereDrawn(t, docs);
  delete docs.finalization;
  delete docs.barrier;
  delete docs.directoryPages;
  delete docs.users;
  delete docs.consoleTwins;
  delete docs.plainReads;
  delete docs.drillDowns;
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
  // EACH DISTINCT MODEL IS COMPILED ONCE (run 29, memory, 2026-11-14). This
  // loop compiled every row — 4780 of them — and only 890 are distinct: the
  // shared refusal model is on every operation, and `management` and
  // `console` are two views of `admin`'s routes. Each compile costs in
  // proportion to the document's `components` (1.4 MB for `admin`), which
  // ajv walks in full for every root it is handed, so the loop grew with
  // rows times components as the models grew: 120-240 s of this file's
  // 125-242 s in the runs of 11-13 and 11-14, 175 s measured alone in the
  // tests image, and past the runner's 300 s watchdog in the unit pool of
  // run 29 (killed with 151 assertions, the walk done at 9 s). The pool
  // only made it slower; the work was the file's own, so the answer is not
  // a longer watchdog or UNIT_ALONE (this file asserts nothing about time)
  // but not doing the same compile twice. The memory is EXACT, not an
  // approximation: its key is the document's components and the model's
  // own text, everything ajv's answer depends on with one instance and one
  // set of options, and every row sharing a broken model is still named.
  // Measured in the tests image beside a full run: 64 s for the 890
  // against 175 s for the 4780 in a script, and this check 83 s against
  // 181 s in the file itself.
  const outcomes = new Map();
  const broken = [];
  let compiled = 0;
  Object.keys(docs).forEach(function (api) {
    const doc = docs[api];
    const components = JSON.stringify(doc.components || {});
    Object.keys(doc.paths).forEach(function (p) {
      Object.keys(doc.paths[p]).forEach(function (m) {
        const responses = (doc.paths[p][m] || {}).responses || {};
        Object.keys(responses).forEach(function (status) {
          const content = responses[status].content || {};
          Object.keys(content).filter(function (type) {
            return /json/.test(type);
          }).forEach(function (type) {
            const key = components + '\u0000' +
              JSON.stringify(content[type].schema);
            if (!outcomes.has(key)) {
              outcomes.set(key, compileProblem(ajv, content[type].schema,
                                               doc.components));
            }
            const problem = outcomes.get(key);
            if (problem === null) {
              compiled += 1;
            } else {
              broken.push(api + ' ' + m + ' ' + p + ' ' + status + ': ' +
                          problem);
            }
          });
        });
      });
    });
  });
  t.check(broken.length === 0 && compiled > 1000, 'every model compiles (' +
          compiled + ', ' + outcomes.size + ' distinct): ' +
          broken.slice(0, 20).join('; '));
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
  compileFailureContained(t);
  pollutionNamed(t);
  unionsAndExceptions(t);
  sharingKeepsWhatModelsSay(t);
  nothingAnswersRoundTheDoor(t);
  ruleOverDocuments(t);
  log.debug("Leaving run().");
}

if (require.main === module && process.argv[2] === '--build') {
  buildDocuments(process.argv[3]).then(function () {
    process.exit(0);
  }, function (e) {
    log.debug("Caught in the --build child: " + ((e && e.message) || e));
    process.stderr.write(String((e && e.stack) || e) + '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'openapi_response_models',
  describe: 'Every OpenAPI operation has a closed response model, and every ' +
    'answer is held to it (#1353)',
  run: run,
  documents: documents
};
