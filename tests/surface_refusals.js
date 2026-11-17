// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: surface_refusals.js
//
// ===========================================================================
// A REQUEST REFUSED AHEAD OF EVERY ROUTE IS ANSWERED IN THE ERROR SHAPE OF THE
// API IT WAS SENT TO (2026-11-16).
//
// The fuzzing of the remote PEP's control plane (PR #1858) found two answers
// from this service's own middleware that no model declared: a body over 5 MB
// was Express's HTML error page, and a control character in a query value was
// `text/plain`. `common/surface_refusals.ts` now writes each JSON API's own
// shape for every refusal made before the router. Each section drives the REAL
// `common/app.js` over a socket, with no route registered here — every one of
// these refusals is made before a route could run:
//
//   A. A BODY OVER 5 MB (STS-HTTP-0004) is 413 on every JSON API, in its shape.
//   B. A CHARSET OR CONTENT ENCODING THE PARSERS DO NOT READ (STS-HTTP-0012)
//      is 415, in the same shapes.
//   C. THE VALIDATION GUARD (STS-HTTP-0010, -0011): a control character in a
//      query value, and a polluting parameter name, are 400, in the shapes.
//   D. THE REQUEST CEILING (STS-CORE-0172) is 429 with Retry-After.
//   E. EVERYTHING ELSE ANSWERS AS IT DID: a console page's 413 is Express's
//      page, the authorization endpoint's 400 is plain text, and an unrouted
//      path is still `Cannot GET /path`.
//   F. THE PEP CONTROL PLANE'S MODEL DECLARES WHAT IS SENT: every operation
//      of `xacml-pep/openapi/pep-control-plane.json` declares each refusal at
//      its status, and the body meets the model.
//
// Every answer is held to: the status, the media type, the shape, no error
// code anywhere in it, and `Cache-Control: no-store`. The four published
// APIs' models are held to the same bodies in `openapi_response_models.js`,
// which has their documents.
//
// WHY IN PROCESS: the claim is about the middleware chain before any route;
// a protocol job could make these requests, but nothing in it would need a
// stack, and the shapes for every surface are checked in one place here.
// ===========================================================================

const http = require('http');
const path = require('path');
const fs = require('fs');

const log = require('bunyan').createLogger({
  name: 'surface_refusals',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.resolve(__dirname, '..');

const CODE = /STS-[A-Z0-9]+-\d{4}/;

const SCIM_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';

// One POST per JSON API, at a path that API serves (no route is needed: the
// refusal is made before one is chosen), and the shape it must answer in.
const POSTS = [
  { surface: 'management', path: '/admin-api/users/create' },
  { surface: 'account', path: '/account-api/profile' },
  { surface: 'authn', path: '/authn-api/pending/x/password' },
  { surface: 'report', path: '/report-api/jobs' },
  { surface: 'pep', path: '/xacml/pep/heartbeat' },
  { surface: 'pep', path: '/xacml/pep/saml' },
  { surface: 'pip', path: '/xacml/pip' },
  { surface: 'authzen', path: '/access/v1/evaluation' },
  { surface: 'scim', path: '/scim/v2/Users' },
  { surface: 'oauth', path: '/oauth2/token' },
  { surface: 'oauth', path: '/oauth2/register' },
  { surface: 'oauth', path: '/oid4vci/credential' },
  { surface: 'gnap', path: '/gnap' },
  { surface: 'gnap', path: '/gnap/continue/abc' }
];

// One GET per JSON API for the guard.
const GETS = [
  { surface: 'management', path: '/admin-api/users' },
  { surface: 'account', path: '/account-api' },
  { surface: 'authn', path: '/authn-api' },
  { surface: 'report', path: '/report-api/catalog' },
  { surface: 'pep', path: '/xacml/pep/policies' },
  { surface: 'pep', path: '/xacml/pep/settings' },
  { surface: 'authzen', path: '/access/v1/access-requests/x' },
  { surface: 'scim', path: '/scim/v2/Users' },
  { surface: 'oauth', path: '/oauth2/userinfo' },
  { surface: 'gnap', path: '/gnap/token/x' }
];

/**
 * Sends one request and gathers the answer.
 *
 * @param port - the listener's port
 * @param method - the method
 * @param at - the path and query
 * @param headers - the request headers
 * @param body - the body, or null
 * @returns `{ status, type, cache, retryAfter, text }`
 */
function ask(port, method, at, headers, body) {
  log.debug("Entering ask().");
  log.debug("Leaving ask().");
  return new Promise(function (resolve, reject) {
    const req = http.request({ host: '127.0.0.1', port: port, method: method,
                               path: at, headers: headers || {} },
    function (res) {
      const chunks = [];
      res.on('data', function (c) {
        chunks.push(c);
      });
      res.on('end', function () {
        resolve({ status: res.statusCode,
                  type: String(res.headers['content-type'] || ''),
                  cache: String(res.headers['cache-control'] || ''),
                  retryAfter: String(res.headers['retry-after'] || ''),
                  text: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    if (body !== null && body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

/**
 * Says what is wrong with one answer, against the shape its surface promises,
 * or '' where nothing is.
 *
 * @param surface - the surface's name
 * @param status - the status it must carry
 * @param answer - what `ask()` gathered
 * @returns the problem, or ''
 */
function shapeProblem(surface, status, answer) {
  log.debug("Entering shapeProblem().");
  const wants = { pip: 'application/xml', scim: 'application/scim+json' };
  const media = wants[surface] || 'application/json';
  let problem = '';
  if (answer.status !== status) {
    problem = 'status ' + answer.status;
  } else if (answer.type.split(';')[0].trim() !== media) {
    problem = 'media type ' + answer.type;
  } else if (CODE.test(answer.text)) {
    problem = 'an error code in the body';
  } else if (answer.cache !== 'no-store') {
    problem = 'Cache-Control ' + answer.cache;
  } else if (surface === 'pip') {
    if (!/^<\?xml[^>]*\?>\s*<PIPError xmlns="urn:sts:xacml:pip:1\.0" error="(?:invalid_request|too_many_requests)">\s*<Description>[^<]+<\/Description>\s*<\/PIPError>\s*$/.test(answer.text)) {
      problem = 'not a PIPError: ' + answer.text.slice(0, 200);
    }
  } else {
    let body = null;
    try {
      body = JSON.parse(answer.text);
    } catch (e) {
      log.debug("Caught in shapeProblem(): " + ((e && e.message) || e));
      problem = 'not JSON: ' + answer.text.slice(0, 200);
    }
    if (body) {
      problem = memberProblem(surface, status, body);
    }
  }
  log.debug("Leaving shapeProblem().");
  return problem;
}

/**
 * The member check for one JSON body.
 *
 * @param surface - the surface's name
 * @param status - its status
 * @param body - the parsed body
 * @returns the problem, or ''
 */
function memberProblem(surface, status, body) {
  log.debug("Entering memberProblem().");
  const keys = Object.keys(body).sort().join(',');
  const said = function (s) {
    return typeof s === 'string' && s.length > 10;
  };
  const oauthCode = status === 429 ? 'too_many_requests' : 'invalid_request';
  let ok = false;
  if (surface === 'management' || surface === 'account') {
    ok = keys === 'errors,ok' && body.ok === false &&
      Array.isArray(body.errors) && body.errors.length === 1 &&
      said(body.errors[0]);
  } else if (surface === 'authn') {
    ok = keys === 'error,error_description,errors,ok' && body.ok === false &&
      body.error === oauthCode && said(body.error_description) &&
      body.errors[0] === body.error_description;
  } else if (surface === 'report') {
    ok = keys === 'error,error_description' && body.error === oauthCode &&
      said(body.error_description);
  } else if (surface === 'pep') {
    ok = (status === 429 ?
      keys === 'error,error_description,retryAfterS' && body.retryAfterS >= 1 :
      keys === 'error,error_description') &&
      body.error === oauthCode && said(body.error_description);
  } else if (surface === 'authzen') {
    ok = keys === 'error' && body.error.status === status &&
      Object.keys(body.error).sort().join(',') === 'message,status' &&
      said(body.error.message);
  } else if (surface === 'scim') {
    ok = Array.isArray(body.schemas) && body.schemas[0] === SCIM_ERROR &&
      body.status === String(status) && said(body.detail) &&
      (status === 400 ? ['invalidSyntax', 'invalidValue']
        .indexOf(body.scimType) >= 0 : body.scimType === undefined);
  } else if (surface === 'oauth') {
    ok = keys === 'error,error_description' &&
      body.error === 'invalid_request' && said(body.error_description);
  } else if (surface === 'gnap') {
    ok = keys === 'error' && body.error.code === 'invalid_request' &&
      said(body.error.description);
  }
  log.debug("Leaving memberProblem().");
  return ok ? '' : 'members ' + JSON.stringify(body).slice(0, 300);
}

// ---------------------------------------------------------------------------
// A and B. The body parsers' refusals.
// ---------------------------------------------------------------------------
async function bodyRefusals(t, port) {
  log.debug("Entering bodyRefusals().");
  t.log.info('=== A. a body over 5 MB is 413 in each API\'s shape ===');
  const big = '{"a":"' + 'x'.repeat(5 * 1024 * 1024) + '"}';
  for (const one of POSTS) {
    const type = one.surface === 'pip' ? 'application/xml' :
      one.surface === 'scim' ? 'application/scim+json' : 'application/json';
    const answer = await ask(port, 'POST', one.path,
                             { 'Content-Type': type,
                               'Content-Length': Buffer.byteLength(big) },
                             big);
    const problem = shapeProblem(one.surface, 413, answer);
    t.check(!problem, 'POST ' + one.path + ' with a body over 5 MB is 413 ' +
            'as ' + one.surface + ' answers a refusal', problem);
  }
  t.log.info('=== B. a charset or encoding not read is 415 in each shape ===');
  for (const one of POSTS) {
    const charset = await ask(port, 'POST', one.path,
      { 'Content-Type': 'application/json; charset=x-no-such-charset' },
      '{}');
    const p1 = shapeProblem(one.surface, 415, charset);
    t.check(!p1, 'POST ' + one.path + ' in an unknown charset is 415, ' +
            one.surface + '\'s shape', p1);
    const encoding = await ask(port, 'POST', one.path,
      { 'Content-Type': 'application/json', 'Content-Encoding': 'compress' },
      '{}');
    const p2 = shapeProblem(one.surface, 415, encoding);
    t.check(!p2, 'POST ' + one.path + ' in an unknown content encoding is ' +
            '415, ' + one.surface + '\'s shape', p2);
  }
  log.debug("Leaving bodyRefusals().");
}

// ---------------------------------------------------------------------------
// C. The validation guard.
// ---------------------------------------------------------------------------
async function guardRefusals(t, port) {
  log.debug("Entering guardRefusals().");
  t.log.info('=== C. the guard\'s 400 is in each API\'s shape ===');
  for (const one of GETS) {
    const control = await ask(port, 'GET', one.path + '?since=%01', {}, null);
    const p1 = shapeProblem(one.surface, 400, control);
    t.check(!p1, 'GET ' + one.path + '?since=%01 is 400, ' + one.surface +
            '\'s shape', p1);
    const polluting = await ask(port, 'GET', one.path + '?constructor=1', {},
                                null);
    const p2 = shapeProblem(one.surface, 400, polluting);
    t.check(!p2, 'GET ' + one.path + '?constructor=1 is 400, ' +
            one.surface + '\'s shape', p2);
  }
  // A POST's query is held by the same guard, and the PIP answers XML.
  for (const one of POSTS) {
    const answer = await ask(port, 'POST', one.path + '?x=%0d%0a',
                             { 'Content-Type': 'application/json' }, '{}');
    const problem = shapeProblem(one.surface, 400, answer);
    t.check(!problem, 'POST ' + one.path + '?x=%0d%0a is 400, ' +
            one.surface + '\'s shape', problem);
  }
  const scim = await ask(port, 'GET', '/scim/v2/Users?filter=%00', {}, null);
  t.equal(JSON.parse(scim.text).scimType, 'invalidValue',
          'SCIM names a refused query value invalidValue (RFC 7644 3.12)');
  log.debug("Leaving guardRefusals().");
}

// ---------------------------------------------------------------------------
// D. The request ceiling.
// ---------------------------------------------------------------------------
async function ceilingRefusals(t, port) {
  log.debug("Entering ceilingRefusals().");
  t.log.info('=== D. the request ceiling\'s 429 is in each API\'s shape ===');
  const config = require('../common/config');
  config.setOverride('security.requestsPerAddressPerMinute', 1);
  try {
    for (const one of GETS.concat(POSTS.filter(function (p) {
      return p.surface === 'pip';
    }))) {
      let answer = null;
      for (let i = 0; i < 3 && !(answer && answer.status === 429); i++) {
        answer = await ask(port, one.surface === 'pip' ? 'POST' : 'GET',
                           one.path, {}, null);
      }
      const problem = shapeProblem(one.surface, 429, answer);
      t.check(!problem && answer.retryAfter === '60',
              one.path + ' over the ceiling is 429 with Retry-After, ' +
              one.surface + '\'s shape', problem || answer.retryAfter);
    }
    let html = null;
    for (let i = 0; i < 3 && !(html && html.status === 429); i++) {
      html = await ask(port, 'GET', '/admin/users', {}, null);
    }
    t.check(html.status === 429 && /^text\/plain/.test(html.type),
            'a console page over the ceiling is the plain-text 429 it was',
            html.status + ' ' + html.type);
  } finally {
    config.clearOverride('security.requestsPerAddressPerMinute');
  }
  log.debug("Leaving ceilingRefusals().");
}

// ---------------------------------------------------------------------------
// E. Everything else as it was.
// ---------------------------------------------------------------------------
async function othersUnchanged(t, port) {
  log.debug("Entering othersUnchanged().");
  t.log.info('=== E. pages, the authorization endpoint and an unrouted ' +
             'path answer as they did ===');
  const big = 'x'.repeat(5 * 1024 * 1024 + 1);
  const form = { 'Content-Type': 'application/x-www-form-urlencoded' };
  const page = await ask(port, 'POST', '/admin/users', form, big);
  t.check(page.status === 413 && /^text\/html/.test(page.type) &&
          !CODE.test(page.text),
          'a console page\'s body over 5 MB is still Express\'s 413 page',
          page.status + ' ' + page.type);
  const authorize = await ask(port, 'GET', '/oauth2/authorize?state=%00', {},
                              null);
  t.check(authorize.status === 400 && /^text\/plain/.test(authorize.type) &&
          !CODE.test(authorize.text),
          'the authorization endpoint, a browser\'s, keeps the plain 400',
          authorize.status + ' ' + authorize.type);
  const unrouted = await ask(port, 'GET', '/no-such-path-surface-refusals',
                             {}, null);
  t.check(unrouted.status === 404 &&
          unrouted.text.indexOf('Cannot GET /no-such-path-surface-refusals') >=
            0, 'an unrouted path is still Express\'s own 404',
          unrouted.status + ' ' + unrouted.text.slice(0, 80));
  const unroutedApi = await ask(port, 'GET', '/admin-api-not-an-api', {},
                                null);
  t.check(unroutedApi.status === 404 &&
          unroutedApi.text.indexOf('Cannot GET') >= 0,
          'a path that only starts like an API is not one of them',
          unroutedApi.status);
  log.debug("Leaving othersUnchanged().");
}

// ---------------------------------------------------------------------------
// F. The PEP control plane's model.
// ---------------------------------------------------------------------------
function pepModelDeclares(t) {
  log.debug("Entering pepModelDeclares().");
  t.log.info('=== F. the PEP control plane model declares each refusal ===');
  const doc = JSON.parse(fs.readFileSync(path.join(ROOT, 'xacml-pep',
    'openapi', 'pep-control-plane.json'), 'utf8'));
  const { ResponseModels } = require('../common/response_models');
  const quiet = { debug: function () {}, error: function () {},
                  warn: function () {}, info: function () {} };
  const models = new ResponseModels({ log: quiet, mark: function () {},
                                      tag: function (code) {
                                        return '[' + code + '] ';
                                      } });
  const installed = models.installed(function () {
    return doc;
  });
  const SurfaceRefusals = require('../common/surface_refusals');
  const refusals = new SurfaceRefusals({ log: quiet });
  let held = 0;
  const wrong = [];
  Object.keys(doc.paths).forEach(function (template) {
    Object.keys(doc.paths[template]).forEach(function (method) {
      const op = doc.paths[template][method];
      const concrete = template.replace(/\{[^}]+\}/g, 'x');
      const surface = refusals.surfaceOf(concrete);
      if (!surface) {
        wrong.push(template + ' is no surface');
        return;
      }
      const statuses = [400, 429].concat(op.requestBody ? [413, 415] : []);
      statuses.forEach(function (status) {
        const shaped = refusals.shape(surface, status, 'A refusal ahead of ' +
                                      'every route.', { retryAfterS: 60 });
        held += 1;
        const declared = op.responses[String(status)];
        if (!declared || !declared.content ||
            !declared.content[shaped.type]) {
          wrong.push(method.toUpperCase() + ' ' + template + ' ' + status +
                     ': not declared as ' + shaped.type);
          return;
        }
        const problem = models.problemOf(installed,
          { method: method.toUpperCase(), baseUrl: '', path: concrete },
          { statusCode: status, get: function () {
            return shaped.type;
          } }, shaped.body);
        if (problem) {
          wrong.push(method.toUpperCase() + ' ' + template + ' ' + status +
                     ': ' + problem.where);
        }
      });
    });
  });
  t.check(held >= 40 && wrong.length === 0, 'every one of ' + held +
          ' refusals ahead of the routes is declared by the control plane ' +
          'model at its status, and meets it', wrong.slice(0, 20).join('; '));
  log.debug("Leaving pepModelDeclares().");
}

async function run(t) {
  log.debug("Entering run().");
  const app = require('../common/app');
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  try {
    await bodyRefusals(t, port);
    await guardRefusals(t, port);
    await ceilingRefusals(t, port);
    await othersUnchanged(t, port);
    pepModelDeclares(t);
  } finally {
    await new Promise(function (resolve) {
      server.close(resolve);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'surface_refusals',
  describe: 'a refusal ahead of every route answers in the error shape of ' +
            'the JSON API its path belongs to; everything else as it was',
  run: run
};
