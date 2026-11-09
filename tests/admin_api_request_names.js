// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_request_names.js
//
// ===========================================================================
// WHAT `/admin-api` REFUSES BY NAME (#1476, rcbj 2026-11-09).
//
// A query parameter an operation does not declare, a declared parameter whose
// value does not fit its type and a custom header no specification defines
// are each refused 400 with a code, and everything that is declared or
// standard still reaches the operation. `tests/protocol/schemathesis_kit.js`
// probes the running service; this file holds the rules, and the route
// wrapper with every handler replaced, so nothing here depends on a store.
//
//   A. `common/closed_sets.ts`'s `checkQueryDeclared()`.
//   B. `common/request_headers.ts`: one header per provider, the families,
//      HTTP/2's pseudo-headers and every internal header.
//   C. The wrapper, through the route table: both refusals on a route with
//      and without declared parameters, and a declared value still passing.
//   D. Every `x-sts-` name in the service's source is accepted.
//   E. The console asks an operation only what it declares.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'admin_api_request_names',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// One header from each group the service accepts whatever an operation
// declares.
const ACCEPTED_HEADERS = [
  'Accept-Language', 'Host', 'If-None-Match', 'Sec-CH-UA-Brand-New',
  'Sec-Fetch-Site', 'X-Forwarded-Client-Cert', 'Forwarded', 'X-Real-IP',
  'X-Request-Id',
  'Via', 'traceparent', 'tracestate',
  'X-Client-Cert', 'X-SSL-Client-Verify',
  // AWS
  'CloudFront-Viewer-Country', 'X-Amz-Cf-Id', 'X-Amzn-Trace-Id',
  'X-Origin-Verify',
  // Google Cloud
  'X-Cloud-Trace-Context', 'X-Goog-Request-Id',
  // Azure
  'X-Azure-FDID', 'X-ARR-LOG-ID', 'X-MS-Request-Id', 'X-Original-Host',
  // HTTP/2
  ':authority',
  // This service's own
  'x-sts-pool-protocol-worker', 'x-sts-ldap-drop', 'x-sts-listener',
  'x-sts-peer-certificate', 'x-sts-cell-from'
];

const REFUSED_HEADERS = ['X-Requested-With', 'X-Sts-Garbage', 'x-sts-garbage',
  'X-Foo',
                         'X-Csrf-Token', 'Sts-Whatever'];

/**
 * The child's program: the route table with every handler replaced, driven
 * through `registerRoutes()` against a fake app. A string run by `node -e`,
 * so it logs nothing of its own.
 */
function childMain() {
  const ROOT_DIR = process.env.RN_ROOT;
  const OUT = process.env.RN_OUT;
  const report = { error: null, rows: {} };
  (async function () {
    const api = require(ROOT_DIR + '/mgmt-api/admin_api');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const handlers = {};
    api.ROUTES.forEach(function (entry) {
      entry.handler = function (req, res) {
        res.status(200).send('handled');
      };
    });
    api.registerRoutes({
      use: function () {},
      get: function (p, h) {
        handlers['GET ' + p] = h;
      },
      post: function (p, h) {
        handlers['POST ' + p] = h;
      }
    });
    const call = function (key, query, headers, action) {
      return new Promise(function (resolve) {
        const res = {
          locals: {}, statusCode: 200,
          status: function (s) {
            this.statusCode = s;
            return this;
          },
          type: function () {
            return this;
          },
          set: function () {
            return this;
          },
          send: function (b) {
            resolve({ status: this.statusCode, body: String(b),
                      code: errorCodes.codeOf(this) });
            return this;
          }
        };
        handlers[key]({ params: { action: action || '' }, query: query,
                        headers: headers || {}, method: key.split(' ')[0],
                        body: '{}' }, res);
      });
    };
    const noParameters = 'GET /admin-api/crypto';
    const withParameters = 'GET /admin-api/audit';
    report.rows.routes = Object.keys(handlers).length;
    report.rows.unknownBare = await call(noParameters, { sts_garbage: 'v1' });
    report.rows.unknownDeclared = await call(withParameters,
                                             { sts_garbage: 'v1' });
    report.rows.wrongType = await call(withParameters, { page: 'abcSECRET' });
    report.rows.declared = await call(withParameters, { page: '2', per: '50' });
    report.rows.emptyDeclared = await call(withParameters, { page: '' });
    report.rows.bareOk = await call(noParameters, {});
    report.rows.cell = await call(noParameters, { cell: 'cac1' });
    report.rows.twinSvg = await call('GET /admin-api/delegation/user',
                                     { format: 'svg' });
    report.rows.header = await call(noParameters, {},
      { 'x-sts-garbage': 'hdrSECRET' });
    report.rows.headerOnDeclared = await call(withParameters, { page: '1' },
      { 'x-sts-garbage': 'hdrSECRET' });
    report.rows.internal = await call(noParameters, {},
      { 'x-sts-pool-protocol-worker': '1', 'x-sts-ldap-drop': 'a',
        'sec-ch-ua-new-hint': '?1', dpop: 'proof' });
    report.rows.postUnknown = await call('POST /admin-api/encryption/:action',
      { sts_garbage: '1' }, {}, 'rotate');
    report.rows.postHeader = await call('POST /admin-api/encryption/:action',
      {}, { 'x-sts-garbage': '1' }, 'rotate');
    report.rows.implicit = api.ROUTES.filter(function (entry) {
      const has = function (where, name) {
        return (entry.parameters || []).some(function (p) {
          return p.in === where && p.name === name;
        });
      };
      return !has('header', 'DPoP') || !has('query', 'cell');
    }).map(function (entry) {
      return entry.operationId || entry.path || entry.route;
    });
    // What the refusals read and what the document states are one list
    // (#1476): the routing rows' parameters are held to the model's.
    report.rows.modelParameters = (function () {
      const Spec = require(ROOT_DIR + '/mgmt-api/admin_api_spec').AdminApiSpec;
      const paths = Spec.merged().paths;
      const shape = function (list) {
        return JSON.stringify((list || []).map(function (one) {
          return [one.in, one.name, !!one.required].join(' ');
        }).sort());
      };
      const drift = [];
      api.ROUTES.forEach(function (entry) {
        Spec.keysOf(entry).forEach(function (key) {
          const stated = paths[key.path] && paths[key.path][key.method];
          const own = (entry.parameters || []).concat(
            (key.action && key.action.parameters) || []);
          if (stated && shape(stated.parameters) !== shape(own)) {
            drift.push(key.method + ' ' + key.path + ': the model says ' +
                       shape(stated.parameters) + ', the row ' + shape(own));
          }
        });
      });
      return drift;
    })();
    report.rows.queryNames = api.operationSummaries('all')
      .filter(function (row) {
        return row.method === 'GET';
      }).filter(function (row) {
        return !Array.isArray(row.query);
      }).map(function (row) {
        return row.path;
      });
    fs.writeFileSync(OUT, JSON.stringify(report));
    process.exit(0);
  })().catch(function (e) {
    report.error = String((e && e.stack) || e);
    fs.writeFileSync(OUT, JSON.stringify(report));
    process.exit(0);
  });
}

function loadReport() {
  log.debug("Entering loadReport().");
  const out = path.join(os.tmpdir(), 'rn-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RN_ROOT: ROOT, RN_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in loadReport(): " + ((e && e.message) || e));
    // No report: the child died before writing one; the caller says so.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught removing the report: " + ((e && e.message) || e));
  }
  log.debug("Leaving loadReport().");
  return { report: report, result: result };
}

function queryRules(t) {
  log.debug("Entering queryRules().");
  t.log.info('=== A. what a query may name and hold ===');
  const closedSets = require('../common/closed_sets');
  const declared = [
    { name: 'page', in: 'query', schema: { type: 'integer' } },
    { name: 'on', in: 'query', schema: { type: 'boolean' } },
    { name: 'q', in: 'query', schema: { type: 'string' } },
    { name: 'tags', in: 'query', schema: { type: 'array',
                                           items: { type: 'integer' } } },
    { name: 'DPoP', in: 'header', schema: { type: 'string' } }
  ];
  const ok = function (query) {
    return closedSets.checkQueryDeclared(declared, query).ok;
  };
  ['2', '-1', '+3', ' 7 ', ''].forEach(function (value) {
    t.check(ok({ page: value }), 'an integer accepts ' +
            JSON.stringify(value), '');
  });
  ['abc', '1.5', '1a'].forEach(function (value) {
    const got = closedSets.checkQueryDeclared(declared, { page: value });
    t.check(!got.ok && got.problem === 'type' && got.field === 'page' &&
            got.sentence.indexOf(value) < 0,
            'an integer refuses ' + JSON.stringify(value) +
            ', naming the parameter and not the value', got.sentence);
  });
  t.check(ok({ page: ['1', '2'] }),
          'a repeated integer is each of its values', '');
  t.check(!ok({ page: ['1', 'x'] }),
          'and one wrong member refuses the repeat', '');
  t.check(!ok({ page: { a: '1' } }), 'a nested value is not an integer', '');
  ['true', 'FALSE', '1', 'off'].forEach(function (value) {
    t.check(ok({ on: value }), 'a boolean accepts ' + value, '');
  });
  t.check(!ok({ on: 'maybe' }), 'a boolean refuses a word', '');
  t.check(ok({ tags: '1, 2' }), 'an array of integers, comma-separated', '');
  t.check(!ok({ tags: '1,x' }), 'and refuses a word among them', '');
  t.check(ok({ q: 'anything at all' }), 'a string takes any text', '');
  t.check(!ok({ q: { a: 'b' } }), 'but not a nested value', '');
  const unknown = closedSets.checkQueryDeclared(declared, { dPoP: 'x' });
  t.check(!unknown.ok && unknown.problem === 'unknown',
          'a query name matches a parameter exactly, and only `in: query`',
          JSON.stringify(unknown));
  log.debug("Leaving queryRules().");
}

function headerRules(t) {
  log.debug("Entering headerRules().");
  t.log.info('=== B. what a header may be ===');
  const headers = require('../common/request_headers');
  ACCEPTED_HEADERS.forEach(function (name) {
    t.check(headers.accepted(name), name + ' is accepted', '');
  });
  REFUSED_HEADERS.forEach(function (name) {
    const one = {};
    one[name] = 'hdrSECRET';
    const got = headers.check([], one);
    t.check(!headers.accepted(name) && !got.ok &&
            got.sentence.indexOf(name.toLowerCase()) >= 0 &&
            got.sentence.indexOf('hdrSECRET') < 0,
            name + ' is refused, naming the header and not its value',
            got.sentence);
  });
  const declared = [{ name: 'X-Declared-Here', in: 'header' }];
  t.check(headers.check(declared, { 'x-declared-here': '1' }).ok,
          'a header the operation declares is taken, in any case', '');
  t.check(!headers.check([], { 'x-declared-here': '1' }).ok,
          'and refused on an operation that does not', '');
  t.check(headers.check([{ name: 'x', in: 'query' }], {}).ok &&
          !headers.check([{ name: 'x-q', in: 'query' }],
                         { 'x-q': '1' }).ok,
          'a query parameter does not declare a header', '');
  log.debug("Leaving headerRules().");
}

function wrapper(t) {
  log.debug("Entering wrapper().");
  t.log.info('=== C. through the route wrapper ===');
  const loaded = loadReport();
  const report = loaded.report;
  if (!t.check(!!report && !report.error,
               'the child loaded the management API',
               report && report.error ? report.error.slice(0, 800) :
               'exit ' + loaded.result.status + ' ' +
               String(loaded.result.stderr || '').slice(-800))) {
    log.debug("Leaving wrapper().");
    return;
  }
  const r = report.rows;
  const refused = function (row, name, code) {
    return row.status === 400 && row.code === code &&
           row.body.indexOf(name) >= 0 &&
           row.body.indexOf('STS-') < 0;
  };
  t.check(r.routes > 200, r.routes + ' routes registered', '');
  t.check(refused(r.unknownBare, 'sts_garbage', 'STS-API-0142') &&
          r.unknownBare.body.indexOf('v1') < 0,
          'an unknown parameter on a route that declares none is refused',
          JSON.stringify(r.unknownBare));
  t.check(refused(r.unknownDeclared, 'sts_garbage', 'STS-API-0142'),
          'and on a route that declares some',
          JSON.stringify(r.unknownDeclared));
  t.check(refused(r.wrongType, 'page', 'STS-API-0143') &&
          r.wrongType.body.indexOf('abcSECRET') < 0,
          'a wrong-typed value is refused, and not echoed',
          JSON.stringify(r.wrongType));
  t.check(r.declared.status === 200 && r.declared.body === 'handled',
          'a declared value reaches the operation', JSON.stringify(r.declared));
  t.check(r.emptyDeclared.status === 200,
          'an empty value is absent, as at the other doors',
          JSON.stringify(r.emptyDeclared));
  t.check(r.bareOk.status === 200, 'no query at all is fine',
          JSON.stringify(r.bareOk));
  t.check(r.cell.status === 200, 'every operation takes `cell`',
          JSON.stringify(r.cell));
  t.check(r.twinSvg.status === 400 &&
          /the admin console's/.test(r.twinSvg.body),
          'format=svg at a management address is still told where the ' +
          'drawing is', JSON.stringify(r.twinSvg));
  t.check(refused(r.header, 'x-sts-garbage', 'STS-API-0144') &&
          r.header.body.indexOf('hdrSECRET') < 0,
          'an unknown header is refused, and its value not echoed',
          JSON.stringify(r.header));
  t.check(refused(r.headerOnDeclared, 'x-sts-garbage', 'STS-API-0144'),
          'on a route with parameters too', JSON.stringify(r.headerOnDeclared));
  t.check(r.internal.status === 200,
          'an internal pool header and a Sec-* hint still pass',
          JSON.stringify(r.internal));
  t.check(refused(r.postUnknown, 'sts_garbage', 'STS-API-0142') &&
          refused(r.postHeader, 'x-sts-garbage', 'STS-API-0144'),
          'a POST refuses both too', JSON.stringify([r.postUnknown,
                                                     r.postHeader]));
  t.equal(JSON.stringify(r.modelParameters.slice(0, 5)), '[]',
          'every routing row declares the parameters the model states (' +
          r.modelParameters.length + ' drifted)');
  t.equal(JSON.stringify(r.implicit), '[]',
          'every operation declares DPoP and cell');
  t.equal(JSON.stringify(r.queryNames), '[]',
          'every GET row of the console table names its query');
  log.debug("Leaving wrapper().");
}

function everyInternalName(t) {
  log.debug("Entering everyInternalName().");
  t.log.info('=== D. every internal header name ===');
  const headers = require('../common/request_headers');
  const names = new Set();
  const dirs = ['common', 'cluster', 'tls', 'ldap', 'kerberos', 'persistence',
                'mgmt-api', 'admin-ui', 'admin-core', 'oauth-oidc'];
  dirs.forEach(function (dir) {
    fs.readdirSync(path.join(ROOT, dir)).forEach(function (file) {
      if (!/\.(ts|js)$/.test(file)) {
        return;
      }
      const text = fs.readFileSync(path.join(ROOT, dir, file), 'utf8');
      (text.match(/['"]x-sts-[a-z0-9-]+['"]/g) || []).forEach(function (m) {
        names.add(m.slice(1, -1));
      });
    });
  });
  t.check(names.size >= 13, names.size + ' x-sts- names found', '');
  names.forEach(function (name) {
    t.check(headers.accepted(name), name + ' is accepted', '');
  });
  log.debug("Leaving everyInternalName().");
}

function consoleForwarding(t) {
  log.debug("Entering consoleForwarding().");
  t.log.info('=== E. what the console asks ===');
  const pages = require('../admin-ui/web_pages');
  const WebPages = pages.WebPages || pages;
  const query = { per: '20', notice: 'done', view: 'grid' };
  const forwarded = WebPages.operationQuery('/admin/audit', query,
                                            ['per', 'page']);
  t.equal(JSON.stringify(forwarded), JSON.stringify({ per: '20' }),
          'a page\'s own names are not asked of its operation');
  const unfiltered = WebPages.operationQuery('/admin/audit', query);
  t.equal(Object.keys(unfiltered).length, 3,
          'with no table in hand everything is forwarded');
  const mapped = WebPages.operationQuery('/admin/caep-sessions/session',
                                         { id: 'a', notice: 'b' }, ['session']);
  t.equal(JSON.stringify(mapped), JSON.stringify({ session: 'a' }),
          'a renamed parameter is checked under the operation\'s name');
  log.debug("Leaving consoleForwarding().");
}

function run(t) {
  log.debug("Entering run().");
  queryRules(t);
  headerRules(t);
  wrapper(t);
  everyInternalName(t);
  consoleForwarding(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_api_request_names',
  describe: '/admin-api refuses a query parameter it does not declare, a ' +
            'wrong-typed value and a custom header, each with a 400 and ' +
            'a code (#1476)',
  run: run
};
