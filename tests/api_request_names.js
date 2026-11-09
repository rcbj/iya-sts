// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: api_request_names.js
//
// ===========================================================================
// WHAT `/account-api`, `/authn-api` AND `/report-api` REFUSE BY NAME (#1483,
// rcbj 2026-11-09, on #1476's rules for `/admin-api`).
//
// A query parameter an operation does not declare, a declared parameter whose
// value its type does not hold and a custom header nobody defined are each a
// 400 with a code recorded and never sent, and the sentence names the
// parameter or header and not its value. `schemathesis_kit.js`'s probes hold
// the running service; this file holds the rule, each API's wrapper with its
// gate and handlers stubbed, the examples, and the portal's filter.
//
//   A. `common/request_headers.ts`'s `checkRequest()`, the shared check.
//   B. /account-api, through `run()`: the refusals, an accepted request.
//   C. /authn-api, through the route: the refusals, an accepted request, a
//      browser's own headers, and `X-CSRF-Token` declared on a POST alone.
//   D. /report-api, through `reportShapeRefused()`.
//   E. Every operation that can carry an example has one fitting its schema.
//   F. The portal asks an operation only what it declares.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'api_request_names',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const VALUE = 'SECRETvalue';

/**
 * The child's program: the whole stack loaded, each API's handlers stubbed,
 * driven with a fake request. A string run by `node -e`, so it logs nothing
 * of its own.
 */
function childMain() {
  const ROOT_DIR = process.env.RN_ROOT;
  const OUT = process.env.RN_OUT;
  const report = { error: null, rows: {}, docs: {} };
  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const fakeRes = function () {
      return { locals: {}, headersSent: false, statusCode: 200, body: '',
               status: function (s) {
                 this.statusCode = s;
                 return this;
               },
               set: function () {
                 return this;
               },
               type: function () {
                 return this;
               },
               send: function (b) {
                 this.body = String(b);
                 this.headersSent = true;
                 return this;
               } };
    };
    const summary = function (res) {
      return { status: res.statusCode, body: res.body,
               code: errorCodes.codeOf(res) };
    };
    const SECRET = 'SECRETvalue';

    // --- /account-api ------------------------------------------------------
    const accountApi = require(ROOT_DIR + '/account-api/account_api');
    const account = new accountApi.AccountApi(
      accountApi.AccountApi.defaultDeps());
    const ops = account.operations();
    const opAt = function (key) {
      return ops.filter(function (o) {
        return o.method + ' ' + o.path === key;
      })[0];
    };
    ops.forEach(function (o) {
      o.handler = function (req, res) {
        res.status(200).send('handled');
        return undefined;
      };
    });
    account.authenticate = function () {
      return { username: 'who', sub: 'sub', session: {} };
    };
    const callAccount = async function (key, query, headers) {
      const res = fakeRes();
      await account.run(opAt(key), { method: key.split(' ')[0], query: query,
        headers: headers || {}, body: '{}' }, res);
      return summary(res);
    };
    const R = report.rows;
    R.accountUnknown = await callAccount('GET /account-api/overview',
      { sts_garbage: SECRET });
    R.accountBare = await callAccount('GET /account-api/me',
      { sts_garbage: SECRET });
    R.accountWrongType = await callAccount('GET /account-api/applications',
      { page: 'abc' + SECRET });
    R.accountNested = await callAccount('GET /account-api/overview',
      { done: { a: SECRET } });
    R.accountHeader = await callAccount('GET /account-api/me', {},
      { 'x-sts-garbage': SECRET });
    R.accountDeclared = await callAccount('GET /account-api/applications',
      { page: '2', done: 'ok' });
    R.accountEmpty = await callAccount('GET /account-api/applications',
      { page: '' });
    R.accountBrowser = await callAccount('GET /account-api/me', {},
      { dpop: 'proof', 'x-requested-with': 'com.app', 'sec-fetch-site': 'same',
        accept: 'application/json', 'x-forwarded-for': '1.2.3.4' });
    R.accountPost = await callAccount('POST /account-api/language',
      { sts_garbage: '1' }, { 'content-type': 'application/json' });
    report.indexQuery = {};
    ops.filter(function (o) {
      return o.method === 'GET';
    }).forEach(function (o) {
      report.indexQuery[o.path] = account.queryNamesOf(o);
    });
    report.docs.account = accountApi.AccountApi.prototype.document.call(
      account, { headers: {}, protocol: 'https', get: function () {
        return ''; } });

    // --- /authn-api --------------------------------------------------------
    const authnMod = require(ROOT_DIR + '/authn/authn_api');
    const AuthnApi = authnMod.AuthnApi;
    const authn = new AuthnApi(AuthnApi.defaultDeps());
    const routes = {};
    const handled = [];
    const stub = function (req, res) {
      handled.push(req.path);
      res.status(200).send('handled');
    };
    AuthnApi.operations().forEach(function (o) {
      authn[o.handler] = stub;
    });
    authn.registerRoutes({
      use: function () {},
      get: function (p, h) {
        routes['GET ' + p] = h;
      },
      post: function (p, h) {
        routes['POST ' + p] = h;
      }
    });
    const callAuthn = function (key, query, headers) {
      const res = fakeRes();
      routes[key]({ path: key.split(' ')[1], method: key.split(' ')[0],
        query: query, headers: headers || {}, params: { id: 'abc' },
        body: '{}' }, res);
      return summary(res);
    };
    R.authnUnknown = callAuthn('GET /authn-api/pending/:id',
      { sts_garbage: SECRET });
    R.authnHeader = callAuthn('GET /authn-api/pending/:id', {},
      { 'x-sts-garbage': SECRET });
    R.authnNested = callAuthn('GET /authn-api/mfa/:id',
      { page: { a: SECRET } });
    R.authnDeclared = callAuthn('GET /authn-api/mfa/:id',
      { page: 'totp', key: 'kid' });
    R.authnWebView = callAuthn('GET /authn-api/pending/:id', {},
      { 'x-requested-with': 'com.vendor.app', 'sec-fetch-mode': 'cors',
        cookie: 'sts_session=x', origin: 'https://sts' });
    R.authnCsrfGet = callAuthn('GET /authn-api/pending/:id', {},
      { 'x-csrf-token': 't' });
    R.authnCsrfPost = callAuthn('POST /authn-api/pending/:id/password', {},
      { 'x-csrf-token': 't', 'content-type': 'application/json' });
    R.authnPostUnknown = callAuthn('POST /authn-api/pending/:id/password',
      { sts_garbage: '1' }, {});
    R.authnWalletOk = callAuthn('GET /authn-api/wallet',
      { authn: 'a', siop: '1', login_hint: 'h', did_act: 'publish' });
    R.authnWalletUnknown = callAuthn('GET /authn-api/wallet', { state: 's' });
    R.authnLogoutOk = callAuthn('GET /authn-api/logout',
      { username: 'u', account: 'a', login_hint: 'h' });
    R.authnAccountsOk = callAuthn('GET /authn-api/accounts', {});
    R.authnAccountsUnknown = callAuthn('GET /authn-api/accounts',
      { username: 'u' });
    report.docs.authn = AuthnApi.document({});

    // --- /report-api -------------------------------------------------------
    const reportApi = require(ROOT_DIR + '/report/report_api');
    const callReport = function (method, parts, query, headers) {
      const res = fakeRes();
      const refused = reportApi.shapeRefused({ query: query,
        headers: headers || {} }, res, method, parts);
      return Object.assign({ refused: refused }, summary(res));
    };
    R.reportUnknown = callReport('GET', ['groups'], { sts_garbage: SECRET });
    R.reportWrongType = callReport('GET', ['groups'],
      { page: 'abc' + SECRET });
    R.reportHeader = callReport('GET', ['catalog'], {},
      { 'x-sts-garbage': SECRET });
    R.reportBare = callReport('GET', [], { sts_garbage: '1' });
    R.reportDeclared = callReport('GET', ['jobs'],
      { page: '2', per: '20', after: 'x', limit: '5' });
    R.reportDpop = callReport('GET', ['me'], {},
      { dpop: 'proof', 'x-requested-with': 'com.app' });
    R.reportPathOp = callReport('GET', ['jobs', 'id1', 'result'], {});
    R.reportPost = callReport('POST', ['definitions'], { sts_garbage: '1' });
    R.reportLimit = callReport('GET', ['definitions'], { limit: '9' });
    R.reportUnrouted = callReport('GET', ['no', 'such', 'path'],
      { sts_garbage: '1' });
    const Catalog = require(ROOT_DIR + '/report/catalog');
    const OpenApi = require(ROOT_DIR + '/report/openapi');
    report.docs.report = OpenApi.document(new Catalog());

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
  const out = path.join(os.tmpdir(), 'anr-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RN_ROOT: ROOT, RN_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT,
      maxBuffer: 64 * 1024 * 1024 });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in loadReport(): " + ((e && e.message) || e));
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

function sharedCheck(t) {
  log.debug("Entering sharedCheck().");
  t.log.info('=== A. the shared check ===');
  const RequestHeaders = require('../common/request_headers');
  const declared = [
    { name: 'page', in: 'query', schema: { type: 'integer' } },
    { name: 'X-Own', in: 'header', schema: { type: 'string' } }
  ];
  const unknown = RequestHeaders.checkRequest(declared,
    { nope: VALUE }, {});
  t.check(!unknown.ok && unknown.problem === 'unknown-parameter' &&
          unknown.sentence.indexOf('nope') >= 0 &&
          unknown.sentence.indexOf(VALUE) < 0,
          'an unknown name is unknown-parameter, naming it, not its value',
          JSON.stringify(unknown));
  const wrong = RequestHeaders.checkRequest(declared,
    { page: 'abc' + VALUE }, {});
  t.check(!wrong.ok && wrong.problem === 'wrong-type' &&
          wrong.sentence.indexOf(VALUE) < 0,
          'a wrong type is wrong-type and does not echo the value',
          JSON.stringify(wrong));
  const header = RequestHeaders.checkRequest(declared, {},
    { 'x-other': VALUE });
  t.check(!header.ok && header.problem === 'header' &&
          header.sentence.indexOf('x-other') >= 0 &&
          header.sentence.indexOf(VALUE) < 0,
          'an unknown header is header, naming it, not its value',
          JSON.stringify(header));
  t.check(RequestHeaders.checkRequest(declared, { page: '1' },
    { 'x-own': '1', accept: 'x', 'sec-fetch-site': 'same' }).ok,
    'a declared query and header, and a browser\'s, pass', '');
  log.debug("Leaving sharedCheck().");
}

function refusedRow(row, name, code) {
  log.debug("Entering refusedRow().");
  const ok = row && row.status === 400 && row.code === code &&
             row.body.indexOf(name) >= 0 && row.body.indexOf('STS-') < 0 &&
             row.body.indexOf('SECRETvalue') < 0;
  log.debug("Leaving refusedRow().");
  return ok;
}

function examplesSection(t, docs) {
  log.debug("Entering examplesSection().");
  t.log.info('=== E. every operation that can carry an example has one ===');
  const Ajv = require('ajv').default || require('ajv');
  const ajv = new Ajv({ allErrors: true, strict: false,
                        validateFormats: false });
  Object.keys(docs).forEach(function (name) {
    const doc = docs[name];
    const missing = [];
    const invalid = [];
    let covered = 0;
    let bodies = 0;
    let parameters = 0;
    Object.keys(doc.paths).forEach(function (p) {
      Object.keys(doc.paths[p]).forEach(function (verb) {
        if (verb === 'parameters') {
          return;
        }
        const key = verb.toUpperCase() + ' ' + p;
        const op = doc.paths[p][verb];
        const canCarry = (op.parameters || []).filter(function (one) {
          return one.in === 'query' || one.in === 'path';
        });
        const media = op.requestBody && op.requestBody.content &&
          op.requestBody.content['application/json'];
        if (!canCarry.length && !media) {
          return;
        }
        covered += 1;
        const withExample = canCarry.filter(function (one) {
          return Object.prototype.hasOwnProperty.call(one, 'example');
        });
        const pathOnes = canCarry.filter(function (one) {
          return one.in === 'path';
        });
        const pathDone = pathOnes.every(function (one) {
          return Object.prototype.hasOwnProperty.call(one, 'example');
        });
        const hasBody = media &&
          Object.prototype.hasOwnProperty.call(media, 'example');
        if (!pathDone || (media && !hasBody) ||
            (!media && !withExample.length)) {
          missing.push(key);
        }
        parameters += withExample.length;
        const check = function (schema, value, what) {
          const validate = ajv.compile(Object.assign(
            { components: doc.components || {} }, schema));
          if (!validate(value)) {
            invalid.push(key + ' ' + what + ': ' +
                         JSON.stringify(validate.errors).slice(0, 300));
          }
        };
        withExample.forEach(function (one) {
          if (one.schema) {
            check(one.schema, one.example, one.name);
          }
        });
        if (hasBody) {
          bodies += 1;
          check(media.schema, media.example, 'body');
        }
      });
    });
    t.equal(JSON.stringify(missing), '[]',
            name + ': every one of the ' + covered + ' operations with a ' +
            'parameter or a body carries an example');
    t.equal(JSON.stringify(invalid), '[]',
            name + ': each example (' + parameters + ' parameter, ' + bodies +
            ' body) fits its schema');
    t.log.info(name + ': ' + covered + ' operations carry examples');
  });
  const bodyOf = function (name, key, method) {
    return docs[name].paths[key][method].requestBody
      .content['application/json'].example;
  };
  t.check(JSON.stringify(bodyOf('authn', '/authn-api/logout', 'post').select)
    === '["no-such-row"]',
    'the sign-out example selects a row nobody has', '');
  const pw = bodyOf('account', '/account-api/password', 'post');
  t.check(pw.next !== pw.confirm,
          'the password example changes no password', JSON.stringify(pw));
  const doc = bodyOf('report', '/report-api/definitions', 'post').document;
  t.equal(doc.source, 'no-such-source',
          'the definition example stores nothing');
  t.check(bodyOf('report', '/report-api/queries', 'post').limit === 1,
          'the query example reads one row', '');
  log.debug("Leaving examplesSection().");
}

async function portalFilter(t) {
  log.debug("Entering portalFilter().");
  t.log.info('=== F. what the portal asks ===');
  const PortalRuntime = require('../portal/web_portal_runtime');
  const self = { queryNames: { '/account-api/applications': ['done', 'page'] },
                 ensureFormTable: function () {
                   return Promise.resolve(true);
                 } };
  const kept = await PortalRuntime.prototype.operationQuery.call(self,
    '/account-api/applications',
    { page: '2', notice: 'gone', accounts: 'x', done: 'y' });
  t.equal(JSON.stringify(kept), JSON.stringify({ page: '2', done: 'y' }),
          'a page\'s own names are not asked of its operation');
  const none = await PortalRuntime.prototype.operationQuery.call(self,
    '/account-api/overview', { any: 'thing' });
  t.equal(JSON.stringify(none), JSON.stringify({ any: 'thing' }),
          'an operation the table does not know is asked as before');
  const empty = await PortalRuntime.prototype.operationQuery.call(
    { queryNames: null, ensureFormTable: function () {
      throw new Error('no table is needed for an empty query');
    } }, '/account-api/applications', {});
  t.equal(JSON.stringify(empty), '{}',
          'an empty query asks nothing and costs no request');
  const failing = { queryNames: null, ensureFormTable: function () {
    return Promise.resolve(false);
  } };
  const asIs = await PortalRuntime.prototype.operationQuery.call(failing,
    '/account-api/applications', { page: '2' });
  t.equal(JSON.stringify(asIs), JSON.stringify({ page: '2' }),
          'with no table in hand everything is forwarded');
  log.debug("Leaving portalFilter().");
}

async function run(t) {
  log.debug("Entering run().");
  sharedCheck(t);
  const loaded = loadReport();
  const report = loaded.report;
  if (!t.check(!!report && !report.error,
               'the child loaded the whole stack',
               report && report.error ? report.error.slice(0, 1500) :
               'exit ' + loaded.result.status + ' ' +
               String(loaded.result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  const R = report.rows;

  t.log.info('=== B. /account-api ===');
  t.check(refusedRow(R.accountUnknown, 'sts_garbage', 'STS-ACCOUNT-0020'),
          'an unknown parameter on a route with parameters is 0020',
          JSON.stringify(R.accountUnknown));
  t.check(refusedRow(R.accountBare, 'sts_garbage', 'STS-ACCOUNT-0020'),
          'and on a route with none', JSON.stringify(R.accountBare));
  t.check(R.accountWrongType.status === 400 &&
          R.accountWrongType.body.indexOf('page') >= 0 &&
          R.accountWrongType.body.indexOf('SECRET') < 0 &&
          R.accountWrongType.body.indexOf('STS-') < 0 &&
          /^STS-ACCOUNT-00(16|21)$/.test(R.accountWrongType.code),
          'a wrong-typed page is refused, naming it and not its value',
          JSON.stringify(R.accountWrongType));
  t.check(refusedRow(R.accountNested, 'done', 'STS-ACCOUNT-0021'),
          'a nested value is 0021', JSON.stringify(R.accountNested));
  t.check(refusedRow(R.accountHeader, 'x-sts-garbage', 'STS-ACCOUNT-0022'),
          'an unknown header is 0022', JSON.stringify(R.accountHeader));
  t.check(R.accountDeclared.status === 200 &&
          R.accountDeclared.body === 'handled',
          'a declared query reaches the operation',
          JSON.stringify(R.accountDeclared));
  t.check(R.accountEmpty.status === 200, 'an empty value is absent',
          JSON.stringify(R.accountEmpty));
  t.check(R.accountBrowser.status === 200,
          'DPoP, X-Requested-With, Sec-* and a proxy\'s header pass',
          JSON.stringify(R.accountBrowser));
  t.check(R.accountPost.status === 400 &&
          R.accountPost.code === 'STS-ACCOUNT-0020',
          'a POST refuses an unknown query parameter',
          JSON.stringify(R.accountPost));
  t.equal(JSON.stringify(report.indexQuery['/account-api/me']), '[]',
          'the index says a parameterless GET takes no query');
  t.equal(JSON.stringify(report.indexQuery['/account-api/applications']),
          JSON.stringify(['done', 'page']),
          'and names what one takes');

  t.log.info('=== C. /authn-api ===');
  t.check(refusedRow(R.authnUnknown, 'sts_garbage', 'STS-AUTHN-0552'),
          'an unknown parameter is 0552', JSON.stringify(R.authnUnknown));
  t.check(refusedRow(R.authnHeader, 'x-sts-garbage', 'STS-AUTHN-0554'),
          'an unknown header is 0554', JSON.stringify(R.authnHeader));
  t.check(refusedRow(R.authnNested, 'page', 'STS-AUTHN-0553'),
          'a nested value is 0553', JSON.stringify(R.authnNested));
  t.check(R.authnDeclared.status === 200, 'a declared query is taken',
          JSON.stringify(R.authnDeclared));
  t.check(R.authnWebView.status === 200,
          'a WebView\'s X-Requested-With and a browser\'s headers do not ' +
          'break a sign-in', JSON.stringify(R.authnWebView));
  t.check(refusedRow(R.authnCsrfGet, 'x-csrf-token', 'STS-AUTHN-0554'),
          'a GET does not take X-CSRF-Token', JSON.stringify(R.authnCsrfGet));
  t.check(R.authnCsrfPost.status === 200, 'a POST does',
          JSON.stringify(R.authnCsrfPost));
  t.check(refusedRow(R.authnPostUnknown, 'sts_garbage', 'STS-AUTHN-0552'),
          'and a POST refuses an unknown query parameter',
          JSON.stringify(R.authnPostUnknown));
  t.check(R.authnWalletOk.status === 200,
          'the wallet start takes every name its runtime sends',
          JSON.stringify(R.authnWalletOk));
  // The operation's own closed model has to admit the refusal, or the answer
  // becomes a 500 (#1483; the first full fuzz run).
  ['getWalletStart', 'getWalletWait'].forEach(function (operation) {
    const model = require('../authn/authn_response_models')
      .operations[operation]['400'];
    const members = JSON.stringify(model);
    t.check(members.indexOf('"error_description"') >= 0,
            operation + '\'s 400 model admits the shape refusal', '');
  });
  t.check(refusedRow(R.authnWalletUnknown, 'state', 'STS-AUTHN-0552'),
          'and refuses a name its view does not take',
          JSON.stringify(R.authnWalletUnknown));
  t.check(R.authnLogoutOk.status === 200,
          'the sign-out view takes username, account and login_hint',
          JSON.stringify(R.authnLogoutOk));
  t.check(refusedRow(R.authnAccountsUnknown, 'username', 'STS-AUTHN-0552'),
          'the browser\'s account list takes none',
          JSON.stringify(R.authnAccountsUnknown));

  t.log.info('=== D. /report-api ===');
  t.check(R.reportUnknown.refused &&
          refusedRow(R.reportUnknown, 'sts_garbage', 'STS-REPORT-0056'),
          'an unknown parameter is 0056', JSON.stringify(R.reportUnknown));
  t.check(R.reportWrongType.refused &&
          refusedRow(R.reportWrongType, 'page', 'STS-REPORT-0057'),
          'a word in an integer is 0057', JSON.stringify(R.reportWrongType));
  t.check(R.reportHeader.refused &&
          refusedRow(R.reportHeader, 'x-sts-garbage', 'STS-REPORT-0058'),
          'an unknown header is 0058', JSON.stringify(R.reportHeader));
  t.check(R.reportBare.refused &&
          R.reportBare.code === 'STS-REPORT-0056',
          'on the index too', JSON.stringify(R.reportBare));
  t.check(!R.reportDeclared.refused,
          'the jobs list takes page, per, after and limit',
          JSON.stringify(R.reportDeclared));
  t.check(!R.reportDpop.refused,
          'DPoP and X-Requested-With pass', JSON.stringify(R.reportDpop));
  t.check(!R.reportPathOp.refused,
          'a route with a path parameter is found',
          JSON.stringify(R.reportPathOp));
  t.check(R.reportPost.refused && R.reportPost.code === 'STS-REPORT-0056',
          'a POST refuses too', JSON.stringify(R.reportPost));
  t.check(!R.reportLimit.refused,
          'the definitions list takes the older spelling limit',
          JSON.stringify(R.reportLimit));
  t.check(!R.reportUnrouted.refused,
          'a path no operation is is left to the router',
          JSON.stringify(R.reportUnrouted));

  examplesSection(t, report.docs);
  await portalFilter(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'api_request_names',
  describe: '/account-api, /authn-api and /report-api refuse an undeclared ' +
            'query parameter, a wrong-typed value and a custom header, and ' +
            'every operation that can carry one declares an example (#1483)',
  run: run
};
