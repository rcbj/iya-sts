// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_api_handlers.js
//
// ---------------------------------------------------------------------------
// THE MODEL TYPES THE HANDLERS OF THE FIVE APIS, AND THE CHECKER SAYS SO
// (#1579).
//
// `types/api.generated.d.ts` is generated from `models/api/*.tsp`, and
// `types/api-handlers.d.ts` binds each handler of the Management, Admin
// Console, Account, Authentication and Reports APIs to its operation there.
// `tests/typecheck.js` shows the tree compiles; this file shows that the
// binding is real — that the checker REFUSES a real handler that answers a
// member its operation's answer does not declare, reads a body member or a
// query name its operation does not take, or answers a 2xx status the model
// gives no JSON answer.
//
// **IT CHANGES REAL HANDLERS, IN A COPY.** Each case below is an edit to one
// handler of the service, made in a scratch directory that links every other
// file of the source tree, and `tsc` is run once over the edited files. Each
// edit must produce its own diagnostic in its own file, and nothing else may
// fail: the scratch tree is the real one but for the edits. An anchor that no
// longer matches fails the case, naming it, so the case is moved to the
// handler's new text rather than dropped.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'model_api_handlers',
  level: process.env.LOG_LEVEL || 'info' });

// The pristine source tree in the tests image (`tests/typecheck.js` says
// why), this checkout on the host.
const ROOT = process.env.STS_TYPECHECK_ROOT || path.join(__dirname, '..');
const TSC = path.join(ROOT, 'tests', 'node_modules', 'typescript', 'bin',
                      'tsc');

// THE CASES: a file, the first occurrence of an anchor in it, what replaces
// it, and the diagnostic the checker must give for it.
const CASES = [
  { api: 'Management', file: 'mgmt-api/admin_api.ts',
    what: 'an answer member the operation does not declare',
    anchor: "name: 'IYA STS management API',",
    edit: "name: 'IYA STS management API', modelHasNoSuchMember: 1,",
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Management', file: 'mgmt-api/admin_api.ts',
    what: 'a query name the operation does not declare',
    anchor: 'const base = baseUrlOf(req);',
    edit: 'const base = baseUrlOf(req) + req.query.modelHasNoSuchName;',
    code: 'TS2339', word: 'modelHasNoSuchName' },
  { api: 'Management', file: 'mgmt-api/admin_api.ts',
    what: 'a 2xx status the operation gives no JSON answer',
    anchor: 'log.debug("Entering the management API index.");',
    edit: 'log.debug("Entering the management API index."); ' +
          "self.sendJson(res, 201, { name: 'modelHasNoSuchStatus' });",
    code: 'TS2345', word: 'never' },
  { api: 'Management', file: 'mgmt-api/admin_api.ts',
    what: 'an answer member, in a row of actions',
    anchor: 'units: result.units, message: result.message,',
    edit: 'units: result.units, message: result.message, ' +
          'modelHasNoSuchMember: 1,',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Admin Console', file: 'mgmt-api/admin_api.ts',
    what: 'an answer member the operation does not declare',
    anchor: "{ operations: self.operationSummaries('all') });",
    edit: "{ operations: self.operationSummaries('all'), " +
          'modelHasNoSuchMember: 1 });',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Management', file: 'scep/scep_api.ts',
    what: 'an answer member, in a table the API spreads',
    anchor: 'self.send(res, 200, model.scepView(req));',
    edit: 'self.send(res, 200, { modelHasNoSuchMember: 1 });',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Account', file: 'portal/account_keys.ts',
    what: 'an answer member the operation does not declare',
    anchor: 'return ctx.json(res, 200, self.view(caller, ' +
            'ctx.baseUrlOf(req)));',
    edit: 'return ctx.json(res, 200, { modelHasNoSuchMember: 1 });',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Account', file: 'portal/account_keys.ts',
    what: 'a body member the operation does not take',
    anchor: 'return self.enrol(ctx, req, res, caller, input.body);',
    edit: 'return self.enrol(ctx, req, res, caller, ' +
          'input.body.modelHasNoSuchField);',
    code: 'TS2339', word: 'modelHasNoSuchField' },
  { api: 'Account', file: 'portal/account_keys.ts',
    what: 'an answer member, in the helper a handler hands its response to',
    anchor: "return ctx.json(res, 200, { ok: true, message: '' });",
    edit: "return ctx.json(res, 200, { ok: true, message: '', " +
          'modelHasNoSuchMember: 1 });',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Authentication', file: 'authn/authn_api.ts',
    what: 'an answer member the operation does not declare',
    anchor: "go: authn.LOGIN_PATH + '?authn=' + " +
            'encodeURIComponent(record.id) });',
    edit: "go: authn.LOGIN_PATH + '?authn=' + " +
          'encodeURIComponent(record.id), modelHasNoSuchMember: 1 });',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Management', file: 'admin-core/admin_views.ts',
    what: 'an answer member, in the view an operation answers with',
    anchor: 'return { installed: false, enabled: false, streamDetail: [],',
    edit: 'return { installed: false, enabled: false, streamDetail: [], ' +
          'modelHasNoSuchMember: 1,',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Management', file: 'admin-core/admin_actions.ts',
    what: 'a body member no operation of the action\'s table takes',
    anchor: "const id = String(body.id || body.relationship || '').trim();",
    edit: "const id = String(body.id || body.relationship || '').trim() + " +
          'body.modelHasNoSuchField;',
    code: 'TS2339', word: 'modelHasNoSuchField' },
  { api: 'Authentication', file: 'authn/authn.ts',
    what: 'an answer member, in the step answer the sign-in acts share',
    anchor: 'this.answerJson(res, 200, { ok: true, next: next, step: step, ' +
            'id: id,',
    edit: 'this.answerJson(res, 200, { ok: true, next: next, step: step, ' +
          'id: id, modelHasNoSuchMember: 1,',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Authentication', file: 'authn/email_factor.ts',
    what: 'an answer member, in an emailed factor\'s act',
    anchor: "authn.answerJson(res, 200, { ok: true, next: 'stay', " +
            "notice: 'resent' });",
    edit: "authn.answerJson(res, 200, { ok: true, next: 'stay', " +
          "notice: 'resent', modelHasNoSuchMember: 1 });",
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Authentication', file: 'oid4vc/vc_signin.ts',
    what: 'an answer member, in a wallet sign-in\'s act',
    anchor: "authn.answerJson(res, 200, { ok: true, next: 'wait', " +
            'state: tx.state,',
    edit: "authn.answerJson(res, 200, { ok: true, next: 'wait', " +
          'state: tx.state, modelHasNoSuchMember: 1,',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Authentication', file: 'oauth-oidc/consent_screen.ts',
    what: 'an answer member, in the consent screen\'s act',
    anchor: "authn.answerJson(res, 200, { ok: true, next: 'redirect',",
    edit: "authn.answerJson(res, 200, { ok: true, next: 'redirect', " +
          'modelHasNoSuchMember: 1,',
    code: 'TS2353', word: 'modelHasNoSuchMember' },
  { api: 'Reports', file: 'report/report_api.ts',
    what: 'an answer member the operation does not declare',
    anchor: "reportJson(res, 200, { photo: who && who.kind === 'user'",
    edit: 'reportJson(res, 200, { modelHasNoSuchMember: 1, ' +
          "photo: who && who.kind === 'user'",
    code: 'TS2353', word: 'modelHasNoSuchMember' }
];

// A scratch tree: every top-level entry of ROOT linked, but the directories
// holding an edited file, which are real directories of links bar the edited
// files themselves. Imports out of an edited file resolve to the real tree,
// and the real file is what every other module still imports.
function scratchTree(edited) {
  log.debug("Entering scratchTree().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-api-handlers-'));
  const dirs = {};
  Object.keys(edited).forEach(function (rel) {
    dirs[rel.split('/')[0]] = true;
  });
  fs.readdirSync(ROOT).forEach(function (name) {
    if (name === '.git') {
      return;
    }
    if (!dirs[name]) {
      fs.symlinkSync(path.join(ROOT, name), path.join(dir, name));
      return;
    }
    fs.mkdirSync(path.join(dir, name));
    fs.readdirSync(path.join(ROOT, name)).forEach(function (inner) {
      const rel = name + '/' + inner;
      if (Object.prototype.hasOwnProperty.call(edited, rel)) {
        fs.writeFileSync(path.join(dir, rel), edited[rel]);
      } else {
        fs.symlinkSync(path.join(ROOT, rel), path.join(dir, rel));
      }
    });
  });
  log.debug("Leaving scratchTree(). " + dir);
  return dir;
}

// A handler parameter that names its own type opts out of the row's: the
// checker would take `req: any` over the model's. A type of the model's own
// (`IyaApi.…`) is the binding written out, and is allowed.
const ANNOTATED = /handler: (?:async )?function \(([^)]*)\)/g;

function read(rel) {
  log.debug("Entering read(). " + rel);
  log.debug("Leaving read().");
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

function annotatedHandlers(text) {
  log.debug("Entering annotatedHandlers().");
  const out = [];
  let m = null;
  ANNOTATED.lastIndex = 0;
  while ((m = ANNOTATED.exec(text)) !== null) {
    if (/\b(req|res|input|next)\s*:(?!\s*IyaApi\.)/.test(m[1])) {
      out.push(m[0].replace(/\s+/g, ' '));
    }
  }
  log.debug("Leaving annotatedHandlers(). " + out.length);
  return out;
}

// EVERY HANDLER IS IN A TYPED PLACE, which is what makes the cases below
// stand for all of them rather than for the ones they edit.
function everyHandlerBound(t) {
  log.debug("Entering everyHandlerBound().");
  t.log.info('=== every handler of the five APIs is typed by the model ===');
  // The management and console table, and every table it spreads.
  const admin = read('mgmt-api/admin_api.ts');
  const spread = [];
  const loader =
    /\n  load(\w+)\(\):\s*typeof import\('(\.\.?\/[^']+)'\);/g;
  let m = null;
  while ((m = loader.exec(admin)) !== null) {
    if (admin.indexOf('...load' + m[1] + '().ROUTES') >= 0) {
      spread.push(path.posix.join('mgmt-api', m[2]) + '.ts');
    }
  }
  t.check(spread.length >= 18, 'the management API spreads ' + spread.length +
          ' other route tables');
  ['mgmt-api/admin_api.ts'].concat(spread).forEach(function (rel) {
    const text = read(rel);
    t.check(/const ROUTES: (IyaApi\.)?AdminRow\[\] = \[/.test(text),
            rel + ': its route table is typed IyaApi.AdminRow[]');
    t.equal(annotatedHandlers(text).join('; '), '',
            rel + ': no handler names its own parameter types');
    const unwrapped = text.match(
      /(?<!ApiRows\.actions\()\{ method: '\w+',\s*route:/g) || [];
    t.equal(unwrapped.length, 0, rel + ': every row of actions is typed by ' +
            'its actions (ApiRows.actions())');
  });
  // The Account API: its operations and every page module's.
  const accountFiles = ['account-api/account_api.ts'].concat(
    fs.readdirSync(path.join(ROOT, 'portal')).filter(function (name) {
      return /\.ts$/.test(name) &&
        read('portal/' + name).indexOf('accountOperations(') >= 0;
    }).map(function (name) {
      return 'portal/' + name;
    }));
  accountFiles.forEach(function (rel) {
    t.equal(annotatedHandlers(read(rel)).join('; '), '',
            rel + ': no Account API handler names its own parameter types');
  });
  // The Authentication API: every handler a row names.
  const authn = read('authn/authn_api.ts');
  const names = {};
  (authn.match(/handler: '\w+'/g) || []).forEach(function (one) {
    names[one.slice(10, -1)] = true;
  });
  const untyped = Object.keys(names).filter(function (name) {
    return !new RegExp('\\n  (async )?' + name + '\\(req: AuthnRequest<\'' +
      name + '\'>,\\s*res: AuthnAnswering<\'' + name + '\'>').test(authn);
  });
  t.equal(untyped.join(', '), '', 'authn/authn_api.ts: each of the ' +
          Object.keys(names).length + ' handlers its rows name is typed by ' +
          'the operations that name it');
  // THE ACTS THE AUTHENTICATION API HANDS ITS RESPONSE TO, in the modules
  // that answer them: each is typed by its operations.
  const handedTo = {
    'authn/authn.ts': /\bauthn\.(\w+)\(req,\s*res\b/g,
    'authn/email_factor.ts': /\bef\.(\w+)\(req,\s*res\b/g,
    'oauth-oidc/consent_screen.ts': /\bscreen\.(\w+)\(req,\s*res\b/g
  };
  Object.keys(handedTo).forEach(function (rel) {
    const target = read(rel);
    const acts = {};
    let one = null;
    while ((one = handedTo[rel].exec(authn)) !== null) {
      acts[one[1]] = true;
    }
    const loose = Object.keys(acts).filter(function (name) {
      return !new RegExp('\\n  (async |private )*' + name +
        '\\(\\s*req(: \\w+)?,\\s*res: IyaApi\\.AuthnAnswering<').test(target);
    });
    t.equal(loose.join(', '), '', rel + ': each of the ' +
            Object.keys(acts).length + ' acts /authn-api hands its response ' +
            'to is typed by its operations');
  });
  const wallet = read('oid4vc/vc_signin.ts');
  const walletActs = {};
  (authn.match(/walletAct: '\w+'/g) || []).forEach(function (one) {
    walletActs[one.slice(12, -1)] = true;
  });
  const looseWallet = Object.keys(walletActs).filter(function (name) {
    return !new RegExp('\\n  (async )?' + name +
      '\\(req: any, res: IyaApi\\.AuthnAnswering<').test(wallet);
  });
  t.equal(looseWallet.join(', '), '', 'oid4vc/vc_signin.ts: each of the ' +
          Object.keys(walletActs).length + ' wallet acts is typed by its ' +
          'operation');
  // THE ADMIN-CORE ACTIONS the management API's rows of actions call: each
  // is handed the bodies of the model's operations at its path.
  const actions = read('admin-core/admin_actions.ts');
  const called = {};
  (admin.match(/adminActions\.\w+Action\(/g) || []).forEach(function (one) {
    called[one.slice(13, -1)] = true;
  });
  const untypedActions = Object.keys(called).filter(function (name) {
    return !new RegExp('\\n  (async )?' + name +
      '\\(body: IyaApi\\.AdminActionBody<').test(actions);
  });
  t.equal(untypedActions.join(', '), '', 'admin-core/admin_actions.ts: each ' +
          'of the ' + Object.keys(called).length + ' actions the management ' +
          'API calls reads the bodies its operations declare');
  // The Reports API: every function its router hands a response to.
  const report = read('report/report_api.ts');
  const route = report.slice(report.indexOf('async function reportRoute('),
                             report.indexOf('async function reportRun('));
  const served = {};
  (route.match(/report\w+\((req, )?res\b/g) || []).forEach(function (one) {
    served[one.split('(')[0]] = true;
  });
  delete served.reportShapeRefused;
  delete served.reportMissingJob;
  const unserved = Object.keys(served).filter(function (name) {
    return !new RegExp('function ' + name + '\\([^)]*res: ReportAnswering<')
      .test(report);
  });
  t.equal(unserved.join(', '), '', 'report/report_api.ts: each of the ' +
          Object.keys(served).length + ' functions its router serves an ' +
          'operation with is typed by that operation');
  log.debug("Leaving everyHandlerBound().");
}

function run(t) {
  log.debug("Entering run().");
  everyHandlerBound(t);
  t.log.info('=== a real handler that breaks its model does not compile ===');
  if (!fs.existsSync(TSC)) {
    t.bad('the TypeScript compiler is installed', TSC + ' is missing.');
    log.debug("Leaving run(). No compiler.");
    return;
  }
  const edited = {};
  const anchored = CASES.filter(function (one) {
    const text = Object.prototype.hasOwnProperty.call(edited, one.file)
      ? edited[one.file]
      : fs.readFileSync(path.join(ROOT, one.file), 'utf8');
    const at = text.indexOf(one.anchor);
    t.check(at >= 0, one.api + ' API, ' + one.file + ': the anchor of "' +
            one.what + '" is in the handler',
            'Not found: ' + one.anchor + ' — move the case to the ' +
            'handler\'s new text.');
    if (at < 0) {
      return false;
    }
    edited[one.file] = text.slice(0, at) + one.edit +
      text.slice(at + one.anchor.length);
    return true;
  });
  const dir = scratchTree(edited);
  // The service's own options, over the edited files alone: what they import
  // comes in as the real tree does.
  const config = path.join(dir, 'tsconfig.model-api-handlers.json');
  fs.writeFileSync(config, JSON.stringify({
    extends: path.join(ROOT, 'tsconfig.json'),
    compilerOptions: { typeRoots: [path.join(ROOT, 'tests', 'node_modules',
                                             '@types')] },
    include: ['types/**/*.d.ts'],
    files: Object.keys(edited)
  }));
  const result = childProcess.spawnSync(process.execPath,
    [TSC, '-p', config, '--pretty', 'false'],
    { cwd: dir, encoding: 'utf8', timeout: 600000 });
  const lines = (String(result.stdout || '') + String(result.stderr || ''))
    .split('\n').filter(function (line) {
      return / error TS\d+:/.test(line);
    });
  const claimed = {};
  anchored.forEach(function (one) {
    const editLine = edited[one.file].slice(0,
      edited[one.file].indexOf(one.edit)).split('\n').length;
    const found = lines.filter(function (line) {
      return line.indexOf(one.file + '(' + editLine + ',') === 0 &&
        line.indexOf('error ' + one.code + ':') > 0 &&
        line.indexOf(one.word) > 0;
    });
    found.forEach(function (line) {
      claimed[line] = true;
    });
    t.check(found.length === 1, one.api + ' API, ' + one.file + ': ' +
            one.what + ' is refused (' + one.code + ')',
            lines.join('\n').slice(0, 3000));
  });
  const stray = lines.filter(function (line) {
    return !claimed[line];
  });
  t.equal(stray.join('\n'), '', 'and nothing else in the tree fails');
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // A scratch directory left behind costs disk, not a result.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  log.debug("Leaving run().");
}

module.exports = { run: run };
