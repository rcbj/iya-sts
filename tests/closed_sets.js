'use strict';
//
// File: closed_sets.js
//
// ===========================================================================
// THE CLOSED SETS, IN PROCESS (#86, 2026-09-26).
//
// `tests/vendored/sts_admin_closed_sets.js` holds the running service to
// every enum the OpenAPI document declares, at every door. This file holds
// the two things that job cannot see from outside:
//
//   A. `common/closed_sets.ts`'s rules, one by one: an empty string is
//      absent at the form-shaped doors and case is exact; a repeated field is
//      each of its values; an array query parameter is its comma-separated
//      members; an enum inside `anyOf`/`oneOf` is not collected; a `$ref` is
//      followed and a `$ref` cycle ends; only flat fields reach the console
//      register; a control with no action of its own is held by its page's
//      `''` row; and the sentence names the field, the value, the count and
//      every value.
//   B. THE WRAPPER `mgmt-api/admin_api.ts` puts round every POST, driven
//      through the route table itself: `registerRoutes()` against a fake app
//      captures each handler, and each is called with a body holding a value
//      outside one enum. Every one must answer 400 with the sentence and
//      never reach the operation (the fake response would record a 2xx).
//      Then the console register that module filled at wire time: every
//      control in it refuses a value outside each of its fields, and the
//      register is not empty (a mirrors parse that broke would leave it so,
//      and the console door would pass everything).
//
// B RUNS IN A CHILD, because loading the management API loads most of the
// service and a stack loaded into the runner is shared with every file
// after this one — `realm_support.js`'s arrangement.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'closed_sets',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const closedSets = require(path.join(ROOT, 'common', 'closed_sets'));

// The floors for B, set below what was measured once #86's audit had
// declared its enums (116 body enums, 154 console controls), for
// `sts_admin_closed_sets.js`'s reason.
const MINIMUM_BODY_ENUMS = 100;
const MINIMUM_CONSOLE_CONTROLS = 100;

function unitRules(t) {
  log.debug("Entering unitRules().");
  t.log.info('=== A. the rules of common/closed_sets.ts ===');
  const sentence = closedSets.sentence('deliver', 'fax', ['show', 'mail']);
  t.equal(sentence, '"deliver" is "fax", which is not one of the 2 values ' +
          'it accepts: "show", "mail".', 'the sentence names the field, the ' +
          'value, the count and every value');

  const schema = {
    type: 'object',
    properties: {
      kind: { type: 'string', enum: ['a', 'b'] },
      doors: { type: 'array', items: { type: 'string', enum: ['x', 'y'] } },
      nested: { type: 'object',
                properties: { mode: { type: 'string', enum: ['m'] } } },
      either: { oneOf: [{ type: 'string', enum: ['p'] },
                        { type: 'integer' }] },
      shared: { $ref: '#/components/schemas/Shared' }
    }
  };
  const components = {
    Shared: { type: 'object',
              properties: { level: { type: 'string', enum: ['lo', 'hi'] },
                            again: { $ref: '#/components/schemas/Shared' } } }
  };
  const got = closedSets.collect(schema, components).map(function (f) {
    return f.path.join('.') + '=' + f.values.join('|');
  });
  t.check(got.indexOf('kind=a|b') >= 0 && got.indexOf('doors.*=x|y') >= 0 &&
          got.indexOf('nested.mode=m') >= 0 &&
          got.indexOf('shared.level=lo|hi') >= 0,
          'collect() finds a flat enum, an array\'s items, a nested member ' +
          'and one behind a $ref', got.join(', '));
  t.check(!got.some(function (g) {
    return /^either/.test(g);
  }), 'collect() leaves an enum inside oneOf to ajv', got.join(', '));
  t.check(got.length < 40, 'a $ref cycle ends', got.length + ' rows');

  const P = '/admin/probe86';
  closedSets.registerConsole(P, 'save', closedSets.collect(schema,
                                                           components));
  const held = closedSets.forConsole(P, 'save').map(function (f) {
    return f.path[0];
  }).sort();
  t.equal(held.join(','), 'doors,kind', 'only flat fields (and a flat ' +
          'repeated one) reach the console register');
  t.check(closedSets.checkForm(P, 'save', { kind: '' }).ok,
          'an empty form field is absent', '');
  t.check(!closedSets.checkForm(P, 'save', { kind: 'A' }).ok,
          'case is exact', '');
  const repeated = closedSets.checkForm(P, 'save', { doors: ['x', 'z'] });
  t.check(!repeated.ok && repeated.value === 'z',
          'a repeated field is each of its values', JSON.stringify(repeated));
  t.check(closedSets.checkForm(P, 'other', { kind: 'zz' }).ok,
          'another action on the page is not held to this one\'s fields', '');
  closedSets.registerConsole('/admin/probe86-plain', '',
                             [{ path: ['kind'], values: ['a'] }]);
  t.check(!closedSets.checkForm('/admin/probe86-plain', 'anything',
                                { kind: 'b' }).ok,
          'a control with no action of its own is held by the page\'s row',
          '');
  closedSets.registerConsole(P, '', [{ path: ['other'], values: ['o'] }]);
  t.check(closedSets.checkForm(P, 'unregistered', { other: 'x' }).ok,
          'on a page with actions, one action\'s fields are never applied ' +
          'to another\'s (the page\'s \'\' row is not a fallback there)', '');

  const req = { headers: { 'content-type':
                           'application/x-www-form-urlencoded' },
                body: 'doors=x&doors=y&kind=a' };
  const values = closedSets.formValues(req, { doors: 'y', kind: 'a' });
  t.equal(JSON.stringify(values.doors), '["x","y"]',
          'formValues() keeps every value of a repeated field');

  const params = [
    { name: 'state', in: 'query', schema: { type: 'string',
                                            enum: ['live', 'spent'] } },
    { name: 'kinds', in: 'query', schema: { type: 'array',
      items: { type: 'string', enum: ['a', 'b'] } } }
  ];
  t.check(closedSets.checkQuery(params, { state: 'live' }).ok,
          'a query value from the set is accepted', '');
  t.check(closedSets.checkQuery(params, { state: '' }).ok,
          'an empty query value is absent', '');
  t.check(!closedSets.checkQuery(params, { state: 'dead' }).ok,
          'a query value outside the set is refused', '');
  t.check(!closedSets.checkQuery(params, { state: ['live', 'dead'] }).ok,
          'a repeated query parameter is each of its values', '');
  t.check(!closedSets.checkQuery(params, { kinds: 'a,c' }).ok &&
          closedSets.checkQuery(params, { kinds: 'a,b' }).ok,
          'an array query parameter is its comma-separated members', '');
  log.debug("Leaving unitRules().");
}

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so the function can be
// shipped as source with `node -e`. Every judgement is made in the parent.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const fs = require('fs');
  const ROOT_DIR = process.env.CS_ROOT;
  const OUT = process.env.CS_OUT;
  const OUTSIDE = '__not-a-value-86__';
  const report = { error: null, body: [], console: [], ties: [] };
  const done = function () {
    fs.writeFileSync(OUT, JSON.stringify(report));
    process.exit(0);
  };
  (async function () {
    const api = require(ROOT_DIR + '/mgmt-api/admin_api');
    const spec = require(ROOT_DIR + '/mgmt-api/admin_api_spec');
    const closedSets = require(ROOT_DIR + '/common/closed_sets');
    const handlers = {};
    const fakeApp = {
      use: function () {},
      get: function () {},
      post: function (p, h) {
        handlers[p] = h;
      }
    };
    api.registerRoutes(fakeApp);
    const bodyAt = function (p, value) {
      let inner = value;
      for (let i = p.length - 1; i >= 0; i--) {
        if (p[i] === '*') {
          inner = [inner];
        } else {
          const o = {};
          o[p[i]] = inner;
          inner = o;
        }
      }
      return inner;
    };
    const answer = function (handler, action, body) {
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
            resolve({ status: this.statusCode, body: String(b) });
            return this;
          }
        };
        const req = { params: { action: action }, query: {},
                      headers: { 'content-type': 'application/json' },
                      body: JSON.stringify(body), method: 'POST' };
        let ran;
        try {
          ran = handler(req, res);
        } catch (e) {
          resolve({ status: -1, body: String(e && e.message) });
          return;
        }
        Promise.resolve(ran).then(function () {
          setTimeout(function () {
            resolve({ status: -2, body: 'the handler did not answer' });
          }, 2000);
        }, function (e) {
          resolve({ status: -1, body: String(e && e.message) });
        });
      });
    };
    for (const entry of api.ROUTES) {
      if (entry.method === 'GET' || entry.handlerOwnsBody) {
        continue;
      }
      const route = entry.route || entry.path;
      const rows = (entry.actions || []).map(function (a) {
        return { action: a.action, body: a.requestBody };
      });
      if (entry.requestBody && !(entry.actions || []).length) {
        rows.push({ action: '', body: entry.requestBody });
      }
      for (const row of rows) {
        const fields = closedSets.collect(row.body, spec.SCHEMAS);
        for (const f of fields) {
          const got = await answer(handlers[route], row.action,
                                   bodyAt(f.path, OUTSIDE));
          report.body.push({ where: route + ' ' + row.action + ' ' +
                                    f.path.join('.'),
                             path: f.path, values: f.values,
                             status: got.status, body: got.body });
        }
      }
    }
    // THE TWO SETS WRITTEN OUT BY HAND, held to the constant each mirrors.
    const tie = function (what, written, owner) {
      report.ties.push({ what: what, written: written, owner: owner });
    };
    tie('est_api ENROLLMENT_PROFILES = cert_enrollment PROFILE_IDS',
        require(ROOT_DIR + '/est/est_api').EstApi.ENROLLMENT_PROFILES,
        require(ROOT_DIR + '/common/cert_enrollment').PROFILE_IDS);
    tie('scep_api ENROLLMENT_PROFILES = cert_enrollment PROFILE_IDS',
        require(ROOT_DIR + '/scep/scep_api').ScepApi.ENROLLMENT_PROFILES,
        report.ties[0].owner);
    const caepRow = require(ROOT_DIR + '/ssf/ssf_events').CAEP_COMMON_MEMBERS
      .filter(function (m) {
        return m.name === 'initiating_entity';
      })[0] || {};
    const emit = api.ROUTES.filter(function (e) {
      return (e.actions || []).some(function (a) {
        return a.operationId === 'emitCaepEvent';
      });
    })[0];
    const emitAction = emit && emit.actions.filter(function (a) {
      return a.operationId === 'emitCaepEvent';
    })[0];
    tie('emitCaepEvent initiating_entity = ssf_events CAEP_COMMON_MEMBERS',
        emitAction && emitAction.requestBody.properties.initiating_entity.enum,
        caepRow.values);
    // AND NO CONTROL IS HELD TO TWO DIFFERENT SETS: two routes mirroring one
    // console page and action with different enums would leave the register
    // holding whichever registered first.
    const seen = {};
    for (const entry of api.ROUTES) {
      (entry.actions || []).forEach(function (a) {
        const m = String(a.mirrors || entry.mirrors || '');
        const pages = m.match(/POST \/admin\S*/g) || [];
        closedSets.collect(a.requestBody, spec.SCHEMAS).forEach(function (f) {
          pages.forEach(function (pg) {
            const k = pg.replace(/,$/, '') + ' ' + a.action + ' ' + f.path[0];
            const v = JSON.stringify(f.values);
            if (seen[k] && seen[k] !== v) {
              report.ties.push({ what: 'one set for ' + k,
                                 written: seen[k], owner: v });
            }
            seen[k] = v;
          });
        });
      });
    }
    closedSets.consoleRegister().forEach(function (row) {
      if (/probe86/.test(row.page)) {
        return;
      }
      row.fields.forEach(function (f) {
        const body = {};
        body[f.path[0]] = OUTSIDE;
        const checked = closedSets.checkForm(row.page, row.action, body);
        report.console.push({ where: row.page + ' ' + row.action + ' ' +
                                     f.path[0],
                              refused: !checked.ok,
                              sentence: checked.sentence || '' });
      });
    });
    done();
  })().catch(function (e) {
    // Carried on the report: the parent says what went wrong.
    report.error = String((e && e.stack) || e);
    done();
  });
}

function loadReport() {
  log.debug("Entering loadReport().");
  const out = path.join(os.tmpdir(), 'cs-' + process.pid + '-' +
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
                                  CS_ROOT: ROOT, CS_OUT: out }),
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
    // Never written, which the read above has already reported.
    log.debug("Caught in loadReport(): " + ((e && e.message) || e));
  }
  log.debug("Leaving loadReport().");
  return { report: report, result: result };
}

function wrapperAndRegister(t) {
  log.debug("Entering wrapperAndRegister().");
  const loaded = loadReport();
  const report = loaded.report;
  if (!t.check(!!report && !report.error,
               'the child loaded the management API and probed it',
               report && report.error ? report.error.slice(0, 800) :
               'exit ' + loaded.result.status + ' ' +
               String(loaded.result.stderr || '').slice(-800))) {
    log.debug("Leaving wrapperAndRegister().");
    // Every assertion below reads the report.
    return;
  }
  t.log.info('=== B. every body enum, through the route wrapper ===');
  report.body.forEach(function (row) {
    const spelt = row.path.map(function (p) {
      return p === '*' ? '0' : p;
    }).join('.');
    let said = '';
    try {
      said = (JSON.parse(row.body).errors || []).join(' ');
    } catch (e) {
      // Not the API's JSON refusal; the check below reports the body.
      log.debug("Caught in wrapperAndRegister(): " + ((e && e.message) || e));
    }
    t.check(row.status === 400 &&
            /which is not one of the \d+ values? it accepts:/.test(said) &&
            said.indexOf('"' + spelt + '"') >= 0 &&
            row.values.every(function (v) {
              return said.indexOf(JSON.stringify(v)) >= 0;
            }),
            row.where + ' is refused outside its set, before the operation',
            'status ' + row.status + ': ' + row.body.slice(0, 400));
  });
  t.check(report.body.length >= MINIMUM_BODY_ENUMS,
          report.body.length + ' body enums reached through the wrapper ' +
          '(floor ' + MINIMUM_BODY_ENUMS + ')', '');
  t.log.info('=== B. the sets written out by hand ===');
  report.ties.forEach(function (row) {
    t.equal(JSON.stringify(row.written), JSON.stringify(row.owner), row.what);
  });
  t.log.info('=== B. every console control in the register ===');
  const controls = {};
  report.console.forEach(function (row) {
    controls[row.where.split(' ').slice(0, 2).join(' ')] = true;
    t.check(row.refused && /it accepts:/.test(row.sentence),
            row.where + ' is refused outside its set', row.sentence);
  });
  t.check(Object.keys(controls).length >= MINIMUM_CONSOLE_CONTROLS,
          Object.keys(controls).length + ' console controls hold a closed ' +
          'set (floor ' + MINIMUM_CONSOLE_CONTROLS + ')', '');
  log.debug("Leaving wrapperAndRegister().");
}

function run(t) {
  log.debug("Entering run().");
  unitRules(t);
  wrapperAndRegister(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'closed_sets',
  describe: 'every closed set an administrator can type into is refused ' +
            'outside its enum: the leaf\'s rules, every /admin-api body ' +
            'enum through the route wrapper, and the console register',
  run: run
};
