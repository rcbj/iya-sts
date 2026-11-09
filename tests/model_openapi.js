// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_openapi.js
//
// ---------------------------------------------------------------------------
// THE API NAMESPACE KEEPS TODAY'S DOCUMENTS (#1390).
//
// A captured document emits as `JSON.stringify` of the object that was
// captured, key order included. The index lists every path and method. A
// response with no schema is a gap. Ajv checks a value against the
// captured schema. The five served documents are built in a child, the
// same way `tests/openapi_response_models.js` builds them, and this file
// does not require that test.
//
// Response-model tables are not imported. The child that builds documents
// is the stack, and the library does not start that child itself.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const url = require('url');
const { spawnSync } = require('child_process');

const log = require('bunyan').createLogger({
  name: 'model_openapi',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.resolve(__dirname, '..');

function operationCount(document) {
  log.debug("Entering operationCount().");
  let count = 0;
  const paths = document && document.paths || {};
  Object.keys(paths).forEach(function (onePath) {
    const item = paths[onePath] || {};
    Object.keys(item).forEach(function (method) {
      if (['get', 'put', 'post', 'delete', 'options', 'head', 'patch',
          'trace'].indexOf(method) >= 0) {
        count += 1;
      }
    });
  });
  log.debug("Leaving operationCount().");
  return count;
}

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
  const out = path.join(os.tmpdir(), 'model-openapi-' + process.pid +
    '.json');
  const child = spawnSync(process.execPath, [__filename, '--build', out], {
    cwd: ROOT,
    stdio: ['ignore', 'ignore', 'pipe'],
    timeout: 180000,
    env: Object.assign({}, process.env, {
      LOG_LEVEL: 'fatal',
      STS_LOG_LEVEL: 'fatal'
    })
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

function fixture(t, OpenApiImport) {
  log.debug("Entering fixture().");
  const tiny = { b: 1, a: 2, paths: {} };
  const capturedTiny = OpenApiImport.capture('tiny', tiny);
  t.equal(OpenApiImport.emit(capturedTiny), JSON.stringify(tiny),
    'emit() is the builder JSON, and b stays before a');
  t.check(OpenApiImport.emit(capturedTiny).indexOf('"b"') <
    OpenApiImport.emit(capturedTiny).indexOf('"a"'),
    'keys are not sorted');

  const document = {
    openapi: '3.0.3',
    info: { title: 'Fixture', version: '0' },
    paths: {
      '/x': {
        post: {
          operationId: 'doX',
          'x-vendor': true,
          responses: {
            '200': {
              description: 'ok',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Thing' }
                }
              }
            },
            '204': { description: 'none' }
          }
        }
      }
    },
    components: {
      schemas: {
        Thing: {
          type: 'object',
          additionalProperties: false,
          properties: { b: { type: 'string' } }
        }
      }
    }
  };
  const captured = OpenApiImport.capture('fixture', document);
  t.equal(OpenApiImport.emit(captured), JSON.stringify(document),
    'a document with a ref emits unchanged');
  t.equal(captured.operations.length, 1, 'the one operation is indexed');
  t.equal(captured.operations[0].vendor['x-vendor'], true,
    'a vendor key is indexed and the document still carries it');
  t.check(JSON.stringify(captured.operations[0].responses[0].schema)
      .indexOf('additionalProperties') < 0,
    'a ref is not replaced with the component');
  t.check(captured.gaps.some(function (gap) {
    return gap.code === 'response-without-schema' &&
      gap.name === 'doX.204';
  }), 'a 204 with no schema is a gap');
  const good = OpenApiImport.parse(captured, 'Thing', { b: 'ok' });
  t.check(good.ok, 'a value the schema allows matches',
    good.errors.join(';'));
  const extra = OpenApiImport.parse(captured, 'Thing',
    { b: 'ok', extra: 1 });
  t.check(!extra.ok, 'an extra property fails');

  const broken = {
    openapi: '3.0.3',
    info: { title: 't', version: '0' },
    paths: {},
    components: { schemas: { Bad: { type: 'not-a-type' } } }
  };
  const capturedBad = OpenApiImport.capture('broken', broken);
  let threw = false;
  try {
    OpenApiImport.parse(capturedBad, 'Bad', {});
  } catch (error) {
    log.debug("Caught in fixture(): " + ((error && error.message) || error));
    threw = true;
  }
  t.check(!threw, 'a schema Ajv cannot compile does not throw');
  log.debug("Leaving fixture().");
}

function served(t, OpenApiImport, ModelEmit) {
  log.debug("Entering served().");
  const source = fs.readFileSync(path.join(ROOT, 'common',
    'openapi_import.ts'), 'utf8');
  t.check(source.indexOf('tests/openapi_response_models.js') >= 0,
    'response models stay the other check');
  t.equal(OpenApiImport.served.join(','),
    'management,console,account,authn,report',
    'five served documents');
  t.check(OpenApiImport.served.indexOf('admin') < 0,
    'the unfiltered admin document is not a served document');

  const docs = documents();
  t.check(!!docs.admin, 'the child still builds the unfiltered document');
  const named = OpenApiImport.served.map(function (name) {
    return { name: name, document: docs[name] };
  });
  const captured = ModelEmit.captureDocuments(named);
  t.equal(captured.length, 5, 'capture does not add a sixth document');
  captured.forEach(function (model) {
    const document = docs[model.name];
    sameText(t, OpenApiImport.emit(model), JSON.stringify(document),
      model.name + ' emits as the builder JSON');
    const actual = operationCount(document);
    t.check(actual > 0, model.name + ' has operations');
    t.equal(model.operations.length, actual,
      model.name + ' indexes every path and method');
    const indexed = model.operations.map(function (operation) {
      return operation.method + ' ' + operation.path;
    }).sort();
    const present = [];
    Object.keys(document.paths || {}).forEach(function (onePath) {
      const item = document.paths[onePath] || {};
      Object.keys(item).forEach(function (method) {
        if (['get', 'put', 'post', 'delete', 'options', 'head', 'patch',
            'trace'].indexOf(method) >= 0) {
          present.push(method + ' ' + onePath);
        }
      });
    });
    present.sort();
    sameText(t, indexed.join('\n'), present.join('\n'),
      model.name + ' indexes each operation once');
  });
  log.debug("Leaving served().");
  return docs;
}

function sameText(t, actual, expected, what) {
  log.debug("Entering sameText().");
  if (actual === expected) {
    t.check(true, what);
    log.debug("Leaving sameText(). Equal.");
    return;
  }
  let at = 0;
  const end = Math.min(actual.length, expected.length);
  while (at < end && actual.charAt(at) === expected.charAt(at)) {
    at += 1;
  }
  t.check(false, what, 'lengths ' + actual.length + ' and ' +
    expected.length + ', first difference at ' + at + ', expected ' +
    JSON.stringify(expected.slice(at, at + 60)) + ', got ' +
    JSON.stringify(actual.slice(at, at + 60)));
  log.debug("Leaving sameText(). Differ.");
}

// `required` is a set, so its order is not a difference. Object keys are
// sorted for the same reason; arrays keep theirs.
function canonical(value) {
  log.debug("Entering canonical().");
  const text = JSON.stringify(value, function (key, held) {
    if (!held || typeof held !== 'object' || Array.isArray(held)) {
      return held;
    }
    const out = {};
    Object.keys(held).sort().forEach(function (name) {
      out[name] = name === 'required' && Array.isArray(held[name]) ?
        held[name].slice().sort() : held[name];
    });
    return out;
  });
  log.debug("Leaving canonical().");
  return text;
}

function bindReport(generated) {
  log.debug("Entering bindReport().");
  const OpenApi = require('../report/openapi');
  const Catalog = require('../report/catalog');
  const bound = OpenApi.bind(generated, new Catalog());
  log.debug("Leaving bindReport().");
  return bound;
}

async function typeSpec(t, docs) {
  log.debug("Entering typeSpec().");
  const compiler = await import(url.pathToFileURL(path.join(__dirname,
    'node_modules', '@typespec', 'compiler', 'dist', 'src', 'index.js')).href);
  const lib = await import(url.pathToFileURL(path.join(ROOT, 'models', 'lib',
    'api_lib.mjs')).href);
  const program = await compiler.compile(compiler.NodeHost,
    path.join(ROOT, 'models', 'api', 'main.tsp'), { noEmit: true });
  t.equal(program.diagnostics.filter(function (one) {
    return one.severity === 'error';
  }).map(function (one) {
    return one.code + ': ' + one.message;
  }).join('\n'), '', 'models/api compiles with the TypeSpec compiler');
  const built = lib.documents(program);
  ['management', 'console', 'account', 'authn', 'report'].forEach(
    function (name) {
      const compiled = name === 'report' ? bindReport(built[name]) :
        built[name];
      sameText(t, canonical(compiled), canonical(docs[name]),
        name + ' from the compiled model is the served document. A change ' +
        'to the API owes tests/tools/regenerate-model-docs.sh');
    });
  log.debug("Leaving typeSpec().");
}

async function run(t) {
  log.debug("Entering run().");
  const OpenApiImport = require('../common/openapi_import');
  const ModelEmit = require('../common/model_emit');
  fixture(t, OpenApiImport);
  const docs = served(t, OpenApiImport, ModelEmit);
  await typeSpec(t, docs);
  log.debug("Leaving run().");
}

if (require.main === module && process.argv[2] === '--build') {
  buildDocuments(process.argv[3]);
  process.exit(0);
}

module.exports = {
  name: 'model_openapi',
  run: run
};
