// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_pep.js
//
// ---------------------------------------------------------------------------
// THE REMOTE PEP'S MODEL, ITS GENERATED FILES, AND THE CODE IT DESCRIBES
// (#1830).
//
// `models/pep/` is the TypeSpec source of every HTTP surface the remote PEP
// serves or calls. This holds three things:
//
//   A. the committed OpenAPI documents (`xacml-pep/openapi/`) and Rust types
//      (`rust/crates/sts-model-pep/src/generated/`) are what the model makes
//      — run `tests/tools/regenerate-pep-model.sh` when this fails;
//   B. each document is well formed: OpenAPI 3.1.0, every operation with an
//      operationId unique across the four, every response with a
//      description;
//   C. NO DRIFT, IN EITHER DIRECTION, as `tests/protocol/sts_metadata.js`
//      holds the service's endpoints: every path the PEP's dispatch matches
//      (`rust/bins/xacml-pep/src/`, its test modules left out) and every
//      `/xacml/pep/*` or `/xacml/pip` route the service registers
//      (`xacml/xacml.ts`) is a path of a document, and every path of a
//      document is one of those. The reverse proxy's configured routes are
//      not paths of the PEP's: configuration decides them.
//
// That the Rust types read the PEP's real answers is `cargo test -p
// xacml-pep`'s (`model_answers` in `service.rs`, `authzen.rs` and
// `proxy.rs`), and that they read every example the documents carry is
// `cargo test -p sts-model-pep`'s.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const url = require('url');

const log = require('bunyan').createLogger({
  name: 'model_pep',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');
const PEP_SRC = path.join(ROOT, 'rust', 'bins', 'xacml-pep', 'src');

const METHODS = ['get', 'put', 'post', 'patch', 'delete', 'head', 'options'];

/**
 * A Rust source file without its test module: everything from the first
 * `#[cfg(test)]` on, which is where every file of the PEP keeps its tests.
 *
 * @param file - the file's path
 * @returns the text before its tests
 */
function withoutTests(file) {
  log.debug("Entering withoutTests().");
  const text = fs.readFileSync(file, 'utf8');
  const at = text.indexOf('#[cfg(test)]');
  log.debug("Leaving withoutTests().");
  return at < 0 ? text : text.slice(0, at);
}

/**
 * Every path the PEP's own dispatch matches, as a document writes it: a
 * `*_PATH` constant, a `path == "..."` comparison and a
 * `strip_prefix("/x/")`, which is the path parameter `{name}`.
 *
 * @returns the paths, sorted
 */
function pepPaths() {
  log.debug("Entering pepPaths().");
  const found = new Set();
  fs.readdirSync(PEP_SRC).filter(function (one) {
    return /\.rs$/.test(one) && !/_tests\.rs$/.test(one);
  }).forEach(function (one) {
    const text = withoutTests(path.join(PEP_SRC, one));
    let match;
    const constant = /pub const [A-Z_]+_PATH: &str = "(\/[^"]*)"/g;
    while ((match = constant.exec(text)) !== null) {
      found.add(match[1]);
    }
    const compared = /\bpath == "(\/[^"]*)"/g;
    while ((match = compared.exec(text)) !== null) {
      found.add(match[1]);
    }
    const prefix = /\bpath\.strip_prefix\("(\/[^"]*\/)"\)/g;
    while ((match = prefix.exec(text)) !== null) {
      found.add(match[1] + '{name}');
    }
  });
  log.debug("Leaving pepPaths(). " + found.size);
  return Array.from(found).sort();
}

/**
 * Every control-plane route the service registers for a remote PEP.
 *
 * @returns the paths, sorted
 */
function controlPlanePaths() {
  log.debug("Entering controlPlanePaths().");
  const text = fs.readFileSync(path.join(ROOT, 'xacml', 'xacml.ts'), 'utf8');
  const found = new Set();
  const route = /app\.(?:get|post|put|delete)\(\s*'(\/xacml\/(?:pep\/[^']+|pip))'/g;
  let match;
  while ((match = route.exec(text)) !== null) {
    found.add(match[1]);
  }
  log.debug("Leaving controlPlanePaths(). " + found.size);
  return Array.from(found).sort();
}

/**
 * The committed documents, by file name.
 *
 * @returns the parsed documents
 */
function committedDocuments() {
  log.debug("Entering committedDocuments().");
  const dir = path.join(ROOT, 'xacml-pep', 'openapi');
  const out = {};
  fs.readdirSync(dir).filter(function (one) {
    return /\.json$/.test(one);
  }).forEach(function (one) {
    out[one] = JSON.parse(fs.readFileSync(path.join(dir, one), 'utf8'));
  });
  log.debug("Leaving committedDocuments().");
  return out;
}

/**
 * A. The committed files are what the model makes.
 *
 * @param t - the test context
 */
async function generated(t) {
  log.debug("Entering generated().");
  const generator = await import(url.pathToFileURL(path.join(ROOT, 'models',
    'tools', 'generate_pep.mjs')).href);
  const rendered = await generator.render();
  const wrong = generator.differences(rendered);
  t.check(wrong.length === 0, 'every file models/pep/ generates is ' +
    'committed as it makes it (tests/tools/regenerate-pep-model.sh)',
  wrong.join(', '));
  t.check(Object.keys(rendered).length >= 6, 'it makes four documents and ' +
    'the Rust modules', String(Object.keys(rendered).length));
  log.debug("Leaving generated().");
}

/**
 * B. Each document is well formed.
 *
 * @param t - the test context
 * @param documents - from `committedDocuments()`
 */
function wellFormed(t, documents) {
  log.debug("Entering wellFormed().");
  const ids = new Map();
  t.equal(Object.keys(documents).sort().join(','),
    'pep-authzen.json,pep-control-plane.json,pep-proxy.json,' +
    'pep-service.json', 'the four surfaces each have a document');
  Object.keys(documents).forEach(function (file) {
    const document = documents[file];
    t.equal(document.openapi, '3.1.0', file + ' is OpenAPI 3.1.0');
    Object.keys(document.paths || {}).forEach(function (one) {
      Object.keys(document.paths[one]).filter(function (method) {
        return METHODS.indexOf(method) >= 0;
      }).forEach(function (method) {
        const operation = document.paths[one][method];
        const where = file + ' ' + method.toUpperCase() + ' ' + one;
        t.check(Boolean(operation.operationId), where + ' has an operationId');
        t.check(!ids.has(operation.operationId), where + '\'s operationId ' +
          'is unique across the four documents',
        ids.get(operation.operationId) || '');
        ids.set(operation.operationId, where);
        Object.keys(operation.responses || {}).forEach(function (status) {
          t.check(Boolean(operation.responses[status].description),
            where + ' ' + status + ' has a description');
        });
      });
    });
  });
  log.debug("Leaving wellFormed().");
}

/**
 * C. No drift between the documents and the code, in either direction.
 *
 * @param t - the test context
 * @param documents - from `committedDocuments()`
 */
function noDrift(t, documents) {
  log.debug("Entering noDrift().");
  const pathsOf = function (file) {
    return Object.keys((documents[file] || {}).paths || {});
  };
  const served = new Set(pathsOf('pep-service.json')
    .concat(pathsOf('pep-authzen.json'), pathsOf('pep-proxy.json')));
  const code = pepPaths();
  t.check(code.length >= 10, 'the PEP\'s dispatch is read',
    code.join(', '));
  const undescribed = code.filter(function (one) {
    return !served.has(one);
  });
  t.check(undescribed.length === 0, 'every path the PEP matches is in a ' +
    'document', undescribed.join(', '));
  const unrouted = Array.from(served).filter(function (one) {
    return code.indexOf(one) < 0;
  });
  t.check(unrouted.length === 0, 'every path a PEP document describes is ' +
    'one the PEP matches', unrouted.join(', '));
  const control = new Set(pathsOf('pep-control-plane.json'));
  const registered = controlPlanePaths();
  t.check(registered.length >= 10, 'the service\'s control-plane routes are ' +
    'read', registered.join(', '));
  const missing = registered.filter(function (one) {
    return !control.has(one);
  });
  t.check(missing.length === 0, 'every /xacml/pep/* and /xacml/pip route ' +
    'the service registers is in the control-plane document',
  missing.join(', '));
  const stale = Array.from(control).filter(function (one) {
    return registered.indexOf(one) < 0;
  });
  t.check(stale.length === 0, 'every control-plane path described is one ' +
    'the service registers', stale.join(', '));
  log.debug("Leaving noDrift().");
}

async function run(t) {
  log.debug("Entering run().");
  await generated(t);
  const documents = committedDocuments();
  wellFormed(t, documents);
  noDrift(t, documents);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_pep',
  describe: 'the remote PEP\'s model, its OpenAPI documents and Rust types, ' +
    'and the code it describes (#1830)',
  run: run
};
