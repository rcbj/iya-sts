// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_registers.js
//
// ---------------------------------------------------------------------------
// EVERY ID A REGISTER IN THE MODEL STATES HAS BEHAVIOUR, AND EVERY ID THE
// BEHAVIOUR NAMES IS IN THE MODEL (#1579).
//
// Four registers the code branches on are written once, in the model: the
// authentication policy's `mechanisms`, the service-account policy's
// `doors`, and a federation relationship's `mechanisms` and
// `subjectPolicies` terms. The modules read their rows from the generated
// facts and hold no copy, so what is left to go wrong is the line between a
// row and what it DOES:
//
//   * an id with no behaviour — a row the model adds that no code answers,
//     which a page would offer and a sign-in would then ignore;
//   * behaviour with no id — a literal the code compares against or asks the
//     policy about that the model does not state, which can never be true.
//
// The behaviour is spread across the modules that sign people in, so it is
// found in their source: every id has to appear as a quoted literal in a
// service source file (a register's rows are no longer in code, so any
// literal is a reader), and every literal at the named call sites has to be
// an id. A call site added with a new spelling is the case the second half
// is for.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'model_registers',
  level: process.env.LOG_LEVEL || 'info'
});

const ROOT = path.join(__dirname, '..');

// Not service source: the model, the tests, the pages, what is generated,
// and what is not this repository's.
const SKIPPED = new Set(['models', 'tests', 'docs', 'node_modules', 'rust',
  'deploy', 'debugger', 'companion', 'xacml-pep', 'postgres', 'mariadb',
  'openbao', 'icap-clamav', 'types', 'env', '.git', 'apidocs']);

function sources() {
  log.debug("Entering sources().");
  const out = [];
  const walk = function (dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      if (entry.isDirectory()) {
        if (!SKIPPED.has(entry.name)) {
          walk(path.join(dir, entry.name));
        }
        return;
      }
      if (/\.(js|ts)$/.test(entry.name) && !/\.d\.ts$/.test(entry.name)) {
        out.push(path.join(dir, entry.name));
      }
    });
  };
  walk(ROOT);
  // A compiled tree holds both x.ts and x.js; the TypeScript is the source.
  const files = out.filter(function (file) {
    return !(/\.js$/.test(file) && out.indexOf(file.replace(/\.js$/, '.ts')) >=
      0);
  }).map(function (file) {
    return { file: path.relative(ROOT, file),
             text: fs.readFileSync(file, 'utf8') };
  });
  log.debug("Leaving sources().");
  return files;
}

function literalsAt(files, only, pattern) {
  log.debug("Entering literalsAt().");
  const found = [];
  files.filter(function (one) {
    return !only || only.indexOf(one.file) >= 0;
  }).forEach(function (one) {
    const re = new RegExp(pattern.source, 'g');
    let m = re.exec(one.text);
    while (m) {
      found.push({ file: one.file, value: m[1] });
      m = re.exec(one.text);
    }
  });
  log.debug("Leaving literalsAt().");
  return found;
}

function register(t, files, spec) {
  log.debug("Entering register().");
  t.check(spec.ids.length > 0, spec.name + ': the model states its ids');
  spec.ids.forEach(function (id) {
    const quoted = new RegExp('[\'"`]' + id.replace(/[.*+?^${}()|[\]\\]/g,
      '\\$&') + '[\'"`]');
    const reader = files.filter(function (one) {
      return quoted.test(one.text);
    })[0];
    t.check(!!reader, spec.name + ' ' + id + ' has behaviour in the code',
      reader ? reader.file : 'no service source names it');
  });
  const used = [];
  spec.sites.forEach(function (site) {
    literalsAt(files, site.only, site.pattern).forEach(function (one) {
      used.push(one);
    });
  });
  t.check(used.length > 0, spec.name + ': the call sites were found');
  const allowed = spec.ids.concat(spec.besides || []);
  used.forEach(function (one) {
    t.check(allowed.indexOf(one.value) >= 0, spec.name + ': ' + one.file +
      ' names ' + one.value + ', which the model states');
  });
  log.debug("Leaving register().");
}

function run(t) {
  log.debug("Entering run().");
  const ModelTables = require('../common/model_tables');
  const files = sources();
  const authn = ModelTables.facts('policy.authn').mechanisms.map(
    function (row) {
      return row.id;
    });
  register(t, files, {
    name: 'authentication policy mechanism',
    ids: authn,
    sites: [{ pattern: /(?:authnPolicy|policy)\.allows\(\s*'([^']+)'/ }]
  });
  const doors = ModelTables.facts('policy.serviceAccount').doors.map(
    function (row) {
      return row.id;
    });
  register(t, files, {
    name: 'service-account door',
    ids: doors,
    // `browser` is answered by the sign-in funnel, not by a door row.
    besides: ['browser'],
    sites: [{ pattern: /allowsDoor\(\s*'([^']+)'/ },
            { pattern: /RefusesDoor\([^,()]+,\s*'([^']+)'/ }]
  });
  const terms = ModelTables.facts('federationRelationship').terms;
  register(t, files, {
    name: 'federation mechanism',
    ids: terms.mechanisms.map(function (row) {
      return row.id;
    }),
    sites: [{ only: ['authn/authn.ts'],
              pattern: /(?:chosen\.mechanism ===|declared ===)\s*'([^']+)'/ },
            { only: ['authn/authn.ts'],
              pattern: /(?<![.\w])(?:allows|offers)\(\s*'([^']+)'\s*\)/ }]
  });
  register(t, files, {
    name: 'federation subject policy',
    ids: terms.subjectPolicies.map(function (row) {
      return row.id;
    }),
    sites: [{ only: ['federation/federation_sp.ts'],
              pattern: /\bpolicy [!=]== '([^']+)'/ }]
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_registers',
  run: run
};
