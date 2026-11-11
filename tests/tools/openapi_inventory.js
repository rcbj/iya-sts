#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi_inventory.js
//
// ---------------------------------------------------------------------------
// THE PER-OPERATION INVENTORY OF RESPONSE MODELS (#1353).
//
// Reads OpenAPI documents from files named on the command line and prints,
// per operation and per status it declares, whether that status has a model
// and whether the model is closed. A tool for a person and for the ticket;
// `tests/openapi_response_models.js` is what holds the rule.
//
//   node tests/tools/openapi_inventory.js [--json] admin=a.json account=b.json
//
// Terms in the `state` column:
//   none      the status declares no content at all
//   bare      an object with no declared members (`{ type: 'object' }`)
//   open      declared members, but something inside admits undeclared ones
//   closed    every object inside is closed, or is a typed map
//   free-form a member is `Kit.freeForm()`, carrying the reason
//   not-json  a declared non-JSON media type
// ---------------------------------------------------------------------------

const fs = require('fs');

// Runs in a developer's shell against files, with no service loaded, so it
// carries no logger: `mgmt-api/admin_api_explorer.js`'s console arrangement.
const log = {
  debug: function () {}
};

function resolveRef(doc, schema) {
  log.debug("Entering resolveRef().");
  let out = schema;
  let hops = 0;
  while (out && out.$ref && hops < 16) {
    const name = String(out.$ref).split('/').pop();
    out = ((doc.components || {}).schemas || {})[name];
    hops += 1;
  }
  log.debug("Leaving resolveRef().");
  return out;
}

function stateOf(doc, schema, seen) {
  log.debug("Entering stateOf().");
  const s = resolveRef(doc, schema);
  if (!s || seen.has(s)) {
    log.debug("Leaving stateOf(). Nothing further.");
    return s ? 'closed' : 'none';
  }
  seen.add(s);
  if (s['x-free-form']) {
    log.debug("Leaving stateOf(). Free-form.");
    return 'free-form';
  }
  const worse = function (a, b) {
    const order = ['closed', 'free-form', 'open', 'bare', 'none'];
    return order.indexOf(a) > order.indexOf(b) ? a : b;
  };
  let out = 'closed';
  const types = [].concat(s.type || []);
  const isObject = types.indexOf('object') >= 0 ||
    (!s.type && (s.properties || s.additionalProperties !== undefined));
  if (isObject) {
    const typedMap = s.additionalProperties &&
      typeof s.additionalProperties === 'object' &&
      Object.keys(s.additionalProperties).length > 0;
    const members = Object.keys(s.properties || {}).length > 0;
    if (!members && !typedMap && s.additionalProperties !== false &&
        !s.oneOf && !s.anyOf && !s.allOf) {
      out = 'bare';
    } else if (s.additionalProperties !== false && !typedMap &&
               !s.oneOf && !s.anyOf && !s.allOf) {
      out = 'open';
    }
  }
  if (s.additionalProperties && typeof s.additionalProperties === 'object') {
    out = worse(out, stateOf(doc, s.additionalProperties, seen));
  }
  Object.keys(s.properties || {}).forEach(function (k) {
    out = worse(out, stateOf(doc, s.properties[k], seen));
  });
  if (s.items) {
    out = worse(out, stateOf(doc, s.items, seen));
  }
  ['oneOf', 'anyOf', 'allOf'].forEach(function (k) {
    (s[k] || []).forEach(function (one) {
      out = worse(out, stateOf(doc, one, seen));
    });
  });
  log.debug("Leaving stateOf(). " + out);
  return out;
}

function rowsOf(api, doc) {
  log.debug("Entering rowsOf(). " + api);
  const rows = [];
  Object.keys(doc.paths || {}).sort().forEach(function (path) {
    Object.keys(doc.paths[path]).forEach(function (method) {
      const op = doc.paths[path][method];
      if (!op || !op.responses) {
        return;
      }
      Object.keys(op.responses).forEach(function (status) {
        const content = op.responses[status].content;
        const type = content && Object.keys(content)[0];
        let state = 'none';
        if (type && !/json/.test(type)) {
          state = 'not-json';
        } else if (type) {
          state = stateOf(doc, content[type].schema, new Set());
        }
        rows.push({ api: api, method: method.toUpperCase(), path: path,
                    operationId: op.operationId || '', status: status,
                    state: state });
      });
    });
  });
  log.debug("Leaving rowsOf(). " + rows.length);
  return rows;
}

function main(argv) {
  log.debug("Entering main().");
  const json = argv.indexOf('--json') >= 0;
  let rows = [];
  argv.filter(function (a) {
    return a.indexOf('=') > 0;
  }).forEach(function (pair) {
    const at = pair.indexOf('=');
    rows = rows.concat(rowsOf(pair.slice(0, at),
      JSON.parse(fs.readFileSync(pair.slice(at + 1), 'utf8'))));
  });
  if (json) {
    process.stdout.write(JSON.stringify(rows, null, 1) + '\n');
    log.debug("Leaving main(). JSON.");
    return;
  }
  process.stdout.write('api\tmethod\tpath\toperationId\tstatus\tstate\n');
  rows.forEach(function (r) {
    process.stdout.write([r.api, r.method, r.path, r.operationId, r.status,
                          r.state].join('\t') + '\n');
  });
  log.debug("Leaving main().");
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = { rowsOf: rowsOf, stateOf: stateOf };
