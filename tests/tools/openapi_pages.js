#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi_pages.js
//
// ---------------------------------------------------------------------------
// THE OPENAPI DOCUMENTS AS PAGES SOMEBODY CAN READ (rcbj, 2026-11-06).
//
// `pagesOf(documents)` turns the documents each published API answers into the
// markdown under `docs/openapi/`: every operation, its parameters, its request
// body and each status's response, with every member of a model on a line of
// its own at its dotted path. A pure function of the documents, with no service
// loaded, so `tests/openapi_pages.js` can hold the committed pages to what the
// running code's documents produce. `tests/tools/regenerate-openapi-pages.sh`
// writes them.
//
// The volatile parts of a document are not drawn: `servers` is whatever address
// answered, and `info.version` carries the build instant.
// ---------------------------------------------------------------------------

// Runs in a developer's shell against files, with no service loaded, so it
// carries no logger: `mgmt-api/admin_api_explorer.js`'s console arrangement.
const log = {
  debug: function () {}
};

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

// The deepest a model is walked. Recursion through `$ref` stops at the first
// repeat anyway; this is for a model that is merely very deep.
const MAX_DEPTH = 8;

const APIS = [
  { key: 'management', file: 'admin-api', title: 'Management API',
    base: '/admin-api', order: 2, byTag: true,
    intro: 'Every console control, reachable by a machine. ' +
           '[How to get a token and call it](../management-api.html).' },
  { key: 'console', file: 'admin-console-api',
    title: 'Admin console operations', base: '/admin-api/console', order: 3,
    intro: 'The operations that exist to draw the console. They are not the ' +
           'management API, and a machine client has no use for them.' },
  { key: 'account', file: 'account-api', title: 'Account API',
    base: '/account-api', order: 4,
    intro: 'What a person can see and do about their own account. ' +
           '[How it is used](../account-api.html).' },
  { key: 'authn', file: 'authn-api', title: 'Sign-in API',
    base: '/authn-api', order: 5,
    intro: 'What the sign-in screens read and send. ' +
           '[How it is used](../authn-api.html).' },
  { key: 'report', file: 'report-api', title: 'Report API',
    base: '/report-api', order: 6,
    intro: 'Reports: what can be queried, and the jobs that run a query.' }
];

// No HTML from a description, outside a code span: markdown already escapes what
// is inside one, and `&lt;` there would be read as those four characters.
function escaped(text) {
  log.debug("Entering escaped().");
  log.debug("Leaving escaped().");
  return String(text).split(/(`[^`\n]*`)/).map(function (part) {
    return part.charAt(0) === '`' ? part
      : part.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  }).join('');
}

// A table cell: one line, its pipes escaped.
function cell(text) {
  log.debug("Entering cell().");
  log.debug("Leaving cell().");
  return escaped(String(text === undefined || text === null ? '' : text)
    .replace(/\s*\n\s*/g, ' ')).replace(/\|/g, '\\|').trim();
}

// Prose from a document: its own markdown, with no HTML from it.
function prose(text) {
  log.debug("Entering prose().");
  log.debug("Leaving prose().");
  return escaped(String(text || '')).trim();
}

// A heading's kramdown id is its text; a tag page's file is this.
function slug(text) {
  log.debug("Entering slug().");
  log.debug("Leaving slug().");
  return String(text).toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'other';
}

function resolve(doc, schema, seen) {
  log.debug("Entering resolve().");
  let out = schema || {};
  let hops = 0;
  while (out && out.$ref && hops < 16) {
    if (seen) {
      seen.push(out.$ref);
    }
    out = out.$ref.split('/').slice(1).reduce(function (at, part) {
      return at && at[part.replace(/~1/g, '/').replace(/~0/g, '~')];
    }, doc) || {};
    hops += 1;
  }
  log.debug("Leaving resolve().");
  return out;
}

function branchesOf(schema) {
  log.debug("Entering branchesOf().");
  log.debug("Leaving branchesOf().");
  return schema.anyOf || schema.oneOf || null;
}

// A union's arms with nested unions opened and refs read: `nullable(oneOf(a, b))`
// is three arms for a reader, not one of two of which one is one of two.
function armsOf(doc, schema) {
  log.debug("Entering armsOf().");
  const out = [];
  (branchesOf(schema) || []).forEach(function (one) {
    const inner = resolve(doc, one);
    if (branchesOf(inner)) {
      out.push.apply(out, armsOf(doc, inner));
    } else {
      out.push(one);
    }
  });
  log.debug("Leaving armsOf().");
  return out;
}

function typeWords(schema) {
  log.debug("Entering typeWords().");
  const types = [].concat(schema.type || []);
  const words = types.filter(function (one) {
    return one !== 'null';
  });
  let said = words.join(' or ');
  if (schema.format) {
    said += (said ? ', ' : '') + schema.format;
  }
  if (schema.enum) {
    said = 'one of ' + schema.enum.map(function (one) {
      return '`' + JSON.stringify(one).replace(/^"|"$/g, '') + '`';
    }).join(', ');
  }
  if (schema.const !== undefined) {
    said = '`' + JSON.stringify(schema.const).replace(/^"|"$/g, '') + '`';
  }
  if (types.indexOf('null') >= 0) {
    said += (said ? ', or ' : '') + 'null';
  }
  log.debug("Leaving typeWords().");
  return said;
}

// The rows of one schema, each `{ path, type, required, about }`. `trail` is the
// list of `$ref`s being walked, so a model that holds itself says so and stops.
function rowsOf(doc, given, at, required, trail, depth) {
  log.debug("Entering rowsOf().");
  const refs = [];
  const schema = resolve(doc, given, refs);
  const about = given.description || schema.description || '';
  const again = refs.some(function (ref) {
    return trail.indexOf(ref) >= 0;
  });
  const walked = trail.concat(refs);
  const row = function (type, note) {
    return [{ path: at, type: type, required: required,
              about: [about, note].filter(Boolean).join(' ') }];
  };
  let rows = null;
  const branches = branchesOf(schema);
  if (again || depth > MAX_DEPTH) {
    rows = row('object', again ? 'The same shape as the member holding it.'
      : 'Nested deeper than this page draws.');
  } else if (schema['x-free-form']) {
    rows = row('any JSON', schema['x-free-form']);
  } else if (branches) {
    const arms = armsOf(doc, schema);
    const isShape = function (one) {
      const inner = resolve(doc, one);
      return !!(inner.properties || inner.items ||
                inner.additionalProperties || inner['x-free-form']);
    };
    const words = arms.filter(function (one) {
      return !isShape(one);
    }).map(function (one) {
      return typeWords(resolve(doc, one));
    }).filter(Boolean);
    const shapes = arms.filter(isShape);
    // `null` last, however the union wrote it.
    const scalars = words.filter(function (one) {
      return one !== 'null';
    }).concat(words.indexOf('null') >= 0 ? ['null'] : []);
    if (!shapes.length) {
      rows = row(scalars.join(', or ') || 'any JSON');
    } else if (shapes.length === 1) {
      // One shape beside scalars needs no numbering: its members hang off it.
      const members = rowsOf(doc, shapes[0], at, required, walked, depth + 1);
      if (scalars.length && members.length && members[0].path === at) {
        members[0].type += ', or ' + scalars.join(', or ');
      } else if (scalars.length) {
        members.unshift(row('object, or ' + scalars.join(', or '))[0]);
      }
      rows = members;
    } else {
      rows = row('one of ' + shapes.length + ' shapes' +
                 (scalars.length ? ', or ' + scalars.join(', or ') : ''))
        .concat(shapes.reduce(function (all, one, index) {
          return all.concat(rowsOf(doc, one,
            at + (at ? ' ' : '') + '(shape ' + (index + 1) + ')', false, walked,
            depth + 1));
        }, []));
    }
  } else if (schema.properties) {
    const needed = schema.required || [];
    rows = (at ? row('object') : []).concat(
      Object.keys(schema.properties).sort().reduce(function (all, name) {
        return all.concat(rowsOf(doc, schema.properties[name],
          at ? at + '.' + name : name, needed.indexOf(name) >= 0, walked,
          depth + 1));
      }, []));
  } else if (schema.items) {
    rows = row('list').concat(rowsOf(doc, schema.items, at + '[]', false, walked,
                                     depth + 1).filter(function (one) {
      return one.path !== at + '[]' || !isPlainObjectRow(one);
    }));
  } else if (schema.additionalProperties &&
             typeof schema.additionalProperties === 'object') {
    rows = row('map').concat(rowsOf(doc, schema.additionalProperties,
      at + '.{key}', false, walked, depth + 1).filter(function (one) {
      return one.path !== at + '.{key}' || !isPlainObjectRow(one);
    }));
  } else {
    rows = row(typeWords(schema) || 'any JSON');
  }
  log.debug("Leaving rowsOf().");
  return rows;
}

// A list's element or a map's value that is an object says nothing the members
// under it do not.
function isPlainObjectRow(one) {
  log.debug("Entering isPlainObjectRow().");
  log.debug("Leaving isPlainObjectRow().");
  return one.type === 'object' && !one.about;
}

function memberTable(rows) {
  log.debug("Entering memberTable().");
  const lines = ['| Member | Type | Required | What it is |',
                 '|---|---|---|---|'];
  rows.forEach(function (one) {
    lines.push('| ' + (one.path ? '`' + cell(one.path) + '`' : '(the answer)') +
               ' | ' + cell(one.type) + ' | ' +
               (one.required ? 'yes' : '') + ' | ' + cell(one.about) + ' |');
  });
  log.debug("Leaving memberTable().");
  return lines.join('\n');
}

function bodyLines(doc, content) {
  log.debug("Entering bodyLines().");
  const lines = [];
  Object.keys(content || {}).sort().forEach(function (media) {
    const schema = content[media].schema;
    if (!/json/.test(media)) {
      lines.push('As `' + media + '`.', '');
      return;
    }
    const rows = rowsOf(doc, schema || {}, '', false, [], 0);
    if (Object.keys(content).length > 1) {
      lines.push('As `' + media + '`:', '');
    }
    lines.push(rows.length ? memberTable(rows) : 'An empty object.', '');
  });
  log.debug("Leaving bodyLines().");
  return lines;
}

function securityWords(doc, operation) {
  log.debug("Entering securityWords().");
  const rules = operation.security || doc.security || [];
  const scopes = [];
  rules.forEach(function (rule) {
    Object.keys(rule).forEach(function (scheme) {
      (rule[scheme] || []).forEach(function (scope) {
        if (scopes.indexOf(scope) < 0) {
          scopes.push(scope);
        }
      });
    });
  });
  log.debug("Leaving securityWords().");
  return scopes.map(function (one) {
    return '`' + one + '`';
  }).join(', ');
}

function operationLines(doc, method, path, operation, refusal) {
  log.debug("Entering operationLines().");
  const lines = ['## ' + method.toUpperCase() + ' ' + path, ''];
  if (operation.operationId) {
    lines.push('`' + operation.operationId + '`' +
               (operation.deprecated ? ', deprecated' : ''), '');
  }
  if (operation.summary) {
    lines.push('**' + prose(operation.summary) + '**', '');
  }
  if (operation.description) {
    lines.push(prose(operation.description), '');
  }
  const scopes = securityWords(doc, operation);
  if (scopes) {
    lines.push('Scope: ' + scopes + '.', '');
  }
  const parameters = (operation.parameters || []).map(function (one) {
    return resolve(doc, one);
  });
  if (parameters.length) {
    lines.push('**Parameters**', '', '| Name | In | Type | Required | ' +
               'What it is |', '|---|---|---|---|---|');
    parameters.forEach(function (one) {
      lines.push('| `' + cell(one.name) + '` | ' + cell(one.in) + ' | ' +
                 cell(typeWords(resolve(doc, one.schema))) + ' | ' +
                 (one.required ? 'yes' : '') + ' | ' +
                 cell(one.description) + ' |');
    });
    lines.push('');
  }
  const requestBody = resolve(doc, operation.requestBody);
  if (requestBody.content) {
    lines.push('**Request body**' +
               (requestBody.required ? '' : ' (optional)'), '');
    if (requestBody.description) {
      lines.push(prose(requestBody.description), '');
    }
    lines.push.apply(lines, bodyLines(doc, requestBody.content));
  }
  Object.keys(operation.responses || {}).sort().forEach(function (status) {
    const answer = resolve(doc, operation.responses[status]);
    if (status === 'default' && refusal &&
        JSON.stringify(answer.content) === refusal) {
      return;
    }
    lines.push('**' + (status === 'default' ? 'Any other status' : status) +
               '**' + (answer.description ? ': ' +
               prose(answer.description).replace(/\s*\n\s*/g, ' ') : ''), '');
    lines.push.apply(lines, bodyLines(doc, answer.content));
  });
  lines.push('');
  log.debug("Leaving operationLines().");
  return lines;
}

// The refusal most operations share is said once, at the top of the page, rather
// than on six hundred operations.
function commonRefusal(doc) {
  log.debug("Entering commonRefusal().");
  const counts = {};
  Object.keys(doc.paths || {}).forEach(function (path) {
    METHODS.forEach(function (method) {
      const operation = doc.paths[path][method];
      const answer = operation && operation.responses &&
        operation.responses.default;
      if (answer) {
        const text = JSON.stringify(resolve(doc, answer).content);
        counts[text] = (counts[text] || 0) + 1;
      }
    });
  });
  const best = Object.keys(counts).sort(function (a, b) {
    return counts[b] - counts[a] || (a < b ? -1 : 1);
  })[0];
  log.debug("Leaving commonRefusal().");
  return best || null;
}

function front(title, order) {
  log.debug("Entering front().");
  log.debug("Leaving front().");
  return ['---', 'title: ' + JSON.stringify(title), 'nav_order: ' + order]
    .concat(['---', '',
      '<!-- GENERATED by tests/tools/regenerate-openapi-pages.sh from the ' +
      'OpenAPI',
      '     documents. Do not edit this file by hand: tests/openapi_pages.js ' +
      'fails',
      '     when it differs from what the documents produce. -->', '']);
}

// Liquid must not read `{{` in somebody's description or example.
function wrap(lines) {
  log.debug("Entering wrap().");
  log.debug("Leaving wrap().");
  return '{% raw %}\n' + lines.join('\n').replace(/\n{3,}/g, '\n\n').trim() +
    '\n{% endraw %}\n';
}

function operationsOf(doc) {
  log.debug("Entering operationsOf().");
  const out = [];
  Object.keys(doc.paths || {}).sort().forEach(function (path) {
    METHODS.forEach(function (method) {
      const operation = doc.paths[path][method];
      if (operation && operation.responses) {
        out.push({ path: path, method: method, operation: operation,
                   tag: (operation.tags || ['Other'])[0] });
      }
    });
  });
  log.debug("Leaving operationsOf().");
  return out;
}

function refusalLines(doc, refusal) {
  log.debug("Entering refusalLines().");
  if (!refusal) {
    log.debug("Leaving refusalLines(). None.");
    return [];
  }
  log.debug("Leaving refusalLines().");
  return ['## A refusal', '', 'Unless an operation below says otherwise, any ' +
          'status it does not list answers this:', ''].concat(
    bodyLines(doc, JSON.parse(refusal)));
}

const CLOSED = 'Every answer is checked against the model shown here before ' +
  'it is sent, and no answer carries a member its model does not list. A ' +
  'member shown as *any JSON* is one whose shape belongs to somebody else, ' +
  'and says whose. `.{key}` is a key that is data, and `[]` an element of a ' +
  'list.';

/**
 * The pages for the documents.
 *
 * @param documents - `{ admin, console, account, authn, report }`
 * @returns a map of a file name under `docs/openapi/` to its text
 */
function pagesOf(documents) {
  log.debug("Entering pagesOf().");
  const pages = {};
  const index = ['The OpenAPI document of each API this service publishes, as ' +
    'pages to read. A running service answers the same documents as JSON, at ' +
    '`/admin-api/openapi.json` and its equivalent on each API, and the ' +
    '[Endpoints](../endpoints.html) page lists what else it serves.', '',
    CLOSED, '', '| API | Base path | Operations |', '|---|---|---|'];
  APIS.forEach(function (api) {
    const doc = documents[api.key];
    if (!doc) {
      return;
    }
    const all = operationsOf(doc);
    const refusal = commonRefusal(doc);
    index.push('| [' + api.title + '](' + api.file + '.html) | `' + api.base +
               '` | ' + all.length + ' |');
    const head = [api.intro, ''].concat(
      doc.info && doc.info.description ? [prose(doc.info.description), ''] : [],
      [CLOSED, '']);
    if (!api.byTag) {
      pages[api.file + '.md'] = front(api.title, api.order)
        .join('\n') + wrap(head.concat(refusalLines(doc, refusal),
          all.reduce(function (lines, one) {
            return lines.concat(operationLines(doc, one.method, one.path,
              one.operation, refusal));
          }, [])));
      return;
    }
    // Hundreds of operations on one page is a page nobody can open: one page
    // per tag, and this page says which.
    const tags = {};
    all.forEach(function (one) {
      (tags[one.tag] = tags[one.tag] || []).push(one);
    });
    const names = Object.keys(tags).sort();
    const about = {};
    (doc.tags || []).forEach(function (one) {
      about[one.name] = one.description || '';
    });
    const list = ['## Sections', '', '| Section | Operations | What it covers |',
                  '|---|---|---|'];
    names.forEach(function (name, at) {
      const file = api.file + '-' + slug(name);
      list.push('| [' + cell(name) + '](' + file + '.html) | ' +
                tags[name].length + ' | ' +
                cell(String(about[name]).split(/\n\s*\n/)[0]) + ' |');
      pages[file + '.md'] = front(api.title + ': ' + name, 100 + at).join('\n') +
        wrap(['[' + api.title + '](' + api.file + '.html)', '']
          .concat(about[name] ? [prose(about[name]), ''] : [],
                  [CLOSED, ''], refusalLines(doc, refusal),
                  tags[name].reduce(function (lines, one) {
                    return lines.concat(operationLines(doc, one.method, one.path,
                      one.operation, refusal));
                  }, [])));
    });
    pages[api.file + '.md'] = front(api.title, api.order)
      .join('\n') + wrap(head.concat(list, ['']));
  });
  pages['index.md'] = front('OpenAPI reference', 1).join('\n') +
    wrap(index.concat(['']));
  log.debug("Leaving pagesOf(). " + Object.keys(pages).length + " pages.");
  return pages;
}

// `--write <dir>`: the pages for what this image's code answers, replacing what
// is there. Run by tests/tools/regenerate-openapi-pages.sh inside the tests
// image, because the service is compiled only in an image build.
function write(dir) {
  log.debug("Entering write().");
  const fs = require('fs');
  const path = require('path');
  const { documents } = require('../openapi_response_models');
  const pages = pagesOf(documents());
  fs.readdirSync(dir).forEach(function (name) {
    if (/\.md$/.test(name)) {
      fs.unlinkSync(path.join(dir, name));
    }
  });
  Object.keys(pages).forEach(function (name) {
    fs.writeFileSync(path.join(dir, name), pages[name]);
  });
  log.debug("Leaving write().");
  return Object.keys(pages).length;
}

if (require.main === module) {
  const at = process.argv.indexOf('--write');
  if (at < 0 || !process.argv[at + 1]) {
    process.stderr.write('usage: openapi_pages.js --write <dir>\n');
    process.exit(2);
  }
  process.stdout.write('wrote ' + write(process.argv[at + 1]) + ' pages\n');
}

module.exports = { pagesOf: pagesOf, APIS: APIS };
