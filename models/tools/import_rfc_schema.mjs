#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/tools/import_rfc_schema.mjs
//
// ---------------------------------------------------------------------------
// THE LDAP DEFINITIONS THE STANDARDS PUBLISH, READ FROM THE STANDARDS (#1390).
//
// Reads the text of each RFC and writes `models/directory/rfc_schema.json`:
// every attribute type and object class the document defines, with its OID,
// syntax, matching rules, superior and MUST/MAY. A name two documents define
// keeps the definition of the document listed first, so RFC 4519's `cn` wins
// over RFC 2798's repeat of it. A superior's syntax and matching rules are
// resolved onto the attribute that inherits them.
//
//   node models/tools/import_rfc_schema.mjs <dir of texts> <out.json>
//
// The texts are named rfcNNNN.txt, and behera.txt for
// draft-behera-ldap-password-policy-11. Running it twice writes one file.
// ---------------------------------------------------------------------------

import fs from 'fs';
import path from 'path';

const log = {
  debug: function (message) {
    if (process.env.STS_LOG_LEVEL === 'debug') {
      console.error(message);
    }
  }
};

const SOURCES = [
  ['rfc4512.txt', 'RFC 4512'], ['rfc4519.txt', 'RFC 4519'],
  ['rfc4523.txt', 'RFC 4523'], ['rfc4524.txt', 'RFC 4524'],
  ['rfc4530.txt', 'RFC 4530'], ['rfc5020.txt', 'RFC 5020'],
  ['rfc2798.txt', 'RFC 2798'], ['rfc2307.txt', 'RFC 2307'],
  ['behera.txt', 'draft-behera-ldap-password-policy-11']
];

// RFC 2307 writes its OIDs through this macro.
const NIS_SCHEMA = '1.3.6.1.1.1';

/**
 * The text with page breaks and page furniture removed.
 *
 * @param text - the document
 * @returns the text
 */
function clean(text) {
  log.debug("Entering clean().");
  const out = text.split(/\r?\n/).filter(function (line) {
    return !/\[Page \d+\]\s*$/.test(line) &&
      !/^(RFC \d+|Internet-Draft)\s+.*\s\d{4}\s*$/.test(line) &&
      !/^\f/.test(line);
  }).join('\n').replace(/nisSchema\./g, NIS_SCHEMA + '.');
  log.debug("Leaving clean().");
  return out;
}

/**
 * Every balanced `( oid NAME ... )` in a document.
 *
 * @param text - the cleaned document
 * @returns the definitions, as text
 */
function definitions(text) {
  log.debug("Entering definitions().");
  const found = [];
  const start = /\(\s*\d+(?:\.\d+)+\s+NAME\s/g;
  let match = start.exec(text);
  while (match) {
    let depth = 0;
    let quoted = false;
    let i = match.index;
    for (; i < text.length; i += 1) {
      const ch = text.charAt(i);
      if (ch === "'") {
        quoted = !quoted;
      } else if (!quoted && ch === '(') {
        depth += 1;
      } else if (!quoted && ch === ')') {
        depth -= 1;
        if (depth === 0) {
          break;
        }
      }
    }
    found.push(text.slice(match.index + 1, i));
    start.lastIndex = i;
    match = start.exec(text);
  }
  log.debug("Leaving definitions().");
  return found;
}

/**
 * The tokens of a definition. A quoted string is one token, marked.
 *
 * @param body - the definition, without its outer parentheses
 * @returns the tokens
 */
function tokens(body) {
  log.debug("Entering tokens().");
  const out = body.match(/'[^']*'|[()$]|[^\s()$']+/g) || [];
  log.debug("Leaving tokens().");
  return out;
}

/**
 * The value after a keyword: one token, or a parenthesized list.
 *
 * @param list - the tokens
 * @param at - the index of the first value token
 * @returns the values and the index after them
 */
function values(list, at) {
  log.debug("Entering values().");
  const unquote = function (token) {
    return token.replace(/^'|'$/g, '');
  };
  if (list[at] !== '(') {
    log.debug("Leaving values(). One.");
    return { values: [unquote(list[at])], next: at + 1 };
  }
  const out = [];
  let i = at + 1;
  while (i < list.length && list[i] !== ')') {
    if (list[i] !== '$') {
      out.push(unquote(list[i]));
    }
    i += 1;
  }
  log.debug("Leaving values(). A list.");
  return { values: out, next: i + 1 };
}

/**
 * One definition as a record.
 *
 * @param body - the definition
 * @param source - the document it came from
 * @returns the record
 */
function parse(body, source) {
  log.debug("Entering parse().");
  const list = tokens(body);
  const row = { oid: list[0], source: source };
  let i = 1;
  while (i < list.length) {
    const word = list[i];
    if (word === 'SINGLE-VALUE') {
      row.singleValue = true;
      i += 1;
    } else if (word === 'NO-USER-MODIFICATION') {
      row.noUserModification = true;
      i += 1;
    } else if (word === 'OBSOLETE') {
      row.obsolete = true;
      i += 1;
    } else if (word === 'STRUCTURAL' || word === 'AUXILIARY' ||
        word === 'ABSTRACT') {
      row.classType = word.toLowerCase();
      i += 1;
    } else if (/^[A-Z-]+$/.test(word) && i + 1 < list.length) {
      const taken = values(list, i + 1);
      row[word] = taken.values;
      i = taken.next;
    } else {
      i += 1;
    }
  }
  log.debug("Leaving parse().");
  return row;
}

/**
 * A record in the shape the model keeps.
 *
 * @param row - a parsed definition
 * @returns the entry
 */
function entry(row) {
  log.debug("Entering entry().");
  const first = function (key) {
    return row[key] ? row[key][0] : undefined;
  };
  const isClass = row.classType !== undefined || row.MUST !== undefined ||
    row.MAY !== undefined || row.SYNTAX === undefined && !row.EQUALITY &&
    !row.SUP;
  const out = { oid: row.oid, names: row.NAME, source: row.source };
  if (first('DESC')) {
    out.desc = first('DESC').replace(/\s+/g, ' ');
  }
  if (isClass) {
    out.classType = row.classType || 'structural';
    out.sup = row.SUP || [];
    out.must = row.MUST || [];
    out.may = row.MAY || [];
  } else {
    ['SUP', 'EQUALITY', 'ORDERING', 'SUBSTR', 'SYNTAX', 'USAGE'].forEach(
      function (key) {
        if (first(key)) {
          out[key.toLowerCase()] = first(key);
        }
      });
    out.singleValue = row.singleValue === true;
    if (row.noUserModification) {
      out.noUserModification = true;
    }
  }
  log.debug("Leaving entry().");
  return { isClass: isClass, value: out };
}

/**
 * Copies a superior's syntax and matching rules onto what inherits them.
 *
 * @param attributes - the attributes, keyed by lower-case name
 */
function inherit(attributes) {
  log.debug("Entering inherit().");
  Object.keys(attributes).forEach(function (key) {
    const attribute = attributes[key];
    let parent = attribute.sup && attributes[attribute.sup.toLowerCase()];
    let guard = 0;
    while (parent && guard < 8) {
      ['syntax', 'equality', 'ordering', 'substr'].forEach(function (field) {
        if (attribute[field] === undefined && parent[field] !== undefined) {
          attribute[field] = parent[field];
        }
      });
      parent = parent.sup && attributes[parent.sup.toLowerCase()];
      guard += 1;
    }
  });
  log.debug("Leaving inherit().");
}

/**
 * Sorts an object's keys.
 *
 * @param table - the table
 * @returns a copy in key order
 */
function sorted(table) {
  log.debug("Entering sorted().");
  const out = {};
  Object.keys(table).sort().forEach(function (key) {
    out[key] = table[key];
  });
  log.debug("Leaving sorted().");
  return out;
}

/**
 * Reads the documents and writes the table.
 *
 * @param from - the directory of texts
 * @param to - the file to write
 */
function main(from, to) {
  log.debug("Entering main().");
  const attributes = {};
  const classes = {};
  SOURCES.forEach(function (source) {
    const text = clean(fs.readFileSync(path.join(from, source[0]), 'utf8'));
    definitions(text).forEach(function (body) {
      const made = entry(parse(body, source[1]));
      const table = made.isClass ? classes : attributes;
      (made.value.names || []).forEach(function (name) {
        const key = name.toLowerCase();
        if (!table[key]) {
          table[key] = made.value;
        }
      });
    });
  });
  inherit(attributes);
  fs.writeFileSync(to, JSON.stringify({
    attributes: sorted(attributes),
    classes: sorted(classes)
  }, null, 1) + '\n');
  log.debug("Leaving main().");
}

main(process.argv[2], process.argv[3]);
