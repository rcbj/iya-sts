// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: subject_urn_literals.js
//
// ===========================================================================
// THE NAMES A LEAF GIVES ITS HOLDER ARE SPELT IN ONE PLACE (#1827).
//
// rcbj, 2026-11-16: "Let's make these references more centrally defined and
// easy to change." `common/subject_urn.ts` holds every `urn:sts:<kind>:`
// prefix a certificate this service issues names its holder by — person,
// sa (a service account), application, federation, cell, device — and
// every writer and reader goes through it. This file holds that: it reads
// every JavaScript and TypeScript file of the SERVICE and fails on one of
// those prefixes in EXECUTABLE code anywhere else.
//
// WHAT COUNTS. Comments are dropped first (a reader is told the form in
// prose, and that is the point of a comment). Then, in what is left:
//
//   * a STRING or TEMPLATE literal with one of the prefixes and NO
//     WHITESPACE — `'urn:sts:person:'`, `"URI:urn:sts:sa:"`,
//     `` `urn:sts:application:${id}` `` — is a spelling written by hand;
//   * a prefix OUTSIDE any string literal — a regular expression such as
//     `/^URI:urn:sts:(application|person):/` — is one too.
//
// A literal WITH whitespace is a sentence: an error-code summary, a setting's
// description, a refusal's `why`, `sts_metadata.ts`'s coverage prose. Those
// tell an operator the form, and are allowed to name it. That is why this
// reads TOKENS rather than lines (the root CLAUDE.md's 80-column note: a
// source-inspection test reads a statement, not a line) — a sentence broken
// across a concatenation is still a sentence, and `'urn:sts:person:' + name`
// is still a hand-spelt prefix however it is wrapped.
//
// WHAT IS NOT READ: `tests/` (fixtures spell the forms on purpose, to check
// what the service wrote), `docs/`, the build output `debugger/embedded/`,
// the vendored `common/crypto_impl/`, the `node-ldapjs` submodule, `rust/`,
// and `common/subject_urn.ts` itself. EXEMPT, each with its reason, is the
// table below.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'subject_urn_literals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The kinds `common/subject_urn.ts` defines. Kept here by hand rather than
// read from the module, so that a kind added there without this list
// growing is caught by section A below.
const KINDS = ['person', 'sa', 'application', 'federation', 'cell', 'device'];

const PREFIX = new RegExp('urn:sts:(' + KINDS.join('|') + '):');

// file → why. A file listed here may spell a prefix; nothing else may.
const EXEMPT = {
  'common/subject_urn.ts': 'the one table',
  // `urn:sts:federation:tenant-not-allowed` is an ERROR the consumer
  // provider answers in a redirect, not a certificate's holder: it shares
  // the `federation` word and names nobody.
  'federation/consumer_providers.ts': 'an error URN, not a holder name'
};

const SKIP = [/^tests\//, /^docs\//, /^debugger\/embedded\//,
              /^common\/crypto_impl\//, /^node-ldapjs\//, /^rust\//,
              /\.d\.ts$/];

/**
 * Lists the service's own JavaScript and TypeScript files.
 *
 * @returns repository-relative paths
 */
function sourceFiles() {
  log.debug("Entering sourceFiles().");
  let listed = '';
  try {
    listed = childProcess.execFileSync('git', ['ls-files', '*.js', '*.ts'],
      { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
        maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    log.debug("Caught in sourceFiles(): " + ((e && e.message) || e));
    listed = '';
  }
  let files = listed.split('\n').filter(Boolean);
  if (!files.length) {
    // An image has no `.git`: walk the tree instead.
    files = [];
    const walk = function (dir) {
      fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })
        .forEach(function (one) {
          const rel = dir ? dir + '/' + one.name : one.name;
          if (one.isDirectory()) {
            if (one.name !== 'node_modules' && one.name !== '.git') {
              walk(rel);
            }
          } else if (/\.(js|ts)$/.test(one.name)) {
            files.push(rel);
          }
        });
    };
    walk('');
  }
  const out = files.filter(function (rel) {
    return !SKIP.some(function (re) { return re.test(rel); }) &&
           fs.existsSync(path.join(ROOT, rel));
  }).filter(function (rel) {
    // A compiled `x.js` beside its `x.ts` (inside an image) is the same
    // source twice; the `.ts` is read.
    return !(/\.js$/.test(rel) &&
             fs.existsSync(path.join(ROOT, rel.replace(/\.js$/, '.ts'))));
  });
  log.debug("Leaving sourceFiles(). " + out.length);
  return out;
}

/**
 * Splits source into its comments, its string and template literals, and
 * the code between them. A light scanner, not a parser: it knows the
 * literal forms and tells a regular expression from a division by the
 * token before it, which is what this needs.
 *
 * @param text - the source
 * @returns `{ strings: [text], code: text }` with comments dropped
 */
function tokens(text) {
  log.debug("Entering tokens().");
  const strings = [];
  let code = '';
  let i = 0;
  let last = '';
  const n = text.length;
  const regexMayStart = function () {
    const trimmed = code.replace(/\s+$/, '');
    const c = trimmed.slice(-1);
    if (!c) {
      return true;
    }
    if ('(,=:[!&|?{};+-*%<>~^'.indexOf(c) >= 0) {
      return true;
    }
    return /(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|void|yield|await|throw|delete|instanceof|new)$/
      .test(trimmed);
  };
  while (i < n) {
    const c = text[i];
    const d = text[i + 1];
    if (c === '/' && d === '/') {
      const end = text.indexOf('\n', i);
      i = end < 0 ? n : end;
      continue;
    }
    if (c === '/' && d === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? n : end + 2;
      code += ' ';
      continue;
    }
    if (c === '\'' || c === '"') {
      let j = i + 1;
      let body = '';
      while (j < n && text[j] !== c && text[j] !== '\n') {
        if (text[j] === '\\') {
          body += text[j] + (text[j + 1] || '');
          j += 2;
          continue;
        }
        body += text[j];
        j += 1;
      }
      strings.push(body);
      code += ' "" ';
      i = j + 1;
      last = c;
      continue;
    }
    if (c === '`') {
      let j = i + 1;
      let body = '';
      while (j < n && text[j] !== '`') {
        if (text[j] === '\\') {
          body += text[j] + (text[j + 1] || '');
          j += 2;
          continue;
        }
        if (text[j] === '$' && text[j + 1] === '{') {
          // The expression inside is code; its braces are counted, and a
          // string inside it is read as one.
          let depth = 1;
          let k = j + 2;
          let inner = '';
          while (k < n && depth > 0) {
            if (text[k] === '{') {
              depth += 1;
            } else if (text[k] === '}') {
              depth -= 1;
            }
            if (depth > 0) {
              inner += text[k];
            }
            k += 1;
          }
          const nested = tokens(inner);
          nested.strings.forEach(function (one) { strings.push(one); });
          code += ' ' + nested.code + ' ';
          body += '${}';
          j = k;
          continue;
        }
        body += text[j];
        j += 1;
      }
      strings.push(body);
      code += ' "" ';
      i = j + 1;
      last = c;
      continue;
    }
    if (c === '/' && regexMayStart()) {
      // A regular expression literal: it is CODE for this test's purpose,
      // kept whole so that a prefix inside it is found.
      let j = i + 1;
      let inClass = false;
      while (j < n && text[j] !== '\n') {
        if (text[j] === '\\') {
          j += 2;
          continue;
        }
        if (text[j] === '[') {
          inClass = true;
        } else if (text[j] === ']') {
          inClass = false;
        } else if (text[j] === '/' && !inClass) {
          break;
        }
        j += 1;
      }
      code += text.slice(i, j + 1);
      i = j + 1;
      last = '/';
      continue;
    }
    code += c;
    last = c;
    i += 1;
  }
  log.debug("Leaving tokens(). " + strings.length + " strings; last " +
            JSON.stringify(last));
  return { strings: strings, code: code };
}

/**
 * Finds the hand-spelt prefixes in one file.
 *
 * @param text - the source
 * @returns what was found, each as a short excerpt
 */
function findingsIn(text) {
  log.debug("Entering findingsIn().");
  const read = tokens(text);
  const out = [];
  read.strings.forEach(function (one) {
    if (PREFIX.test(one) && !/\s/.test(one)) {
      out.push('literal "' + one.slice(0, 80) + '"');
    }
  });
  const lines = read.code.split('\n');
  lines.forEach(function (line) {
    // A prefix, or a group of kinds (`urn:sts:(person|application):`).
    if (PREFIX.test(line) || /urn:sts:\(/.test(line)) {
      out.push('code `' + line.trim().slice(0, 100) + '`');
    }
  });
  log.debug("Leaving findingsIn(). " + out.length);
  return out;
}

function run(t) {
  log.debug("Entering run().");
  // A. The kinds here are the table's.
  let SubjectUrn = null;
  try {
    SubjectUrn = require('../common/subject_urn');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    SubjectUrn = null;
  }
  if (SubjectUrn) {
    t.equal(SubjectUrn.FORM_IDS.slice().sort().join(','),
            KINDS.slice().sort().join(','),
            'A. this file checks every kind common/subject_urn.ts defines');
  } else {
    t.bad('A. common/subject_urn could not be loaded');
  }

  // B. The scanner itself, on what it must and must not find.
  const caught = findingsIn(
    "const a = 'urn:sts:person:' + x;\n" +
    'const b = /^URI:urn:sts:(application|person):/;\n' +
    'const c = `urn:sts:sa:${name}`;\n');
  t.equal(caught.length, 3, 'B1. the scanner finds a literal, a regular ' +
          'expression and a template', JSON.stringify(caught));
  const passed = findingsIn(
    '// a comment naming urn:sts:person:<name>\n' +
    "const s = 'names it in a urn:sts:person: or ' +\n" +
    "  'urn:sts:application: subjectAltName';\n" +
    "/* urn:sts:sa: */ const d = a / b; const e = 'urn:sts:client:x';\n");
  t.equal(passed.length, 0, 'B2. and passes a comment, a sentence, a ' +
          'division and a kind this table does not hold',
          JSON.stringify(passed));

  // C. Every file of the service.
  const files = sourceFiles();
  t.check(files.length > 100, 'C0. the service\'s files were found',
          String(files.length));
  const bad = [];
  files.forEach(function (rel) {
    if (Object.prototype.hasOwnProperty.call(EXEMPT, rel)) {
      return;
    }
    const found = findingsIn(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    found.forEach(function (one) {
      bad.push(rel + ': ' + one);
    });
  });
  t.check(bad.length === 0, 'C. no file of the service spells a holder\'s ' +
          'urn:sts: prefix outside common/subject_urn.ts (#1827)',
          bad.slice(0, 20).join('\n'));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'subject_urn_literals',
  describe: 'the urn:sts:<kind>: prefixes a certificate names its holder ' +
            'by are spelt only in common/subject_urn.ts (#1827)',
  run: run
};
