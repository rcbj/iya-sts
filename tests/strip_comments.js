// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: strip_comments.js
//
// ---------------------------------------------------------------------------
// THE SERVICE IMAGE'S COMMENT STRIPPER TAKES OUT COMMENTS AND NOTHING ELSE
// (#365, 2026-09-30).
//
// `tests/tools/strip-comments.js` runs only in the service image's build,
// where a mistake would be a service that behaves differently from its
// repository with nothing to say so. This holds it to its header twice:
//
//   * on a set of hand-made sources that each hold one thing a pattern-based
//     remover gets wrong — `//` in a string, a template literal and a regular
//     expression, a comment INSIDE a template's `${}`, a block comment
//     carrying the line break automatic semicolon insertion reads, `a/**/b`,
//     the hashbang, the `'use strict'` directive — each RUN before and after
//     and compared, with the line count held; and
//   * on every file the image build would strip, from this image's own tree
//     (read, never written): each one strips, keeps its line count, and
//     proves its token stream — so a new file the build could not strip
//     fails here, in `npm test`, before it fails an image build.
// ---------------------------------------------------------------------------

const path = require('path');
const fs = require('fs');
const vm = require('vm');
const log = require('bunyan').createLogger({ name: 'strip_comments',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const stripper = require('./tools/strip-comments');

// Each case: a source whose last expression is its result, run in a fresh
// context before and after stripping.
const CASES = [
  { name: '// inside strings',
    comments: 1,
    src: 'var a = "x // y"; var b = \'/* z */\'; a + b // tail\n' },
  { name: '// and /* inside a template literal',
    comments: 0,
    src: 'var t = `a // b /* c */ d`; t\n' },
  { name: 'a comment inside a template\'s ${}',
    comments: 2,
    src: 'var x = 2; `v=${ /* two */ x // n\n }!`\n' },
  { name: 'regular expressions holding // and /*',
    comments: 0,
    src: 'var r = /\\/\\/[^*]*\\/*/g; var s = /a\\/*b/.source;' +
         ' String(r) + s\n' },
  { name: 'division beside a regular expression',
    comments: 1,
    src: 'var a = 10, g = 2; var r = a / g /* half */ / 1; r + /x/.source\n' },
  { name: 'a block comment carrying the line break ASI reads',
    comments: 1,
    src: 'function f() { return /*\n*/ 42; } String(f())\n' },
  { name: 'a block comment between two tokens with no space',
    comments: 2,
    src: 'var a = 1; var b = 2; typeof/**/a + (a/**/+b)\n' },
  { name: 'the use strict directive after a header',
    comments: 2,
    src: '// header\n/* more */\n\'use strict\';\n' +
         '(function () { return this === undefined; })()\n' },
  { name: 'nested-looking comments and a lone slash-star in a string',
    comments: 1,
    src: 'var s = "/*"; /* a // b */ var t = "*/"; s + t\n' }
];

/**
 * Runs `src` in a fresh context and returns its completion value, or the
 * error's message.
 *
 * @param {string} src - a script
 * @returns {string}
 */
function runScript(src) {
  log.debug("Entering runScript().");
  try {
    const value = vm.runInNewContext(src, {}, { timeout: 1000 });
    log.debug("Leaving runScript().");
    return 'value ' + JSON.stringify(value);
  } catch (e) {
    log.debug("Caught in runScript(): " + ((e && e.message) || e));
    // A case that throws is compared by what it threw.
    log.debug("Leaving runScript(). Threw.");
    return 'threw ' + ((e && e.message) || e);
  }
}

/**
 * The number of lines in a text.
 *
 * @param {string} text - the text
 * @returns {number}
 */
function lineCount(text) {
  log.debug("Entering lineCount().");
  log.debug("Leaving lineCount().");
  return text.split(/\r\n|\r|\n|\u2028|\u2029/).length;
}

module.exports = {
  name: 'strip_comments',
  describe: 'the service image\'s comment stripper removes comments and ' +
    'nothing else, keeps every line, and can strip every file it will be ' +
    'given',
  run: function run(t) {
    CASES.forEach(function (c) {
      const out = stripper.strip(c.src);
      t.equal(out.comments, c.comments,
        c.name + ': every comment was found, and nothing else');
      t.equal(runScript(out.text), runScript(c.src),
        c.name + ': the stripped script computes what the original did');
      t.equal(lineCount(out.text), lineCount(c.src),
        c.name + ': every line is kept');
      t.check(!/\/\/ (tail|header|n)|\/\* (z|c|two|half|more|a)/.test(
        out.text.replace(/"[^"]*"|'[^']*'|`[^`]*`/g, '')),
        c.name + ': no comment is left outside a literal', out.text);
    });

    const bang = stripper.strip('#!/usr/bin/env node\n// c\nvar a = 1;\n');
    t.check(bang.text.indexOf('#!/usr/bin/env node\n') === 0,
      'the hashbang line is kept', bang.text);

    const strict = stripper.strip(CASES[7].src);
    t.check(/^\s*'use strict';/.test(strict.text),
      'the use strict directive is still the first statement', strict.text);

    let refused = '';
    try {
      stripper.strip('var a = ;\n');
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      // The refusal IS the assertion: a file that does not parse fails.
      refused = String((e && e.message) || e);
    }
    t.check(refused !== '', 'a file that does not parse is refused, not ' +
      'passed through', refused);

    // Every file the image build will strip, as this tree holds it.
    const files = stripper.filesUnder(ROOT);
    const failed = [];
    const moved = [];
    let before = 0;
    let after = 0;
    files.forEach(function (rel) {
      const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
      before = before + text.length;
      try {
        const out = stripper.strip(text);
        after = after + out.text.length;
        if (lineCount(out.text) !== lineCount(text)) {
          moved.push(rel);
        }
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
        // Collected, so the assertion names every file at once.
        failed.push(rel + ': ' + ((e && e.message) || e));
      }
    });
    t.check(files.length > 400, 'the walk found the service\'s JavaScript',
      files.length + ' file(s)');
    t.check(files.every(function (rel) {
      return !/^(tests|node_modules|node-ldapjs|xacml-pep|deploy|docs|openbao)\//
        .test(rel) && rel.indexOf('debugger/embedded/') !== 0 &&
        rel.indexOf('/node_modules/') < 0;
    }), 'nothing the stripper must leave alone is in its list');
    t.equal(failed.join('\n'), '', 'every file the image build strips ' +
      'strips, with its token stream proved unchanged');
    t.equal(moved.join(', '), '', 'no stripped file gained or lost a line');
    t.check(after < before, 'the stripped tree is smaller',
      before + ' -> ' + after + ' characters');
  }
};
