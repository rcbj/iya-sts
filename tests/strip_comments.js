// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   * on the ESCAPING of characters above U+00FF in string and regex
//     literals (#369): strings, an identity escape, character classes, a
//     code point outside the BMP with and without the `u` flag, an escape
//     already there, a line continuation left as it was, and a template
//     literal and `String.raw` left alone — each RUN before and after and
//     compared, the regular expressions against probe strings; and
//   * on every file the image build would strip, from this image's own tree
//     (read, never written): each one strips and escapes, keeps its line
//     count, and proves its token stream — so a new file the build could not
//     strip fails here, in `npm test`, before it fails an image build — and
//     only the files named in STILL_TWO_BYTE stay two-byte.
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

// THE ESCAPING CASES (#369). Each is run before and after
// `escapeLiterals()`, and what `escaped` must be and whether the result may
// still be two-byte are stated.
const ESCAPES = [
  { name: 'an em-dash in a double- and a single-quoted string',
    escaped: 2, oneByte: true,
    src: 'var a = "x — y"; var b = \'– z\'; a + b\n' },
  { name: 'an identity escape of a wide character (\\—)',
    escaped: 1, oneByte: true, src: 'var a = "\\— z"; a\n' },
  { name: 'a code point outside the BMP in two strings',
    escaped: 2, oneByte: true, src: '"\u{1F600}".length + "😀"\n' },
  { name: 'regular expressions: a class, the u flag, no u flag, an ' +
          'identity escape',
    // Four patterns and the three probe strings holding a wide character.
    escaped: 7, oneByte: true,
    src: 'var p = ["—–—", "😀😀", "x😀", "\\uD83D", "a"];' +
         ' [/[—–]+/g, /😀+/u, /😀/, /\\—/].map(function (r) {' +
         ' return p.map(function (s) { return String(s.match(r)); }); })\n' },
  { name: 'an escape already written is left as it is',
    escaped: 0, oneByte: true, src: 'var a = "\\u2014 already"; a\n' },
  { name: 'a template literal and String.raw are not touched',
    escaped: 0, oneByte: false,
    src: 'var x = 1; `— ${x}` + String.raw`\\— ${x}`\n' },
  { name: 'a line continuation (a backslash before U+2028) is left as it was',
    escaped: 0, oneByte: false, src: 'var a = "a\\\u2028b"; a\n' }
];

// The files the image may leave two-byte, each with its reason: a
// character above U+00FF in a template literal, which is not escaped.
const STILL_TWO_BYTE = {
  'env/generate_defaults.js': 'a template literal (a build tool the ' +
                              'service does not load)'
};

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

    t.log.info('=== characters above U+00FF in literals are escaped (#369) ' +
               '===');
    ESCAPES.forEach(function (c) {
      const out = stripper.escapeLiterals(c.src);
      t.equal(out.escaped, c.escaped, c.name + ': ' + c.escaped +
              ' literal(s) rewritten');
      t.equal(runScript(out.text), runScript(c.src),
              c.name + ': the same result before and after');
      t.equal(!stripper.isTwoByte(out.text), c.oneByte,
              c.name + ': ' + (c.oneByte ? 'one-byte afterwards'
                                         : 'left two-byte, as it must be'));
    });

    // Every file the image build will strip, as this tree holds it.
    const files = stripper.filesUnder(ROOT);
    const failed = [];
    const moved = [];
    const twoByte = [];
    let before = 0;
    let after = 0;
    files.forEach(function (rel) {
      const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
      before = before + text.length;
      try {
        const stripped = stripper.strip(text);
        const out = stripper.escapeLiterals(stripped.text);
        after = after + out.text.length;
        if (lineCount(out.text) !== lineCount(text)) {
          moved.push(rel);
        }
        if (stripper.isTwoByte(out.text) && !STILL_TWO_BYTE[rel]) {
          twoByte.push(rel);
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
    t.equal(twoByte.join(', '), '', 'every stripped file is one-byte but ' +
      'those STILL_TWO_BYTE names with a reason (#369)');
    t.check(after < before, 'the stripped tree is smaller',
      before + ' -> ' + after + ' characters');
  }
};
