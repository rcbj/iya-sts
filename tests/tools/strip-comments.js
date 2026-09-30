#!/usr/bin/env node
// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: strip-comments.js
//
// ---------------------------------------------------------------------------
// TAKE THE COMMENTS OUT OF THE SERVICE IMAGE'S JAVASCRIPT, AND NOTHING ELSE
// (#365, 2026-09-30).
//
// V8 keeps the source text of every script it has compiled for the life of
// the process — lazy compilation, deoptimisation and
// `Function.prototype.toString` all go back to it — and it keeps a script as
// UTF-16 whenever the script holds one character outside Latin-1. This
// repository's comments are dense on purpose (the root CLAUDE.md, *Code
// style*) and carry em-dashes and curly quotes, so a heap snapshot of a
// fresh front process held 79 MB of source strings: the ~38 MB of `.js` in
// the image, doubled. Every process pays it — the front process and every
// request and surface worker (#339).
//
// So `build-typescript.sh --strip`, which runs only in the SERVICE image's
// build (`Dockerfile`, the `typescript` stage), runs this over the tree it is
// about to ship. The repository is unchanged, and so is the tests image,
// which never passes `--strip`: its in-process tests read the sources as text
// and must read them whole.
//
// WHAT IT DOES TO A FILE, AND WHY IT IS THAT LITTLE:
//
//   * A comment is found by PARSING the file (acorn, MIT, a dependency of
//     `tests/package.json` and so never in the service image), never by a
//     pattern: `//` inside a string, a template literal or a regular
//     expression is not a comment, and only a parser knows which is which.
//   * Each comment is removed, with the spaces and tabs before it on its
//     line. **Every line break is kept** — the ones inside a block comment
//     too — so a line number in a stack trace from the image is the line
//     number in the repository, and no statement boundary that automatic
//     semicolon insertion reads can move. A block comment with no line break
//     in it, between two tokens, becomes one space, so `a/**/b` cannot
//     become `ab`.
//   * Nothing else changes: no name is mangled, no whitespace between tokens
//     is touched, no module is bundled. `#!` on the first line stays.
//   * **And it is PROVED, per file**: the stripped text is parsed again and
//     its token stream compared with the original's, token by token, as
//     source text. A file whose tokens differ, or that does not parse,
//     FAILS THE BUILD naming the file — a comment remover that is wrong
//     once is a service that behaves differently from its repository with
//     nothing to say so.
//
// WHAT IT DOES NOT TOUCH: `node_modules` (somebody else's, and a library may
// read its own text), the `node-ldapjs` submodule (a library, changed only
// in its fork), `tests` and `xacml-pep` (removed from the service image
// anyway), `deploy`, `docs` and `openbao` (never run by the service), and
// `debugger/embedded` (another project's build output, copied into the image
// after this runs). The vendored copies — `common/vendored/` and the eight
// Kerberos codec files — ARE stripped, in the image only: what may not be
// edited is the repository's copy, and that one is untouched.
//
// It also reports which of the files it leaves are still TWO-BYTE — a
// character above U+00FF left in a string literal or a regular expression —
// because V8 stores those as UTF-16 whatever this does. It does not rewrite
// them: a string literal is behaviour.
//
// Usage: node tests/tools/strip-comments.js <root> [--report=N]
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'strip-comments',
  level: process.env.LOG_LEVEL || 'info' });

// Top-level directories under the root that are never stripped (see the
// header), and paths below it.
const SKIP_TOP = ['node_modules', 'node-ldapjs', 'tests', 'xacml-pep',
                  'deploy', 'docs', 'openbao', '.git', '.github', '.claude',
                  'types'];
const SKIP_PATHS = ['debugger/embedded'];

// The parser, required when first needed so that `require()` of this file by
// a test that only reads its constants costs nothing.
let acorn = null;

/**
 * Parses a script and returns its comments and tokens, or throws.
 *
 * CommonJS first, since every module of this service is one; a file that
 * only parses as an ES module (none today) is tried as one rather than
 * refused.
 *
 * @param {string} text - the file's text
 * @returns {{ comments: any[], tokens: any[] }}
 */
function parse(text) {
  log.debug("Entering parse().");
  if (!acorn) {
    acorn = require('acorn');
  }
  const attempt = function (sourceType) {
    const comments = [];
    const tokens = [];
    acorn.parse(text, {
      ecmaVersion: 'latest',
      sourceType: sourceType,
      allowHashBang: true,
      allowReturnOutsideFunction: sourceType === 'script',
      onComment: comments,
      onToken: tokens
    });
    return { comments: comments, tokens: tokens };
  };
  try {
    const parsed = attempt('script');
    log.debug("Leaving parse().");
    return parsed;
  } catch (e) {
    log.debug("Caught in parse(): " + ((e && e.message) || e));
    // Not a script; an ES module is the one other thing a `.js` can be, and
    // if it is not that either, the module parse's error is the one thrown.
    const parsed = attempt('module');
    log.debug("Leaving parse(). As a module.");
    return parsed;
  }
}

/**
 * The token stream as source text, for comparing two versions of a file.
 *
 * @param {string} text - the file's text
 * @param {any[]} tokens - acorn's tokens for it
 * @returns {string[]}
 */
function tokenTexts(text, tokens) {
  log.debug("Entering tokenTexts().");
  const out = tokens.map(function (t) {
    return text.slice(t.start, t.end);
  });
  log.debug("Leaving tokenTexts().");
  return out;
}

/**
 * Returns `text` with its comments removed as the header describes, and
 * proves the token stream unchanged.
 *
 * @param {string} text - a JavaScript file's text
 * @returns {{ text: string, comments: number }}
 */
function strip(text) {
  log.debug("Entering strip().");
  const parsed = parse(text);
  let out = '';
  let cursor = 0;
  let removed = 0;
  parsed.comments.forEach(function (c) {
    if (c.start === 0 && text.slice(0, 2) === '#!') {
      // acorn reports the hashbang line as a comment; it is the one that
      // is not, since the kernel reads it.
      return;
    }
    // The code before the comment, less the spaces and tabs between it and
    // the comment. Those are always trivia: no token ends in a space.
    out += text.slice(cursor, c.start).replace(/[ \t]+$/, '');
    const body = text.slice(c.start, c.end);
    const breaks = body.match(/\r\n|\r|\n|\u2028|\u2029/g);
    if (breaks) {
      out += breaks.join('');
    } else if (c.type === 'Block') {
      const before = out.length ? out[out.length - 1] : '\n';
      const after = c.end < text.length ? text[c.end] : '\n';
      if (!/\s/.test(before) && !/\s/.test(after)) {
        out += ' ';
      }
    }
    cursor = c.end;
    removed = removed + 1;
  });
  out += text.slice(cursor);
  if (removed === 0) {
    log.debug("Leaving strip(). No comments.");
    return { text: text, comments: 0 };
  }
  const again = parse(out);
  const was = tokenTexts(text, parsed.tokens);
  const now = tokenTexts(out, again.tokens);
  if (was.length !== now.length) {
    log.debug("Leaving strip(). Token count changed.");
    throw new Error('stripping changed the token count from ' + was.length +
                    ' to ' + now.length);
  }
  for (let i = 0; i < was.length; i++) {
    if (was[i] !== now[i]) {
      log.debug("Leaving strip(). A token changed.");
      throw new Error('stripping changed token ' + i + ' from ' +
                      JSON.stringify(was[i].slice(0, 80)) + ' to ' +
                      JSON.stringify(now[i].slice(0, 80)));
    }
  }
  log.debug("Leaving strip().");
  return { text: out, comments: removed };
}

/**
 * Is this string one V8 must store as UTF-16: does it hold a character
 * above U+00FF?
 *
 * @param {string} text - the text
 * @returns {boolean}
 */
function isTwoByte(text) {
  log.debug("Entering isTwoByte().");
  log.debug("Leaving isTwoByte().");
  return /[^\u0000-ÿ]/.test(text);
}

/**
 * Every `.js` file under `root` this strips, as paths relative to it.
 *
 * @param {string} root - the package root
 * @returns {string[]}
 */
function filesUnder(root) {
  log.debug("Entering filesUnder().");
  const found = [];
  const walk = function (rel) {
    const entries = fs.readdirSync(path.join(root, rel),
                                   { withFileTypes: true });
    entries.forEach(function (entry) {
      const child = rel ? rel + '/' + entry.name : entry.name;
      if (entry.isDirectory()) {
        if ((!rel && SKIP_TOP.indexOf(entry.name) >= 0) ||
            SKIP_PATHS.indexOf(child) >= 0 ||
            entry.name === 'node_modules') {
          return;
        }
        walk(child);
        return;
      }
      if (entry.isFile() && /\.(js|cjs|mjs)$/.test(entry.name)) {
        found.push(child);
      }
    });
  };
  walk('');
  log.debug("Leaving filesUnder().");
  return found.sort();
}

/**
 * Strips every file under `root` in place and prints what it did.
 *
 * @param {string} root - the package root
 * @param {number} report - how many two-byte files to name
 * @returns {number} the process exit code
 */
function main(root, report) {
  log.debug("Entering main().");
  const files = filesUnder(root);
  let before = 0;
  let after = 0;
  let comments = 0;
  const failed = [];
  const twoByte = [];
  files.forEach(function (rel) {
    const full = path.join(root, rel);
    const text = fs.readFileSync(full, 'utf8');
    before = before + Buffer.byteLength(text);
    let result = null;
    try {
      result = strip(text);
    } catch (e) {
      log.debug("Caught in main(): " + ((e && e.message) || e));
      // Recorded and the build failed below, after every file is tried, so
      // one run names every file that needs looking at.
      failed.push(rel + ': ' + ((e && e.message) || e));
      after = after + Buffer.byteLength(text);
      return;
    }
    if (result.comments) {
      fs.writeFileSync(full, result.text);
    }
    comments = comments + result.comments;
    after = after + Buffer.byteLength(result.text);
    if (isTwoByte(result.text)) {
      twoByte.push({ rel: rel, bytes: Buffer.byteLength(result.text) });
    }
  });
  const MB = function (n) {
    return (n / 1048576).toFixed(1) + ' MB';
  };
  console.log('strip-comments.js: ' + files.length + ' file(s), ' +
              comments + ' comment(s) removed, ' + MB(before) + ' -> ' +
              MB(after));
  twoByte.sort(function (a, b) {
    return b.bytes - a.bytes;
  });
  const twoByteBytes = twoByte.reduce(function (sum, one) {
    return sum + one.bytes;
  }, 0);
  console.log('strip-comments.js: ' + twoByte.length + ' file(s), ' +
              MB(twoByteBytes) + ', still hold a character above U+00FF ' +
              '(stored as UTF-16 by V8); the largest:');
  twoByte.slice(0, report).forEach(function (one) {
    console.log('  ' + (one.bytes / 1024).toFixed(0).padStart(6) + ' KB  ' +
                one.rel);
  });
  if (failed.length) {
    failed.forEach(function (line) {
      console.error('strip-comments.js: FAILED ' + line);
    });
    log.debug("Leaving main(). Failed.");
    return 1;
  }
  log.debug("Leaving main().");
  return 0;
}

module.exports = { strip: strip, isTwoByte: isTwoByte,
                   filesUnder: filesUnder, SKIP_TOP: SKIP_TOP,
                   SKIP_PATHS: SKIP_PATHS };

if (require.main === module) {
  const args = process.argv.slice(2);
  const root = args.filter(function (a) {
    return !/^--/.test(a);
  })[0];
  const reportArg = args.filter(function (a) {
    return /^--report=\d+$/.test(a);
  })[0];
  if (!root) {
    console.error('usage: node tests/tools/strip-comments.js <root> ' +
                  '[--report=N]');
    process.exit(2);
  }
  process.exit(main(path.resolve(root),
                    reportArg ? Number(reportArg.split('=')[1]) : 15));
}
