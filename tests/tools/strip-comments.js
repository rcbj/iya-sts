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
// AND IT WRITES THE CHARACTERS ABOVE U+00FF AS ESCAPES, IN STRINGS AND
// REGULAR EXPRESSIONS (#369, 2026-09-30). After the comments go, what keeps
// a file two-byte is string literals — 8,103 em-dashes among 8,435 such
// characters in 283 files, about 20 MB of heap per isolate. So each is
// written as `\uXXXX` (a surrogate pair as two, which means the same code
// point in a string, in a regular expression without the `u` flag and in
// one with it). A character that was already escaped (`\—`) becomes the
// escape itself; a backslash before U+2028 or U+2029 is a line continuation,
// which contributes nothing to the value, and is left as it is. **Template
// literals are not touched**: a tagged template's `.raw` and `String.raw`
// see the source text, so an escape there would change a value. **And this
// is proved too**: a string token must have the same cooked value before
// and after, a regular expression the same flags and the same pattern once
// both are written with the same escapes, and every other token the same
// text. The files still two-byte after it — a template literal, an
// identifier or a line continuation — are named in the report.
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

// ---------------------------------------------------------------------------
// ESCAPING (#369). `escapeWide()` rewrites one string or regex token's text;
// `escapeLiterals()` does every such token of a file and proves it.
// ---------------------------------------------------------------------------
function hex4(code) {
  log.debug("Entering hex4().");
  log.debug("Leaving hex4().");
  return '\\u' + code.toString(16).toUpperCase().padStart(4, '0');
}

// HOT PATH: once per string and regex token of every shipped file; no
// Entering/Leaving pair, which would drown the build log.
/**
 * A string or regex-literal token's source text with every UTF-16 unit
 * above U+00FF written as `\uXXXX`, whether it stood alone or after a
 * backslash; a backslash before U+2028 or U+2029 (a line continuation) is
 * left as it was.
 *
 * @param {string} tokenText - the token's source text
 * @returns {string}
 */
function escapeWide(tokenText) {
  let out = '';
  for (let i = 0; i < tokenText.length; i++) {
    const ch = tokenText[i];
    const code = tokenText.charCodeAt(i);
    if (ch === '\\' && i + 1 < tokenText.length) {
      const next = tokenText.charCodeAt(i + 1);
      if (next > 0xff && next !== 0x2028 && next !== 0x2029) {
        out += hex4(next);
      } else {
        out += ch + tokenText[i + 1];
      }
      i++;
      continue;
    }
    out += code > 0xff ? hex4(code) : ch;
  }
  return out;
}

// The pattern of a regular expression with every `\uXXXX` above U+00FF
// written as the character, for comparing two spellings of one pattern: the
// two sides are normalised the same way, so an escape the original already
// had and one this wrote compare equal, and nothing else does.
function widePattern(pattern) {
  log.debug("Entering widePattern().");
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === '\\') {
      const m = /^u([0-9A-Fa-f]{4})/.exec(pattern.slice(i + 1, i + 6));
      if (m && parseInt(m[1], 16) > 0xff) {
        out += String.fromCharCode(parseInt(m[1], 16));
        i += 5;
        continue;
      }
      // An identity escape of a wide character (`\\—`) is that character.
      if (i + 1 < pattern.length && pattern.charCodeAt(i + 1) > 0xff) {
        out += pattern[i + 1];
        i++;
        continue;
      }
      out += pattern[i] + (pattern[i + 1] || '');
      i++;
      continue;
    }
    out += pattern[i];
  }
  log.debug("Leaving widePattern().");
  return out;
}

/**
 * Returns `text` with the characters above U+00FF in its string and regex
 * literals written as escapes, and proves every token's meaning unchanged.
 *
 * @param {string} text - a JavaScript file's text (already stripped)
 * @returns {{ text: string, escaped: number }}
 */
function escapeLiterals(text) {
  log.debug("Entering escapeLiterals().");
  if (!isTwoByte(text)) {
    log.debug("Leaving escapeLiterals(). One-byte already.");
    return { text: text, escaped: 0 };
  }
  const parsed = parse(text);
  let out = '';
  let cursor = 0;
  let escaped = 0;
  parsed.tokens.forEach(function (t) {
    const label = t.type && t.type.label;
    if (label !== 'string' && label !== 'regexp') {
      return;
    }
    const raw = text.slice(t.start, t.end);
    if (!isTwoByte(raw)) {
      return;
    }
    const written = escapeWide(raw);
    if (written === raw) {
      return;
    }
    out += text.slice(cursor, t.start) + written;
    cursor = t.end;
    escaped = escaped + 1;
  });
  out += text.slice(cursor);
  if (!escaped) {
    log.debug("Leaving escapeLiterals(). Nothing in a literal.");
    return { text: text, escaped: 0 };
  }
  const again = parse(out);
  if (again.tokens.length !== parsed.tokens.length) {
    log.debug("Leaving escapeLiterals(). Token count changed.");
    throw new Error('escaping changed the token count from ' +
                    parsed.tokens.length + ' to ' + again.tokens.length);
  }
  for (let i = 0; i < parsed.tokens.length; i++) {
    const a = parsed.tokens[i];
    const b = again.tokens[i];
    const label = a.type && a.type.label;
    let same;
    if (label === 'string') {
      same = b.type === a.type && a.value === b.value;
    } else if (label === 'regexp') {
      same = b.type === a.type && a.value.flags === b.value.flags &&
        widePattern(a.value.pattern) === widePattern(b.value.pattern);
    } else {
      same = text.slice(a.start, a.end) === out.slice(b.start, b.end);
    }
    if (!same) {
      log.debug("Leaving escapeLiterals(). A token changed.");
      throw new Error('escaping changed token ' + i + ' (' + label + ') ' +
                      JSON.stringify(text.slice(a.start, a.end).slice(0, 80)));
    }
  }
  log.debug("Leaving escapeLiterals().");
  return { text: out, escaped: escaped };
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
  let literals = 0;
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
    let escaped = null;
    try {
      escaped = escapeLiterals(result.text);
    } catch (e) {
      log.debug("Caught in main(): " + ((e && e.message) || e));
      // As a failed strip: recorded, and the build failed below.
      failed.push(rel + ': ' + ((e && e.message) || e));
      after = after + Buffer.byteLength(text);
      return;
    }
    if (result.comments || escaped.escaped) {
      fs.writeFileSync(full, escaped.text);
    }
    literals = literals + escaped.escaped;
    result = { text: escaped.text, comments: result.comments };
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
              comments + ' comment(s) removed, ' + literals + ' string or ' +
              'regular-expression literal(s) escaped to one-byte, ' +
              MB(before) + ' -> ' + MB(after));
  twoByte.sort(function (a, b) {
    return b.bytes - a.bytes;
  });
  const twoByteBytes = twoByte.reduce(function (sum, one) {
    return sum + one.bytes;
  }, 0);
  console.log('strip-comments.js: ' + twoByte.length + ' file(s), ' +
              MB(twoByteBytes) + ', still hold a character above U+00FF ' +
              'outside a string or regular expression — a template ' +
              'literal, an identifier or a line continuation — (stored as ' +
              'UTF-16 by V8); the largest:');
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
                   escapeLiterals: escapeLiterals, escapeWide: escapeWide,
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
