'use strict';
//
// File: random_values.js
//
// ===========================================================================
// RANDOM VALUES COME FROM ONE GENERATOR, UNIFORMLY (#65, 2026-09-23).
//
// `common/crypto.js` section 13 argues the design; this holds it, in two
// halves.
//
//   1. **THE DISTRIBUTION.** `randomString()` over GNAP's 31-character
//      user-code alphabet, 620,000 draws, a chi-square against uniform — the
//      test nanoid runs on its own `customAlphabet`. **The same statistic is
//      computed for `byte % 31` as the CONTROL**, because a distribution test
//      that cannot tell the old code from the new asserts nothing: the
//      modulo scores about 1,700 where the bound is 80 (df 30, p ≈ 1e-6, so
//      a correct generator fails it about once in a million runs). Then the
//      refusals: fewer than 128 bits, an alphabet with a repeat, and
//      `genId()`'s shape.
//   2. **THE SOURCE.** Every `.js` and `.ts` the service runs from — not the
//      vendored copies, which may not be edited here, and not the tests — is
//      read with comments and strings blanked, and must hold no
//      `Math.random(`, no `forge.random` and no `X[<expr>] % Y.length` used
//      as an index, which is the shape of a random byte taken modulo an
//      alphabet. There is no allow list, because nothing needs one: a new
//      need is a call to section 13.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'random_values',
  level: process.env.LOG_LEVEL || 'info' });

// What is not the service's own source — no_periodic_timers.js's list.
const SKIP = new RegExp('(^|/)(node_modules|tests|coverage|debugger/embedded|' +
                        'common/vendored|node-ldapjs|deploy|xacml-pep|docs|' +
                        '\\.claude|types)(/|$)');

// GNAP's user-code alphabet (gnap/gnap_grants.ts), the one that was biased.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const PER_CHARACTER = 20000;
// chi-square, 30 degrees of freedom, upper tail about 1e-6.
const BOUND = 80;

// The three shapes the source may not hold, read after blank().
const FORBIDDEN = [
  { re: /\bMath\.random\s*\(/g, what: 'Math.random() — not a CSPRNG' },
  { re: /\bforge\.random\b/g, what: 'forge.random — a second generator' },
  { re: /\[\s*[\w$.]+\s*\[[^\]]*\]\s*%\s*[\w$.]+\.length\s*\]/g,
    what: 'an index taken modulo an alphabet\'s length — biased unless the ' +
          'length divides 256; use stsCrypto.randomString()' }
];

function walk(dir, out) {
  log.debug('Entering walk().');
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(ROOT, full).split(path.sep).join('/');
    if (SKIP.test(rel)) {
      return;
    }
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (/\.(js|ts)$/.test(entry.name) &&
               !/\.d\.ts$/.test(entry.name) &&
               // In an image a `.ts` has its compiled `.js` beside it.
               !(/\.js$/.test(entry.name) &&
                 fs.existsSync(full.replace(/\.js$/, '.ts')))) {
      out.push(rel);
    }
  });
  log.debug('Leaving walk().');
  return out;
}

// Comments and string contents blanked, same length, so a line number found
// in the result is the line in the file. no_periodic_timers.js's blank().
function blank(src) {
  log.debug('Entering blank().');
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') {
        out += ' ';
        i++;
      }
      continue;
    }
    if (c === '/' && d === '*') {
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  ';
      i += 2;
      continue;
    }
    if (c === '"' || c === '\'' || c === '`') {
      out += c;
      i++;
      while (i < n && src[i] !== c) {
        if (src[i] === '\\') {
          out += '  ';
          i += 2;
          continue;
        }
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += c;
      i++;
      continue;
    }
    out += c;
    i++;
  }
  log.debug('Leaving blank().');
  return out;
}

function findingsIn(rel, src) {
  log.debug('Entering findingsIn(). ' + rel);
  const s = blank(src);
  const out = [];
  FORBIDDEN.forEach(function (rule) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(s))) {
      out.push(rel + ':' + s.slice(0, m.index).split('\n').length + ' ' +
               rule.what);
    }
  });
  log.debug('Leaving findingsIn(). ' + out.length + '.');
  return out;
}

function chiSquare(text) {
  log.debug('Entering chiSquare().');
  const counts = Object.create(null);
  for (const ch of text) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  const expected = text.length / ALPHABET.length;
  let sum = 0;
  for (const ch of ALPHABET) {
    const d = (counts[ch] || 0) - expected;
    sum += d * d / expected;
  }
  log.debug('Leaving chiSquare(). ' + sum.toFixed(1));
  return sum;
}

function throws(fn) {
  log.debug('Entering throws().');
  try {
    fn();
  } catch (e) {
    log.debug('Caught in throws(): ' + ((e && e.message) || e));
    log.debug('Leaving throws(). Threw.');
    return true;
  }
  log.debug('Leaving throws(). Did not throw.');
  return false;
}

function run(t) {
  log.debug('Entering run().');
  const stsCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');
  const nodeCrypto = require('crypto');
  const draws = ALPHABET.length * PER_CHARACTER;

  // ---- 1. THE DISTRIBUTION, and the control that proves it can see bias.
  const drawn = stsCrypto.randomString(ALPHABET, draws);
  t.equal(drawn.length, draws, 'randomString() makes the length asked for');
  t.check(Array.from(drawn).every(function (ch) {
    return ALPHABET.indexOf(ch) >= 0;
  }), 'randomString() draws only from the alphabet');
  const fair = chiSquare(drawn);
  t.check(fair < BOUND, 'randomString() is uniform over a 31-character ' +
          'alphabet (chi-square under ' + BOUND + ')', fair.toFixed(1));
  const bytes = nodeCrypto.randomBytes(draws);
  let modulo = '';
  for (let i = 0; i < draws; i++) {
    modulo += ALPHABET[bytes[i] % ALPHABET.length];
  }
  const biased = chiSquare(modulo);
  t.check(biased > BOUND * 5, 'the control: a byte modulo 31 — the code #65 ' +
          'replaced — fails the same statistic', biased.toFixed(1));

  // ---- the refusals and the shapes.
  t.equal(stsCrypto.randomToken().length, 43,
          'randomToken() defaults to 256 bits, 43 base64url characters');
  t.equal(stsCrypto.randomToken(128).length, 22,
          'randomToken(128) is 16 bytes, 22 characters');
  t.check(throws(function () {
    stsCrypto.randomToken(64);
  }), 'randomToken() refuses fewer than ' + stsCrypto.RANDOM_TOKEN_MIN_BITS +
      ' bits');
  t.check(throws(function () {
    stsCrypto.randomString('AAB', 8);
  }), 'randomString() refuses an alphabet with a repeated character');
  t.check(throws(function () {
    stsCrypto.randomString('A', 8);
  }), 'randomString() refuses an alphabet of one');
  t.equal(stsCrypto.randomString(ALPHABET, 0), '',
          'randomString() of length 0 is empty');
  t.check(/^_[0-9a-f]{32}$/.test(helpers.genId()),
          'genId() is an NCName: an underscore and 128 bits in hex',
          helpers.genId());
  t.check(helpers.genId() !== helpers.genId(), 'two genId()s differ');

  // ---- 2. THE SOURCE.
  const files = walk(ROOT, []);
  t.check(files.length > 200,
          'the service\'s own source was found to read', String(files.length));
  const found = [];
  files.forEach(function (rel) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    Array.prototype.push.apply(found, findingsIn(rel, src));
  });
  t.check(found.length === 0, 'no source draws a random value but through ' +
          'node\'s generator, uniformly (common/crypto.js section 13)',
          found.join('; '));

  // THE DETECTOR ITSELF: it must see the shapes it claims to, and not a
  // mention in a comment or a string.
  [
    ['x = A[b[i] % A.length];', 1],
    ['code += USER_CODE_ALPHABET[bytes[i] % USER_CODE_ALPHABET.length];', 1],
    ['const k = forge.random.getBytesSync(16);', 1],
    ['n = Math.floor(Math.random() * 10);', 1],
    ['// Math.random() and forge.random, A[b[i] % A.length]', 0],
    ['s = "it was Math.random() until #65";', 0],
    ['h = n % 1000000;', 0]
  ].forEach(function (shape) {
    const got = findingsIn('x.js', shape[0]).length;
    t.equal(got, shape[1], 'the detector ' + (shape[1] ? 'finds' : 'ignores') +
            ': ' + shape[0]);
  });
  log.debug('Leaving run().');
}

module.exports = {
  name: 'random_values',
  describe: 'random values from node\'s generator only, drawn uniformly over ' +
            'an alphabet (#65): a chi-square with its control, the ' +
            'refusals, and the source read for Math.random, forge.random and ' +
            'a modulo',
  run: run
};
