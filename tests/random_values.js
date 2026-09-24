'use strict';
//
// File: random_values.js
//
// ===========================================================================
// RANDOM VALUES COME FROM ONE GENERATOR, UNIFORMLY (#65, 2026-09-23).
//
// `common/crypto.js` section 13 argues the design; this holds it, in five
// parts.
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
//      read with comments and strings blanked, and must hold none of the
//      shapes in FORBIDDEN: `Math.random(`, `forge.random`, `forge.prng`,
//      `pseudoRandomBytes`, forge's own envelope and key encryption, an
//      element of a random or byte buffer taken modulo anything or scaled
//      by 256, and an integer read out of a buffer taken modulo anything.
//      A second pass reads the STRINGS those shapes cannot see: a require of
//      a second random-value package, and an RSA encrypt or decrypt handed a
//      forge scheme name. And `package.json` may depend on none of those
//      packages. There is no allow list, because nothing needs one: a new
//      need is a call to section 13.
//   3. **FORGE'S GENERATOR IS NODE'S** (the second pass of #65). The
//      literal `forge.random` was gone and forge went on drawing from its
//      own Fortuna INSIDE the library — the blinding of every RSA signature
//      `vendored/xmldsig.js` makes, OAEP seeds, PKCS#1 v1.5 padding. The
//      source cannot see that, so this watches node's `randomBytes` while
//      forge signs and encrypts, and fails if forge drew without it.
//   4. **THE OLDER XML KEY TRANSPORTS ARE NODE'S**: `rsa-oaep-mgf1p` and
//      `rsa-1_5` wrap through `publicEncrypt()`, and the wrapped key is read
//      back by forge — an independent RSA — so the wire format is shown
//      unchanged.
//   5. **THE PASSWORD GENERATOR** draws each character uniformly over its
//      pools (a chi-square, with the two excluded characters never drawn),
//      and a strict draw that cannot hold every pool answers nothing rather
//      than looping.
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

// The shapes the source may not hold, read after blank().
const FORBIDDEN = [
  { re: /\bMath\.random\s*\(/g, what: 'Math.random() — not a CSPRNG' },
  { re: /\bforge\.(?:random|prng)\b/g,
    what: 'forge\'s generator — a second one; use stsCrypto' },
  { re: /\bpseudoRandomBytes\b/g,
    what: 'crypto.pseudoRandomBytes — deprecated, not a CSPRNG promise' },
  { re: /\bforge\.(?:pkcs7\.createEnvelopedData|pkcs12\.toPkcs12Asn1|pki\.encrypt\w*)\b/g,
    what: 'forge encrypting a secret with keys and salts of its own; do it ' +
          'with node' },
  { re: /\[\s*[\w$.]+\s*\[[^\]]*\]\s*%\s*[\w$.]+\.length\s*\]/g,
    what: 'an index taken modulo an alphabet\'s length — biased unless the ' +
          'length divides 256; use stsCrypto.randomString()' },
  { re: /\b[\w$]*(?:rand|byte|buf)[\w$]*\s*\[[^\]\n]*\]\s*%/gi,
    what: 'a random byte taken modulo something — biased unless it divides ' +
          '256; use stsCrypto.randomInt()' },
  { re: /\b[\w$]*(?:rand|byte|buf)[\w$]*\s*\[[^\]\n]*\]\s*\/\s*(?:256|255|0x100|0xff)\b/gi,
    what: 'a random byte scaled to a range — biased; use ' +
          'stsCrypto.randomInt()' },
  { re: /\.read(?:U?Int(?:8|16|32)|BigUInt64)(?:BE|LE)?\s*\([^)]*\)\s*%/g,
    what: 'an integer read from a buffer taken modulo something — biased; ' +
          'use stsCrypto.randomInt()' }
];

// Packages that are a second random-value source, or a Math.random path, or
// a modulo (section 13's review). Read out of the STRINGS a require names.
const SECOND_GENERATORS = new RegExp('^(?:generate-password|randomstring|' +
  'rand-token|random-js|seedrandom|chance|uuid|nanoid|shortid|' +
  'crypto-random-string|secure-random|uid-safe|random-bytes|randombytes)' +
  '(?:/|$)');

// THE TESTS' OWN FILES, which the service's walk skips. They are held to the
// Math.random rule only (a test may use forge's envelope to play a client),
// and it is not for their sake: GitHub's code scanning (CodeQL
// `js/insecure-randomness`) follows a value from a test's `Math.random()` —
// a realm id, a username suffix — into the service code it is handed to,
// and reports the SERVICE line. Sixteen alerts on `ldap/ldap_server.js` were
// that, every one with its source in a file under tests/. The parent
// project's copies (`MANIFEST.allFiles()`) are not ours to edit and are
// left out; everything else under tests/vendored/ is ours.
function testFiles() {
  log.debug('Entering testFiles().');
  const manifest = require('./vendored/MANIFEST.js');
  const theirs = new Set(manifest.allFiles().map(function (f) {
    return 'tests/vendored/' + f.rel;
  }));
  const out = [];
  const visit = function (dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(ROOT, full).split(path.sep).join('/');
      if (/(^|\/)(node_modules|report|coverage)(\/|$)/.test(rel) ||
          theirs.has(rel) || rel === 'tests/random_values.js') {
        return;
      }
      if (entry.isDirectory()) {
        visit(full);
      } else if (/\.js$/.test(entry.name)) {
        out.push(rel);
      }
    });
  };
  visit(path.join(ROOT, 'tests'));
  log.debug('Leaving testFiles(). ' + out.length + '.');
  return out;
}

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
function blank(src, keepStrings) {
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
          out += keepStrings ? src.slice(i, i + 2) : '  ';
          i += 2;
          continue;
        }
        out += keepStrings || src[i] === '\n' ? src[i] : ' ';
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
  const lineOf = function (index) {
    return rel + ':' + s.slice(0, index).split('\n').length + ' ';
  };
  FORBIDDEN.forEach(function (rule) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(s))) {
      out.push(lineOf(m.index) + rule.what);
    }
  });
  // THE STRINGS. `blank()` keeps offsets, so a require found in the blanked
  // text names the string at the same place in the text with strings kept —
  // and a require written INSIDE a string or a comment is never found.
  const kept = blank(src, true);
  const requires = /\b(?:require\s*\(\s*|from\s+)(['"])/g;
  let r;
  while ((r = requires.exec(s))) {
    const start = r.index + r[0].length;
    const name = kept.slice(start, kept.indexOf(r[1], start));
    if (SECOND_GENERATORS.test(name)) {
      out.push(lineOf(r.index) + 'a second random-value package (' + name +
               ') — use stsCrypto');
    }
  }
  const rsaCalls = /\.(?:en|de)crypt\s*\(/g;
  while ((r = rsaCalls.exec(s))) {
    const args = kept.slice(r.index, r.index + 240);
    if (/['"](?:RSAES-PKCS1-V1_5|RSA-OAEP)['"]/.test(args)) {
      out.push(lineOf(r.index) + 'an RSA encrypt or decrypt by forge — ' +
               'its padding and blinding are its own; use node\'s ' +
               'publicEncrypt()/privateDecrypt()');
    }
  }
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

  // THE TESTS: Math.random only, for the code-scanning reason above.
  const tests = testFiles();
  t.check(tests.length > 200, 'the tests\' own files were found to read',
          String(tests.length));
  const inTests = [];
  tests.forEach(function (rel) {
    const s = blank(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    const re = /\bMath\.random\s*\(/g;
    let m;
    while ((m = re.exec(s))) {
      inTests.push(rel + ':' + s.slice(0, m.index).split('\n').length);
    }
  });
  t.check(inTests.length === 0, 'no test draws a value from Math.random() — ' +
          'code scanning follows it into the service it is handed to',
          inTests.join('; '));

  // THE DETECTOR ITSELF: it must see the shapes it claims to, and not a
  // mention in a comment or a string. The found shapes are each a line this
  // tree held before #65 or one of the ways the same bias is usually written.
  [
    ['x = A[b[i] % A.length];', true],
    ['code += USER_CODE_ALPHABET[bytes[i] % USER_CODE_ALPHABET.length];', true],
    ['nonce += ALPHANUMERIC[random[i] % ALPHANUMERIC.length];', true],
    ['const d = String(bytes[0] % 10);', true],
    ['const code = buf.readUInt32BE(0) % 1000000;', true],
    ['const i = Math.floor(randomBytes[0] / 256 * n);', true],
    ['const k = forge.random.getBytesSync(16);', true],
    ['const p = forge.prng.create(md);', true],
    ['const b = crypto.pseudoRandomBytes(8);', true],
    ['const p7 = forge.pkcs7.createEnvelopedData();', true],
    ['const x = forge.pki.encryptRsaPrivateKey(k, pw);', true],
    ['n = Math.floor(Math.random() * 10);', true],
    ['const r = require(\'randomstring\');', true],
    ['import { nanoid } from "nanoid";', true],
    ['k = key.decrypt(wrapped.toString(\'binary\'), \'RSAES-PKCS1-V1_5\');', true],
    ['w = pub.encrypt(k, \'RSA-OAEP\', { md: sha1 });', true],
    ['// Math.random() and forge.random, A[b[i] % A.length]', false],
    ['s = "it was Math.random() until #65";', false],
    ['s = "require(\'uuid\')";', false],
    ['// key.decrypt(x, \'RSAES-PKCS1-V1_5\')', false],
    ['h = n % 1000000;', false],
    ['const i = counter[k] % 16;', false],
    ['const r = require(\'./crypto\');', false],
    ['v = nodeCrypto.privateDecrypt({ key: k, padding: p }, w);', false],
    ['const scheme = { scheme: \'RSA-OAEP\' };', false]
  ].forEach(function (shape) {
    const got = findingsIn('x.js', shape[0]).length > 0;
    t.equal(got, shape[1], 'the detector ' + (shape[1] ? 'finds' : 'ignores') +
            ': ' + shape[0]);
  });

  // ---- 3. FORGE'S GENERATOR IS NODE'S. Node's randomBytes is watched while
  // forge draws, signs and encrypts: every one of those must reach it, which
  // is what shows forge's own Fortuna is not drawn from inside the library.
  // THE SERVICE'S forge, resolved from common/: `require('node-forge')` here
  // would find tests/node_modules' own copy, a second instance nothing
  // redirected — and the first version of this section counted that copy's
  // Fortuna reseeding from node as a pass.
  const forgePath = require.resolve('node-forge',
                                    { paths: [path.join(ROOT, 'common')] });
  const forge = require(forgePath);
  t.check(forge.random.drawsFromNode === true,
          'crypto.js pointed forge\'s generator at node\'s when it loaded');
  t.check(forge.random.createInstance() === forge.random,
          'forge.random.createInstance() answers node\'s generator too, so ' +
          'no forge generator of forge\'s own exists in this process');
  const realRandomBytes = nodeCrypto.randomBytes;
  let nodeDraws = 0;
  nodeCrypto.randomBytes = function () {
    nodeDraws += 1;
    return realRandomBytes.apply(this, arguments);
  };
  try {
    const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const forgePrivate = forge.pki.privateKeyFromPem(
      pair.privateKey.export({ type: 'pkcs1', format: 'pem' }));
    const forgePublic = forge.pki.setRsaPublicKey(forgePrivate.n,
                                                  forgePrivate.e);
    // The decisive one: forge hands back EXACTLY the bytes node drew. A
    // Fortuna seeded from node would hand back its own output instead.
    const marked = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    nodeCrypto.randomBytes = function (n) {
      nodeDraws += 1;
      return n === 16 ? Buffer.from(marked) : realRandomBytes(n);
    };
    t.equal(Buffer.from(forge.random.getBytesSync(16), 'binary')
      .toString('hex'), marked.toString('hex'),
            'forge.random.getBytesSync() returns node\'s bytes unchanged');
    nodeCrypto.randomBytes = function () {
      nodeDraws += 1;
      return realRandomBytes.apply(this, arguments);
    };
    [
      ['getBytesSync', function () {
        return forge.random.getBytesSync(16).length === 16;
      }],
      ['getBytes', function () {
        return forge.random.getBytes(16).length === 16;
      }],
      ['an RSA signature (its blinding)', function () {
        const md = forge.md.sha256.create();
        md.update('#65', 'utf8');
        return forgePublic.verify(md.digest().bytes(), forgePrivate.sign(md));
      }],
      ['RSA-OAEP encryption (its seed)', function () {
        return forgePublic.encrypt('k', 'RSA-OAEP').length === 256;
      }],
      ['PKCS#1 v1.5 encryption (its padding)', function () {
        return forgePublic.encrypt('k', 'RSAES-PKCS1-V1_5').length === 256;
      }]
    ].forEach(function (use) {
      const before = nodeDraws;
      const worked = use[1]();
      t.check(worked && nodeDraws > before, 'forge ' + use[0] + ' draws from ' +
              'node\'s generator', (nodeDraws - before) + ' draw(s)');
    });
  } finally {
    nodeCrypto.randomBytes = realRandomBytes;
  }

  // ---- 4. THE OLDER XML KEY TRANSPORTS ARE NODE'S, AND THE WIRE IS
  // UNCHANGED. Each wraps through publicEncrypt() and forge — an RSA written
  // apart from OpenSSL — unwraps the key the element carries.
  const keys = stsCrypto.selfSignedRsaCertificate({ commonName: 'random-65' });
  const forgeKey = forge.pki.privateKeyFromPem(keys.privateKeyPem);
  const plain = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
      'assertion" ID="_r65"><saml:Subject/></saml:Assertion>';
  [
    ['rsa-oaep-mgf1p', 'RSA-OAEP',
     { md: forge.md.sha1.create(), mgf1: { md: forge.md.sha1.create() } }],
    ['rsa-1_5', 'RSAES-PKCS1-V1_5', undefined]
  ].forEach(function (transport) {
    const realPublicEncrypt = nodeCrypto.publicEncrypt;
    let nodeWraps = 0;
    nodeCrypto.publicEncrypt = function () {
      nodeWraps += 1;
      return realPublicEncrypt.apply(this, arguments);
    };
    let sealed = '';
    try {
      sealed = stsCrypto.encryptElement(plain, keys.certPem,
        { algorithm: 'aes256-gcm', keyTransport: transport[0] });
    } finally {
      nodeCrypto.publicEncrypt = realPublicEncrypt;
    }
    t.equal(nodeWraps, 1, transport[0] + ' wraps the content key through ' +
            'node\'s publicEncrypt()');
    const wrapped = /<xenc:EncryptedKey>[\s\S]*?<xenc:CipherValue>([^<]+)</
      .exec(sealed);
    let unwrapped = '';
    try {
      unwrapped = forgeKey.decrypt(forge.util.decode64(wrapped[1]),
                                   transport[1], transport[2]);
    } catch (e) {
      log.debug('Caught in run(): ' + ((e && e.message) || e));
      unwrapped = '';
    }
    t.equal(unwrapped.length, 32, transport[0] + '\'s wrapped key is read ' +
            'back by an independent RSA as the 32-byte AES-256 key');
    const opened = stsCrypto.decryptElement(sealed, keys.privateKeyPem);
    t.check(opened.ok && opened.xml === plain, transport[0] + ' round-trips ' +
            'through node\'s privateDecrypt()', opened.why);
  });
  const other = stsCrypto.selfSignedRsaCertificate({ commonName: 'other-65' });
  const wrongKey = stsCrypto.decryptElement(
    stsCrypto.encryptElement(plain, other.certPem,
      { keyTransport: 'rsa-1_5' }), keys.privateKeyPem);
  t.check(!wrongKey.ok, 'rsa-1_5 to another certificate is refused — ' +
          'implicit rejection unwraps a value, and the length check names it',
          wrongKey.why);

  // ---- 5. THE PASSWORD GENERATOR.
  const policy = require('../common/password_policy');
  const excluded = policy.GENERATOR_EXCLUDES;
  const pool = Array.from(Object.keys(policy.GENERATOR_POOLS).map(
    function (name) {
      return policy.GENERATOR_POOLS[name];
    }).join('')).filter(function (ch) {
    return excluded.indexOf(ch) < 0;
  });
  const generated = policy.PasswordGenerator.generate({
    length: pool.length * 2000, lowercase: true, uppercase: true,
    numbers: true, symbols: true, strict: false, exclude: excluded });
  t.check(Array.from(excluded).every(function (ch) {
    return generated.indexOf(ch) < 0;
  }), 'the password generator never draws an excluded character');
  const counts = Object.create(null);
  for (const ch of generated) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  let passwordChi = 0;
  pool.forEach(function (ch) {
    const d = (counts[ch] || 0) - 2000;
    passwordChi += d * d / 2000;
  });
  // Wilson-Hilferty, upper tail about 1e-6, for the pool's degrees of freedom.
  const df = pool.length - 1;
  const passwordBound = df * Math.pow(1 - 2 / (9 * df) +
                                      4.753 * Math.sqrt(2 / (9 * df)), 3);
  t.check(passwordChi < passwordBound, 'the password generator is uniform ' +
          'over its ' + pool.length + '-character pool (chi-square under ' +
          passwordBound.toFixed(0) + ')', passwordChi.toFixed(1));
  t.equal(policy.PasswordGenerator.generate({
    length: 3, lowercase: true, uppercase: true, numbers: true,
    symbols: true, strict: true, exclude: excluded }), '',
    'a strict draw too short to hold every pool answers nothing, rather ' +
    'than drawing for ever');
  const made = policy.generate();
  t.equal(policy.problemsWith(made, policy.read('default')).length, 0,
          'a generated password satisfies the default profile', made.length +
          ' characters');
  const manifest = require('../package.json');
  const depended = Object.keys(Object.assign({}, manifest.dependencies,
                                             manifest.optionalDependencies))
    .filter(function (name) {
      return SECOND_GENERATORS.test(name);
    });
  t.equal(depended.join(', '), '', 'the service depends on no second ' +
          'random-value package');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'random_values',
  describe: 'random values from node\'s generator only, drawn uniformly ' +
            '(#65): ' +
            'a chi-square with its control, the refusals, the source read ' +
            'for every biased or second-generator shape, forge\'s generator ' +
            'watched drawing from node\'s, the XML key transports through ' +
            'node read back by forge, and the password generator\'s ' +
            'distribution',
  run: run
};
