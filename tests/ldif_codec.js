// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: ldif_codec.js
//
// ===========================================================================
// THE RFC 2849 CODEC BEHIND persistence.mode=ldif, ASSERTED IN PROCESS.
//
// WHY THIS IS HERE RATHER THAN IN THE PARENT PROJECT'S SUITE, which is the
// question `tests/CLAUDE.md` says every file in this directory has to answer.
// The line is "can it be asserted by driving the running service over HTTP?",
// and for this it is no, twice over:
//
//   1. THE FAILURE IS INVISIBLE UNTIL A RESTART. A value that is written
//      wrongly — a leading space eaten, a folded line rejoined without its
//      fold, UTF-8 mangled — is still in memory and still correct on every
//      endpoint for as long as the process lives. Nothing an HTTP client can
//      ask shows it. The damage appears on the NEXT start, in a different
//      process, as an attribute that is quietly not what it was.
//   2. IT NEEDS NO SERVICE AT ALL. The codec is a pure function of a string,
//      so a test that started a listener to reach it would be slower, more
//      fragile and no more convincing.
//
// WHAT IS ASSERTED IS A ROUND TRIP AND ITS EDGES, because the round trip is
// the whole contract: `fromLdif(toLdif(x))` must equal `x` for every value
// this service can put in an attribute. The edges are where it breaks —
// RFC 2849 section 2 has a specific list of characters that force base64, and
// getting any one of them wrong produces a file that is still VALID LDIF and
// no longer says what it said.
//
// THE ONE NON-STANDARD THING IS ALSO ASSERTED: `origin` has no home in LDIF
// and is carried as a `# sts-origin:` comment. That is exactly the kind of
// private convention that survives a refactor by accident and then does not,
// so it is pinned here rather than trusted.
//
// A NOTE ON ONE TEST VALUE. The NUL cases below should be written with a
// `\u0000` ESCAPE rather than as literal bytes, and that is not style: a
// source file in this repository containing a real NUL becomes INVISIBLE TO
// grep, which reports it as a binary file and skips it, while node, sed and
// this suite all read it perfectly. That has cost time here before — and this
// file has held two literal NULs (in `VALUES` and `mustBase64`) since it was
// written, so `grep -a` is what finds anything in it until they are escaped.
//
// MUTATION-TESTED BEFORE IT WAS COMMITTED, which tests/CLAUDE.md requires and
// which is the only evidence that a green test tests anything. Four deliberate
// breakages:
//   * dropping the trailing-space rule from needsBase64()  -> 1 assertion red
//   * folding at WRAP_AT instead of WRAP_AT - 1            -> 3 assertions red
//   * ignoring the sts-origin comment on the way in        -> 2 assertions red
//   * unfolding with .trim() instead of .slice(1)          -> 1 assertion red
//
// **THE FOURTH SURVIVED THE FIRST VERSION OF THIS FILE, AND THAT IS THE MOST
// USEFUL THING IN THIS HEADER.** Every folded value the file tried was a run of
// one repeated letter, so trimming a continuation line removed nothing and the
// whole suite stayed green against an unfolder that eats the value's own
// whitespace. The assertion that catches it now had to be CONSTRUCTED — a value
// whose own space falls exactly on the fold boundary, so the continuation line
// begins with two spaces — and it is in checkFolding() with the arithmetic
// written out. The lesson is the one tests/CLAUDE.md keeps making: a guard that
// has never failed has not been shown to guard anything, and a round trip over
// convenient data is exactly the shape that passes while proving nothing.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: what is
// asserted here must be true of the service as it ships, not of whatever
// appconfig file happens to be exported in a developer's shell. The codec
// itself reads no configuration, but requiring the module pulls in config.js.
delete process.env.CONFIG_FILE;

const bunyan = require('bunyan');
const ldif = require('../persistence/persistence_ldif');

// Quiet: this file makes several hundred codec calls and each logs at debug.
const log = bunyan.createLogger({ name: 'ldif-codec-test', level: 'fatal' });

// ---------------------------------------------------------------------------
// The values that have to survive, one per reason. Every one of these is
// something this service really can put in an attribute — the DNs it accepts
// are unconstrained, SCIM will write any string, and a client may `ldapadd`
// whatever it likes.
// ---------------------------------------------------------------------------
const VALUES = [
  ['ordinary content', 'alice'],
  ['spaces inside', 'Alice Anderson'],
  ['a leading space', ' leading'],
  ['a trailing space', 'trailing '],
  ['two spaces inside', 'two  spaces'],
  ['a leading colon', ':colon'],
  ['a leading less-than', '<less'],
  ['an interior colon', 'urn:sts:idp:acme'],
  ['non-ASCII', 'café'],
  ['CJK', '日本語'],
  ['an emoji', 'a 🔐 key'],
  ['a newline', 'two\nlines'],
  ['a carriage return', 'crlf\r\nhere'],
  ['a tab', 'a\tb'],
  ['a NUL', 'before\u0000after'],
  ['nothing in it', ''],
  ['a lone hash', '#'],
  ['content that looks like base64', 'YWxpY2U='],
  ['a long folded value', 'x'.repeat(400)],
  ['a fold landing on a space', 'y'.repeat(75) + ' tail'],
  ['an escaped comma in a DN',
   'cn=Example\\, Ltd,ou=applications,dc=example,dc=com'],
  ['XML, which must not be escaped here', '<saml:Assertion ID="_1"/>'],
  ['a PEM-looking blob',
   '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----']
];

// One entry carrying every value above as its own attribute, which is what
// makes the round trip a single comparison rather than twenty-three.
function everyValueEntry() {
  log.debug("Entering everyValueEntry().");
  const attributes = { objectclass: ['top', 'inetOrgPerson'], uid: ['alice'] };
  VALUES.forEach(function (row, i) {
    attributes['test' + i] = [row[1]];
  });
  log.debug("Leaving everyValueEntry().");
  return { dn: 'uid=alice,ou=users,dc=example,dc=com',
           origin: 'seed',
           attributes: attributes };
}

function roundTrip(entries) {
  log.debug("Entering roundTrip().");
  log.debug("Leaving roundTrip().");
  return ldif.fromLdif(ldif.toLdif(entries, ['a test']), log);
}

// ---------------------------------------------------------------------------
// EVERY VALUE COMES BACK BYTE FOR BYTE. The assertion that matters most, and
// the one a mutation to any encoding rule fails.
// ---------------------------------------------------------------------------
function checkValues(t) {
  log.debug("Entering checkValues().");
  const original = everyValueEntry();
  const back = roundTrip([original]);

  t.equal(back.length, 1, 'one entry in, one entry out');
  if (back.length !== 1) {
    log.debug("Leaving checkValues().");
    return;
  }
  t.equal(back[0].dn, original.dn, 'the DN survives exactly, as written');

  VALUES.forEach(function (row, i) {
    const name = 'test' + i;
    const got = (back[0].attributes[name] || [])[0];
    t.equal(got, row[1],
            'a value with ' + row[0] + ' survives the round trip');
  });
  log.debug("Leaving checkValues().");
}

// ---------------------------------------------------------------------------
// AND EVERY VALUE THAT NEEDED base64 GOT IT. The round trip above can pass
// while the ENCODING choice is wrong in the permissive direction — a value
// base64'd that did not need to be is still read back correctly — but not in
// the other. This pins the direction that loses data: RFC 2849 section 2 names
// the characters a SAFE-STRING may not start with or contain, and a value
// carrying one of them written as plain text comes back truncated or shifted.
// ---------------------------------------------------------------------------
function checkEncodingChoice(t) {
  log.debug("Entering checkEncodingChoice().");
  const mustBase64 = [
    [' leading', 'a value starting with a space'],
    ['trailing ', 'a value ending with a space'],
    [':colon', 'a value starting with a colon'],
    ['<less', 'a value starting with a less-than'],
    ['café', 'a non-ASCII value'],
    ['two\nlines', 'a value containing a newline'],
    ['cr\rhere', 'a value containing a carriage return'],
    ['nul\u0000here', 'a value containing a NUL']
  ];
  mustBase64.forEach(function (row) {
    t.check(ldif.needsBase64(row[0]) === true,
            row[1] + ' is written base64, as RFC 2849 section 2 requires');
  });

  const mustNot = [
    ['alice', 'a plain value'],
    ['Alice Anderson', 'a value with an interior space'],
    ['urn:sts:idp:acme', 'a value with an interior colon'],
    ['a<b', 'a value with an interior less-than'],
    ['', 'an empty value'],
    ['a\tb', 'a value containing a tab, which section 2 permits']
  ];
  mustNot.forEach(function (row) {
    t.check(ldif.needsBase64(row[0]) === false,
            row[1] + ' is written as plain text rather than base64');
  });
  log.debug("Leaving checkEncodingChoice().");
}

// ---------------------------------------------------------------------------
// FOLDING. A line longer than the wrap width is continued on the next physical
// line with ONE leading space, and unfolding removes exactly that space. The
// off-by-one here is the interesting failure: a continuation of WRAP_AT
// characters plus its space is one column too wide, which is legal and no
// longer lines up with what OpenLDAP's tools emit — and a value whose own
// content begins with a space at a fold boundary is where "exactly one space"
// stops being pedantry.
// ---------------------------------------------------------------------------
function checkFolding(t) {
  log.debug("Entering checkFolding().");
  const long = 'z'.repeat(300);
  const text = ldif.ldifLine('description', long);
  const lines = text.split('\n');

  t.check(lines.length > 1, 'a long value is folded across several lines');
  lines.forEach(function (line, i) {
    t.check(line.length <= 76,
            'folded line ' + (i + 1) + ' is within the 76-column wrap width');
    if (i > 0) {
      t.check(line.charAt(0) === ' ',
              'continuation line ' + (i + 1) + ' begins with a space');
      t.check(line.charAt(1) !== ' ',
              'continuation line ' + (i + 1) + ' begins with only one space ' +
              '— a second would be part of the value');
    }
  });

  const back = roundTrip([{ dn: 'cn=x,dc=example,dc=com',
                            attributes: { description: [long] } }]);
  t.equal((back[0].attributes.description || [])[0], long,
          'a folded value is rejoined to exactly what was written');

  // -------------------------------------------------------------------------
  // A SPACE LANDING EXACTLY ON A FOLD BOUNDARY, which is the only shape that
  // tells `.slice(1)` and `.trim()` apart — and this assertion exists because
  // MUTATION TESTING FOUND THAT IT DIDN'T. The first version of this file
  // replaced the unfolder's `.slice(1)` with `.trim()` and the whole suite
  // stayed green: every folded value it tried was a run of one repeated
  // letter, so trimming the continuation removed nothing.
  //
  // `'description: '` is thirteen characters, and the first physical line
  // takes seventy-six, so index 63 of the value is the first character of the
  // continuation. Putting a space there makes the continuation line begin with
  // TWO spaces — one that is the fold marker and one that belongs to the value
  // — and an unfolder that trims eats both. The result is a description with a
  // word silently joined to the one before it, in a file that is still
  // perfectly valid LDIF.
  // -------------------------------------------------------------------------
  const onBoundary = 'a'.repeat(63) + ' ' + 'b'.repeat(74) + ' ' +
                     'c'.repeat(10);
  const boundaryLines = ldif.ldifLine('description', onBoundary).split('\n');
  t.check(boundaryLines.length > 1 && boundaryLines[1].charAt(0) === ' ' &&
          boundaryLines[1].charAt(1) === ' ',
          'a value whose own space falls on the fold boundary produces a ' +
          'continuation line starting with two spaces — the fold marker and ' +
          'the value\'s own');
  const boundaryBack = roundTrip([{ dn: 'cn=y,dc=example,dc=com',
                                    attributes: {
                                      description: [onBoundary] } }]);
  t.equal((boundaryBack[0].attributes.description || [])[0], onBoundary,
          'and it is rejoined with that space intact — unfolding removes ' +
          'EXACTLY the one fold marker, never the value\'s own whitespace');
  log.debug("Leaving checkFolding().");
}

// ---------------------------------------------------------------------------
// THE SHAPE OF THE FILE. Not aesthetics: `version: 1` and the `dn:` line first
// are what make this file loadable by anything other than us, which is the
// entire reason LDIF was chosen over a JSON dump of our own.
// ---------------------------------------------------------------------------
function checkFileShape(t) {
  log.debug("Entering checkFileShape().");
  const text = ldif.toLdif([
    { dn: 'uid=alice,ou=users,dc=example,dc=com', origin: 'seed',
      attributes: { uid: ['alice'] } },
    { dn: 'uid=bob,ou=users,dc=example,dc=com',
      attributes: { uid: ['bob'] } }
  ], ['a test header']);

  const lines = text.split('\n');
  t.check(lines.indexOf('version: 1') >= 0,
          'the file carries the RFC 2849 version header');
  t.check(lines[0].charAt(0) === '#',
          'the header comment comes before it, which section 2 permits');

  const records = text.split('\n\n').filter(function (block) {
    return block.indexOf('dn:') >= 0;
  });
  t.equal(records.length, 2, 'one record per entry, separated by a blank line');
  records.forEach(function (block, i) {
    const first = block.split('\n').filter(function (line) {
      return line.charAt(0) !== '#';
    })[0];
    t.check(/^dn:/.test(first),
            'record ' + (i + 1) +
            ' opens with its dn: line, after any comment');
  });
  log.debug("Leaving checkFileShape().");
}

// ---------------------------------------------------------------------------
// `origin` — THE ONE THING LDIF HAS NO FIELD FOR.
//
// It rides as a comment, and both halves of that need pinning: it must come
// back, and it must NOT have become an attribute. The second is the one worth
// asserting — an implementation that "fixed" this by writing `stsOrigin: seed`
// would pass a round-trip test and would have added a real attribute to every
// entry in the directory, visible in every search and matchable by every
// filter.
// ---------------------------------------------------------------------------
function checkOrigin(t) {
  log.debug("Entering checkOrigin().");
  const text = ldif.toLdif([
    { dn: 'uid=alice,ou=users,dc=example,dc=com', origin: 'seed',
      attributes: { uid: ['alice'] } }
  ], []);

  t.check(text.indexOf('# sts-origin: seed') >= 0,
          'origin is written as a comment');

  const back = ldif.fromLdif(text, log);
  t.equal(back[0].origin, 'seed', 'origin comes back');
  t.equal(Object.keys(back[0].attributes).indexOf('stsorigin'), -1,
          'origin did NOT become an attribute — it would be searchable, and ' +
          'it is a private marker rather than directory content');
  t.equal(Object.keys(back[0].attributes).indexOf('origin'), -1,
          'and it did not become an attribute called "origin" either');

  // An entry with no origin must come back with none, rather than with the
  // previous record's. The parser carries a pending comment forward, so this
  // is a real adjacency bug rather than a hypothetical one.
  const two = ldif.fromLdif(ldif.toLdif([
    { dn: 'uid=a,dc=example,dc=com', origin: 'seed',
      attributes: { uid: ['a'] } },
    { dn: 'uid=b,dc=example,dc=com', attributes: { uid: ['b'] } }
  ], []), log);
  t.equal(two[0].origin, 'seed', 'the first entry keeps its origin');
  t.equal(two[1].origin, undefined,
          'the next entry does NOT inherit it — a pending comment is cleared ' +
          'at the record boundary');
  log.debug("Leaving checkOrigin().");
}

// ---------------------------------------------------------------------------
// MULTI-VALUED ATTRIBUTES AND THEIR ORDER. `member` on a group is the case
// that matters: membership is a multi-valued attribute, and an order that
// changed on every restart would make every restored group's file differ from
// the last one for no reason — which is the kind of churn that makes a diff
// useless and hides a real change.
// ---------------------------------------------------------------------------
function checkMultiValued(t) {
  log.debug("Entering checkMultiValued().");
  const members = ['uid=alice,ou=users,dc=example,dc=com',
                   'uid=bob,ou=users,dc=example,dc=com',
                   'uid=carol,ou=users,dc=example,dc=com'];
  const back = roundTrip([{
    dn: 'cn=developers,ou=groups,dc=example,dc=com',
    attributes: { objectclass: ['top', 'groupOfNames'], cn: ['developers'],
                  member: members }
  }]);
  t.equal(JSON.stringify(back[0].attributes.member), JSON.stringify(members),
          'a multi-valued attribute comes back with its values in order');
  t.equal(JSON.stringify(back[0].attributes.objectclass),
          JSON.stringify(['top', 'groupOfNames']),
          'and so does objectClass, which decides what an entry IS');
  log.debug("Leaving checkMultiValued().");
}

// ---------------------------------------------------------------------------
// A URL-VALUED ATTRIBUTE IS REFUSED RATHER THAN FOLLOWED.
//
// RFC 2849 defines `name:< url`, and this service will not dereference one.
// That is a security property rather than an unimplemented feature: following
// a `file:` or `http:` URL out of a data file is reading something whoever
// wrote the file chose, and these files are meant to be hand-editable.
// ---------------------------------------------------------------------------
function checkUrlValueRefused(t) {
  log.debug("Entering checkUrlValueRefused().");
  const text = 'version: 1\n\n' +
               'dn: uid=alice,ou=users,dc=example,dc=com\n' +
               'uid: alice\n' +
               'jpegPhoto:< file:///etc/passwd\n' +
               'cn: Alice\n';
  const back = ldif.fromLdif(text, log);
  t.equal(back.length, 1, 'the entry still loads');
  t.equal(back[0].attributes.jpegphoto, undefined,
          'a URL-valued attribute is NOT loaded, and nothing is dereferenced');
  t.equal((back[0].attributes.cn || [])[0], 'Alice',
          'and the attributes after it still load');
  log.debug("Leaving checkUrlValueRefused().");
}

// ---------------------------------------------------------------------------
// THE TWO OPERATIONAL TIMESTAMPS ARE REBUILT FROM THE ATTRIBUTES, not written
// twice. `putEntry()` keeps `createdAt`/`modifiedAt` on the stored object AND
// as `createTimestamp`/`modifyTimestamp` attributes; writing both to the file
// would be two copies of one fact, and this asserts which copy is the file's.
// ---------------------------------------------------------------------------
function checkTimestamps(t) {
  log.debug("Entering checkTimestamps().");
  const back = roundTrip([{
    dn: 'uid=alice,ou=users,dc=example,dc=com',
    createdAt: '20260827120000Z',
    modifiedAt: '20260827130000Z',
    attributes: { uid: ['alice'],
                  createtimestamp: ['20260827120000Z'],
                  modifytimestamp: ['20260827130000Z'] }
  }]);
  t.equal(back[0].createdAt, '20260827120000Z',
          'createdAt is rebuilt from createTimestamp');
  t.equal(back[0].modifiedAt, '20260827130000Z',
          'modifiedAt is rebuilt from modifyTimestamp');

  // An entry with neither — one somebody added by hand with ldapadd — must
  // load rather than fail, with nulls that ldap_server.js fills the way it
  // fills them for any entry that arrives without them.
  const bare = ldif.fromLdif(
    'dn: uid=bob,ou=users,dc=example,dc=com\nuid: bob\n', log);
  t.equal(bare.length, 1, 'a hand-written entry with no timestamps loads');
  t.equal(bare[0].createdAt, null,
          'and reports no createdAt rather than a lie');
  log.debug("Leaving checkTimestamps().");
}

function run(t) {
  log.debug("Entering run().");
  checkValues(t);
  checkEncodingChoice(t);
  checkFolding(t);
  checkFileShape(t);
  checkOrigin(t);
  checkMultiValued(t);
  checkUrlValueRefused(t);
  checkTimestamps(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ldif_codec',
  describe: 'the RFC 2849 codec behind persistence.mode=ldif, round trip and ' +
            'edges',
  run: run
};
