'use strict';
//
// File: inetorgperson.js
//
// ===========================================================================
// THE SCHEMA THE ACCOUNT PAGE IS DRAWN FROM, AND THE TWO REFUSALS IN IT.
//
// `common/inetorgperson.ts` is the fixed list `/portal`'s Overview looks each
// attribute up in. Four things about it are worth asserting in process, and
// the middle two are the ones that matter:
//
//   1. **IT IS THE UNION OF THREE OBJECT CLASSES**, in inheritance order, with
//      the MUST set on the right one. "The inetOrgPerson attributes" is not
//      one document's list — it is `person` plus `organizationalPerson` plus
//      RFC 2798's own — and a reading that took only the third would leave
//      `cn` and `sn` off the page that requires them.
//   2. **`rowFor()` REFUSES A SECRET**, whatever the entry holds.
//   3. **`rowFor()` REFUSES OCTETS**, and answers a size instead.
//   4. **NO `sts`-PREFIXED NAME IS ON THE LIST**, which is the invariant the
//      whole design rests on.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Claims 2 and 3 are **not reachable over HTTP**, and finding that out is what
// this file is for. `tests/vendored/sts_portal_directory_attributes.js` drives
// the page and asserts that a password hash is never printed — and that job
// PASSES with the refusal in this module deleted, because the page has a
// branch of its own that words the cell (*set — a scrypt hash rather than the
// value*) and so never reaches the values. That is belt and braces and is
// right for a password hash; it also means the page cannot tell whether this
// module still refuses.
//
// So the refusal is pinned here, at the function, where deleting it fails
// something. Mutation-tested: removing the `secret` branch from `rowFor()`
// fails this file and passes the whole protocol suite.
//
// Claim 1 is reachable over HTTP and is asserted there too — deliberately, and
// not as duplication: that job asserts what the PAGE drew, this one asserts
// what the LIST is, and a page that stopped calling the list would pass this
// file perfectly.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const schema = require('../common/inetorgperson');
// THE OTHER CATALOGUE OF LDAP SPELLINGS IN THIS REPOSITORY. Required for the
// cross-check at the end, and it is a LEAF (`crypto`, `realms`, `helpers`,
// `admin_stats`, `mode`, `error_codes`) so requiring it here costs nothing and
// registers nothing.
const vcClaims = require('../oid4vc/vc_claims');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'inetorgperson',
  level: process.env.LOG_LEVEL || 'info' });

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the union of three object classes, in inheritance order ===');
  const classes = schema.classes();
  t.equal(classes.slice(0, 3).map(function (k) { return k.name; })
            .join(' > '),
          'person > organizationalPerson > inetOrgPerson',
          'the three classes are in inheritance order, which is also the ' +
          'order the page draws them in');
  t.equal(classes.length === 4 && classes[3].id, 'identityClaims',
          'and the Identity Assurance claims (#128) follow them, as a group ' +
          'that says it is not an object class');
  t.equal(classes[0].oid, '2.5.6.6', 'person is X.500\'s 2.5.6.6');
  t.equal(classes[1].oid, '2.5.6.7', 'organizationalPerson is 2.5.6.7');
  t.equal(classes[2].oid, '2.16.840.1.113730.3.2.2',
          'and inetOrgPerson is Netscape\'s, which is where the class was ' +
          'actually defined');

  // THE MUST SET, AND WHERE IT IS. Only `person` has one, and taking RFC
  // 2798's own MAY list alone — the reading somebody reaches for when they
  // hear "the inetOrgPerson attributes" — would leave both of these off the
  // page that requires them.
  const must = schema.attributes().filter(function (row) { return row.must; });
  t.equal(must.map(function (row) { return row.ldap; }).sort().join(','),
          'cn,sn',
          'exactly two attributes are REQUIRED, and they are the ones RFC ' +
          '4519 section 3.12 puts on `person`');
  t.check(classes[0].attributes.some(function (r) { return r.must; }) &&
          !classes[1].attributes.some(function (r) { return r.must; }) &&
          !classes[2].attributes.some(function (r) { return r.must; }),
          'and both are on the BASE class rather than on inetOrgPerson — the ' +
          'reading that takes RFC 2798\'s MAY list alone loses them');

  t.log.info('=== the list itself ===');
  const all = schema.attributes();
  const names = all.map(function (row) { return row.ldap; });
  t.check(new Set(names.map(function (n) { return n.toLowerCase(); })).size ===
          names.length,
          'no attribute is listed twice. `telephoneNumber` is on the MAY ' +
          'list of BOTH person and organizationalPerson in the documents — ' +
          'X.521 repeats it and RFC 4519 carries the repetition — and a page ' +
          'that drew it twice would look like a bug in the page',
          names.length + ' name(s)');
  t.check(all.every(function (row) { return !!row.label && !!row.rfc; }),
          'every row names a label and the document it comes from, because ' +
          'the page prints both and a reader on a mock is about to go and ' +
          'write the attribute over LDAP');

  // THE INVARIANT. `common/inetorgperson.ts`'s whole reason for existing is
  // that the account page draws a LIST rather than the entry, because this
  // service writes credentials onto the same object. If one of those names
  // ever reached this list the page would print it, and nothing else in the
  // repository would notice.
  t.check(!names.some(function (n) { return /^sts/i.test(n); }),
          'NO `sts`-PREFIXED NAME IS ON THE LIST. This service writes four ' +
          'credentials onto the same entry — a TOTP shared secret, recovery ' +
          'codes, a WebAuthn credential and an activation token — and the ' +
          'page draws whatever is here');
  t.check(!names.some(function (n) { return /^oauth|^fed/i.test(n); }),
          'and no `oauthClientSecret` or `fedClientSecret` either, which are ' +
          'on APPLICATION entries rather than person ones and are the other ' +
          'two secrets this directory holds in the clear');

  t.log.info('=== the lookup is case-insensitive, which is not cosmetic ===');
  // A STORED entry has lower-cased names — RFC 4512 section 2.5 makes
  // attribute descriptions case-insensitive and `ldap_server.js` normalises on
  // the way in. A lookup that did not fold the case would find NOTHING, and
  // every row on the account page would draw as "not set" on an entry that was
  // full. That is the one mistake this table exists to make impossible, and it
  // fails silently in exactly the shape nobody reports.
  t.check(!!schema.attribute('departmentnumber'),
          'a lower-cased name resolves — which is how a stored entry spells ' +
          'every one of them');
  t.check(!!schema.attribute('DepartmentNumber'),
          'and so does any other casing');
  t.equal(schema.attribute('departmentnumber').ldap, 'departmentNumber',
          'and the row answers with the CANONICAL spelling, which is what ' +
          'the page prints');
  t.check(schema.attribute('stsTotpCredential') === null,
          'and a name that is not on the list resolves to nothing rather ' +
          'than to something empty');

  t.log.info('=== rowFor(): the two refusals ===');
  // A REAL-SHAPED STORED MAP: lower-cased keys, array values.
  const entry = {
    cn: ['Alice Example'],
    sn: ['Example'],
    mail: ['alice@example.org', 'a.example@example.org'],
    userpassword: ['scrypt$16384$8$1$abcdef0123456789'],
    jpegphoto: [Buffer.alloc(4096)],
    userpkcs12: [Buffer.alloc(2048)],
    departmentnumber: ['Probing']
  };

  const password = schema.rowFor(schema.attribute('userPassword'), entry);
  t.check(password.present,
          'the password attribute is reported as PRESENT — it is on the ' +
          '`person` MAY list and a page that left it out would be a page ' +
          'that had quietly stopped being the schema');
  t.equal(password.values.length, 0,
          'AND IT CARRIES NO VALUE. This is the assertion the page cannot ' +
          'make: that page has a branch of its own that words the cell, so ' +
          'it passes with this refusal deleted');
  t.check(password.secret, 'and the row says WHY, so the page can word it');
  t.check(JSON.stringify(password).indexOf('scrypt$') < 0,
          'and the hash is nowhere in the row at all — not in a field a ' +
          'caller might render by accident');

  const photo = schema.rowFor(schema.attribute('jpegPhoto'), entry);
  t.check(photo.present && photo.binary, 'a binary attribute is present and ' +
          'says it is binary');
  t.equal(photo.bytes, 4096, 'and reports its SIZE');
  t.equal(photo.values.length, 0,
          'and carries no octets — interpolating them into HTML is mojibake ' +
          'at best');

  const p12 = schema.rowFor(schema.attribute('userPKCS12'), entry);
  t.equal(p12.values.length, 0,
          'and `userPKCS12` the same way, which is the one of the five that ' +
          'matters most: a PKCS#12 bundle conventionally carries a PRIVATE ' +
          'KEY, so that refusal is on the KIND rather than on a list of names');

  t.log.info('=== rowFor(): the ordinary cases ===');
  const mail = schema.rowFor(schema.attribute('mail'), entry);
  t.equal(mail.count, 2, 'a multi-valued attribute keeps both values');
  t.equal(mail.values.join('|'), 'alice@example.org|a.example@example.org',
          'in order, as a LIST — a page that joined them with a comma would ' +
          'render two addresses as one address containing a comma');

  const absent = schema.rowFor(schema.attribute('carLicense'), entry);
  t.check(!absent.present && absent.values.length === 0,
          'an attribute the entry does not carry is absent rather than empty');

  // AN EMPTY STRING IS NOT A VALUE. `ldap_server.js` drops blanks on the way
  // in for this reason, but an entry written over the raw socket can carry
  // one, and a page drawing a row as "set" with nothing beside it is worse
  // than drawing it as unset.
  const blank = schema.rowFor(schema.attribute('title'), { title: [''] });
  t.check(!blank.present,
          'and an attribute present with an empty value is reported as NOT ' +
          'set, because a row that says "set" with nothing beside it is the ' +
          'most confusing of the three answers');

  t.log.info('=== describe(): what the page is handed ===');
  const described = schema.describe(entry);
  t.equal(described.total, all.length,
          'every attribute on the list is accounted for');
  // SEVEN: cn, sn, userPassword, mail, departmentNumber, jpegPhoto,
  // userPKCS12. **THE TWO REFUSED ONES ARE COUNTED**, which is the part worth
  // an assertion rather than a number: a set of recovery codes that this
  // process cannot open is still a set somebody holds, and the same reading
  // applies here — a password that is not shown is still a password that is
  // SET, and a heading saying *2 of 6 set* about an entry with three would be
  // the page lying in the direction of reassurance.
  t.equal(described.held, 7,
          'the count is every attribute really on the entry, INCLUDING the ' +
          'two whose values are refused — not shown is not the same as not set',
          JSON.stringify(described.classes.map(function (k) {
            return k.name + '=' + k.held;
          })));
  t.equal(described.classes.reduce(function (n, k) { return n + k.total; }, 0),
          all.length,
          'and the classes partition the list rather than overlapping it');
  t.check(described.classes.every(function (k) {
            return k.held === k.rows.filter(function (
                r) { return r.present; }).length;
          }),
          'each class\'s count agrees with its own rows, so the page does ' +
          'not have to walk them twice to draw a heading');

  t.equal(schema.describe({}).held, 0,
          'a person with a bare entry holds none of them, and the page still ' +
          'draws all ' + all.length);

  t.log.info('=== the spellings agree with the other catalogue ===');
  // `oid4vc/vc_claims.ts` is the credential-claim catalogue and the THIRD
  // independently maintained list of LDAP spellings in this repository
  // (`ldap_server.js`'s STANDARD_NAMES is the second, and `learnName()` merges
  // all of them so a disagreement is REPORTED at startup rather than resolved
  // by merge order). This asserts the overlap directly, because a warning in a
  // log is a check nobody reads on the day it starts firing.
  const disagreements = [];
  Object.keys(schema.CANONICAL_NAMES).forEach(function (lower) {
    const theirs = vcClaims.CANONICAL_NAMES[lower];
    if (theirs && theirs !== schema.CANONICAL_NAMES[lower]) {
      disagreements.push(lower + ': "' + schema.CANONICAL_NAMES[lower] +
                         '" here, "' + theirs + '" there');
    }
  });
  t.check(disagreements.length === 0,
          'every name both catalogues carry is spelt the same way in each — ' +
          'a page rendering `seealso` where the schema document says ' +
          '`seeAlso` reads as a bug in the page',
          disagreements.join('; '));
  t.check(Object.keys(schema.CANONICAL_NAMES).some(function (lower) {
            return !!vcClaims.CANONICAL_NAMES[lower];
          }),
          'and the two DO overlap, so the check above is not passing on an ' +
          'empty intersection');

  // ---------------------------------------------------------------------
  // AND THE SECTION NUMBERS, WHICH IS THE CHECK THAT FOUND SOMETHING.
  //
  // Both catalogues cite the document each attribute is defined in, and those
  // citations exist so that a reader can go and look the attribute up — which
  // makes a wrong one worse than none, because it is followed. **Nothing
  // could have caught one before this**: a section number is not a spelling,
  // so `learnName()` never sees it, and nobody re-reads an RFC to check a
  // string in a table.
  //
  // When this was first written it found two, both of which had been in the
  // repository since those tables were: `givenName` cited as RFC 4519 2.6 (2.6
  // is `destinationIndicator` — that section is alphabetical, and `givenName`
  // is 2.12) and `labeledURI` as RFC 2079 2, in a document whose sections are
  // unnumbered. `scim/scim_map.ts` had a third, `employeeType` at RFC 2798 2.7
  // rather than 2.5.
  //
  // It cannot check a citation against the RFC — nothing in this process can
  // reach one — so what it does is make the two tables AGREE. That turns the
  // next divergence into a failure rather than into something a reader would
  // have to notice.
  // ---------------------------------------------------------------------
  const sections = [];
  let compared = 0;
  schema.attributes().forEach(function (row) {
    const lower = row.ldap.toLowerCase();
    const theirs = (vcClaims.VC_ATTRIBUTES || []).filter(function (one) {
      return one.ldap.toLowerCase() === lower;
    })[0];
    if (!theirs || !theirs.schema) {
      return;
    }
    compared++;
    if (theirs.schema !== row.rfc) {
      sections.push(row.ldap + ': "' + row.rfc + '" here, "' + theirs.schema +
                    '" in the credential claim catalogue');
    }
  });
  t.check(compared > 5,
          'the two catalogues share enough attributes for the comparison to ' +
          'mean something', compared + ' compared');
  t.check(sections.length === 0,
          'AND THEY CITE THE SAME SECTION FOR EVERY ONE. A citation exists ' +
          'so that a reader can go and look the attribute up, which makes a ' +
          'wrong one worse than none — it gets followed',
          sections.join('; '));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'inetorgperson',
  describe: 'the schema the account page is drawn from: the union of three ' +
            'object classes, the two refusals in rowFor(), and that no ' +
            'credential this service invents can reach the list',
  run: run
};
