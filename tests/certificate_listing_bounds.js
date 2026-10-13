// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/certificate_listing_bounds.js — THE CERTIFICATE LISTS DO PER-ROW WORK
// FOR THE ROWS THEY SHOW (#352, 2026-09-29).
//
// `/admin-api/users` took ten seconds on testidp's 29,267 people because it
// built and decorated everybody to show fifty; #352's audit found the same
// shape on every certificate list. This file holds the five that part
// "certs" fixed to the rule *page before per-row work*, and each claim is a
// COUNT of the expensive call against a population much larger than a page,
// never a time — the times are logged, for information only:
//
//   A. `personAssertions.holders()` reads presence in ONE directory walk, with
//      no read per person and NO `keystore.open()` — the old one read every
//      person and opened both private keys of every holder. Same answer.
//   B. `/admin/pki` asks for a certificate's key (`pqcOf()`) only for the rows
//      it draws; `GET /admin-api/pki` still carries `pqc` on every row, equal
//      to `pqc_support.of()`'s, and a second call parses nothing.
//   C. `GET /admin-api/certificates` parses the page's certificates and no
//      others; a filter parses each certificate once per process; the answer
//      is the one the parse-everything list gave. The details lookup finds a
//      holder's certificate without parsing every certificate.
//   D. The enrollment listings read holders WITH their values in one walk
//      (no read per holder), skip another family's records before the
//      parse, and the monitors count rather than list; ACME looks accounts
//      up for the shown rows only. Same answers as the old walk.
//   E. The GNAP monitor reads the store's grants and tokens once, not once
//      per application. Same rows.
//
// A and D-E use a stand-in directory or store, because what is counted is the
// calls a module makes through its slot; B and C run on the real directory in
// a throwaway realm holding a few thousand people, which is removed after.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pkijs = require('pkijs');
const keystore = require('../common/keystore');
const realms = require('../common/realms');
const helpers = require('../common/helpers');
const pki = require('../common/pki');
const pqcSupport = require('../common/pqc_support');
const registry = require('../common/cache_registry');
// Fills the directory slots. It registers HTTP views and binds nothing.
const ldap = require('../ldap/ldap_server');
const personAssertions = require('../common/person_assertions');
const certificateViews = require('../admin-core/certificate_views');
const certEnrollment = require('../common/cert_enrollment');
const pkiAdmin = require('../admin-ui/pki_admin');
const app = require('../common/app');
pkiAdmin.registerRoutes(app);

const log = require('bunyan').createLogger({
  name: 'certificate_listing_bounds',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const REALM = 'clb-' + RUN;
const POPULATION = 3000;
const HOLDERS = 40;
const SAML_HOLDERS = 8;
const PER = 25;

function elapsed(since) {
  log.debug("Entering elapsed().");
  const ms = Number(process.hrtime.bigint() - since) / 1e6;
  log.debug("Leaving elapsed().");
  return ms.toFixed(1) + ' ms';
}

// Replaces `obj[name]` with a counting wrapper for the length of `fn`.
async function counting(obj, name, fn) {
  log.debug("Entering counting(). " + name);
  const original = obj[name];
  const tally = { calls: 0 };
  obj[name] = function () {
    tally.calls += 1;
    return original.apply(this, arguments);
  };
  try {
    tally.result = await fn();
  } finally {
    obj[name] = original;
  }
  log.debug("Leaving counting(). " + tally.calls + " call(s).");
  return tally;
}

function missesOf(name) {
  log.debug("Entering missesOf().");
  // `detail()` and not `report()`: the one store asked about, so another
  // store's descriptor (one loaded by another file in the same run) cannot
  // make the count throw.
  const held = registry.detail(name);
  log.debug("Leaving missesOf().");
  return held ? Number(held.summary.misses || 0) : 0;
}

// ---------------------------------------------------------------------------
// A. THE HOLDER REGISTER, on a fresh copy of the module with a stand-in
// directory, so every call it makes through its slot is counted.
// ---------------------------------------------------------------------------
function freshPersonAssertions() {
  log.debug("Entering freshPersonAssertions().");
  const file = require.resolve('../common/person_assertions');
  const held = require.cache[file];
  delete require.cache[file];
  let fresh;
  try {
    fresh = require('../common/person_assertions');
  } finally {
    require.cache[file] = held;
  }
  log.debug("Leaving freshPersonAssertions().");
  return fresh;
}

function standInPeople() {
  log.debug("Entering standInPeople().");
  const people = [];
  for (let n = 0; n < POPULATION; n++) {
    const name = 'pa-' + String(n).padStart(5, '0');
    const attrs = { cn: [name] };
    if (n % 75 === 3) {
      attrs.stsAssertionJwks = ['{"keys":[]}'];
      attrs.stsAssertionCertificate = ['-----BEGIN CERTIFICATE-----\nA' + n +
                                       '\n-----END CERTIFICATE-----\n'];
      attrs.stsAssertionPrivateKey = ['$aesgcm$sealed-' + n];
      attrs.stsAssertionKid = ['kid-' + n];
      attrs.stsAssertionExpiresAt = ['20300101000000Z'];
    }
    if (n % 140 === 5) {
      attrs.stsSamlAssertionCertificate = ['-----BEGIN CERTIFICATE-----\nS' +
                                           n + '\n-----END CERTIFICATE-----\n'];
      attrs.stsSamlAssertionPrivateKey = ['$aesgcm$sealed-saml-' + n];
      attrs.stsSamlAssertionThumbprint = ['tp-' + n];
    }
    if (n % 500 === 7) {
      attrs.stsAssertionIssuer = ['https://issuer-' + n + '.example'];
    }
    if (n % 999 === 11) {
      // An attribute present with nothing in it, which is no holder.
      attrs.stsSamlAssertionIssuer = [''];
    }
    people.push({ name: name, attrs: attrs });
  }
  log.debug("Leaving standInPeople().");
  return people;
}

function standInDirectory(people, counts, withHoldingAny) {
  log.debug("Entering standInDirectory().");
  const byName = {};
  people.forEach(function (one) {
    byName[one.name] = one;
  });
  const pick = function (attrs) {
    const out = {};
    personAssertions.ATTRIBUTES.forEach(function (name) {
      if (attrs[name] && attrs[name].length) {
        out[name] = attrs[name].slice();
      }
    });
    return out;
  };
  const hooks = {
    read: function (name) {
      counts.read += 1;
      return byName[name] ? pick(byName[name].attrs) : null;
    },
    write: function () {
      return true;
    },
    persons: function () {
      counts.persons += 1;
      return people.map(function (one) { return one.name; });
    }
  };
  if (withHoldingAny) {
    hooks.holdingAny = function (names) {
      counts.holdingAny += 1;
      return people.filter(function (one) {
        return names.some(function (name) {
          return (one.attrs[name] || []).length > 0;
        });
      }).map(function (one) {
        return { username: one.name, attributes: pick(one.attrs) };
      });
    };
  }
  log.debug("Leaving standInDirectory().");
  return hooks;
}

// THE OLD `holders()`, kept here as the reference the new one must agree
// with: every name, `recordFor()` each (which opens the private keys).
function oldHolders(register) {
  log.debug("Entering oldHolders().");
  const out = [];
  register.holdersNames().forEach(function (name) {
    const record = register.recordFor(name);
    if (!record || (!record.hasKeyPair && !record.issuers.length &&
                    !record.hasSamlKeyPair && !record.samlIssuers.length)) {
      return;
    }
    out.push({ username: record.username,
               hasKeyPair: record.hasKeyPair,
               declaredIssuers: record.issuers.slice(),
               issuers: record.effectiveIssuers.slice(),
               declared: record.issuers.length > 0,
               kid: record.stsAssertionKid,
               expiresAt: record.stsAssertionExpiresAt,
               source: record.stsAssertionKeySource ||
                       (record.hasKeyPair ? 'issued' : ''),
               certificatePem: record.stsAssertionCertificate,
               saml: { hasKeyPair: record.hasSamlKeyPair,
                       declaredIssuers: record.samlIssuers.slice(),
                       issuers: record.samlEffectiveIssuers.slice(),
                       declared: record.samlIssuers.length > 0,
                       thumbprint: record.stsSamlAssertionThumbprint,
                       expiresAt: record.stsSamlAssertionExpiresAt,
                       source: record.stsSamlAssertionKeySource ||
                               (record.hasSamlKeyPair ? 'issued' : ''),
                       certificatePem: record.stsSamlAssertionCertificate } });
  });
  log.debug("Leaving oldHolders().");
  return out;
}

async function claimA(t) {
  log.debug("Entering claimA().");
  t.log.info('=== A. holders(): one walk, no read per person, no unseal ===');
  const people = standInPeople();
  const counts = { read: 0, persons: 0, holdingAny: 0 };
  const fresh = freshPersonAssertions();
  t.check(fresh !== personAssertions, 'a fresh copy of the register, so the ' +
          'real one keeps the real directory');
  fresh.setDirectory(standInDirectory(people, counts, true));
  fresh.holdersNames = function () {
    return people.map(function (one) { return one.name; });
  };
  const opened = await counting(keystore, 'open', async function () {
    const began = process.hrtime.bigint();
    const rows = fresh.holders();
    t.log.info('holders() after: ' + elapsed(began) + ' over ' + POPULATION +
               ' people, ' + rows.length + ' holder(s)');
    return rows;
  });
  const rows = opened.result;
  t.equal(counts.read, 0, 'holders() made NO read per person');
  t.equal(counts.holdingAny, 1, 'it asked the directory once, for holders');
  t.equal(counts.persons, 0, 'and never listed the realm\'s names');
  t.equal(opened.calls, 0, 'and opened NO private key');
  t.check(rows.length > 0 && rows.length < POPULATION / 10,
          'the answer is the holders, not the population', rows.length);

  counts.read = 0;
  const reference = await counting(keystore, 'open', async function () {
    const began = process.hrtime.bigint();
    const out = oldHolders(fresh);
    t.log.info('holders() before (a read and an unseal per person): ' +
               elapsed(began));
    return out;
  });
  t.log.info('before: ' + counts.read + ' read(s) and ' + reference.calls +
             ' keystore.open() call(s); after: 0 and 0');
  t.check(counts.read === POPULATION && reference.calls > 0,
          'the old shape read every person and opened the sealed keys',
          counts.read + ' reads, ' + reference.calls + ' opens');
  t.check(JSON.stringify(rows) ===
          JSON.stringify(reference.result),
          'and the answer is the same rows, in the same order, member for ' +
          'member');
  t.check(JSON.stringify(rows).indexOf('$aesgcm$') < 0,
          'no private key, sealed or open, is in the answer');

  // A directory with no `holdingAny()` is walked the old way, still with no
  // unseal, and answers the same.
  const older = { read: 0, persons: 0, holdingAny: 0 };
  fresh.setDirectory(standInDirectory(people, older, false));
  const fallback = await counting(keystore, 'open', function () {
    return fresh.holders();
  });
  t.check(JSON.stringify(fallback.result) ===
          JSON.stringify(rows),
          'an older directory with no holdingAny() gives the same answer');
  t.equal(fallback.calls, 0, 'and opens no private key either');
  log.debug("Leaving claimA().");
}

// ---------------------------------------------------------------------------
// B and C: THE REAL DIRECTORY, in a throwaway realm.
// ---------------------------------------------------------------------------
function inRealm(fn) {
  log.debug("Entering inRealm().");
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(REALM), fn);
}

// THE PAGE AS THE STATIC CONSOLE DRAWS IT (#446): its `/admin-api`
// operation's answer, drawn by its renderer (`tests/tools/console_page.js`),
// where it was the console route's handler until the cutover.
const drawer = require('./tools/console_page.js')
  .consolePage(__dirname + '/..');

async function drawPage(query) {
  log.debug("Entering drawPage().");
  const drawn = await drawer.draw('/admin/pki', query);
  log.debug("Leaving drawPage(). " + drawn.html.length +
            " character(s).");
  return drawn.html;
}

// Writes an issued key pair to a person with the private half SEALED, as it
// is wherever the key-encryption key persists — the state the old register
// opened on every page view. The seal is a stand-in for the length of the
// write only.
function writeSealed(name, record, purpose) {
  log.debug("Entering writeSealed().");
  const persists = keystore.persists;
  const seal = keystore.seal;
  keystore.persists = function () {
    return true;
  };
  keystore.seal = function (plain) {
    return '$aesgcm$' + Buffer.from(String(plain)).toString('base64');
  };
  try {
    return personAssertions.write(name, record, { purpose: purpose });
  } finally {
    keystore.persists = persists;
    keystore.seal = seal;
    log.debug("Leaving writeSealed().");
  }
}

// The stand-in's open, for the measurement: it opens what the stand-in
// sealed, so the old reference can run, and it is COUNTED.
function standInOpen(value) {
  log.debug("Entering standInOpen().");
  const text = String(value || '');
  log.debug("Leaving standInOpen().");
  return text.indexOf('$aesgcm$') === 0
    ? Buffer.from(text.slice(8), 'base64').toString() : null;
}

async function seedRealm(t) {
  log.debug("Entering seedRealm().");
  await keystore.start();
  realms.create({ id: REALM, name: 'Certificate listing bounds' });
  if (!pki.hasChain()) {
    await pki.start({ realmIds: [''],
      keySetFor: function (id) {
        return helpers.stsKeysFor.of(id);
      },
      keySetHeldFor: function () {
        return false;
      } });
  }
  await pki.ensureScope(REALM);
  const began = process.hrtime.bigint();
  const names = [];
  inRealm(function () {
    for (let n = 0; n < POPULATION; n++) {
      const name = 'clb-' + RUN + '-' + String(n).padStart(5, '0');
      const made = ldap.createUser(name, { invent: false });
      if (made && made.ok) {
        names.push(name);
      }
    }
  });
  t.equal(names.length, POPULATION, POPULATION + ' people are created in ' +
          REALM);
  t.log.info('seeded ' + names.length + ' people in ' + elapsed(began));
  const holders = [];
  for (let i = 0; i < HOLDERS + SAML_HOLDERS; i++) {
    const name = names[(i * 61) % names.length];
    const purpose = i < HOLDERS ? 'jwt' : 'saml';
    const issued = await inRealm(function () {
      return pki.issueSigningKeyPair(undefined, {
        identifier: name, purpose: purpose, subjectKind: 'person',
        commonName: name, keyAlg: 'ec-p256', days: 30 });
    });
    if (!issued.ok) {
      t.check(false, 'a key pair is issued to ' + name,
              (issued.errors || []).join(' '));
      continue;
    }
    const written = inRealm(function () {
      return writeSealed(name, issued.issued, purpose);
    });
    if (written.ok) {
      holders.push(name);
    }
  }
  t.equal(holders.length, HOLDERS + SAML_HOLDERS,
          'and ' + holders.length + ' of them hold a key pair, SEALED');
  log.debug("Leaving seedRealm().");
  return names;
}

async function claimB(t) {
  log.debug("Entering claimB().");
  t.log.info('=== B. /admin/pki reads the drawn rows\' certificates only ===');
  const originalOpen = keystore.open;
  let opens = 0;
  keystore.open = function (value) {
    opens += 1;
    return standInOpen(value);
  };
  let page;
  let json;
  let pqcCalls;
  let reference;
  try {
    // The reference: the old register's shape over the real directory, and
    // `pqc_support.of()` on every certificate, as `pkiJson()` built it.
    reference = await counting(keystore, 'open', function () {
      return inRealm(function () {
        const began = process.hrtime.bigint();
        const out = oldHolders({
          holdersNames: function () {
            return ldap.allPersons().map(function (entry) {
              return ldap.usernameOfEntry(entry);
            }).filter(Boolean);
          },
          recordFor: personAssertions.recordFor
        }).map(function (one) {
          return Object.assign({}, one, {
            pqc: pqcSupport.of({ certificatePem: one.certificatePem }),
            saml: Object.assign({}, one.saml, {
              pqc: pqcSupport.of({ certificatePem: one.saml.certificatePem }) })
          });
        });
        t.log.info('/admin/pki people, before (a read per person, an unseal ' +
                   'and a parse per holder): ' + elapsed(began));
        return out;
      });
    });
    t.check(reference.calls >= HOLDERS + SAML_HOLDERS,
            'before: the old register opened ' + reference.calls +
            ' sealed private key(s) to list ' + reference.result.length +
            ' holder(s)');
    opens = 0;
    certificateViews.forgetFacts();
    const drawn = await counting(certificateViews, 'pqcOf', function () {
      return inRealm(async function () {
        const began = process.hrtime.bigint();
        const body = await drawPage({});
        t.log.info('/admin/pki page, after: ' + elapsed(began));
        return body;
      });
    });
    page = drawn.result;
    pqcCalls = drawn.calls;
    t.equal(opens, 0, 'drawing /admin/pki opened NO private key');
    const whole = await counting(certificateViews, 'pqcOf', function () {
      return inRealm(function () {
        const began = process.hrtime.bigint();
        const out = pkiAdmin.pkiView({ query: {} });
        t.log.info('GET /admin-api/pki, after: ' + elapsed(began));
        return out;
      });
    });
    json = whole.result;
    t.equal(opens, 0, 'and neither did the JSON');
    const peopleShown = Math.min(PER, json.persons.length);
    const appsShown = Math.min(PER, json.issued.length);
    t.check(pqcCalls <= 2 * peopleShown + appsShown,
            'the page asked for ' + pqcCalls + ' certificate reading(s), for ' +
            'the rows it drew (at most ' + (2 * peopleShown + appsShown) +
            ') and not for the ' + json.persons.length + ' holder(s)');
    t.check(json.persons.length > PER,
            'there are more holders than one page', json.persons.length);
    t.equal(whole.calls, 2 * json.persons.length + json.issued.length,
            'the JSON reads every row\'s, because it carries every row');
    const before = missesOf('certificates.parsed-facts');
    inRealm(function () {
      return pkiAdmin.pkiView({ query: {} });
    });
    t.equal(missesOf('certificates.parsed-facts') - before, 0,
            'and a second JSON call parses nothing: each answer is held');
  } finally {
    keystore.open = originalOpen;
  }
  t.check(JSON.stringify(json.persons) ===
          JSON.stringify(reference.result),
          '`persons` is what the old register and pqc_support.of() gave, ' +
          'row for row and member for member');
  t.check(json.issued.every(function (row) {
    const keys = Object.keys(row);
    return keys[keys.length - 1] === 'pqc';
  }), 'every `issued` row still ends with `pqc`');
  t.check(page.indexOf('people holding one') >= 0 &&
          page.indexOf('/admin/users?user=clb-' + RUN) >= 0,
          'the page drew its People table');
  t.check(JSON.stringify(json).indexOf('$aesgcm$') < 0 &&
          JSON.stringify(json).indexOf('PRIVATE KEY') < 0,
          'no private key, sealed or open, is in the JSON');
  log.debug("Leaving claimB().");
}

async function claimC(t) {
  log.debug("Entering claimC().");
  t.log.info('=== C. /admin-api/certificates parses the page it answers ===');
  certificateViews.forgetFacts();
  const parses = await counting(pkijs.Certificate, 'fromBER', function () {
    return inRealm(function () {
      const began = process.hrtime.bigint();
      const out = certificateViews.listView({ query: { per: '10' } });
      t.log.info('certificates list, page of 10, after: ' + elapsed(began));
      return out;
    });
  });
  const list = parses.result;
  t.check(list.total > HOLDERS, 'the catalogue holds every holder\'s ' +
          'certificate (' + list.total + ')');
  t.equal(list.certificates.length, 10, 'the page holds ten');
  t.equal(certificateViews.factsHeld(), 10,
          'and exactly ten certificates were parsed for the list');
  t.log.info('certificates list: ' + parses.calls + ' pkijs parse(s) in all, ' +
             'the authority sources included, against ' + list.total +
             ' certificate(s)');

  // The reference, parsed from nothing with the old code's own steps.
  const x509 = require('../common/vendored/x509');
  const whole = inRealm(function () {
    return certificateViews.listView({ query: { per: '100000' } });
  });
  const pemOf = {};
  inRealm(function () {
    personAssertions.holders().forEach(function (one) {
      [one.certificatePem, one.saml.certificatePem].forEach(function (pem) {
        if (pem) {
          const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '')
            .replace(/\s+/g, ''), 'base64');
          pemOf[nodeCrypto.createHash('sha256').update(der)
            .digest('hex')] = pem;
        }
      });
    });
  });
  let checked = 0;
  const agrees = whole.certificates.every(function (row) {
    const pem = pemOf[row.fingerprint];
    if (!pem) {
      return true;
    }
    checked += 1;
    const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
    const cert = pkijs.Certificate.fromBER(new Uint8Array(der));
    return row.subject === x509.dnToString(cert.subject) &&
           row.issuer === x509.dnToString(cert.issuer) &&
           row.notAfter === cert.notAfter.value.toISOString() &&
           row.selfIssued === (row.subject === row.issuer);
  });
  t.check(agrees && checked === HOLDERS + SAML_HOLDERS,
          'every holder row\'s subject, issuer and notAfter are the ones a ' +
          'fresh parse reads (' + checked + ' checked)');
  t.check(JSON.stringify(list.certificates) ===
          JSON.stringify(whole.certificates.slice(0, 10)),
          'and page one is the first ten of the whole list, in its order');

  // A filter: the labels first, then a parse — once per certificate.
  certificateViews.forgetFacts();
  const byLabel = inRealm(function () {
    return certificateViews.listView({ query: { q: 'RFC 7522', per: '5' } });
  });
  t.equal(byLabel.matched, SAML_HOLDERS,
          'a filter on where a certificate appears matches the SAML holders');
  // Every certificate the labels do not match has to be read to be ruled
  // out; the ones they match are parsed only if they are on the page.
  t.equal(certificateViews.factsHeld(),
          byLabel.total - SAML_HOLDERS + Math.min(5, SAML_HOLDERS),
          'and parsed the certificates the labels could not decide, plus the ' +
          'page — never a label match that is off the page');
  certificateViews.forgetFacts();
  const bySubject = inRealm(function () {
    return certificateViews.listView({ query: { q: 'CN=clb-' + RUN,
                                                per: '5' } });
  });
  const firstPass = certificateViews.factsHeld();
  const misses = missesOf('certificates.parsed-facts');
  const again = inRealm(function () {
    return certificateViews.listView({ query: { q: 'CN=clb-' + RUN,
                                                per: '5' } });
  });
  t.check(bySubject.matched >= HOLDERS && firstPass <= whole.total,
          'a filter on the subject finds the holders (' + bySubject.matched +
          '), parsing each certificate at most once (' + firstPass + ')');
  t.equal(missesOf('certificates.parsed-facts') - misses, 0,
          'and asking again parses nothing');
  t.check(JSON.stringify(again) ===
          JSON.stringify(bySubject),
          'with the same answer');
  const reference = whole.certificates.filter(function (row) {
    const hay = (row.subject + ' ' + row.issuer + ' ' +
                 row.appearances.map(function (a) { return a.label; })
                   .join(' ')).toLowerCase();
    return hay.indexOf(('CN=clb-' + RUN).toLowerCase()) >= 0;
  });
  t.check(JSON.stringify(bySubject.certificates) ===
          JSON.stringify(reference.slice(0, 5)),
          'which is the old filter\'s answer over the whole list');

  // The details lookup of a HOLDER's certificate: the miss path, which reads
  // the holders; it must not parse every certificate on the way.
  const target = whole.certificates.filter(function (row) {
    return !!pemOf[row.fingerprint];
  })[3];
  // Every parse is looked at: the chain is built over the AUTHORITIES, so a
  // parse of any OTHER holder's certificate would be the per-holder work.
  const others = new Set(Object.keys(pemOf).filter(function (fp) {
    return fp !== target.fingerprint;
  }));
  let holderParses = 0;
  const fromBER = pkijs.Certificate.fromBER;
  pkijs.Certificate.fromBER = function (bytes) {
    try {
      const fp = nodeCrypto.createHash('sha256')
        .update(Buffer.from(bytes)).digest('hex');
      if (others.has(fp)) {
        holderParses += 1;
      }
    } catch (e) {
      log.debug("Caught in the parse spy: " + ((e && e.message) || e));
    }
    return fromBER.apply(this, arguments);
  };
  let detail;
  try {
    detail = await counting(pkijs.Certificate, 'fromBER', function () {
      return inRealm(function () {
        return certificateViews.detailsView(null, target.fingerprint);
      });
    });
  } finally {
    pkijs.Certificate.fromBER = fromBER;
  }
  t.check(detail.result.ok && detail.result.appearances.some(function (a) {
    return a.where === 'persons';
  }), 'a holder\'s certificate opens by fingerprint');
  t.equal(holderParses, 0,
          'and the lookup parsed none of the other ' + others.size +
          ' holders\' certificates (' + detail.calls + ' parse(s) in all, ' +
          'the chain over the authorities) — they are fingerprinted, not ' +
          'parsed');
  log.debug("Leaving claimC().");
}

// ---------------------------------------------------------------------------
// D. ENROLLMENT, on an instance of its own over a stand-in directory.
// ---------------------------------------------------------------------------
const FAMILIES = ['acme', 'est', 'scep'];

function enrollmentRecord(n, family, nowMs) {
  log.debug("Entering enrollmentRecord().");
  log.debug("Leaving enrollmentRecord().");
  const revoked = n % 11 === 0;
  const expired = !revoked && n % 7 === 0;
  return JSON.stringify({
    family: family, serialHex: (1000 + n).toString(16),
    profile: 'digital-signature', subject: 'CN=holder-' + n, names: [],
    keyAlg: 'ec-p256',
    notBefore: new Date(nowMs - 86400000).toISOString(),
    notAfter: new Date(nowMs + (expired ? -3600000 : 86400000 * 30))
      .toISOString(),
    issuedAt: new Date(nowMs - n * 1000).toISOString(),
    revoked: revoked ? { at: new Date(nowMs).toISOString(),
                         reason: 'keyCompromise' } : null,
    certificatePem: '-----BEGIN CERTIFICATE-----\nAAAA\n' +
                    '-----END CERTIFICATE-----\n' });
}

// ONE instant for both directories, so the old walk and the new one are
// handed byte-identical records.
const ENROLLMENT_NOW = Date.now();

function enrollmentDirectory(counts, withValues) {
  log.debug("Entering enrollmentDirectory().");
  const A = certEnrollment.ATTRIBUTES;
  const nowMs = ENROLLMENT_NOW;
  const entries = { person: {}, application: {} };
  let serial = 0;
  for (let n = 0; n < POPULATION; n++) {
    entries.person['en-' + n] = {};
  }
  for (let n = 0; n < 50; n++) {
    entries.application['app-' + n] = {};
  }
  // Three hundred certificates on a hundred and twenty holders, the three
  // families mixed on one entry as they are in a realm.
  for (let n = 0; n < 300; n++) {
    const kind = n % 6 === 0 ? 'application' : 'person';
    const id = kind === 'person' ? 'en-' + ((n * 37) % 100)
                                 : 'app-' + (n % 20);
    const name = A[kind].certificate;
    const attrs = entries[kind][id];
    attrs[name] = (attrs[name] || []).concat([
      enrollmentRecord(serial++, FAMILIES[n % 3], nowMs)]);
  }
  // Two hand-written values the family test must not lose: whitespace, and
  // an escaped family name.
  entries.person['en-1'][A.person.certificate].push(
    '{ "family" : "scep", "serialHex": "ff01", "issuedAt": "2026-01-01T00:00' +
    ':00.000Z", "notAfter": "2099-01-01T00:00:00.000Z" }');
  entries.person['en-2'][A.person.certificate] =
    (entries.person['en-2'][A.person.certificate] || []).concat([
      '{"family":"sc\\u0065p","serialHex":"ff02","issuedAt":"2026-01-02T00:' +
      '00:00.000Z","notAfter":"2099-01-01T00:00:00.000Z"}']);
  for (let n = 0; n < 40; n++) {
    entries.person['en-' + (n * 3)][A.person.eab] = [JSON.stringify({
      kid: 'kid-' + n, createdAt: new Date(nowMs - n * 1000).toISOString(),
      expiresAt: new Date(nowMs + 3600000).toISOString(), createdBy: 'test',
      boundAccount: n % 2 ? 'thumb-' + n : null })];
    entries.person['en-' + (n * 5)][A.person.challenge] = [JSON.stringify({
      id: 'ch-' + n, profile: 'digital-signature',
      createdAt: new Date(nowMs - n * 1000).toISOString(),
      expiresAt: new Date(nowMs + 3600000).toISOString() })];
    entries.person['en-' + (n * 7)][A.person.hostName] =
      ['h' + n + '.example.test', 'NOT A HOST'];
  }
  const holdersOf = function (kind, name) {
    return Object.keys(entries[kind]).filter(function (id) {
      return (entries[kind][id][name] || []).length > 0;
    });
  };
  const directory = {
    read: function (kind, id, names) {
      counts.read += 1;
      const attrs = entries[kind] && entries[kind][id];
      if (!attrs) {
        return null;
      }
      const out = {};
      (names || []).forEach(function (name) {
        if (attrs[name] && attrs[name].length) {
          out[name] = attrs[name].slice();
        }
      });
      return { dn: 'uid=' + id, attributes: out };
    },
    write: function () {
      return true;
    },
    holders: function (kind, name) {
      counts.holders += 1;
      return holdersOf(kind, name);
    }
  };
  if (withValues) {
    directory.holdersWithValues = function (kind, name) {
      counts.holdersWithValues += 1;
      return holdersOf(kind, name).map(function (id) {
        return { id: id, values: entries[kind][id][name].slice() };
      });
    };
  }
  log.debug("Leaving enrollmentDirectory().");
  return directory;
}

function enrollmentInstance(counts, withValues) {
  log.debug("Entering enrollmentInstance().");
  const Core = certEnrollment.CertEnrollment;
  const core = new Core(Core.defaultDeps());
  core.setDirectory(enrollmentDirectory(counts, withValues));
  const parse = core.parseJsonValues;
  core.parseJsonValues = function (values) {
    counts.parsed += (values || []).length;
    return parse.call(core, values);
  };
  log.debug("Leaving enrollmentInstance().");
  return core;
}

// THE OLD LISTING, as the reference: every holder, a read each, every
// record parsed, filtered after.
function oldCertificates(core, family) {
  log.debug("Entering oldCertificates().");
  const out = [];
  core.holdersOf('certificate').forEach(function (entry) {
    core.enrolledOf(entry).forEach(function (record) {
      if (!family || record.family === family) {
        out.push(Object.assign({ entry: entry,
                                 entryUri: core.entryUri(entry) }, record));
      }
    });
  });
  log.debug("Leaving oldCertificates().");
  return out.sort(function (a, b) {
    return String(b.issuedAt).localeCompare(String(a.issuedAt));
  });
}

function fresh() {
  log.debug("Entering fresh().");
  log.debug("Leaving fresh().");
  return { read: 0, holders: 0, holdersWithValues: 0, parsed: 0 };
}

async function claimD(t) {
  log.debug("Entering claimD().");
  t.log.info('=== D. enrollment: one walk, the family before the parse ===');
  const oldCounts = fresh();
  const oldCore = enrollmentInstance(oldCounts, false);
  const newCounts = fresh();
  const newCore = enrollmentInstance(newCounts, true);
  const holders = oldCore.holdersOf('certificate').length;
  oldCounts.read = 0;
  oldCounts.parsed = 0;
  for (const family of FAMILIES.concat([undefined])) {
    oldCounts.read = 0;
    oldCounts.parsed = 0;
    newCounts.read = 0;
    newCounts.parsed = 0;
    let began = process.hrtime.bigint();
    const before = oldCertificates(oldCore, family);
    const beforeTime = elapsed(began);
    began = process.hrtime.bigint();
    const after = newCore.certificatesInRealm(family);
    t.log.info('certificatesInRealm(' + (family || 'all') + '): before ' +
               oldCounts.read + ' read(s), ' + oldCounts.parsed +
               ' parse(s), ' + beforeTime + '; after ' + newCounts.read +
               ' read(s), ' + newCounts.parsed + ' parse(s), ' +
               elapsed(began));
    t.check(JSON.stringify(after) ===
          JSON.stringify(before),
            'certificatesInRealm(' + (family || '') + ') is the old answer, ' +
            'row for row (' + after.length + ')');
    t.equal(newCounts.read, 0, 'with no read per holder (the old: ' +
            oldCounts.read + ')');
    if (family) {
      // The one value spelling its family with a `\u` escape is parsed for
      // every family asked about: that is the test declining to decide.
      t.check(newCounts.parsed <= after.length + 1 &&
              newCounts.parsed < oldCounts.parsed,
              'and it parsed ' + family + '\'s records only (and the one ' +
              'escaped value) — ' + newCounts.parsed + ' against the old ' +
              oldCounts.parsed);
      const counts = newCore.certificateCountsInRealm(family);
      t.equal(JSON.stringify(counts), JSON.stringify({
        held: before.length,
        valid: before.filter(function (one) {
          return one.status === 'valid';
        }).length,
        revoked: before.filter(function (one) {
          return one.status === 'revoked';
        }).length,
        expired: before.filter(function (one) {
          return one.status === 'expired';
        }).length }), 'the counts are the old list\'s, state by state ' +
        JSON.stringify(counts));
    }
  }
  t.check(holders > 100, 'over ' + holders + ' holders among ' + POPULATION +
          ' people');
  const scep = newCore.certificatesInRealm('scep').map(function (one) {
    return one.serialHex;
  });
  t.check(scep.indexOf('ff01') >= 0 && scep.indexOf('ff02') >= 0,
          'a record written with spaces, and one with an escaped family ' +
          'name, are still SCEP\'s');

  ['eabsInRealm', 'challengesInRealm', 'hostNamesInRealm']
    .forEach(function (name) {
      oldCounts.read = 0;
      newCounts.read = 0;
      const after = newCore[name]();
      // The old walk: the same function over a directory without the
      // values, which falls back to a read per holder.
      const before = oldCore[name]();
      t.check(JSON.stringify(after) ===
          JSON.stringify(before),
              name + '() is the answer the read-per-holder walk gives (' +
              after.length + ')');
      t.check(newCounts.read === 0 && oldCounts.read > 0,
              'with no read per holder (the old: ' + oldCounts.read + ')');
    });

  // The consoles, over this instance.
  const acme = require('../acme/acme_console');
  const est = require('../est/est_console');
  const scepConsole = require('../scep/scep_console');
  const acmeStore = require('../acme/acme_store');
  const accounts = [];
  for (let n = 0; n < 300; n++) {
    accounts.push({ id: 'acct-' + n, status: 'valid',
                    entry: { kind: 'person', id: 'en-' + n },
                    thumbprint: 'thumb-' + n, contact: [], orderIds: [],
                    createdAt: new Date(Date.now() - n * 1000).toISOString() });
  }
  const lookups = { bySerial: 0, byThumbprint: 0 };
  const store = Object.assign({}, acmeStore, {
    listAccounts: function () {
      return accounts.slice();
    },
    certificateBySerial: function () {
      lookups.bySerial += 1;
      return null;
    },
    accountByThumbprint: function (thumb) {
      lookups.byThumbprint += 1;
      return accounts.filter(function (one) {
        return one.thumbprint === thumb;
      })[0] || null;
    }
  });
  // The console reads the core's TABLES off the module (PROFILE_IDS and
  // the rest), and its functions off the instance.
  const coreOf = function (instance) {
    const out = Object.create(instance);
    Object.keys(certEnrollment).forEach(function (key) {
      if (typeof certEnrollment[key] !== 'function') {
        out[key] = certEnrollment[key];
      }
    });
    return out;
  };
  const acmeView = new acme.AcmeConsole(Object.assign(
    acme.AcmeConsole.defaultDeps(), { core: coreOf(newCore), store: store }));
  const req = { query: { per: '10' }, headers: { host: 'sts.example.test' },
                protocol: 'https', get: function () {
                  return 'sts.example.test';
                } };
  const view = acmeView.acmeView(req);
  t.equal(view.certificates.rows.length, 10, 'ACME draws ten certificates');
  t.equal(lookups.bySerial, 10, 'and looked ten up in its store, not ' +
          view.certificates.paging.total);
  t.equal(lookups.byThumbprint, view.eabKeys.rows.filter(function (one) {
    return one.boundAccount;
  }).length, 'an account lookup per EAB key SHOWN and bound (' +
    lookups.byThumbprint + '), not per key in the realm (' +
    view.eabKeys.paging.total + ')');
  t.equal(view.accounts.rows.length, 10, 'ten accounts of ' +
          view.accounts.paging.total);
  t.equal(view.certificates.paging.total,
          newCore.certificatesInRealm('acme').length,
          'and the paging counts the whole list');

  const spied = function (core) {
    const tally = { listed: 0 };
    const listed = coreOf(core);
    listed.certificatesInRealm = function () {
      tally.listed += 1;
      return core.certificatesInRealm.apply(core, arguments);
    };
    return { core: listed, tally: tally };
  };
  const s1 = spied(newCore);
  const acmeMonitor = new acme.AcmeConsole(Object.assign(
    acme.AcmeConsole.defaultDeps(), { core: s1.core, store: store }));
  const am = acmeMonitor.acmeMonitorView({ query: {} });
  t.equal(am.totals.certificatesHeld,
          newCore.certificatesInRealm('acme').length,
          'the ACME monitor\'s tile is the list\'s length');
  const s2 = spied(newCore);
  const estMonitor = new est.EstConsole(Object.assign(
    est.EstConsole.defaultDeps(), { core: s2.core }));
  const em = estMonitor.estMonitorView({ query: {} });
  const estList = newCore.certificatesInRealm('est');
  t.equal(JSON.stringify(em.certificates), JSON.stringify({
    held: estList.length,
    valid: estList.filter(function (one) {
      return one.status === 'valid';
    }).length,
    revoked: estList.filter(function (one) {
      return one.status === 'revoked';
    }).length,
    expired: estList.filter(function (one) {
      return one.status === 'expired';
    }).length }), 'the EST monitor\'s four tiles are the list\'s counts');
  const s3 = spied(newCore);
  const scepMonitor = new scepConsole.ScepConsole(Object.assign(
    scepConsole.ScepConsole.defaultDeps(), { core: s3.core }));
  const sm = scepMonitor.scepMonitorView({ query: {} });
  t.equal(sm.issuedCertificates, newCore.certificatesInRealm('scep').length,
          'the SCEP monitor\'s tile is the list\'s length');
  t.equal(s1.tally.listed + s2.tally.listed + s3.tally.listed, 0,
          'and none of the three monitors built the list to count it');
  log.debug("Leaving claimD().");
}

// ---------------------------------------------------------------------------
// E. THE GNAP MONITOR, over a stand-in store.
// ---------------------------------------------------------------------------
async function claimE(t) {
  log.debug("Entering claimE().");
  t.log.info('=== E. the GNAP monitor reads the store once ===');
  const gnapConsole = require('../gnap/gnap_console');
  const realGrants = require('../gnap/gnap_grants');
  const APPS = 200;
  const now = 1800000000;
  const apps = [];
  for (let n = 0; n < APPS; n++) {
    apps.push({ identifier: 'gapp-' + String(n).padStart(3, '0'),
                name: 'App ' + n, kinds: n % 3 ? ['gnap-client'] :
                  ['gnap-client', 'gnap-resource-server'],
                registered: true, fields: {} });
  }
  const grantRows = [];
  const tokenRows = [];
  const states = ['pending', 'approved', 'finalized'];
  for (let n = 0; n < 3000; n++) {
    grantRows.push({ id: 'g' + n, state: states[n % 3],
                     client: n % 17 === 0 ? null
                       : { identifier: apps[(n * 13) % APPS].identifier } });
    tokenRows.push({ instanceId: apps[(n * 7) % APPS].identifier,
                     revoked: n % 5 === 0, exp: n % 4 === 0 ? now - 10
                       : (n % 9 === 0 ? 0 : now + 100) });
  }
  const calls = { grants: 0, tokens: 0 };
  const store = {
    listGrants: function () {
      calls.grants += 1;
      return grantRows.slice();
    },
    listTokens: function () {
      calls.tokens += 1;
      return tokenRows.slice();
    }
  };
  const grants = Object.assign({}, realGrants, {
    gnapApplications: function () {
      return apps.slice();
    },
    fieldValues: function () {
      return [];
    },
    KIND_RS: 'gnap-resource-server', KIND_CLIENT: 'gnap-client'
  });
  const monitor = {
    snapshot: function () {
      return { startedAt: 'then', events: [], formats: [], rows: {},
               blank: { lastAt: null, lastEvent: null } };
    }
  };
  const view = new gnapConsole.GnapConsole(Object.assign(
    gnapConsole.GnapConsole.defaultDeps(), {
      store: store, grants: grants, monitor: monitor,
      nowSec: function () {
        return now;
      } }));
  const began = process.hrtime.bigint();
  const json = view.gnapMonitorView({ query: { per: '500' } });
  t.log.info('GNAP monitor over ' + APPS + ' applications and ' +
             grantRows.length + ' grants, after: ' + elapsed(began));
  t.equal(calls.grants, 1, 'listGrants() once, not once per application ' +
          '(the old: ' + APPS + ')');
  t.equal(calls.tokens, 1, 'listTokens() once');
  let same = json.rows.length === APPS;
  json.rows.forEach(function (row) {
    const mine = grantRows.filter(function (grant) {
      return grant.client && grant.client.identifier === row.identifier;
    });
    const active = tokenRows.filter(function (record) {
      return record.instanceId === row.identifier && !record.revoked &&
             (!record.exp || record.exp > now);
    }).length;
    const expected = { total: mine.length,
      pending: mine.filter(function (g) {
        return g.state === 'pending';
      }).length,
      approved: mine.filter(function (g) {
        return g.state === 'approved';
      }).length,
      finalized: mine.filter(function (g) {
        return g.state === 'finalized';
      }).length };
    if (JSON.stringify(row.grantsHeld) !== JSON.stringify(expected) ||
        row.activeTokens !== active) {
      same = false;
    }
  });
  t.check(same, 'every row\'s grants and live tokens are the old ' +
          'per-application filters\' answers');
  log.debug("Leaving claimE().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await claimA(t);
    await seedRealm(t);
    await claimB(t);
    await claimC(t);
    await claimD(t);
    await claimE(t);
  } finally {
    certificateViews.forgetFacts();
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'certificate_listing_bounds',
  describe: '#352: the certificate lists — /admin/pki, /admin-api/' +
            'certificates, the ACME, EST and SCEP consoles and monitors and ' +
            'the GNAP monitor — do per-row work for the rows they show, ' +
            'read holders in one walk and unseal nothing, and answer what ' +
            'they answered before.',
  run: run
};
