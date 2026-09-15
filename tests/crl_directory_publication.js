'use strict';
//
// File: crl_directory_publication.js
//
// ===========================================================================
// THE DIRECTORY COPY OF EVERY CRL: WHERE IT IS WRITTEN, WHO MAY READ IT, AND
// UNDER WHICH NAME (2026-09-13).
//
// **WHY THIS IS IN PROCESS**, which is `tests/CLAUDE.md`'s question.
// `tests/vendored/sts_pki_distribution_points.js` follows every `ldap://`
// distribution point over the socket, and two mutants of what this file
// guards SURVIVED it. Both for a reason no socket-side job can get around:
//
//   * **A LIST PUBLISHED WITH NO REALM AMBIENT.** `publishCrl()` writes through
//     `putEntry()`, which writes the AMBIENT realm's store — and the startup
//     pass and the refresh timer run in no request at all. Over HTTP the only
//     publications a job can cause are inside a request, and a deferred publish
//     inherits that request's realm through AsyncLocalStorage, so every one
//     lands in the right store by accident. The broken path is a realm that
//     existed at STARTUP, or the timer thirty minutes in. Here it is one call.
//   * **PRODUCT MODE.** An anonymous base search of a CRL entry is allowed in
//     product mode where every other unbound read is refused, and the suite
//     runs every stack in development mode, where no read needs a bind — so
//     neither the exemption nor its NARROWNESS is visible on the wire.
//     `global.mode` is a runtime override here.
//
// And two more that are cheap here and awkward there: that no two authorities
// in the process share a CRL DN (the process branch and the default realm did),
// and that RFC 4522's binary transfer option names ONE attribute whichever way a
// request or a filter spells it.
//
// Mutation-tested against nine: `publishCrl()` without `inRealmOf()` (5
// assertions red), the process branch's `ou=process` removed from `crlDn()`
// (2), the product-mode exemption widened to any base search (1) and to any
// scope (1), the exemption removed (1), `toSearchEntry()` matching the
// `;binary` spelling only (2), the filter alias removed (1), and the refresh
// timer never armed (1). One more was EQUIVALENT and is recorded rather than
// counted: dropping only the `ou=crl` path test leaves the objectClass test
// guarding exactly the same entries.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const keystore = require('../common/keystore');
const helpers = require('../common/helpers');
const pki = require('../common/pki');
const revocation = require('../common/pki_revocation');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({
  name: 'crl_directory_publication',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'crlpub-' + Date.now().toString(36);

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function search(base, scope, attributes, filter) {
  log.debug("Entering search().");
  log.debug("Leaving search().");
  return ldap.performOperation('search', {
    dn: base, boundDn: '', channel: 'ldap', scope: scope,
    filter: filter || '(objectclass=*)', attributes: attributes || [],
    sizeLimit: 0
  });
}

// The DN inside an `ldap://` distribution point, decoded.
function dnOf(url) {
  log.debug("Entering dnOf().");
  const m = /^ldap:\/\/[^/]*\/([^?]*)\?/.exec(url);
  log.debug("Leaving dnOf().");
  return m ? decodeURIComponent(m[1]) : '';
}

// The CRL bytes an entry came back with, off any spelling of the attribute.
function crlBytesOf(entry) {
  log.debug("Entering crlBytesOf().");
  const attribute = ((entry && entry.attributes) || []).filter(function (one) {
    return /^certificateRevocationList(;binary)?$/i.test(one.type);
  })[0];
  log.debug("Leaving crlBytesOf().");
  return attribute && attribute.values.length
    ? Buffer.from(attribute.values[0], 'base64') : null;
}

// Whether DER bytes are a CRL whose issuer is `authority`'s subject.
function isCrlOf(der, authority) {
  log.debug("Entering isCrlOf().");
  if (!der || der[0] !== 0x30) {
    log.debug("Leaving isCrlOf(). Not DER.");
    return false;
  }
  const x509 = new (require('crypto').X509Certificate)(
    authority.tier.certificatePem);
  // The authority's subject Name, as bytes, inside the list. Two authorities
  // here never share a subject — the process branch's is "(Process)" and a
  // realm's names the realm — so a list carrying another issuer's name is a
  // list that does not carry this one. `sts_pki_distribution_points.js` makes
  // the exact section 6.3.3 comparison and verifies the signature.
  log.debug("Leaving isCrlOf().");
  return der.includes(subjectDerOf(x509.raw));
}

// The DER of a certificate's subject Name, read by walking the TLV structure
// the few levels it takes.
function subjectDerOf(certDer) {
  log.debug("Entering subjectDerOf().");
  function tlv(buf, pos) {
    let len = buf[pos + 1];
    let hdr = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) {
        len = len * 256 + buf[pos + 2 + i];
      }
      hdr = 2 + n;
    }
    return { start: pos, body: pos + hdr, end: pos + hdr + len };
  }
  const cert = tlv(certDer, 0);
  const tbs = tlv(certDer, cert.body);
  let p = tbs.body;
  const fields = [];
  while (p < tbs.end && fields.length < 6) {
    const one = tlv(certDer, p);
    fields.push(one);
    p = one.end;
  }
  const offset = certDer[fields[0].start] === 0xa0 ? 1 : 0;
  const subject = fields[offset + 4];
  log.debug("Leaving subjectDerOf().");
  return certDer.subarray(subject.start, subject.end);
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY THIS FILE FINDS IS THE ONE IT LEAVES. `run.js`
// runs every file in ONE process, and `pki.start()` here builds a service Root
// and the default realm's branch — which `tests/pki.js` then meets when it asks
// for a Root of its own, so its "the Root carries the organisation it was
// asked for" failed in the suite and passed alone. Whatever was absent on the
// way in is removed on the way out; what was already there is left exactly as
// it was. The same pair `tests/person_credentials.js` and
// `tests/application_credentials.js` carry.
// ---------------------------------------------------------------------------
function heldAuthority(pki, keystore) {
  log.debug("Entering heldAuthority().");
  log.debug("Leaving heldAuthority().");
  return { root: !!keystore.pkiFor(pki.SERVICE_SCOPE),
           chain: pki.hasChain() };
}

function restoreAuthority(pki, keystore, before) {
  log.debug("Entering restoreAuthority().");
  if (!before.chain && pki.hasChain()) {
    pki.clearChain(undefined);
  }
  if (!before.root && keystore.pkiFor(pki.SERVICE_SCOPE)) {
    keystore.attachPki(pki.SERVICE_SCOPE, null);
  }
  log.debug("Leaving restoreAuthority().");
}

async function run(t) {
  log.debug("Entering run().");
  const before = heldAuthority(pki, keystore);
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + REALM + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    await keystore.start();
    const started = await pki.start({
      realmIds: ['', REALM],
      keySetFor: function (id) {
        log.debug("Entering keySetFor().");
        log.debug("Leaving keySetFor().");
        return helpers.stsKeysFor.of(id);
      }
    });
    t.check(started.ok, 'the hierarchy is built for the default realm and ' +
            REALM, JSON.stringify(started.errors || []));
    await pki.ensureScope(REALM);

    const all = revocation.authorities(pki.knownScopes());
    const mine = all.filter(function (one) {
      return String(one.scope) === REALM || one.scope === pki.PROCESS_SCOPE;
    });
    t.check(mine.some(function (one) {
              return String(one.scope) === REALM;
            }) && mine.some(function (one) {
              return one.scope === pki.PROCESS_SCOPE;
            }),
            'there are authorities in the new realm and in the process branch',
            all.map(function (one) {
              return revocation.scopeSegment(one.scope) + '/' + one.ca;
            }).join(' '));

    t.log.info('=== A. one DN per authority, and it is the DN the ' +
               'certificates name ===');

    const seen = new Map();
    const clashes = [];
    all.forEach(function (one) {
      const points = revocation.distributionPoints(one.scope, one.ca);
      const key = points.dn.toLowerCase();
      const label = revocation.scopeSegment(one.scope) + '/' + one.ca;
      if (seen.has(key)) {
        clashes.push(label + ' and ' + seen.get(key) + ' share ' + points.dn);
      }
      seen.set(key, label);
      if (dnOf(points.ldap).toLowerCase() !== key) {
        clashes.push(label + ': its ldap:// URL names ' + dnOf(points.ldap) +
                     ' where crlDn() says ' + points.dn);
      }
    });
    t.equal(clashes.join('; '), '',
            'no two authorities publish their CRLs to one directory entry — ' +
            'the process branch\'s Intermediate and the default realm\'s did, ' +
            'so an LDAP fetch of one list returned the other issuer\'s');

    t.log.info('=== B. published with NO realm ambient, found in the realm ' +
               'the DN names ===');

    // This call is the startup pass and the refresh timer: no request, no
    // realm. Everything below it reads each list back the way the socket does,
    // in the realm the DN names.
    const published = await revocation.publishAll(pki.knownScopes());
    t.check(published >= all.length,
            'publishAll() wrote a list for every authority (' + published +
            ' of ' + all.length + ')');
    const missing = [];
    all.forEach(function (one) {
      const points = revocation.distributionPoints(one.scope, one.ca);
      const found = search(points.dn, 0,
                           ['certificateRevocationList;binary']);
      const bytes = found.ok && found.entries.length
        ? crlBytesOf(found.entries[0]) : null;
      if (!bytes || !isCrlOf(bytes, one)) {
        missing.push(revocation.scopeSegment(one.scope) + '/' + one.ca +
                     ' at ' + points.dn + ': ' +
                     (found.ok ? (bytes ? 'a CRL from another issuer'
                                        : 'no list') : found.errorName));
      }
    });
    t.equal(missing.join('; '), '',
            'EVERY authority\'s list — the new realm\'s included — is found at ' +
            'its own DN, signed by that authority. Written into whichever ' +
            'realm was ambient, a realm\'s entries landed in the default ' +
            'realm\'s store and its ldap:// distribution points answered ' +
            'noSuchObject');

    t.log.info('=== C. RFC 4522: the binary option names the same ' +
               'attribute ===');

    const realmJose = revocation.distributionPoints(REALM, 'jose');
    const plain = search(realmJose.dn, 0, ['certificateRevocationList']);
    t.check(plain.ok && plain.entries.length === 1 &&
            !!crlBytesOf(plain.entries[0]),
            'a request for `certificateRevocationList` WITHOUT `;binary` ' +
            'returns the list (RFC 4522 section 3 — the two descriptions ' +
            'reference exactly the same attribute)',
            JSON.stringify(plain.entries && plain.entries[0]));
    const returnedType = plain.ok && plain.entries.length
      ? (plain.entries[0].attributes.filter(function (a) {
        return /^certificateRevocationList/i.test(a.type);
      })[0] || {}).type : '';
    t.equal(returnedType, 'certificateRevocationList;binary',
            'and it comes back under the binary spelling, canonically cased ' +
            '(section 5: returned in binary form whether or not the option ' +
            'was asked for)');
    const filtered = search(realmJose.dn, 0, ['cn'],
                            '(certificateRevocationList=*)');
    t.check(filtered.ok && filtered.entries.length === 1,
            'and a presence filter on the plain type matches the entry',
            JSON.stringify({ ok: filtered.ok,
                             n: filtered.entries && filtered.entries.length }));

    t.log.info('=== D. product mode: an anonymous base read of a CRL, and ' +
               'nothing wider ===');

    withSettings({ 'global.mode': 'product' }, function () {
      const read = search(realmJose.dn, 0,
                          ['certificateRevocationList;binary']);
      t.check(read.ok && read.entries.length === 1 &&
              !!crlBytesOf(read.entries[0]),
              'an UNBOUND base search of a CRL entry is answered — a relying ' +
              'party following an ldap:// distribution point holds no ' +
              'credential for this directory',
              JSON.stringify({ ok: read.ok, errorName: read.errorName }));
      // Based AT the CRL entry, so the only thing that can refuse it is the
      // scope: a probe based at the ou=crl container is refused by the path
      // test first and would pass against an exemption that ignored scope.
      const subtree = search(realmJose.dn, 2, []);
      t.check(subtree.ok === false &&
              subtree.errorName === 'InsufficientAccessRightsError',
              'a SUBTREE search based at that same CRL entry is still refused ' +
              'unbound — the exemption is a base read of one list, not a way ' +
              'to walk the tree',
              JSON.stringify({ ok: subtree.ok, errorName: subtree.errorName }));
      const container = realmJose.dn.slice(realmJose.dn.indexOf(',') + 1);
      const listing = search(container, 1, []);
      t.check(listing.ok === false &&
              listing.errorName === 'InsufficientAccessRightsError',
              'and so is a one-level search of the ou=crl container',
              JSON.stringify({ ok: listing.ok, errorName: listing.errorName }));
      const people = search('ou=users,dc=' + REALM + ',' +
                            config.value('ldap.baseDn'), 0, []);
      t.check(people.ok === false &&
              people.errorName === 'InsufficientAccessRightsError',
              'and a base search of anything that is not a CRL entry is ' +
              'still refused unbound',
              JSON.stringify({ ok: people.ok, errorName: people.errorName }));
    });

    t.log.info('=== E. the directory copy is kept current ===');

    t.check(typeof revocation.keepDirectoryCurrent === 'function' &&
            revocation.keepDirectoryCurrent() === false,
            'pki.start() armed the refresh timer, and arming it again does ' +
            'nothing — without it every ldap:// list was past its nextUpdate ' +
            'an hour after start');
  } finally {
    realms.remove(REALM);
    restoreAuthority(pki, keystore, before);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'crl_directory_publication',
  describe: 'the directory copy of every CRL: one DN per authority, written ' +
            'in the realm its DN names, readable anonymously in product mode ' +
            'by base search only, and named by either spelling of the binary ' +
            'option',
  run: run
};
