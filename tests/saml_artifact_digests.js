// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml_artifact_digests.js
//
// ===========================================================================
// THE SAML ARTIFACT STORES KEEP DIGESTS, ARE BOUNDED, AND A KEPT SAML 1.1
// ASSERTION EXPIRES WITH ITSELF (#614).
//
//   A. A SAML 2.0 artifact delivered on HTTP-Artifact is stored under
//      `credentialDigest(artifact)` and under nothing else: the artifact the
//      browser was sent appears in no key and no value of the store, and in
//      no row `/admin/caches` draws. Presented at `/saml2/ars`, it resolves
//      once, through the digest.
//   B. The bound, `saml2.maxArtifacts`: a store full of live artifacts
//      REFUSES the next delivery — a 503 page, STS-SAML-0110, nothing
//      evicted, no redirect to the service provider — and a store full of
//      EXPIRED artifacts clears them and takes the new one.
//   C. An expired artifact is refused AT THE READ (STS-SAML-0018) and
//      deleted, however long it has been since the last sweep.
//   D. A resolved artifact's delete is journalled under the DIGEST, which is
//      the key the minted flush deletes and names in `sts_changes`; the
//      store answers the replication applier's `remove()` under it. (The
//      applier itself — a row gone from `sts_minted` removed here — is
//      `persistence_minted.applyChange()`'s, held by
//      `kerberos_principal_store.js` section B.)
//   E. A–C for SAML 1.1: digest key, `saml11.maxArtifacts`, expiry at the
//      read (STS-SAML-0037).
//   F. `saml11_sso.assertionsById` keeps `{ xml, expires }`, expiring at the
//      assertion's NotOnOrAfter — or `saml11.assertionCacheTtlS` after it is
//      kept when it carries none; an expired one is not handed back by
//      AssertionIDReference (STS-SAML-0038) and is deleted; and
//      `cacheRegistry.ejectExpired()` — the `caches.eject-expired` scheduler
//      job's work — ejects what has expired from all three stores.
//
// WHY IN PROCESS: the stores are read and filled directly, the settings
// change mid-run, and `deliver()` is driven without a sign-in.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./tools/saml_signing_kit');

const log = require('bunyan').createLogger({
  name: 'saml_artifact_digests',
  level: process.env.LOG_LEVEL || 'info' });

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_SAMLP11 = 'urn:oasis:names:tc:SAML:1.0:protocol';
const NS_SAML11 = 'urn:oasis:names:tc:SAML:1.0:assertion';
const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';
const BINDING_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';
const SP = 'https://sp.digests.example/saml';
const ACS = 'https://sp.digests.example/acs';

function soap(inner) {
  log.debug("Entering soap().");
  log.debug("Leaving soap().");
  return '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' + inner +
    '</soap:Body></soap:Envelope>';
}

function artifactResolve(artifact, id) {
  log.debug("Entering artifactResolve().");
  log.debug("Leaving artifactResolve().");
  return soap('<samlp:ArtifactResolve xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '">' +
    '<saml:Issuer>' + SP + '</saml:Issuer>' +
    '<samlp:Artifact>' + artifact + '</samlp:Artifact>' +
    '</samlp:ArtifactResolve>');
}

function request11(inner, id) {
  log.debug("Entering request11().");
  log.debug("Leaving request11().");
  return soap('<samlp:Request xmlns:samlp="' + NS_SAMLP11 + '" ' +
    'MajorVersion="1" MinorVersion="1" RequestID="' + id + '" ' +
    'IssueInstant="' + new Date().toISOString() + '">' + inner +
    '</samlp:Request>');
}

function assertion11(id, notOnOrAfter) {
  log.debug("Entering assertion11().");
  log.debug("Leaving assertion11().");
  return '<saml:Assertion xmlns:saml="' + NS_SAML11 + '" ' +
    'MajorVersion="1" MinorVersion="1" AssertionID="' + id + '">' +
    (notOnOrAfter
      ? '<saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="' +
        notOnOrAfter + '"/>'
      : '') +
    '</saml:Assertion>';
}

// The SAMLart a delivery redirected the browser with.
function artOf(res) {
  log.debug("Entering artOf().");
  const m = /[?&]SAMLart=([^&]+)/.exec(String(res.location || ''));
  log.debug("Leaving artOf().");
  return m ? decodeURIComponent(m[1]) : '';
}

// Everything a realm's partition of a store holds, keys and values, as text.
// `store` is the store's registry row (`realms.handleFor()`), whose `dump()`
// answers the live rows.
function everything(store, realmId) {
  log.debug("Entering everything().");
  const out = [];
  store.dump(realmId).forEach(function (row) {
    out.push(String(row.key), JSON.stringify(row.value));
  });
  log.debug("Leaving everything().");
  return out.join('\n');
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const stsCrypto = require('../common/crypto');
  const realms = require('../common/realms');
  const cacheRegistry = require('../common/cache_registry');
  const app = require('../common/app');
  require('../ldap/ldap_server');
  const saml2sso = require('../saml/saml2_sso');
  const saml11sso = require('../saml/saml11_sso');
  saml2sso.registerRoutes(app);
  saml11sso.registerRoutes(app);
  const ars = kit.handlerFor(app, 'post', '/saml2/ars');
  const responder = kit.handlerFor(app, 'post', '/saml11/responder');
  const direct2 = new saml2sso.Saml2Sso(saml2sso.Saml2Sso.defaultDeps());
  const direct11 = new saml11sso.Saml11Sso(saml11sso.Saml11Sso.defaultDeps());
  const artifacts2 = realms.handleFor('saml2_sso.artifacts');
  const artifacts11 = realms.handleFor('saml11_sso.artifacts');
  const byId = realms.handleFor('saml11_sso.assertionsById');
  const DEFAULT = realms.DEFAULT_REALM.id;

  const codeOf = function (res) {
    log.debug("Entering codeOf().");
    log.debug("Leaving codeOf().");
    return errorCodes.codeOf(res) || '';
  };
  // A snapshot of the default realm's partition, as a Map whose VALUES are
  // the live records — so a test may age one in place.
  const mapOf = function (store) {
    log.debug("Entering mapOf().");
    const out = new Map();
    store.dump(DEFAULT).forEach(function (row) {
      out.set(row.key, row.value);
    });
    log.debug("Leaving mapOf().");
    return out;
  };
  const clear = function (store) {
    log.debug("Entering clear().");
    store.dump(DEFAULT).forEach(function (row) {
      store.remove(DEFAULT, row.key);
    });
    log.debug("Leaving clear().");
  };
  const sizeOf = function (store) {
    log.debug("Entering sizeOf().");
    log.debug("Leaving sizeOf().");
    return store.dump(DEFAULT).length;
  };
  const deliver2 = function (marker) {
    log.debug("Entering deliver2().");
    const res = kit.fakeRes();
    direct2.deliver(res, {
      binding: BINDING_ARTIFACT, destination: ACS, field: 'SAMLResponse',
      xml: '<samlp:Response xmlns:samlp="' + NS_SAMLP + '" ID="' + marker +
           '"/>',
      relayState: '', issuer: direct2.idpEntityId(), spEntityId: SP,
      inResponseTo: '_req', note: { title: 't', sub: 's' }
    });
    log.debug("Leaving deliver2().");
    return res;
  };
  const deliver11 = function (marker) {
    log.debug("Entering deliver11().");
    const res = kit.fakeRes();
    direct11.deliver(res, {
      profile: 'artifact', providerId: direct11.providerId(), rpId: '',
      scopedId: '', destination: ACS, target: 'tgt',
      assertion: assertion11(marker, ''), subject: 'alice',
      note: { title: 't', sub: 's' }
    });
    log.debug("Leaving deliver11().");
    return res;
  };
  const resolve2 = async function (artifact) {
    log.debug("Entering resolve2().");
    const res = kit.fakeRes();
    ars(kit.fakeReq('POST', '/saml2/ars', {}, '',
                    artifactResolve(artifact, '_r' + Date.now())), res);
    await res.done;
    log.debug("Leaving resolve2().");
    return res;
  };
  const resolve11 = async function (inner) {
    log.debug("Entering resolve11().");
    const res = kit.fakeRes();
    responder(kit.fakeReq('POST', '/saml11/responder', {}, '',
                          request11(inner, '_q' + Date.now())), res);
    await res.done;
    log.debug("Leaving resolve11().");
    return res;
  };

  // A recorder for the persistence journal (section D), installed for this
  // file and replaced by a no-op at the end: an unfilled slot and a no-op are
  // the same answer, "persist nothing".
  const journal = [];
  realms.setPersistObserver(function (handle, realmId, key) {
    journal.push({ handle: handle, realm: realmId, key: key });
  });

  try {
    // -----------------------------------------------------------------------
    t.log.info('A. SAML 2.0: the artifact is stored under its digest only');
    // -----------------------------------------------------------------------
    clear(artifacts2);
    const sent = deliver2('_digest-one');
    const art = artOf(sent);
    t.check(sent.statusCode === 303 && art.length === 60,
            'a delivery on HTTP-Artifact redirects with a 44-byte artifact',
            sent.statusCode + ' ' + art);
    const map2 = mapOf(artifacts2);
    t.check(map2 && map2.size === 1 &&
            map2.has(stsCrypto.credentialDigest(art)),
            'the store holds ONE entry, keyed by credentialDigest(artifact)');
    t.check(everything(artifacts2, DEFAULT).indexOf(art) < 0 &&
            everything(artifacts2, DEFAULT).indexOf(
              art.slice(art.length - 27)) < 0,
            'the artifact, and its MessageHandle, appear in no key and no ' +
            'value of the store');
    t.check(/_digest-one/.test(everything(artifacts2, DEFAULT)),
            'the VALUE is the whole message, which resolution hands back');
    const rows2 = (cacheRegistry.detail('saml2.artifacts') || {}).rows || [];
    t.check(rows2.length === 1 &&
            JSON.stringify(rows2).indexOf(art) < 0 &&
            /^sha256:/.test(rows2[0].key),
            '/admin/caches has a saml2.artifacts row, drawn as a digest',
            JSON.stringify(rows2));
    journal.length = 0;
    const resolved = await resolve2(art);
    t.check(/status:Success/.test(resolved.body) &&
            /_digest-one/.test(resolved.body),
            'presented at /saml2/ars, it resolves through the digest',
            codeOf(resolved) + ' ' + resolved.body.slice(0, 300));
    t.check(sizeOf(artifacts2) === 0, 'and is gone from the store');
    const again = await resolve2(art);
    t.check(!/_digest-one/.test(again.body) &&
            codeOf(again) === 'STS-SAML-0018',
            'a second resolution finds nothing (STS-SAML-0018)',
            codeOf(again));

    // -----------------------------------------------------------------------
    t.log.info('D. the delete is journalled under the digest');
    // -----------------------------------------------------------------------
    const deletes = journal.filter(function (row) {
      return row.handle === 'saml2_sso.artifacts';
    });
    t.check(deletes.length >= 1 && deletes.every(function (row) {
      return row.key === stsCrypto.credentialDigest(art);
    }), 'resolving journals the DIGEST for the flush to delete and name in ' +
        'the change log — never the artifact', JSON.stringify(deletes));
    artifacts2.restore(DEFAULT, stsCrypto.credentialDigest('ANOTHER-NODE'),
                       { expires: Date.now() + 60000, spEntityId: SP,
                         xml: '<x/>' });
    artifacts2.remove(DEFAULT, stsCrypto.credentialDigest('ANOTHER-NODE'));
    t.check(sizeOf(artifacts2) === 0, 'the replication applier\'s remove(), ' +
            'under the digest, drops this process\'s copy');

    // -----------------------------------------------------------------------
    t.log.info('B. SAML 2.0: saml2.maxArtifacts refuses when full');
    // -----------------------------------------------------------------------
    clear(artifacts2);
    await kit.withSettings(config, { 'saml2.maxArtifacts': 2 }, function () {
      const one = deliver2('_cap-1');
      const two = deliver2('_cap-2');
      const three = deliver2('_cap-3');
      t.check(one.statusCode === 303 && two.statusCode === 303,
              'two artifacts fit a bound of two');
      t.check(three.statusCode === 503 && !three.location &&
              codeOf(three) === 'STS-SAML-0110',
              'the third is REFUSED — a 503 page, STS-SAML-0110, and no ' +
              'redirect to the service provider',
              three.statusCode + ' ' + codeOf(three) + ' ' + three.location);
      t.check(sizeOf(artifacts2) === 2 &&
              /_cap-1/.test(everything(artifacts2, DEFAULT)),
              'and nothing was evicted to make room: the unresolved ' +
              'artifacts are both still held');
      const map = mapOf(artifacts2);
      map.forEach(function (held) {
        held.expires = Date.now() - 1;
      });
      const four = deliver2('_cap-4');
      t.check(four.statusCode === 303 && sizeOf(artifacts2) === 1,
              'a store full of EXPIRED artifacts clears them and takes the ' +
              'next one', four.statusCode + ' ' + sizeOf(artifacts2));
    });

    // -----------------------------------------------------------------------
    t.log.info('C. SAML 2.0: expired is refused at the read');
    // -----------------------------------------------------------------------
    clear(artifacts2);
    const stale = deliver2('_stale');
    const staleArt = artOf(stale);
    mapOf(artifacts2).forEach(function (held) {
      held.expires = Date.now() - 1;
    });
    const late = await resolve2(staleArt);
    t.check(!/_stale/.test(late.body) && codeOf(late) === 'STS-SAML-0018' &&
            sizeOf(artifacts2) === 0,
            'an artifact past its lifetime is not answered, and is deleted',
            codeOf(late) + ' ' + sizeOf(artifacts2));

    // -----------------------------------------------------------------------
    t.log.info('E. SAML 1.1: digest key, bound, expiry at the read');
    // -----------------------------------------------------------------------
    clear(artifacts11);
    const sent11 = deliver11('_a11-one');
    const art11 = artOf(sent11);
    t.check(sent11.statusCode === 303 && art11.length === 56,
            'a Browser/Artifact delivery redirects with a 42-byte artifact',
            sent11.statusCode + ' ' + art11);
    const map11 = mapOf(artifacts11);
    t.check(map11 && map11.size === 1 &&
            map11.has(stsCrypto.credentialDigest(art11)) &&
            everything(artifacts11, DEFAULT).indexOf(art11) < 0 &&
            everything(artifacts11, DEFAULT).indexOf(
              art11.slice(art11.length - 27)) < 0,
            'the SAML 1.1 store holds the digest and not the artifact');
    const rows11 = (cacheRegistry.detail('saml11.artifacts') || {}).rows ||
                   [];
    t.check(rows11.length === 1 && JSON.stringify(rows11).indexOf(art11) < 0,
            '/admin/caches has a saml11.artifacts row, drawn as a digest');
    const got11 = await resolve11('<samlp:AssertionArtifact>' + art11 +
                                  '</samlp:AssertionArtifact>');
    t.check(/samlp:Success/.test(got11.body) && /_a11-one/.test(got11.body) &&
            sizeOf(artifacts11) === 0,
            'presented at /saml11/responder, it resolves once through the ' +
            'digest', codeOf(got11) + ' ' + got11.body.slice(0, 300));
    await kit.withSettings(config, { 'saml11.maxArtifacts': 1 }, function () {
      const first = deliver11('_c11-1');
      const second = deliver11('_c11-2');
      t.check(first.statusCode === 303 && second.statusCode === 503 &&
              codeOf(second) === 'STS-SAML-0110' && !second.location &&
              sizeOf(artifacts11) === 1,
              'saml11.maxArtifacts: a full store refuses the next artifact ' +
              '(503, STS-SAML-0110) and keeps the unresolved one',
              second.statusCode + ' ' + codeOf(second));
    });
    clear(artifacts11);
    const stale11 = artOf(deliver11('_s11'));
    mapOf(artifacts11).forEach(function (held) {
      held.expires = Date.now() - 1;
    });
    const late11 = await resolve11('<samlp:AssertionArtifact>' + stale11 +
                                   '</samlp:AssertionArtifact>');
    t.check(!/_s11/.test(late11.body) && codeOf(late11) === 'STS-SAML-0037' &&
            sizeOf(artifacts11) === 0,
            'an expired SAML 1.1 artifact is refused at the read and deleted',
            codeOf(late11));

    // -----------------------------------------------------------------------
    t.log.info('F. SAML 1.1: a kept assertion expires with itself');
    // -----------------------------------------------------------------------
    clear(byId);
    const future = new Date(Date.now() + 600000).toISOString()
      .replace(/\.\d+Z$/, 'Z');
    direct11.rememberAssertion(assertion11('_kept-live', future));
    const kept = mapOf(byId).get('_kept-live');
    t.check(kept && typeof kept.xml === 'string' &&
            kept.expires === Date.parse(future),
            'an entry is { xml, expires }, expiring at the assertion\'s ' +
            'NotOnOrAfter', JSON.stringify(kept && kept.expires));
    const before = Date.now();
    await kit.withSettings(config, { 'saml11.assertionCacheTtlS': 120 },
      function () {
        direct11.rememberAssertion(assertion11('_kept-bare', ''));
      });
    const bare = mapOf(byId).get('_kept-bare');
    t.check(bare && bare.expires >= before + 120000 &&
            bare.expires <= Date.now() + 120000,
            'one with no NotOnOrAfter expires saml11.assertionCacheTtlS ' +
            'after it was kept', JSON.stringify(bare && bare.expires));
    const ref = function (id) {
      return '<samlp:AssertionIDReference>' + id +
             '</samlp:AssertionIDReference>';
    };
    const liveRef = await resolve11(ref('_kept-live'));
    t.check(/samlp:Success/.test(liveRef.body) &&
            /_kept-live/.test(liveRef.body),
            'a live assertion is answered by AssertionIDReference',
            codeOf(liveRef));
    mapOf(byId).get('_kept-live').expires = Date.now() - 1;
    const deadRef = await resolve11(ref('_kept-live'));
    t.check(!/<saml:Assertion\b/.test(deadRef.body) &&
            codeOf(deadRef) === 'STS-SAML-0038' &&
            !mapOf(byId).has('_kept-live'),
            'one past its NotOnOrAfter is NOT answered (STS-SAML-0038), and ' +
            'is deleted', codeOf(deadRef));
    byId.restore(DEFAULT, '_old-shape', '<saml:Assertion/>');
    const oldShape = await resolve11(ref('_old-shape'));
    t.check(codeOf(oldShape) === 'STS-SAML-0038',
            'a row of the old shape (the bare XML) is simply not found');

    // The scheduler job's work: every store's ejector.
    clear(byId);
    clear(artifacts2);
    clear(artifacts11);
    direct11.rememberAssertion(assertion11('_eject-me', future));
    direct11.rememberAssertion(assertion11('_keep-me', future));
    mapOf(byId).get('_eject-me').expires = Date.now() - 1;
    artOf(deliver2('_eject2'));
    mapOf(artifacts2).forEach(function (held) {
      held.expires = Date.now() - 1;
    });
    artOf(deliver11('_eject11'));
    mapOf(artifacts11).forEach(function (held) {
      held.expires = Date.now() - 1;
    });
    const ejected = cacheRegistry.ejectExpired();
    t.check((ejected.byCache['saml11.assertions'] || 0) >= 1 &&
            (ejected.byCache['saml2.artifacts'] || 0) >= 1 &&
            (ejected.byCache['saml11.artifacts'] || 0) >= 1 &&
            !mapOf(byId).has('_eject-me') &&
            mapOf(byId).has('_keep-me') &&
            sizeOf(artifacts2) === 0 && sizeOf(artifacts11) === 0,
            'cacheRegistry.ejectExpired() (the caches.eject-expired job) ' +
            'ejects the expired from all three stores and nothing live',
            JSON.stringify(ejected.byCache));
    t.check(cacheRegistry.ejecting().indexOf('saml11.assertions') >= 0 &&
            cacheRegistry.ejecting().indexOf('saml2.artifacts') >= 0 &&
            cacheRegistry.ejecting().indexOf('saml11.artifacts') >= 0,
            'all three stores are on the ejection job');
  } finally {
    clear(artifacts2);
    clear(artifacts11);
    clear(byId);
    realms.setPersistObserver(function () {
      return undefined;
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_artifact_digests',
  describe: 'the SAML artifact stores keep digests and refuse when full, and ' +
            'a kept SAML 1.1 assertion expires with itself (#614)',
  run: run
};
