'use strict';
//
// File: pki_hierarchy.js
//
// ===========================================================================
// ONE ROOT FOR THE SERVICE, AN INTERMEDIATE PER SCOPE, AN ISSUING CA PER USE
// CASE — AND EVERY KEY THIS SERVICE GENERATES AS A LEAF OF IT (2026-09-11).
//
// `tests/pki.js` holds what `common/pki.js` did BEFORE this change and still
// does: the three-tier view, the path check, the algorithm pairing, what is
// stored against what is handed out. It was updated for the reversal rather
// than replaced, and the two sections it grew are the ones that record it.
//
// **THIS FILE IS ABOUT THE SHAPE AND THE STARTUP**, which are four claims no
// running service can be asked:
//
//   * **THE BOUNDARY MOVED DOWN A TIER.** Until this date every realm had a
//     Root of its own, so "does this chain to our Root" WAS the realm
//     boundary. One Root makes that test true of every certificate this
//     service has ever issued — so it silently stopped being a boundary, and
//     what replaced it is that the path must pass through THIS realm's own
//     Intermediate. Over HTTP the two are indistinguishable: both refuse the
//     foreign certificate, and only one of them refuses it for a reason that
//     survives the next realm being created.
//   * **THE STARTUP ORDER.** The hierarchy has to exist before a key is
//     certified and before anything binds, and the only way to assert an
//     ordering is to run it.
//   * **WHAT IS NOT A LEAF, AND WHY.** Two families are deliberately outside
//     the tree, and an absence is exactly what no request can report.
//   * **THE EDITING ACTS ARE FOUR DIFFERENT THINGS.** Reissue, renew, import
//     and pin are easy to confuse and their consequences are not alike — a
//     renewal must leave every key verifying and a reissue must not.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const helpers = require('../common/helpers');
const stsCrypto = require('../common/crypto');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pki_hierarchy',
  level: process.env.LOG_LEVEL || 'info' });

const REALM_A = 'hier-a';
const REALM_B = 'hier-b';

// A path check with node's own verifier rather than this module's, which is
// the point of using it: `verifyLeaf()` is the thing under test in
// `tests/pki.js`, and an assertion about a chain that used it would be the
// implementation checking itself.
function chainsTo(leafPem, chainPems, anchorPem) {
  log.debug("Entering chainsTo().");
  const leaf = new nodeCrypto.X509Certificate(leafPem);
  let current = leaf;
  const rest = chainPems.map(function (pem) {
    return new nodeCrypto.X509Certificate(pem);
  });
  const anchor = new nodeCrypto.X509Certificate(anchorPem);
  for (let hop = 0; hop < 8; hop++) {
    if (current.issuer === anchor.subject) {
      log.debug("Leaving chainsTo().");
      return current.verify(anchor.publicKey);
    }
    const next = rest.filter(function (one) {
      return one.subject === current.issuer;
    })[0];
    if (!next || !current.verify(next.publicKey)) {
      log.debug("Leaving chainsTo().");
      return false;
    }
    current = next;
  }
  log.debug("Leaving chainsTo().");
  return false;
}

async function run(t) {
  log.debug("Entering run().");
  await keystore.start();

  t.log.info('=== the shape: one Root, an Intermediate per scope, an ' +
             'Issuing CA per use case ===');
  const started = await pki.start({ realmIds: [REALM_A, REALM_B] });
  t.check(started.ok && started.built,
          'pki.start() builds the tree', JSON.stringify(started));
  t.check(pki.hasRoot(), 'the service has a Root CA');

  const tree = pki.describeTree([REALM_A, REALM_B]);
  t.equal(tree.scopes.length, 3,
          'three scopes — the process branch and the two realms');
  const process = tree.scopes.filter(function (one) {
    return one.kind === 'process';
  })[0];
  const a =
      tree.scopes.filter(function (one) { return one.scope === REALM_A; })[0];
  const b =
      tree.scopes.filter(function (one) { return one.scope === REALM_B; })[0];

  t.equal(a.issuing.map(function (one) { return one.id; }).join(','),
          'jose,xml,assertions,spiffe',
          'a REALM carries the four use cases whose keys belong to a realm. ' +
          'It was three until 2026-09-11, when the SPIFFE authority moved ' +
          'here from the process branch — a realm signs its own SVIDs now, ' +
          'and what keeps that coherent with four SHARED sockets is that the ' +
          'anchor is the service Root and no realm\'s');
  t.equal(process.issuing.map(function (one) { return one.id; }).join(','),
          'tls',
          'and the PROCESS branch carries the one whose key is shared by ' +
          'every realm — a realm\'s Intermediate signing the TLS certificate ' +
          'would be one realm vouching for every other realm\'s front door');
  t.check(a.issuing.every(function (one) { return one.built; }) &&
          process.issuing.every(function (one) { return one.built; }),
          'every Issuing CA in every scope is built, because a branch is ' +
          'built whole or not at all');

  t.log.info('=== the Root is SHARED and the Intermediate is NOT ===');
  t.equal(stsCrypto.stripPem(pki.trustAnchorsFor(REALM_A)[0]),
          stsCrypto.stripPem(pki.trustAnchorsFor(REALM_B)[0]),
          'two realms share ONE Root CA — which is the reversal this whole ' +
          'change is, and what lets an operator install one anchor');
  t.check(stsCrypto.stripPem(a.intermediate.certificatePem) !==
          stsCrypto.stripPem(b.intermediate.certificatePem),
          'and each has an Intermediate of its own');
  t.check(stsCrypto.stripPem(process.intermediate.certificatePem) !==
          stsCrypto.stripPem(a.intermediate.certificatePem),
          'and the process branch has one that is neither realm\'s');
  // THE STORAGE HALF: one Root means one copy of its private key.
  t.check(!keystore.pkiFor(REALM_A).root && !keystore.pkiFor(REALM_B).root,
          'a realm\'s row does NOT hold the Root — it is composed back on ' +
          'top of the branch on the way out, so there is one copy of that ' +
          'private key rather than one per realm');
  t.check(String(keystore.pkiFor(pki.SERVICE_SCOPE).root.privateKeyPem)
            .indexOf('PRIVATE KEY') >= 0,
          'and the service row holds it, once, with its key');

  t.log.info('=== EVERY SIGNING KEY IS A LEAF OF IT ===');
  // ==========================================================================
  // **THIS SECTION USES THE DEFAULT REALM AND THE ONES ABOVE DO NOT, AND THE
  // DIFFERENCE IS NOT COSMETIC.**
  //
  // `helpers.stsKeysFor.of(id)` resolves through the realm registry, and
  // `hier-a` is not a realm anybody created — it is an id this file hands the
  // PKI store directly, which is all the sections above need. Ask the key
  // factory for it and you get the DEFAULT realm's key set, whose certificates
  // live in the default realm's row: so `certifyKeySet('hier-a', keys)` would
  // write certificates for one realm's keys into another realm's row, and
  // every assertion about "the key set publishes what was certified" would
  // compare two things that were never connected.
  //
  // It survived a mutation round exactly that way — the kid assertion below
  // passed against a build where the kid FOLLOWS the published certificate,
  // because re-certifying `hier-a` could never change what the default
  // realm's key set published. The fixture was the bug, which is what a
  // surviving mutant most often means here.
  // ==========================================================================
  const KEY_REALM = '';
  const keys = helpers.stsKeysFor.of(KEY_REALM);
  const certified = await pki.certifyKeySet(KEY_REALM, keys);
  t.check(certified.ok, 'a realm\'s key set certifies',
          (certified.failed || []).join('; '));
  t.equal(certified.certified, 2 + keys.extraKeys.length,
          'one certificate per curve key, and TWO for the RSA key — it signs ' +
          'JWTs and it signs XML documents, and those are two use cases with ' +
          'two authorities, so a relying party that trusts this service for ' +
          'SAML has said nothing about its OAuth tokens');

  const root = pki.serviceRoot().certificatePem;
  const underJose = pki.certificatesFor(KEY_REALM, 'jose');
  t.equal(underJose.length, 1 + keys.extraKeys.length,
          'the JOSE Issuing CA certified the RSA key and every curve key');
  let verified = 0;
  underJose.forEach(function (one) {
    if (chainsTo(one.certificatePem, one.chainPem, root)) {
      verified += 1;
    }
  });
  t.equal(verified, underJose.length,
          'and EVERY ONE of them builds a path to the service Root — checked ' +
          'with node\'s own verifier rather than this module\'s, so the ' +
          'thing under test is not also the judge');

  t.log.info('=== the key set PUBLISHES the certified certificate ===');
  const published = new nodeCrypto.X509Certificate(keys.certPem);
  t.check(published.subject !== published.issuer,
          'the certificate this key set publishes is no longer self-signed');
  t.check(published.issuer.replace(/\n/g, ', ')
            .indexOf('JOSE Signing CA') >= 0,
          'it is issued by this realm\'s JOSE Issuing CA',
          published.issuer.replace(/\n/g, ', '));
  t.equal(keys.certChainPem.length, 2,
          'and the chain under it is the Issuing CA and the Intermediate — ' +
          'leaf-first and WITHOUT the Root, which is what RFC 5246 asks of a ' +
          'certificate_list and what every x5c does');
  t.check(!!keys.selfSignedCertPem,
          'the self-signed certificate it was born with is still reachable, ' +
          'because "this key is certified" is a claim a reader should be ' +
          'able to check rather than take');

  t.log.info('=== the kid does NOT move, which is the whole reason it is not ' +
             'derived from the published certificate ===');
  const kidBefore = keys.kid;
  await pki.certifyKeySet(KEY_REALM, keys);
  t.equal(keys.kid, kidBefore,
          'certifying again leaves the kid exactly where it was — it names ' +
          'the KEY, so a token minted before a certificate changed is still ' +
          'verifiable against a key a client can find');
  const reissued = await pki.reissueUseCase(KEY_REALM, 'jose');
  t.check(reissued.ok, 'the JOSE Issuing CA can be re-issued',
          (reissued.errors || []).join(' '));
  t.equal(keys.kid, kidBefore,
          'and REISSUING THE AUTHORITY does not move it either, which is the ' +
          'case that would actually have bitten: the certificate under a key ' +
          'changes and the key does not');

  t.log.info('=== the realm boundary, which is the Intermediate now ===');
  // A leaf issued in REALM_A, made HERE rather than borrowed from the key-set
  // section: that section works in the default realm (see its own note), and
  // what this one needs is a certificate whose path goes through a DIFFERENT
  // realm's Intermediate from the one it is presented to.
  const borrowed = nodeCrypto.createPublicKey(keys.privateKeyPem)
    .export({ type: 'spki', format: 'pem' });
  const madeA = await pki.certify(REALM_A, 'jose', {
    slot: 'RS256', alg: 'RS256', label: 'a leaf in REALM_A',
    commonName: 'boundary probe', publicKeyPem: borrowed
  });
  t.check(madeA.ok, 'a leaf is issued in the first realm',
          (madeA.errors || []).join(' '));
  const leafA = pki.certificatesFor(REALM_A, 'jose')[0];
  const crossed = await pki.verifyLeaf(REALM_B, leafA.certificatePem,
                                       leafA.chainPem);
  t.check(!crossed.ok,
          'a certificate issued in one realm does not verify in another, ' +
          'which is the property the shared Root put at risk', crossed.why);
  t.check(/does NOT pass through/.test(crossed.why || ''),
          'and it is refused for passing through the wrong INTERMEDIATE ' +
          'rather than for the anchor — with one Root the anchor test is ' +
          'true of every certificate this service has ever issued, so a ' +
          'refusal that blamed it would be about a check that can no longer ' +
          'fail', crossed.why);
  // AND THE POSITIVE CASE, so the refusal above is a boundary rather than a
  // function that refuses everything.
  const own = await pki.verifyLeaf(REALM_A, leafA.certificatePem,
                                   leafA.chainPem);
  t.check(own.ok, 'while the realm it was issued in accepts it', own.why);

  t.log.info('=== the four editing acts are four different things ===');
  const beforeRenew = pki.certificatesFor(REALM_A, 'jose').map(function (one) {
    return one.serialHex;
  }).sort().join(',');
  const caBeforeRenew = pki.describeScope(REALM_A).issuing
    .filter(function (one) { return one.id === 'jose'; })[0].ca.thumbprint;

  const renewed = await pki.recertifyUseCase(REALM_A, 'jose');
  t.check(renewed.ok && renewed.recertified > 0,
          'a RENEWAL re-mints the certificates', JSON.stringify(renewed));
  const afterRenew = pki.certificatesFor(REALM_A, 'jose').map(function (one) {
    return one.serialHex;
  }).sort().join(',');
  t.check(beforeRenew !== afterRenew,
          'with fresh serials — two certificates from one issuer sharing a ' +
          'serial are indistinguishable to anything that revokes, caches or ' +
          'pins by (issuer, serial)');
  t.equal(pki.describeScope(REALM_A).issuing
            .filter(function (one) {
              return one.id === 'jose';
            })[0].ca.thumbprint,
          caBeforeRenew,
          'and the AUTHORITY is untouched, which is what makes it a renewal');
  // The keys are untouched too, which is the claim a renewal rests on.
  const stillThere = pki.certificateFor(REALM_A, 'jose', 'RS256');
  t.check(new nodeCrypto.X509Certificate(stillThere.certificatePem)
            .checkPrivateKey(nodeCrypto.createPrivateKey(keys.privateKeyPem)),
          'AND THE RENEWED CERTIFICATE IS STILL OVER THE SAME KEY — this is ' +
          'the assertion the word "renewal" means: nothing that verifies ' +
          'against the published JWKS stops verifying');

  const beforeReissue = pki.describeScope(REALM_A).issuing
    .filter(function (one) { return one.id === 'xml'; })[0].ca.thumbprint;
  const reissuedXml = await pki.reissueUseCase(REALM_A, 'xml');
  t.check(reissuedXml.ok, 'a REISSUE replaces the authority',
          (reissuedXml.errors || []).join(' '));
  t.check(pki.describeScope(REALM_A).issuing
            .filter(function (one) {
              return one.id === 'xml';
            })[0].ca.thumbprint !==
          beforeReissue,
          'with a new key pair, which is what a reissue is and a renewal is ' +
          'not');
  t.equal(pki.describeScope(REALM_A).issuing
            .filter(function (one) {
              return one.id === 'jose';
            })[0].ca.thumbprint,
          caBeforeRenew,
          'and the OTHER use cases are untouched — which is the whole reason ' +
          'each has an authority of its own rather than sharing one');

  t.log.info('=== a use case belongs to a scope, and asking in the wrong one ' +
             'is refused ===');
  const wrongScope = await pki.reissueUseCase(REALM_A, 'tls');
  t.check(!wrongScope.ok,
          'the TLS Issuing CA cannot be built under a realm\'s Intermediate',
          (wrongScope.errors || []).join(' '));
  t.check(/process/.test((wrongScope.errors || []).join(' ')),
          'and the refusal says which scope it belongs to and why',
          (wrongScope.errors || []).join(' '));

  t.log.info('=== importing a CA: the checks that happen BEFORE anything is ' +
             'stored ===');
  const half = await pki.importCa(REALM_A, 'jose',
                                  { certificatePem: 'x', privateKeyPem: '' });
  t.check(!half.ok && /private key/i.test(half.errors.join(' ')),
          'a certificate with no key is refused — it is a trust anchor ' +
          'rather than an authority, and this service cannot issue from it');

  // A REAL PAIR THAT DO NOT BELONG TOGETHER. This is the check that matters:
  // an authority whose key is somebody else's issues certificates that verify
  // nowhere, and the failure arrives at a relying party rather than here.
  const mine = pki.describeScope(REALM_A).issuing
    .filter(function (one) { return one.id === 'jose'; })[0].ca;
  const theirs = keystore.pkiFor(REALM_B).issuing.jose;
  const mismatched = await pki.importCa(REALM_A, 'jose', {
    certificatePem: mine.certificatePem,
    privateKeyPem: theirs.privateKeyPem
  });
  t.check(!mismatched.ok,
          'a CA certificate presented with somebody ELSE\'S private key is ' +
          'refused', (mismatched.errors || []).join(' '));
  t.check(/does not belong/.test((mismatched.errors || []).join(' ')),
          'and the refusal says so in those words rather than reporting a ' +
          'bad signature later');

  // A LEAF is not an authority.
  const leafAsCa = await pki.importCa(REALM_A, 'jose', {
    certificatePem: leafA.certificatePem,
    privateKeyPem: keys.privateKeyPem
  });
  t.check(!leafAsCa.ok && /not a CA/.test(leafAsCa.errors.join(' ')),
          'and a LEAF is refused as an authority — its basicConstraints says ' +
          'cA:FALSE, so nothing it signed would be accepted by a path ' +
          'validator anyway');

  t.log.info('=== a real import, and what it costs ===');
  const own2 = keystore.pkiFor(REALM_B).issuing.xml;
  const imported = await pki.importCa(REALM_A, 'xml', {
    certificatePem: own2.certificatePem,
    privateKeyPem: own2.privateKeyPem
  });
  t.check(imported.ok, 'a matching CA and key are accepted',
          (imported.errors || []).join(' '));
  t.check(pki.describeScope(REALM_A).issuing
            .filter(function (one) { return one.id === 'xml'; })[0].ca.imported,
          'and the authority is MARKED as imported, because "this is not ' +
          'something this service generated" is the first thing a reader ' +
          'needs to know about it');
  const rebuilt = await pki.buildScope(REALM_A, {});
  t.check(rebuilt.ok, 'rebuilding the branch succeeds');
  t.check(pki.describeScope(REALM_A).issuing
            .filter(function (one) { return one.id === 'xml'; })[0].ca.imported,
          'AND LEAVES THE IMPORTED CA ALONE — somebody who pasted a ' +
          'corporate authority in did not press Rebuild to have it thrown ' +
          'away');

  t.log.info('=== pinning a key pair of your own ===');
  const pair = nodeCrypto.generateKeyPairSync('ec',
                                              { namedCurve: 'prime256v1' });
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pinned = await pki.pinKeyPair(REALM_A, 'jose', 'ES256:P-256',
                                      { privateKeyPem: privatePem });
  t.check(pinned.ok, 'a key pair with no certificate is accepted',
          (pinned.errors || []).join(' '));
  const held = pki.pinnedKeyFor(REALM_A, 'jose', 'ES256:P-256');
  t.check(!!held && held.privateKeyPem === privatePem,
          'the private key is kept, because this service has nowhere else to ' +
          'put a key somebody supplied');
  const pinnedCert = pki.certificateFor(REALM_A, 'jose', 'ES256:P-256');
  t.check(chainsTo(pinnedCert.certificatePem, pinnedCert.chainPem, root),
          'AND IT WAS CERTIFIED under this scope\'s own Issuing CA — which ' +
          'is what somebody who wants THEIR key under THIS service\'s Root ' +
          'is asking for');
  t.check(JSON.stringify(pki.describeScope(REALM_A)).indexOf('PRIVATE KEY') < 0,
          'and no private key appears anywhere in the public view of the ' +
          'scope, pinned ones included — this is the assertion that would ' +
          'otherwise be an absence nobody could see');

  t.log.info('=== what is deliberately NOT a leaf of this tree ===');
  // Said as an assertion rather than a comment, because an absence is the one
  // thing no request can report and the page makes a claim about it.
  const pq = pki.certificatesFor(REALM_A, 'jose').filter(function (one) {
    return /ML-DSA|SLH-DSA/i.test(one.alg || '');
  });
  t.equal(pq.length, 0,
          'the post-quantum keys are NOT certified — they come from ' +
          'common/pq_jose.js, this service\'s own reading of those ' +
          'constructions, and handing one to the vendored certificate ' +
          'encoder is exactly the defect that independence exists to expose');
  // **THE SPIFFE AUTHORITY USED TO BE THE SECOND ENTRY ON THIS LIST AND IS
  // NOT ANY MORE (2026-09-11).** The assertions that stood here were:
  //
  //   certificatesFor(PROCESS_SCOPE, 'spiffe').length === 0 —
  //     'the SPIFFE authority is not either — it is self-signed on purpose
  //      (one process, two PKIs) and an Issuing CA here carries pathLen 0, so
  //      it could not sign another authority even if that argument were
  //      dropped'
  //   describeScope(PROCESS_SCOPE).issuing['spiffe'].built —
  //     'the SPIFFE Issuing CA is nevertheless BUILT and certifying nothing,
  //      so reversing that is a decision rather than a rebuild'
  //
  // The decision was taken. What replaces them is in `tests/spiffe_pki.js`,
  // which asserts the chain rather than its absence; the one thing worth
  // keeping HERE is that the register is still empty, because an SVID is
  // issued through `issueUnder()` and is deliberately never recorded.
  t.equal(pki.certificatesFor(REALM_A, 'spiffe').length, 0,
          'and no SVID is in the certificate register: the SPIFFE authority ' +
          'IS in this tree now, but it issues through issueUnder(), which ' +
          'records nothing — an agent re-minting every half-lifetime would ' +
          'otherwise put hundreds of rows in a sealed keystore row that ' +
          'exists to hold certificate AUTHORITIES');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_hierarchy',
  describe: 'One Root for the service, an Intermediate per scope and an ' +
            'Issuing CA per use case: the shape, the realm boundary that ' +
            'moved down a tier when the Root was shared, every signing key ' +
            'as a leaf of it, the kid that does not move, the four editing ' +
            'acts, and what is deliberately outside the tree',
  run: run
};
