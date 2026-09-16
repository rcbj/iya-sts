// ===========================================================================
// tests/spiffe_pki.js — THE SPIFFE AUTHORITY IS A LEAF OF THE SERVICE'S OWN
// ROOT (2026-09-11).
//
// Until this date the trust domain's X.509 authority was SELF-SIGNED and
// outside `common/pki.js` entirely, and both files said so at length: one
// process, two PKIs, on purpose. `/admin/pki` even carried the argument on the
// page, ending *the SPIFFE Issuing CA is built and ready above, certifying
// nothing, so that reversing this is a decision rather than a rebuild.* This
// file is what that reversal owes.
//
// `tests/spiffe_authority.js` holds the other path — a realm with no branch,
// which self-signs exactly as this service always did — in a child process,
// because with a hierarchy built that path is unreachable. The two files are
// not two ways of driving one claim: they assert different things about
// different code, and neither implies the other.
//
// ---------------------------------------------------------------------------
// WHY THIS IS IN PROCESS, WHICH IS THIS DIRECTORY'S ONE RULE.
//
// Three of the four claims cannot be driven over HTTP at all:
//
//   * **THE PATH IS VERIFIED BY OPENSSL AND NOT BY THE LIBRARY THAT BUILT
//     IT.** `pkijs` encoded every certificate in the chain, so asking pkijs
//     whether the chain verifies is this implementation agreeing with itself —
//     the argument `tests/pki_revocation.js` makes about CRLs and
//     `tests/crypto_module.js` makes about keeping xml-crypto as a dependency
//     nothing requires. Node's own `X509Certificate.checkIssued()` and
//     `verify()` are OpenSSL, which is an independent answer, and the
//     interesting inputs are chains no client can be made to send.
//   * **THE `pathLen` ARITHMETIC IS THE WHOLE REASON THIS FEATURE NEEDED A
//     DESIGN.** `NewDownstreamX509CA` asks the SPIFFE authority for a CA, and
//     an Issuing CA in this hierarchy carries `pathLen: 0` — so the use case
//     carries `1` and the realm Intermediate above it is widened to `2`. Both
//     numbers or neither: widening one leaves a chain that encodes cleanly and
//     validates nowhere, and **the failure is at the far end of somebody
//     else's path builder**, reported as a message about basic constraints
//     naming neither certificate. Reading the encoded numbers is the only way
//     to assert that before it ships.
//   * **THE ANCHOR IS SHARED WHILE THE AUTHORITY IS NOT**, which is the single
//     sentence that made a per-realm SPIFFE authority coherent with four
//     sockets that answered in one realm (a realm has sockets and a trust
//     domain of its own since 2026-09-12 — `tests/spiffe_realm_domains.js`).
//     Over HTTP it is two base URLs; here it is the bytes.
//
// The fourth — that an SVID actually carries its chain — is drivable over HTTP
// and is asserted here anyway, because every claim above is about a chain and
// a chain nothing carries is a chain nothing uses.
//
// ---------------------------------------------------------------------------
// IT BUILDS THE HIERARCHY ITSELF RATHER THAN RELYING ON THE SUITE'S ORDER.
//
// `tests/pki_hierarchy.js` builds one, and `run.js` runs files in one process
// — so this file would usually find a hierarchy already there. Usually is not
// a premise: `--only=spiffe_pki` runs it alone, and a file that passes only
// when something else ran first is the shape of flake this directory's own
// CLAUDE.md records getting a test deleted rather than fixed. `ensureRoot()`
// and `ensureScope()` are both idempotent, so calling them costs nothing when
// the suite has already done it.
// ===========================================================================

const nodeCrypto = require('crypto');
const { execFileSync } = require('child_process');

const realms = require('../common/realms');
const keystore = require('../common/keystore');
const pki = require('../common/pki');
const ca = require('../spiffe/spiffe_ca');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'spiffe_pki',
  level: process.env.LOG_LEVEL || 'info' });

// The realm this file works in. A realm of its own for `tests/roles.js`'s
// reason — what is asserted is that this realm's authority is not that
// realm's, which needs two — and both are LEFT STANDING, because
// `realms.remove()` would take the branch with them and the next file in the
// run is entitled to find the default realm exactly as it was.
const REALM_A = 'spiffe-pki-a';
const REALM_B = 'spiffe-pki-b';

function certificateOf(pem) {
  log.debug("Entering certificateOf().");
  log.debug("Leaving certificateOf().");
  return new nodeCrypto.X509Certificate(pem);
}

// **THE PATH, WALKED THE WAY A VALIDATOR WALKS IT.** Each certificate must be
// issued by the next one up and its signature must verify under that one's
// key; the last must be self-signed. `checkIssued()` compares the names and
// the authority key identifier and `verify()` checks the signature, and both
// are OpenSSL rather than the encoder that wrote these bytes.
function pathVerifies(chainPem, anchorPem) {
  log.debug("Entering pathVerifies().");
  const chain = chainPem.map(certificateOf).concat([certificateOf(anchorPem)]);
  for (let i = 0; i < chain.length - 1; i++) {
    if (!chain[i].checkIssued(chain[i + 1])) {
      log.debug("Leaving pathVerifies().");
      return 'certificate ' + i + ' (' + chain[i].subject +
             ') is not issued by ' + chain[i + 1].subject;
    }
    if (!chain[i].verify(chain[i + 1].publicKey)) {
      log.debug("Leaving pathVerifies().");
      return 'certificate ' + i + ' (' + chain[i].subject +
             ') does not verify under ' + chain[i + 1].subject;
    }
  }
  const anchor = chain[chain.length - 1];
  if (anchor.subject !== anchor.issuer || !anchor.verify(anchor.publicKey)) {
    log.debug("Leaving pathVerifies().");
    return 'the anchor (' + anchor.subject + ') is not self-signed';
  }
  log.debug("Leaving pathVerifies().");
  return '';
}

// ---------------------------------------------------------------------------
// THE `pathLenConstraint` A CERTIFICATE ENCODES, READ BY OPENSSL.
//
// **NOT `X509Certificate.toString()`**, which returns the PEM and matches
// nothing — the first version of this function did exactly that and reported
// `undefined` for a certificate whose constraint was correctly encoded, which
// is a fixture saying the feature is broken. Node exposes no basicConstraints
// accessor at all.
//
// So it is `openssl x509 -ext basicConstraints`, which is the arrangement
// `tests/pki_revocation.js` argues: the numbers were written by `pkijs`, and
// asking `pkijs` to read them back is this implementation agreeing with
// itself. What this claim is ABOUT is what a foreign path builder will make of
// the bytes, so a foreign reader is the only one worth asking.
//
// A machine with no openssl answers `undefined` and the two assertions using
// it fail rather than passing quietly — the same choice `tests/pki.js` makes,
// and the opposite of a skip, because this is a claim about encoded bytes
// rather than about an optional surface.
// ---------------------------------------------------------------------------
function pathLenOf(pem) {
  log.debug("Entering pathLenOf().");
  let text;
  try {
    text = execFileSync('openssl',
                        ['x509', '-noout', '-ext', 'basicConstraints'],
                        { input: pem, encoding: 'utf8', stdio: 'pipe' });
  } catch (e) {
    log.debug("Caught in pathLenOf(): " + ((e && e.message) || e));
    log.debug("Leaving pathLenOf().");
    return undefined;
  }
  const match = text.match(/CA:TRUE(?:,\s*pathlen:\s*(\d+))?/i);
  if (!match) {
    log.debug("Leaving pathLenOf().");
    return undefined;
  }
  log.debug("Leaving pathLenOf().");
  return match[1] === undefined ? null : Number(match[1]);
}

// **`realms.run()` TAKES THE REALM OBJECT AND NOT ITS ID**, and getting that
// wrong does not fail where it is written: the id is stored as the ambient
// realm, every `config.value()` under it then looks for `overrides` on a
// string, and the throw arrives from `common/config.js` naming neither the
// realm nor the caller. So this hands back the object.
function makeRealm(t, id) {
  log.debug("Entering makeRealm().");
  const held = realms.get(id);
  if (held) {
    log.debug("Leaving makeRealm().");
    return held;
  }
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving makeRealm().");
    return null;
  }
  log.debug("Leaving makeRealm().");
  return made.realm;
}

async function run(t) {
  log.debug("Entering run().");
  await keystore.start();
  const rooted = await pki.ensureRoot({});
  if (!rooted.ok) {
    // A test that could not RUN rather than one that failed — see this
    // directory's CLAUDE.md.
    throw new Error('the service Root CA could not be built: ' +
                    (rooted.errors || []).join(' '));
  }
  const realmA = makeRealm(t, REALM_A);
  const realmB = makeRealm(t, REALM_B);
  if (!realmA || !realmB) {
    log.debug("Leaving run().");
    return;
  }
  // The realm watcher builds a branch for a realm created at runtime, and it
  // is deliberately not awaited (a realm creation must not block on nine
  // signatures). So the branch is ensured here rather than waited for: both
  // calls are idempotent, and whichever of the two gets there first is the
  // one that builds.
  const branchA = await pki.ensureScope(REALM_A);
  const branchB = await pki.ensureScope(REALM_B);
  // **AND THE PROCESS BRANCH, WHICH THIS FILE READS AS THE CONTROL.** Section
  // 2's whole point is that the widening reached the SPIFFE branch and NO
  // OTHER, so the TLS branch has to exist to be compared with —
  // `pki.start()` builds it and nothing here calls that.
  const branchP = await pki.ensureScope(pki.PROCESS_SCOPE);
  if (!branchA.ok || !branchB.ok || !branchP.ok) {
    throw new Error('a branch could not be built: ' +
                    ((branchA.errors || []).concat(branchB.errors || [],
                                                   branchP.errors || []))
                      .join(' '));
  }

  // -------------------------------------------------------------------------
  // 1. THE AUTHORITY IS THE REALM'S SPIFFE ISSUING CA.
  // -------------------------------------------------------------------------
  t.log.info('=== the X.509 authority comes from common/pki.js ===');
  const authority = ca.activeX509Authority(REALM_A);
  t.check(!!authority, 'the realm has an X.509 authority at all',
          authority ? authority.subject : '(none)');
  t.equal(authority.source, 'pki',
          'and it is the PKI\'s and not a self-signed one — the field every ' +
          'report has to carry, because a reader cannot tell the two apart ' +
          'from a certificate and what they have to DO about them differs');

  const issuer = pki.describeIssuer(REALM_A, 'spiffe');
  t.equal(authority.certificatePem, issuer.certificatePem,
          'and it is the SAME certificate /admin/pki draws as this realm\'s ' +
          'SPIFFE Issuing CA — one authority, not a copy of one');

  // **THE SIGNING ALGORITHM IS THE AUTHORITY'S OWN KEY'S AND NOT THE ONE ITS
  // PARENT SIGNED IT WITH.** Those coincide in a branch whose tiers share a
  // key family, which was true of every hierarchy this service had ever built
  // — so the bug was invisible until the SPIFFE use case was allowed an EC key
  // under an RSA Intermediate, and then it is `Invalid key type` out of Web
  // Crypto naming neither the tier nor the algorithm.
  const issuingCert = certificateOf(issuer.certificatePem);
  t.check(issuer.signatureAlg.indexOf('ecdsa') >= 0,
          'the authority SIGNS with its own key\'s algorithm — reported as ' +
          'what it can produce rather than as what signed it',
          issuer.signatureAlg + ' (it was signed with ' + issuer.signedWith +
          ')');
  t.check(issuer.signedWith !== issuer.signatureAlg,
          'and those two really are different here, which is what makes the ' +
          'assertion above a check rather than a coincidence',
          issuer.signedWith + ' vs ' + issuer.signatureAlg);

  // -------------------------------------------------------------------------
  // 2. THE `pathLen` ARITHMETIC, WHICH HAS TO BE RIGHT IN TWO PLACES.
  // -------------------------------------------------------------------------
  t.log.info('=== the SPIFFE branch has room for a downstream CA ===');
  t.equal(pathLenOf(issuer.certificatePem), 1,
          'the SPIFFE Issuing CA encodes pathLen 1 — leaves AND one further ' +
          'CA, which is what NewDownstreamX509CA asks it for');
  t.equal(pathLenOf(issuer.intermediate.certificatePem), 2,
          'and the realm Intermediate above it encodes pathLen 2 to match. ' +
          'BOTH NUMBERS OR NEITHER: widening one alone gives a chain that ' +
          'encodes cleanly and validates nowhere');

  const tlsIssuer = pki.describeIssuer(pki.PROCESS_SCOPE, 'tls');
  t.equal(pathLenOf(tlsIssuer.certificatePem), 0,
          'while the TLS Issuing CA is still pathLen 0 — the widening is ' +
          'derived from the use case that needs it and reaches no other ' +
          'authority');
  t.equal(pathLenOf(tlsIssuer.intermediate.certificatePem), 1,
          'and so is the process Intermediate, because it carries no use ' +
          'case that needs depth. Writing the 2 in by hand would have ' +
          'widened every Intermediate in the service for one use case in one ' +
          'of them');

  // -------------------------------------------------------------------------
  // 3. AN SVID CARRIES ITS CHAIN, AND THE CHAIN REACHES THE ANCHOR.
  // -------------------------------------------------------------------------
  t.log.info('=== an X509-SVID builds a path to the service Root ===');
  const svid = await realms.run(realmA, function () {
    return ca.mintX509Svid('spiffe://' + ca.trustDomain() + '/ns/t/sa/probe');
  });
  t.equal(svid.chainPem.length, 3,
          'the SVID is delivered as THREE certificates — the leaf, this ' +
          'realm\'s SPIFFE Issuing CA and its Intermediate. It was one for ' +
          'as long as the authority was self-signed, and an agent handed ' +
          'only the leaf cannot build a path to the bundle it was given');
  t.equal(svid.chainCertificatesDer.length, 3,
          'and the SPIRE Server API\'s `repeated bytes cert_chain` is the ' +
          'same list as separate entries rather than one blob');
  t.equal(Buffer.concat(svid.chainCertificatesDer).length,
          svid.chainDer.length,
          'while the Workload API\'s `x509_svid` is those same bytes ' +
          'concatenated — two shapes of one list, decided in one place');

  const bundle = await realms.run(realmA, function () { return ca.bundle(); });
  const anchors = bundle.keys.filter(function (key) {
    return key.use === 'x509-svid';
  });
  t.equal(anchors.length, 1,
          'the bundle publishes exactly ONE x509-svid anchor — the service ' +
          'Root. It published the authorities themselves while they were ' +
          'self-signed, which is what a rotation had to keep adding to');
  const anchorPem = '-----BEGIN CERTIFICATE-----\n' +
    (String(anchors[0].x5c[0]).match(/.{1,64}/g) || []).join('\n') +
    '\n-----END CERTIFICATE-----\n';
  t.equal(certificateOf(anchorPem).subject,
          certificateOf(pki.serviceRoot().certificatePem).subject,
          'and that anchor is this service\'s Root CA');

  // THE PATH ITSELF, walked by OpenSSL. This is the assertion the whole file
  // is for: everything above could be true of a chain nothing can verify.
  t.equal(pathVerifies(svid.chainPem, anchorPem), '',
          'AND OPENSSL BUILDS THE PATH from the SVID to that anchor — every ' +
          'link issued by the next and every signature verifying, checked by ' +
          'the library that did NOT encode them');

  // -------------------------------------------------------------------------
  // 4. THE DOWNSTREAM CA, WHICH IS WHAT THE EXTRA DEPTH IS FOR.
  // -------------------------------------------------------------------------
  t.log.info('=== NewDownstreamX509CA still produces a usable CA ===');
  const downstream = await realms.run(realmA, function () {
    return ca.downstreamCa({});
  });
  t.equal(pathLenOf(downstream.certificatePem), 0,
          'a downstream CA encodes pathLen 0 — it signs leaves and no ' +
          'further authority');
  const downstreamChain = downstream.chainDer.slice(1).map(function (der) {
    return '-----BEGIN CERTIFICATE-----\n' +
      (Buffer.from(der).toString('base64').match(/.{1,64}/g) || []).join('\n') +
      '\n-----END CERTIFICATE-----\n';
  });
  t.equal(pathVerifies([downstream.certificatePem].concat(downstreamChain),
                       anchorPem), '',
          'and OpenSSL builds a path from it to the same anchor — FOUR CAs ' +
          'deep, which is the arrangement the two pathLen numbers exist for');

  // -------------------------------------------------------------------------
  // 4b. THE OTHER ISSUANCE DOOR SIGNS WITH THE SAME KEY, AND THIS IS THE ONLY
  //     PLACE IN THE SERVICE WHERE THAT CAN BE ASKED.
  //
  // `issueUnder()` is the door SVIDs take and section 3 covers it. `certify()`
  // is the OTHER door — the one the signing key sets and every registered key
  // pair take — and it had the same defect: it handed the primitive
  // `ca.signatureAlg`, which is what the INTERMEDIATE signed this authority
  // with, as the algorithm to sign a leaf with using this authority's OWN key.
  //
  // **THE TWO COINCIDE IN EVERY OTHER BRANCH IN THIS SERVICE**, because every
  // other Issuing CA shares its Intermediate's key family — so the SPIFFE
  // authority is the only certificate here under which the mutant is even
  // reachable, and a fix guarded nowhere is a fix that gets reverted by the
  // next person tidying up. It is asserted here rather than in
  // `tests/pki_hierarchy.js` for that reason: that file's branches are RSA
  // throughout and the assertion would pass against the defect.
  // -------------------------------------------------------------------------
  t.log.info('=== certify() signs with the authority\'s own key too ===');
  const probePair = nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'P-256' });
  const certified = await pki.certify(REALM_A, 'spiffe', {
    slot: 'ES256:probe', alg: 'ES256',
    label: 'a probe key', commonName: 'spiffe certify probe',
    publicKeyPem: probePair.publicKey.export({ type: 'spki',
                                               format: 'pem' })
  });
  t.check(certified.ok, 'certify() issues from the SPIFFE Issuing CA at all',
          certified.ok ? certified.record.subject
                       : (certified.errors || []).join(' '));
  if (certified.ok) {
    t.check(certificateOf(certified.record.certificatePem)
              .verify(issuingCert.publicKey),
            'AND THE CERTIFICATE VERIFIES UNDER THAT AUTHORITY\'S KEY — ' +
            'which it does not when the algorithm is taken from what SIGNED ' +
            'the authority rather than from what the authority can PRODUCE',
            certified.record.signatureAlg);
    // Left behind rather than forgotten: `forgetCertificate()` takes it out of
    // the register, because a probe slot on a realm somebody may read later is
    // litter this file put there.
    pki.forgetCertificate(REALM_A, 'spiffe', 'ES256:probe');
  }

  // -------------------------------------------------------------------------
  // 5. THE AUTHORITY IS PER REALM AND THE ANCHOR IS NOT.
  //
  // **THIS IS THE CLAIM THAT MADE THE WHOLE DESIGN COHERENT.** SPIFFE's four
  // sockets were shared and answered in the default realm when it was
  // written (a realm binds its own since 2026-09-12), so an authority per
  // realm would have been incoherent if the ANCHOR were per realm too — a
  // workload holding one bundle could verify SVIDs from one realm and not
  // another. It is not: the Root is the service's, every realm's bundle
  // publishes the same anchor, and what the chain adds is which realm issued
  // it.
  // -------------------------------------------------------------------------
  t.log.info('=== one anchor, an authority per realm ===');
  const otherAuthority = ca.activeX509Authority(REALM_B);
  t.check(otherAuthority && otherAuthority.certificatePem !==
            authority.certificatePem,
          'another realm signs with an authority of its own',
          otherAuthority ? otherAuthority.subject : '(none)');

  const otherBundle = await realms.run(realmB, function () {
    return ca.bundle();
  });
  const otherAnchors = otherBundle.keys.filter(function (key) {
    return key.use === 'x509-svid';
  });
  t.equal(String(otherAnchors[0].x5c[0]), String(anchors[0].x5c[0]),
          'AND ITS BUNDLE PUBLISHES THE SAME ANCHOR, byte for byte. One ' +
          'trust domain, one anchor an operator installs once, an authority ' +
          'per realm — which is what lets the four shared sockets go on ' +
          'answering in the default realm without partitioning anybody');

  const otherSvid = await realms.run(realmB, function () {
    return ca.mintX509Svid('spiffe://' + ca.trustDomain() + '/ns/t/sa/other');
  });
  t.equal(pathVerifies(otherSvid.chainPem, anchorPem), '',
          'and an SVID minted in that realm builds a path to the anchor the ' +
          'FIRST realm published — the property a workload actually depends ' +
          'on');
  t.check(otherSvid.chainPem[1] !== svid.chainPem[1],
          'while its chain still says which realm issued it, which is the ' +
          'boundary that moved down a tier rather than going away',
          'two different SPIFFE Issuing CAs');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_pki',
  describe: 'the SPIFFE authority is this realm\'s SPIFFE Issuing CA under ' +
            'the service Root: the chain an SVID carries, the two pathLen ' +
            'numbers a downstream CA needs, and one anchor across realms',
  run: run
};
