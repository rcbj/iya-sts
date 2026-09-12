'use strict';
//
// File: pki.js
//
// ===========================================================================
// THE CERTIFICATE AUTHORITY: WHAT IT BUILDS, WHAT IT ISSUES, AND THE ONE
// CHECK A SECURITY CLAIM RESTS ON.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Three of the four sections below cannot be reached over HTTP at all, and the
// reason is the same each time: **what this module HANDS OUT is deliberately
// less than what it holds.** `describe()` drops every private key on the way
// out, so an assertion that the Root's key is not in the reply is an assertion
// about a function that has already run — over HTTP there is nothing to
// compare against, because the only evidence would be the absence of a string.
//
//   * **THE PATH CHECK** — `verifyLeaf()` is what decides whether an `x5c`
//     header counts, and the interesting cases are chains a client cannot be
//     made to send: a chain to somebody else's anchor that verifies every link
//     of itself, a leaf presented with the wrong intermediate, an expired tier.
//   * **THE ALGORITHM PAIRING** — an EC key's certificate digest is decided by
//     its CURVE, and a P-521 key signed under SHA-256 is legal, verifies, and
//     is nobody's intention. There is no request that can ask for that.
//   * **THE REALM BOUNDARY** — two realms' hierarchies, held at once, in one
//     process. Over HTTP that is two base URLs and a shared store; here it is
//     the store itself.
//
// The fourth — that the whole thing works end to end and reaches the token
// endpoint — is `tests/vendored/sts_jwt_bearer_grant.js`, which drives
// `/admin-api/pki` and then presents an assertion. **Neither implies the
// other**, which is the split `tests/totp.js` and `sts_portal_totp.js` already
// have: this file says the arithmetic is right and that one says the doors are
// wired up.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const applications = require('../common/applications');
// The registry's store is the directory, and requiring this is what fills the
// slot `applications.js` reads through. It registers HTTP views and starts no
// listener (see the four-modules rule in the root CLAUDE.md), so an in-process
// test may require it and nothing binds a port.
require('../ldap/ldap_server');
const keystore = require('../common/keystore');
const stsCrypto = require('../common/crypto');
const x509 = require('../common/vendored/x509');

// A realm id per section, so that nothing below depends on the order the
// sections run in — every one of these is a partition of `keystore`'s PKI map,
// and a section reusing another's realm would be a test that passes because of
// what the section above it left behind.
const REALM = 'pki-test';
const OTHER = 'pki-other';

// The application the sealing section writes onto, and a PEM that is not a real
// key — what is under test is where the bytes LAND, and generating a key pair
// to prove that would be paying for an assertion nobody makes about it.
const APP = 'pki-seal-probe';
const PEM = '-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n';

async function run(t) {
  t.log.info('=== the three tiers, built in one act ===');

  const built = await pki.buildChain(REALM, { organisation: 'Acme', country: 'US' });
  t.check(built.ok, 'a hierarchy is built', (built.errors || []).join(' '));
  const chain = built.chain;
  t.equal(chain.tiers.length, 3, 'three tiers and not two');
  t.equal(chain.tiers.map(function (one) { return one.tier; }).join(' -> '),
          'root -> intermediate -> issuing',
          'in that order — the order they are BUILT in, which is the reverse ' +
          'of the order a chain is SENT in, and getting the two the wrong way ' +
          'round produces a chain every validator refuses with a message ' +
          'about the leaf');

  // The lifetimes come from the vendored certificate PROFILES rather than from
  // a table here, which is the whole reason this module reuses them. Asserted
  // against that module so that a change to what an Intermediate CA IS fails
  // here rather than drifting.
  ['root', 'intermediate', 'issuing'].forEach(function (id, index) {
    const profile = x509.profile(pki.TIERS[index].profile);
    const tier = chain.tiers[index];
    const years = (new Date(tier.notAfter).getUTCFullYear() -
                   new Date(tier.notBefore).getUTCFullYear());
    t.equal(years, profile.years,
            'the ' + tier.label + '\'s lifetime is the certificate ' +
            'profile\'s (' + pki.TIERS[index].profile + '), not a number ' +
            'written out in common/pki.js');
  });

  t.log.info('=== a subject is a DN and the country is a PrintableString ===');
  // The encoder gives `C` a PrintableString and everything else a UTF8String,
  // which is interoperability rather than taste: several validators refuse a
  // UTF8String country and report it as a signature problem. Checked by
  // reading the certificate back through node's own parser, which is a second
  // implementation and therefore worth something.
  const root = new nodeCrypto.X509Certificate(chain.tiers[0].certificatePem);
  t.check(/CN=/.test(root.subject) && /O=Acme/.test(root.subject),
          'the Root carries the CN and the organisation it was asked for',
          root.subject.replace(/\n/g, ', '));
  t.check(root.subject === root.issuer,
          'and it is SELF-SIGNED, which is what makes it the trust anchor');

  t.log.info('=== the private keys are held and never handed out ===');
  // `describe()` is the ONE place a private key is dropped, so that a caller
  // cannot leak the Root's key by forgetting. Asserted over the whole
  // serialised view rather than field by field, because what is being checked
  // is that nothing anywhere in it is a key.
  t.check(JSON.stringify(chain).indexOf('PRIVATE KEY') < 0,
          'no PRIVATE KEY block appears anywhere in the public view of the ' +
          'hierarchy — this is the assertion that would otherwise be an ' +
          'absence nobody could see');
  t.check(chain.tiers.every(function (one) {
            return String(one.certificatePem).indexOf('BEGIN CERTIFICATE') >= 0;
          }),
          'and every tier\'s CERTIFICATE is there in full, because a ' +
          'certificate is the half of a key pair that is meant to be handed ' +
          'around and the Root is the one thing a relying party has to be ' +
          'given out of band');

  t.log.info('=== what a leaf travels with, and what it does not ===');
  const chainPem = pki.chainPemFor(REALM);
  t.equal(chainPem.length, 2,
          'a leaf travels with TWO certificates — the Issuing CA and the ' +
          'Intermediate — and not three');
  const anchors = pki.trustAnchorsFor(REALM);
  t.equal(anchors.length, 1, 'the trust anchor is the Root, alone');
  t.check(chainPem.every(function (pem) {
            return stsCrypto.stripPem(pem) !== stsCrypto.stripPem(anchors[0]);
          }),
          'AND THE ROOT IS NOT IN THE CHAIN. A root is a trust anchor: a ' +
          'relying party that accepted one because it arrived in the chain ' +
          'would be accepting a certificate that vouched for itself');

  t.log.info('=== issuing a signing key pair ===');
  const issued = await pki.issueSigningKeyPair(REALM, { identifier: 'webapp1' });
  t.check(issued.ok, 'a key pair is issued', (issued.errors || []).join(' '));
  const leaf = issued.issued;
  t.check(String(leaf.privateKeyPem).indexOf('PRIVATE KEY') >= 0,
          'the PRIVATE KEY is returned to the caller — once, at issuance, ' +
          'which is the only time it exists outside this module');
  t.check(pki.describe(REALM).issuedCount === 1,
          'and the hierarchy counts it, which is the one fact about what was ' +
          'issued that this module keeps: it holds no register, because ' +
          'ou=applications is the register');

  t.equal(leaf.jwsAlg, 'RS256',
          'an RSA leaf under a SHA-256 chain signs RS256 — the JWS algorithm ' +
          'is derived from the key and the digest rather than assumed');
  t.check(leaf.publicJwk.kid === leaf.kid && /^app-/.test(leaf.kid),
          'the kid is derived from the KEY MATERIAL (RFC 7638), which is the ' +
          'rule every kid in this service follows: two instances must not ' +
          'publish one name over two keys', leaf.kid);
  t.equal(leaf.publicJwk.x5c.length, 3,
          'the JWK carries the whole path in `x5c` — leaf, Issuing, ' +
          'Intermediate — so a client that registers this JWKS registers the ' +
          'chain with it');
  t.check(leaf.publicJwk['x5t#S256'] ===
            stsCrypto.certificateThumbprint(leaf.certificatePem,
                                            { format: 'base64url' }),
          'and `x5t#S256` is the SHA-256 of the leaf\'s DER, computed by the ' +
          'one function in this service that computes a certificate ' +
          'thumbprint');

  t.log.info('=== the leaf is a signing certificate and NOT a TLS one ===');
  const leafCert = new nodeCrypto.X509Certificate(leaf.certificatePem);
  const described = await x509.describeCertificate(leaf.certificatePem);
  // **MATCHED ON THE OID AND NOT ON THE NAME.** `describeExtension()` names an
  // extension `keyUsage` and `extKeyUsage`, so a `/extended key ?usage/i`
  // pattern matches NEITHER — the first version of the second assertion here
  // was therefore true of every certificate ever issued, and a mutant that
  // gave the leaf `clientAuth` survived it. 2.5.29.15 and 2.5.29.37 are what
  // RFC 5280 assigns and are what the encoder actually writes.
  const usage = described.extensions.filter(function (one) {
    return one.oid === '2.5.29.15';
  })[0];
  t.check(usage && /digitalSignature/i.test(JSON.stringify(usage)),
          'it carries digitalSignature (2.5.29.15)',
          usage ? JSON.stringify(usage.value || usage) : '(no keyUsage)');
  t.check(!described.extensions.some(function (one) {
            return one.oid === '2.5.29.37';
          }),
          'and NO extendedKeyUsage (2.5.29.37). Giving it clientAuth would ' +
          'make it usable for RFC 8705 as well — a DIFFERENT credential with ' +
          'a different registration attribute — and one certificate quietly ' +
          'doing both is how a deployment ends up unable to revoke either',
          described.extensions.map(function (one) {
            return one.name + ' (' + one.oid + ')';
          }).join(', '));
  t.check(/urn:sts-mock:application:webapp1/.test(
            JSON.stringify(described.extensions)),
          'the application\'s identifier is a URI subjectAltName, because a ' +
          'CN is a display name and a SAN is the machine-readable one');
  // **MATCHED AGAINST THE TIER'S OWN SUBJECT AND NOT AGAINST A NAME.** It read
  // `indexOf('Issuing')` until 2026-09-11, when the Issuing CAs grew names
  // that say which of the five they are — "Application Assertion CA" — and a
  // check on a word in a common name is a check on a label somebody is free to
  // change. What is actually being claimed is that the LEAF WAS SIGNED BY THE
  // BOTTOM TIER and not by the Root, so it is asserted against that tier.
  t.equal(leafCert.issuer.replace(/\n/g, ', '),
          chain.tiers[2].subject,
          'and it is signed by the ISSUING CA rather than by the Root or the ' +
          'Intermediate');

  t.log.info('=== the path check, which is what a security claim rests on ===');
  const good = await pki.verifyLeaf(REALM, leaf.certificatePem, leaf.chainPem);
  t.check(good.ok, 'the leaf this hierarchy issued builds a path to its Root',
          good.why || good.anchor);

  // A leaf presented ALONE. The missing intermediates are filled in from this
  // realm's own hierarchy, which is what lets a client send only its
  // certificate — and is why the check must not simply believe what arrived.
  const bare = await pki.verifyLeaf(REALM, leaf.certificatePem, []);
  t.check(bare.ok,
          'and so does the same leaf presented with NO chain at all — the ' +
          'missing tiers are this realm\'s own, so a client may send just its ' +
          'certificate');

  // The case the whole check exists for.
  const foreignPair = await require('../common/vendored/key_material')
    .generateKeyPair('rsa-2048');
  const foreignRoot = await x509.issueCertificate({
    subject: [{ name: 'CN', value: 'Somebody Else Root' }],
    subjectPublicKey: foreignPair.publicPem,
    signatureAlg: 'sha256-rsa',
    profile: 'root-ca',
    issuer: { privateKeyPem: foreignPair.privatePem, keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true, pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] }
    }
  });
  const foreignLeafPair = await require('../common/vendored/key_material')
    .generateKeyPair('rsa-2048');
  const foreignLeaf = await x509.issueCertificate({
    subject: [{ name: 'CN', value: 'mallory' }],
    subjectPublicKey: foreignLeafPair.publicPem,
    signatureAlg: 'sha256-rsa',
    profile: 'digital-signature',
    issuer: { certificatePem: foreignRoot.pem,
              privateKeyPem: foreignPair.privatePem, keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  const elsewhere = await pki.verifyLeaf(REALM, foreignLeaf.pem, [foreignRoot.pem]);
  t.check(!elsewhere.ok,
          'A CHAIN TO SOMEBODY ELSE\'S ANCHOR IS REFUSED. Every link of it ' +
          'verifies — it is a real hierarchy, correctly built — and it means ' +
          'nothing here. That is the check the `x5c` path rests on, and it is ' +
          'the one a "does this chain verify?" implementation gets wrong',
          elsewhere.why);
  t.check(/does not end at this service/.test(elsewhere.why || ''),
          'and the refusal says WHY rather than reporting a bad signature, ' +
          'because the signatures were all fine', elsewhere.why);

  // A leaf whose signature does not match the chain it came with. Built by
  // presenting THIS realm's leaf under SOMEBODY ELSE'S intermediate.
  const mismatched = await pki.verifyLeaf(REALM, foreignLeaf.pem,
                                          pki.chainPemFor(REALM));
  t.check(!mismatched.ok,
          'a leaf presented under an intermediate that did not sign it is ' +
          'refused', mismatched.why);

  t.log.info('=== the realm boundary, WHICH MOVED DOWN A TIER ON 2026-09-11 ===');
  // ==========================================================================
  // **THIS SECTION ASSERTED THE OPPOSITE UNTIL THAT DATE AND THE REVERSAL IS
  // THE POINT OF IT.** It read: "it is a DIFFERENT Root. A CA shared across
  // realms would be one authority vouching for several identity services,
  // which is the one thing a realm boundary exists to prevent."
  //
  // The Root is now ONE, for the whole service, by request — so that sentence
  // is false and the property it was defending has to be defended somewhere
  // else. It is: the INTERMEDIATE is per realm and unique, and `verifyLeaf()`
  // requires the path to pass through this realm's own.
  //
  // **THE SECOND ASSERTION IS UNCHANGED AND IS THE ONE THAT MATTERS.** A
  // certificate issued in one realm must not verify in another, and it still
  // does not — which is what makes this a boundary that moved rather than a
  // boundary that was removed. It is asserted FIRST here, before anything
  // about the shape, because it is the claim a reader needs to be true.
  // ==========================================================================
  const otherBuilt = await pki.buildChain(OTHER, { organisation: 'Beta' });
  t.check(otherBuilt.ok, 'a second realm builds a branch of its own',
          (otherBuilt.errors || []).join(' '));
  const crossed = await pki.verifyLeaf(OTHER, leaf.certificatePem, leaf.chainPem);
  t.check(!crossed.ok,
          'A CERTIFICATE ISSUED IN ONE REALM DOES NOT VERIFY IN ANOTHER, ' +
          'which is that sentence made checkable rather than asserted',
          crossed.why);
  t.check(/does NOT pass through/.test(crossed.why || ''),
          'and the refusal names the INTERMEDIATE rather than the anchor — ' +
          'with one Root, "it ends at our Root" is true of every leaf this ' +
          'service has ever issued, so a refusal blaming the anchor would be ' +
          'about a check that can no longer fail', crossed.why);
  t.equal(stsCrypto.stripPem(pki.trustAnchorsFor(OTHER)[0]),
          stsCrypto.stripPem(pki.trustAnchorsFor(REALM)[0]),
          'the two realms share ONE Root CA, which is what an operator ' +
          'installs once — the reversal this section records');
  const mine = pki.describe(REALM);
  const theirs = pki.describe(OTHER);
  t.check(stsCrypto.stripPem(mine.tiers[1].certificatePem) !==
          stsCrypto.stripPem(theirs.tiers[1].certificatePem),
          'and a DIFFERENT Intermediate, which is what a realm has of its own ' +
          'and is now where the boundary is');
  t.equal(mine.tiers[0].subject, theirs.tiers[0].subject,
          'the three-tier view each realm reports still ends at the same Root, ' +
          'because the Root is composed back on top of the branch rather than ' +
          'copied into it — one private key, one copy');

  t.log.info('=== the algorithm pairing, which no request can ask for ===');
  const badPair = await pki.buildChain('pki-badpair',
                                       { keyAlg: 'ec-p256',
                                         signatureAlg: 'sha256-rsa' });
  t.check(!badPair.ok,
          'an EC key asked to produce an RSA signature is REFUSED here rather ' +
          'than left to Web Crypto, which reports it as a key usage error ' +
          'naming neither the key nor the algorithm',
          (badPair.errors || []).join(' '));
  t.check(/cannot produce/.test((badPair.errors || []).join(' ')),
          'and the refusal lists what that key CAN sign with',
          (badPair.errors || []).join(' '));

  t.equal(pki.defaultSignatureAlgorithmFor('ec-p384'), 'sha384-ecdsa',
          'a P-384 key\'s default digest is SHA-384 — decided by the CURVE ' +
          'rather than by a first-non-weak scan, which would hand a P-521 key ' +
          'SHA-256: legal, verifying, and nobody\'s intention');
  t.equal(pki.defaultSignatureAlgorithmFor('ed25519'), 'ed25519',
          'and an Ed25519 key names its own algorithm, which has no digest to ' +
          'choose');

  const ec = await pki.buildChain('pki-ec', { keyAlg: 'ec-p384' });
  t.check(ec.ok, 'an EC hierarchy builds', (ec.errors || []).join(' '));
  const ecLeaf = await pki.issueSigningKeyPair('pki-ec', { identifier: 'svc' });
  t.equal(ecLeaf.issued.jwsAlg, 'ES384',
          'and its leaf signs ES384 — RFC 7518 pins the algorithm to the ' +
          'CURVE, so a P-384 key is ES384 whatever digest the certificate was ' +
          'signed with');

  t.log.info('=== a leaf may not outlive the CA that signed it ===');
  const long = await pki.issueSigningKeyPair(REALM,
                                             { identifier: 'longlived',
                                               days: 365 * 50 });
  t.check(long.ok, 'a fifty-year certificate is not refused');
  const issuing = pki.describe(REALM).tiers[2];
  t.check(new Date(long.issued.notAfter).getTime() <=
          new Date(issuing.notAfter).getTime(),
          'IT IS CLAMPED to the Issuing CA\'s own expiry rather than refused. ' +
          'The ordinary cause is a five-year Issuing CA in its fifth year, and ' +
          'an operator who asked for a year should get eleven months rather ' +
          'than an error about arithmetic',
          long.issued.notAfter + ' <= ' + issuing.notAfter);

  t.log.info('=== issuing needs a hierarchy, and says which one is missing ===');
  const none = await pki.issueSigningKeyPair('pki-empty',
                                             { identifier: 'nobody' });
  t.check(!none.ok, 'a realm with no CA cannot issue');
  t.check(/\/admin\/pki/.test((none.errors || []).join(' ')),
          'and the refusal names the page that builds one, rather than ' +
          'reporting an absence',
          (none.errors || []).join(' '));

  t.log.info('=== rebuilding replaces the BRANCH, and clearing is destructive ===');
  // **WHAT A REBUILD REPLACES IS THE BRANCH AND NOT THE ROOT, SINCE
  // 2026-09-11**, and the two halves are asserted separately because they are
  // now different claims. The Root is the service's: every other realm's
  // Intermediate is signed by it, so a build here replacing it would break
  // every chain in the process — which is the reason `ensureRoot()` never
  // replaces one and `buildRoot()` is a deliberate act of its own.
  const firstRoot = pki.trustAnchorsFor(REALM)[0];
  const firstIntermediate = pki.describe(REALM).tiers[1].certificatePem;
  const again = await pki.buildChain(REALM, { organisation: 'Acme' });
  t.check(again.ok, 'a second build succeeds', (again.errors || []).join(' '));
  t.equal(stsCrypto.stripPem(pki.trustAnchorsFor(REALM)[0]),
          stsCrypto.stripPem(firstRoot),
          'and KEEPS the Root, because every other realm\'s Intermediate is ' +
          'signed by it and replacing it here would break every chain in the ' +
          'process');
  t.check(stsCrypto.stripPem(pki.describe(REALM).tiers[1].certificatePem) !==
          stsCrypto.stripPem(firstIntermediate),
          'while REPLACING this realm\'s own Intermediate and the Issuing CAs ' +
          'under it, which is what makes everything they issued chain to ' +
          'nothing');
  const orphaned = await pki.verifyLeaf(REALM, leaf.certificatePem,
                                        leaf.chainPem);
  t.check(!orphaned.ok,
          'so everything issued from the old one chains to nothing — which is ' +
          'stated on the page rather than hidden, because there is no honest ' +
          'way to hide it and this service keeps no copy of what it issued');
  t.equal(pki.describe(REALM).issuedCount, 0,
          'and the new hierarchy has issued nothing, because the count is a ' +
          'fact about THIS hierarchy');

  const cleared = pki.clearChain(REALM);
  t.check(cleared.ok, 'the hierarchy can be removed');
  t.check(pki.describe(REALM) === null && !pki.hasChain(REALM),
          'and afterwards there is none');
  t.check(!pki.clearChain(REALM).ok,
          'clearing twice is refused rather than reporting a second success');

  t.log.info('=== where the material lives ===');
  // The one assertion about the STORE, and it is the one that says this is not
  // a store of `pki.js`'s own: what `keystore.pkiFor()` answers is what
  // `describe()` renders.
  const held = keystore.pkiFor(OTHER);
  t.check(held && held.intermediate && held.issuing,
          'a realm\'s BRANCH is held by common/keystore.js — the same module ' +
          'that holds the signing keys, in the same sts_keys row family, ' +
          'sealed under the same key-encryption key where there is one');
  t.check(String(held.intermediate.privateKeyPem || '').indexOf('PRIVATE KEY') >= 0,
          'WITH its private keys, which is the difference between what is ' +
          'stored and what describe() hands out');
  // **AND THE ROOT IS NOT IN IT, WHICH IS THE STORAGE HALF OF THE REVERSAL.**
  // One Root for the service means one copy of its private key: it lives in a
  // row of its own and `rawChainFor()` composes it back on top of each
  // branch. A Root duplicated into every realm's row would be the second
  // answer to "where does this service keep a private key" that this module's
  // placement argument exists to prevent — and the one nobody remembers to
  // rotate.
  t.check(!held.tiers,
          'and the three-tier view is NOT stored — it is composed on the way ' +
          'out, so the Root has one copy rather than one per realm');
  const serviceRow = keystore.pkiFor(pki.SERVICE_SCOPE);
  t.check(serviceRow && serviceRow.root &&
          String(serviceRow.root.privateKeyPem || '').indexOf('PRIVATE KEY') >= 0,
          'the Root lives in the SERVICE row, once, with its private key');

  t.log.info('=== the report the crypto page reads ===');
  const report = pki.report(OTHER);
  t.equal(report.tiers.length, 3, 'three tiers in the report');
  t.check(report.keyAlgorithms.length >= 7,
          'the key algorithms are read from the module that GENERATES them',
          report.keyAlgorithms.map(function (one) { return one.id; }).join(', '));
  t.check(report.signatureAlgorithms.some(function (one) { return one.weak; }),
          'and the two deliberately weak SHA-1 rows are in the list and ' +
          'MARKED, because "does my stack refuse a SHA-1 certificate?" is a ' +
          'question a debugger should be able to ask');
  // **THIS ASSERTION REVERSED ON 2026-09-11 AND IT WENT ON PASSING, WHICH IS
  // WHY IT IS WORTH A PARAGRAPH.** It used to read `/no CRL/ && /OCSP/`, and
  // the sentence it was checking said *NONE. This service publishes no CRL
  // and answers no OCSP.* The service now publishes both — and the NEW
  // sentence contains the words `no CRL` too, in the clause about what this
  // service does not CONSULT. So the old check passed, green, against prose
  // that says the opposite of what it was written to pin.
  //
  // A substring test over prose is what allowed that, so this one pins the
  // two claims SEPARATELY and pins the one that used to be here as an
  // absence: the report must say that revocation is published, must say that
  // it is not consulted, and must NOT say the old thing.
  t.check(/PUBLISHED, NOT ENFORCED/.test(report.revocation),
          'the report states that revocation is PUBLISHED — every authority ' +
          'signs a CRL and answers OCSP, which reversed on 2026-09-11',
          report.revocation);
  t.check(/\/pki\/crl\//.test(report.revocation) &&
          /\/pki\/ocsp\//.test(report.revocation),
          'and names the two addresses a client reads it from, rather than ' +
          'leaving a reader to find them inside a certificate');
  t.check(/CONSULT/.test(report.revocation) &&
          /still gets in here/.test(report.revocation),
          'and keeps the OTHER half in the same breath: this service ' +
          'publishes revocation and checks none of anybody\'s, so a ' +
          'certificate revoked here still authenticates here. Running the ' +
          'two together is the dangerous reading and the sentence exists to ' +
          'prevent it',
          report.revocation);
  t.check(!/^NONE/.test(report.revocation),
          'and the report no longer opens with NONE, which is the claim that ' +
          'reversed');

  await theIssuedKeyIsSealedAtRest(t);
}

// ===========================================================================
// AND THE ISSUED PRIVATE KEY IS SEALED WHERE IT LANDS (2026-09-10).
//
// The three CA key pairs never leave this process; the one this hierarchy
// ISSUES does, onto the application's own directory entry, because
// `common/pki.js` hands it over once and keeps no copy. That attribute was the
// last piece of private key material in this service stored in the clear, and
// it is now sealed under the SAME key-encryption key as the hierarchy it came
// from — `common/applications.js`'s SEALED_FIELDS argues it.
//
// **IN PROCESS, BECAUSE WHAT IS UNDER TEST IS THE DIFFERENCE BETWEEN TWO
// ANSWERS TO ONE READ.** Over HTTP there is exactly one surface — `fields` —
// and it hands over the PEM in both modes, which is the whole design; the
// assertion that matters is that the ENTRY holds ciphertext at the same
// moment, and nothing on the wire can see the entry. `tests/keystore.js`'s
// `keys.source=persisted` is what makes a persisting key-encryption key
// reachable without turning product mode on wholesale, and the environment
// layer is used rather than `setOverride()` because both rows are
// restart-only.
// ===========================================================================
async function theIssuedKeyIsSealedAtRest(t) {
  t.log.info('=== the issued private key, at rest ===');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-pki-seal-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });

  // WITHOUT one first, which is development mode and is the default: the PEM
  // is written as it always was. That assertion is not a formality — sealing
  // under an EPHEMERAL key would leave the certificate readable after a
  // restart and the private half permanent garbage, which is worse than clear,
  // and it is the reason this uses keystore.persists() and not
  // keystore.sealed().
  const made = applications.createApplication({
    identifier: APP, name: 'PKI Seal Probe', protocols: ['oauth2']
  });
  t.check(made.ok, 'an application to issue to', (made.errors || []).join(' '));

  applications.updateApplication(APP,
    { attribute: 'oauthAssertionPrivateKey', mode: 'set', value: PEM });
  let entry = applications.get(APP);
  t.check(!applications.isSealed(String(entry.attributes.oauthAssertionPrivateKey)),
          'in DEVELOPMENT the entry holds the PEM in the clear, because the ' +
          'key-encryption key there is ephemeral and the entry outlives it');
  t.equal(String(entry.fields.oauthAssertionPrivateKey), PEM,
          'and a reader gets what was written');

  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();

  try {
    t.check(keystore.persists(),
            'keys.source=persisted arms a key-encryption key that outlives ' +
            'the process, which is what product mode has');

    const written = applications.updateApplication(APP,
      { attribute: 'oauthAssertionPrivateKey', mode: 'set', value: PEM });
    t.check(written.ok, 'the key pair is written', (written.errors || []).join(' '));

    entry = applications.get(APP);
    const stored = String(entry.attributes.oauthAssertionPrivateKey);
    t.check(applications.isSealed(stored),
            'THE ENTRY HOLDS CIPHERTEXT. This is the assertion the whole ' +
            'change is for: an ldapsearch on TCP 389 where every bind ' +
            'succeeds, an ldif file, a database row and a backup of either ' +
            'see $aesgcm$ and not a usable signing key',
            stored.slice(0, 24));
    t.check(stored.indexOf('PRIVATE KEY') < 0,
            'and no part of the PEM survives in it');

    t.equal(String(entry.fields.oauthAssertionPrivateKey), PEM,
            'while a caller that came through this module — the console and ' +
            'GET /admin-api/applications, both behind a credential — is ' +
            'handed the PEM, because the seal protects the STORE and not the ' +
            'page an operator collects an issued credential from');

    // THE PUBLIC HALF IS UNTOUCHED, and that is a decision rather than an
    // omission: a certificate, a chain and a JWKS are what a relying party is
    // MEANT to be given, and `client_auth.js` reads the JWKS to verify what
    // this key signs. Sealing them would hide something published and break
    // the verification path in the same act.
    applications.updateApplication(APP,
      { attribute: 'oauthAssertionCertificate', mode: 'set', value: 'CERTIFICATE' });
    entry = applications.get(APP);
    t.check(!applications.isSealed(String(entry.attributes.oauthAssertionCertificate)),
            'the CERTIFICATE beside it is stored as it is — five of the six ' +
            'attributes an issue writes are public by construction and only ' +
            'the private half is sealed');

    // A WRITE TO SOMETHING ELSE MUST NOT REWRITE THE KEY IN THE CLEAR. Every
    // update re-saves the whole record, so the sealed value passes through
    // recordFromAttributes() and attributesFor() on every unrelated edit —
    // which is why view() opens and those two do not.
    applications.updateApplication(APP,
      { attribute: 'appName', mode: 'set', value: 'Renamed' });
    t.check(applications.isSealed(
              String(applications.get(APP).attributes.oauthAssertionPrivateKey)),
            'and an unrelated edit to the same entry leaves it sealed — the ' +
            'record round-trips the ciphertext, and only view() opens it');

    // AN ALREADY-SEALED VALUE IS NOT SEALED TWICE. A value copied off one
    // entry onto another through the console's `set` arrives like this, and a
    // second seal would produce something that opens to ciphertext.
    applications.updateApplication(APP,
      { attribute: 'oauthAssertionPrivateKey', mode: 'set', value: stored });
    t.equal(String(applications.get(APP).fields.oauthAssertionPrivateKey), PEM,
            'a value that is ALREADY sealed is stored as it is rather than ' +
            'sealed again, which would open to ciphertext');
  } finally {
    delete process.env.STS_KEYS_SOURCE;
    delete process.env.STS_KEYS_KEK_PROVIDER;
    delete process.env.STS_KEYS_KEK_FILE;
    keystore.reset();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = {
  name: 'pki',
  describe: 'The certificate authority: three tiers built in one act from the ' +
            'vendored profiles, a leaf that is a signing certificate and not ' +
            'a TLS one, the path check that refuses a chain to somebody ' +
            'else\'s anchor, the realm boundary, the algorithm pairing no ' +
            'request can ask for, and what is stored against what is handed out',
  run: run
};
