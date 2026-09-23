'use strict';
//
// File: pq_key_certification.js
//
// ===========================================================================
// THE POST-QUANTUM KEYS ARE ISSUED FROM THE EMBEDDED CA (2026-09-13).
//
// Until this date the eleven post-quantum signing keys per realm and the
// ML-DSA listener certificate were the only key pairs this service generated
// that were NOT leaves of `common/pki.js`'s hierarchy, and `/admin/pki` said
// so in a warning box. They are leaves now: a realm's eleven under its own
// JOSE Issuing CA, the ML-DSA listener certificate under the process TLS
// Issuing CA.
//
// **WHY IT IS HERE AND NOT IN THE PROTOCOL HALF.** Every claim below is about
// what is IN a certificate, where it chains, and which of two independent
// readings of the post-quantum constructions agrees with which — none of it is
// in any HTTP reply. The JWKS a client fetches is byte for byte what it was.
//
// What is held, in order:
//
//   A. THE TABLE. `pki.PQ_JOSE_IN_X509` names every algorithm
//      `common/pq_jose.js` signs with and no other, and each composite's
//      X.509 id carries the same domain-separator label as the JOSE one — so a
//      twelfth algorithm cannot arrive in one file and not the other.
//   B. THE WIRING. Warming a realm's keys certifies them, in that realm, and
//      in no other.
//   C. THE CROSSING IS A CHECK. A signature made by `pq_jose.js` verifies
//      under the VENDORED X.509 reading against the public key read back out
//      of the certificate. That is the independence `common/vendored/CLAUDE.md`
//      insists on being USED: two readings that disagree now fail here, where
//      before a certificate simply did not exist to disagree with. And the one
//      translation — the ECDSA half's 0x04 — is shown to matter.
//   D. REALM ISOLATION. Each leaf verifies in its realm and is refused in
//      another, by the Intermediate boundary `verifyLeaf()` already enforces.
//   E. ONLY PUBLIC HALVES CROSS, THE CERTIFICATION IS IDEMPOTENT, A REPLACED
//      KEY'S CERTIFICATE IS SUPERSEDED, AND A RENEWAL WORKS FOR THE
//      COMPOSITES — whose keys node's OpenSSL cannot read, which is why the
//      register now keeps the subject key beside each certificate.
//   F. THE ML-DSA LISTENER CERTIFICATE, in a child process (it needs
//      `tls.certificateAlgorithms` set before `tls_server.js` loads, and node
//      24's OpenSSL).
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const CHILD_FLAG = 'STS_PQ_CERT_CHILD';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'pq_key_certification',
  level: process.env.LOG_LEVEL || 'info' });

const REALM_A = 'pqcert-a';
const REALM_B = 'pqcert-b';

// node's own verifier, hop by hop, rather than `verifyLeaf()` — which is under
// test in D and would otherwise be the judge of its own case. It reads the
// ISSUER's key at every hop, which node can do for every tier here (they are
// RSA or EC); the post-quantum key is the SUBJECT of the leaf and is never
// asked for.
function chainsTo(leafPem, chainPems, anchorPem) {
  log.debug("Entering chainsTo().");
  let current = new nodeCrypto.X509Certificate(leafPem);
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

// The SubjectPublicKeyInfo, as DER, read out of a CERTIFICATE — not the one
// the register keeps beside it, which is the input to issuance and would make
// C a comparison of a value with itself.
function spkiOf(certificatePem) {
  log.debug("Entering spkiOf().");
  const pkijs = require('pkijs');
  const der = Buffer.from(String(certificatePem)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const cert = pkijs.Certificate.fromBER(new Uint8Array(der));
  log.debug("Leaving spkiOf().");
  return new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false));
}

// A composite's JOSE signature in X.509's form: the ECDSA half is R||S in JOSE
// and a DER Ecdsa-Sig-Value in X.509. The EdDSA halves are the same octets.
function x509SignatureOf(pqJose, alg, signature) {
  log.debug("Entering x509SignatureOf().");
  const x509 = require('../common/vendored/x509');
  const cfg = pqJose.COMPOSITES[alg];
  if (!cfg || pqJose.TRAD[cfg.trad].kind !== 'ec') {
    log.debug("Leaving x509SignatureOf().");
    return Buffer.from(signature);
  }
  const tradLength = pqJose.TRAD[cfg.trad].sigLen;
  const mlPart = signature.subarray(0, signature.length - tradLength);
  const tradPart = signature.subarray(signature.length - tradLength);
  log.debug("Leaving x509SignatureOf().");
  return Buffer.concat([mlPart,
                        Buffer.from(x509.ecdsaRawToDer(tradPart))]);
}

async function waitFor(predicate, ms) {
  log.debug("Entering waitFor().");
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (predicate()) {
      log.debug("Leaving waitFor(). Yes.");
      return true;
    }
    await new Promise(function (resolve) { setTimeout(resolve, 100); });
  }
  log.debug("Leaving waitFor(). Timed out.");
  return predicate();
}

function pqCertificatesIn(pki, pqJose, realmId) {
  log.debug("Entering pqCertificatesIn().");
  log.debug("Leaving pqCertificatesIn().");
  return pki.certificatesFor(realmId, 'jose').filter(function (one) {
    return pqJose.PQ_ALGS.indexOf(one.slot) >= 0;
  });
}

async function inProcess(t) {
  log.debug("Entering inProcess().");
  const pki = require('../common/pki');
  const keystore = require('../common/keystore');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const pqJose = require('../common/pq_jose');
  const pqcX509 = require('../common/vendored/pqc_x509');
  const x509 = require('../common/vendored/x509');

  await keystore.start();
  [REALM_A, REALM_B].forEach(function (id) {
    if (!realms.get(id)) {
      realms.create({ id: id, name: id });
    }
  });
  const started = await pki.start({
    realmIds: ['', REALM_A, REALM_B],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    // Ask-do-not-take, as `service_state.js` wires it: nothing here is made
    // by the realm watcher.
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    }
  });
  t.check(started.ok, 'the hierarchy is built', JSON.stringify(started));
  const root = pki.serviceRoot().certificatePem;

  // -------------------------------------------------------------------------
  t.log.info('=== A. the table names every post-quantum algorithm, and the ' +
             'labels agree ===');
  // -------------------------------------------------------------------------
  const tableAlgs = Object.keys(pki.PQ_JOSE_IN_X509).sort();
  t.equal(tableAlgs.join(','), pqJose.PQ_ALGS.slice().sort().join(','),
          'PQ_JOSE_IN_X509 names exactly the algorithms pq_jose.js signs ' +
          'with — a twelfth added to one and not the other fails here rather ' +
          'than as a key that is silently never certified');
  const labelDrift = [];
  tableAlgs.forEach(function (alg) {
    const entry = pki.PQ_JOSE_IN_X509[alg];
    const x = pqcX509.alg(entry.id);
    const jose = pqJose.COMPOSITES[alg];
    const composite = pqcX509.COMPOSITE_ALGS[entry.id];
    if (!x) {
      labelDrift.push(alg + ' → ' + entry.id + ' is not in the vendored ' +
                      'registry');
      return;
    }
    if (!!jose !== !!composite) {
      labelDrift.push(alg + ' is composite in one reading and not the other');
      return;
    }
    if (jose && jose.label !== composite.label) {
      labelDrift.push(alg + ': "' + jose.label + '" against "' +
                      composite.label + '"');
    }
    const ec = !!jose && pqJose.TRAD[jose.trad].kind === 'ec';
    if (ec !== !!entry.ecField ||
        (ec && pqJose.TRAD[jose.trad].pubLen !== 2 * entry.ecField)) {
      labelDrift.push(alg + ': ecField ' + entry.ecField + ' does not match ' +
                      'the JOSE traditional half');
    }
  });
  t.equal(labelDrift.join('; '), '',
          'and every composite maps to the X.509 id with the SAME domain ' +
          'separator — the label is what both drafts sign under, so a ' +
          'mapping to the wrong composite is a certificate over a key whose ' +
          'signatures verify as nothing');

  // -------------------------------------------------------------------------
  t.log.info('=== B. warming a realm\'s keys certifies them, there and ' +
             'nowhere else ===');
  // -------------------------------------------------------------------------
  const keys = helpers.stsKeysFor.of(REALM_A);
  t.equal(keys.realm, REALM_A, 'the fixture is a real realm\'s key set — ' +
          'an id nobody created would hand back the DEFAULT realm\'s, which ' +
          'is the trap tests/pki_hierarchy.js records');
  await helpers.warmPqKeys(REALM_A);
  const arrived = await waitFor(function () {
    return pqCertificatesIn(pki, pqJose, REALM_A).length ===
           pqJose.PQ_ALGS.length;
  }, 30000);
  const underA = pqCertificatesIn(pki, pqJose, REALM_A);
  t.check(arrived, 'ALL ELEVEN post-quantum keys are certified under ' +
          REALM_A + '\'s JOSE Issuing CA once they are made, with nobody ' +
          'asking', underA.length + ' of ' + pqJose.PQ_ALGS.length);
  t.equal(pqCertificatesIn(pki, pqJose, REALM_B).length, 0,
          'and NONE lands in ' + REALM_B + '\'s register — the certificate ' +
          'goes to the realm the keys are for');

  const jwkByAlg = {};
  (keys.pqKeys || []).forEach(function (one) {
    jwkByAlg[one.alg] = one;
  });
  let chained = 0;
  let signingOnly = 0;
  let publishedMatches = 0;
  underA.forEach(function (one) {
    if (chainsTo(one.certificatePem, one.chainPem, root)) {
      chained += 1;
    }
    const usage = x509.keyUsageOf(require('pkijs').Certificate.fromBER(
      new Uint8Array(Buffer.from(one.certificatePem
        .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'))));
    if (usage.present && usage.usages.indexOf('digitalSignature') >= 0 &&
        usage.usages.indexOf('keyEncipherment') < 0) {
      signingOnly += 1;
    }
    if (jwkByAlg[one.slot] &&
        one.subjectKeyFingerprint === pki.thumbprintOf(
          pki.pqSubjectPublicKeyPem(one.slot, jwkByAlg[one.slot].publicJwk))) {
      publishedMatches += 1;
    }
  });
  t.equal(chained, underA.length,
          'every one builds a path to the service Root — checked with ' +
          'node\'s verifier, hop by hop');
  t.equal(signingOnly, underA.length,
          'every one is a SIGNATURE certificate: digitalSignature and no ' +
          'keyEncipherment, because none of these eleven can encipher ' +
          'anything');
  t.equal(publishedMatches, underA.length,
          'and every one is over the key the realm PUBLISHES — the AKP JWK ' +
          'at /oauth2/jwks — not over some other key of the same algorithm');

  // -------------------------------------------------------------------------
  t.log.info('=== C. the crossing is a check: pq_jose.js signs, the vendored ' +
             'X.509 reading verifies against the certificate ===');
  // -------------------------------------------------------------------------
  const message = Buffer.from('post-quantum leaf of the embedded CA', 'utf8');
  let crossVerified = 0;
  let crossChecked = 0;
  const crossFailures = [];
  for (let i = 0; i < underA.length; i++) {
    const one = underA[i];
    const id = pki.PQ_JOSE_IN_X509[one.slot].id;
    const decoded = pqcX509.decodeSpki(spkiOf(one.certificatePem));
    if (!decoded || decoded.alg !== id) {
      crossFailures.push(one.slot + ' decodes as ' +
                         (decoded ? decoded.alg : 'nothing'));
      continue;
    }
    if (/^SLH-DSA/.test(one.slot)) {
      // An SLH-DSA signature is seconds of this thread. Its X.509 and JOSE
      // public keys are the same octets with no translation, so byte
      // equality is the whole of what a signature would add here.
      crossChecked += 1;
      if (Buffer.from(decoded.pub).equals(
          Buffer.from(jwkByAlg[one.slot].publicJwk.pub, 'base64url'))) {
        crossVerified += 1;
      } else {
        crossFailures.push(one.slot + ' public key differs');
      }
      continue;
    }
    crossChecked += 1;
    const signature = pqJose.sign(one.slot, jwkByAlg[one.slot].privateKey,
                                  message);
    let verified = false;
    try {
      verified = await pqcX509.verify(id,
        x509SignatureOf(pqJose, one.slot, signature), message, decoded.pub);
    } catch (e) {
      crossFailures.push(one.slot + ': ' + e.message);
    }
    if (verified) {
      crossVerified += 1;
    } else {
      crossFailures.push(one.slot + ' did not verify');
    }
  }
  t.equal(crossChecked, pqJose.PQ_ALGS.length,
          'all eleven were compared');
  t.equal(crossVerified, pqJose.PQ_ALGS.length,
          'EVERY SIGNATURE this service\'s own pq_jose.js makes verifies ' +
          'under the vendored X.509 reading against the key IN THE ' +
          'CERTIFICATE — two independent readings of the constructions ' +
          'agreeing is what ' +
          'makes the certificate true rather than merely well formed',
          crossFailures.join('; '));

  // The translation matters: the JOSE bytes of an ECDSA composite, written
  // into a certificate as they are, name a key no X.509 verifier accepts.
  const ecAlg = 'ML-DSA-44-ES256';
  const ecId = pki.PQ_JOSE_IN_X509[ecAlg].id;
  const joseBytes = Buffer.from(jwkByAlg[ecAlg].publicJwk.pub, 'base64url');
  let untranslated = false;
  try {
    untranslated = await pqcX509.verify(ecId,
      x509SignatureOf(pqJose, ecAlg,
                      pqJose.sign(ecAlg, jwkByAlg[ecAlg].privateKey, message)),
      message, joseBytes);
  } catch (e) {
    log.debug("Caught in inProcess(): " + ((e && e.message) || e));
    untranslated = false;
  }
  t.check(!untranslated,
          'and WITHOUT the 0x04 the same signature does not verify — which ' +
          'is why the one translation is written out rather than left to the ' +
          'encoder to guess');

  // -------------------------------------------------------------------------
  t.log.info('=== D. realm isolation: the Intermediate is the boundary ===');
  // -------------------------------------------------------------------------
  let inOwn = 0;
  let refusedElsewhere = 0;
  let refusedForTheRightReason = 0;
  for (let i = 0; i < underA.length; i++) {
    const one = underA[i];
    const own = await pki.verifyLeaf(REALM_A, one.certificatePem, one.chainPem);
    const other = await pki.verifyLeaf(REALM_B, one.certificatePem,
                                       one.chainPem);
    if (own.ok) {
      inOwn += 1;
    }
    if (!other.ok) {
      refusedElsewhere += 1;
      if (/Intermediate/.test(String(other.why || ''))) {
        refusedForTheRightReason += 1;
      }
    }
  }
  t.equal(inOwn, underA.length,
          'every post-quantum leaf verifies in ' + REALM_A);
  t.equal(refusedElsewhere, underA.length,
          'and is REFUSED in ' + REALM_B + ', although both realms share ' +
          'the Root it chains to');
  t.equal(refusedForTheRightReason, underA.length,
          'refused because the path does not pass through ' + REALM_B +
          '\'s own Intermediate — the rule every other leaf is held to, with ' +
          'nothing new written for these');

  // -------------------------------------------------------------------------
  t.log.info('=== E. public halves only, idempotent, superseded, renewable ' +
             '===');
  // -------------------------------------------------------------------------
  const publicOnly = (keys.pqKeys || []).map(function (one) {
    const entry = { alg: one.alg, publicJwk: one.publicJwk };
    Object.defineProperty(entry, 'privateKey', {
      get: function () {
        throw new Error('a private key was read by the certificate authority');
      }
    });
    return entry;
  });
  const serialsBefore = underA.map(function (one) {
    return one.slot + '=' + one.serialHex;
  }).sort().join(',');
  const again = await pki.certifyPqKeys(REALM_A, publicOnly);
  t.check(again.ok, 'certifying reads the PUBLIC half alone — every private ' +
          'key getter here throws, and nothing threw',
          JSON.stringify(again.failed));
  t.check(again.unchanged === pqJose.PQ_ALGS.length && again.certified === 0,
          'and a second certification of the same keys issues NOTHING — it ' +
          'is reached from generation, from startup and from a restore, and ' +
          'must not mint eleven certificates on each',
          JSON.stringify({ unchanged: again.unchanged,
                           certified: again.certified }));
  t.equal(pqCertificatesIn(pki, pqJose, REALM_A).map(function (one) {
    return one.slot + '=' + one.serialHex;
  }).sort().join(','), serialsBefore,
          'every serial is the one issued before');

  const replacement = pqJose.generate('ML-DSA-44');
  const oldMlDsa = pki.certificateFor(REALM_A, 'jose', 'ML-DSA-44');
  const swapped = await pki.certifyPqKeys(REALM_A, [{
    alg: 'ML-DSA-44',
    publicJwk: pqJose.akpPublicJwk('ML-DSA-44', replacement.pub, 'swap')
  }]);
  t.check(swapped.ok && swapped.certified === 1,
          'a DIFFERENT key in the slot is certified', JSON.stringify(swapped));
  const revocation = require('../common/pki_revocation');
  const listed = revocation.listFor(REALM_A, 'jose').some(function (one) {
    return String(one.serialHex).replace(/^0+/, '').toLowerCase() ===
           String(oldMlDsa.serialHex).replace(/^0+/, '').toLowerCase() &&
           one.reason === 'superseded';
  });
  t.check(listed,
          'and the certificate over the key it replaced goes on the JOSE ' +
          'Issuing CA\'s list as SUPERSEDED — the key it vouched for is no ' +
          'longer the one this realm signs with');
  const restored = await pki.certifyPqKeys(REALM_A, publicOnly);
  t.check(restored.ok && restored.certified === 1,
          'putting the realm\'s own key back certifies it again',
          JSON.stringify(restored));

  const beforeRenewal = pqCertificatesIn(pki, pqJose, REALM_A);
  const renewed = await pki.recertifyUseCase(REALM_A, 'jose');
  t.equal((renewed.failed || []).join('; '), '',
          'RENEWING the JOSE Issuing CA\'s certificates succeeds for all ' +
          'eleven — six of them are composites node\'s OpenSSL cannot read, ' +
          'so the renewal takes the subject key the register keeps rather ' +
          'than parsing it out of the old certificate');
  const afterRenewal = pqCertificatesIn(pki, pqJose, REALM_A);
  const sameKeyNewCert = afterRenewal.filter(function (one) {
    const was = beforeRenewal.filter(function (b) {
      return b.slot === one.slot;
    })[0];
    return was && was.serialHex !== one.serialHex &&
           was.subjectKeyFingerprint === one.subjectKeyFingerprint;
  });
  t.equal(sameKeyNewCert.length, pqJose.PQ_ALGS.length,
          'each with a NEW certificate over the SAME key — a renewal, so ' +
          'nothing verifying against the JWKS stops verifying');

  const refused = await pki.certifyPqKeys(REALM_A, [{
    alg: 'ML-DSA-44-ES256',
    publicJwk: { kty: 'AKP', alg: 'ML-DSA-44-ES256',
                 pub: Buffer.alloc(1312 + 65, 4).toString('base64url') }
  }]);
  t.check(!refused.ok && /x \|\| y/.test((refused.failed || []).join(' ')),
          'an ECDSA half that is not the JOSE x || y length is REFUSED by ' +
          'name rather than guessed at', JSON.stringify(refused.failed));

  const withSet = await pki.certifyKeySet(REALM_A, keys);
  t.check(withSet.ok,
          'certifyKeySet() — startup and a restored set — includes the ' +
          'post-quantum keys where the set holds them, and fails none',
          JSON.stringify(withSet.failed));
  log.debug("Leaving inProcess().");
}

// ---------------------------------------------------------------------------
// F. THE ML-DSA LISTENER CERTIFICATE. `tls.certificateAlgorithms` is read when
// `tls_server.js` loads, so the setting has to be in the environment of a
// process that has not loaded it yet — which this one may well have.
// ---------------------------------------------------------------------------
async function childBody() {
  log.debug("Entering childBody().");
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const stsCrypto = require('../common/crypto');
  if (!stsCrypto.mlDsaAvailable()) {
    process.stdout.write('PQ-CERT-CHILD ' +
      JSON.stringify({ unavailable: true }) + '\n');
    log.debug("Leaving childBody(). No ML-DSA in this runtime.");
    return;
  }
  const tls = require('../tls/tls_server');
  await keystore.start();
  await pki.start({ realmIds: [''] });
  const first = tls.serverCertificateChains();
  const firstRoot = pki.serviceRoot().certificatePem;
  // Replace the Root underneath the listener, as `build-root` does.
  const rebuilt = await pki.buildRoot({});
  const reconciled = await tls.reconcileWithHierarchy();
  const second = tls.serverCertificateChains();
  process.stdout.write('PQ-CERT-CHILD ' + JSON.stringify({
    first: first, firstRoot: firstRoot, rebuilt: !!(rebuilt && rebuilt.ok),
    reconciled: reconciled, second: second,
    secondRoot: pki.serviceRoot().certificatePem,
    anchors: tls.trustAnchorPems()
  }) + '\n');
  log.debug("Leaving childBody().");
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.STS_TLS_CERT_ALGS = 'rsa,ml-dsa-65';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: path.resolve(__dirname, '..'), env: clean, encoding: 'utf8',
    timeout: 240000, maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('PQ-CERT-CHILD ') === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1200) };
  }
  log.debug("Leaving spawnChild().");
  return JSON.parse(line.slice('PQ-CERT-CHILD '.length));
}

function theListener(t, got) {
  log.debug("Entering theListener().");
  t.log.info('=== F. the ML-DSA listener certificate is a leaf of the TLS ' +
             'Issuing CA ===');
  if (got.error) {
    t.bad('the listener child did not run', got.error);
    log.debug("Leaving theListener().");
    return;
  }
  if (got.unavailable) {
    t.check(true, 'this runtime has no ML-DSA (node ' + process.versions.node +
            ', OpenSSL ' + process.versions.openssl + '; it needs 3.5, which ' +
            'is node 24 — the Dockerfile pins 24.16.0), so the listener half ' +
            'did not run here');
    t.log.warn('NOT CHECKED HERE: the ML-DSA listener certificate. Run ' +
               './run-tests.sh, or use node 24.');
    log.debug("Leaving theListener().");
    return;
  }
  const mlDsa = function (list) {
    log.debug("Entering mlDsa().");
    log.debug("Leaving mlDsa().");
    return (list || []).filter(function (one) {
      return one.algorithm === 'ml-dsa-65';
    })[0];
  };
  const before = mlDsa(got.first);
  t.check(before && before.certified,
          'the ML-DSA certificate beside the RSA one is CERTIFIED at startup ' +
          '— it was the one key pair on these sockets still self-signed',
          JSON.stringify(before && { certified: before.certified }));
  t.check(before && chainsTo(before.certPem, before.chainPem, got.firstRoot),
          'and it builds a path to the service Root, so one anchor covers ' +
          'whichever certificate OpenSSL hands a client');
  const read = before && new nodeCrypto.X509Certificate(before.certPem);
  t.check(read && read.publicKey.asymmetricKeyType === 'ml-dsa-65' &&
          read.issuer !== read.subject,
          'OpenSSL reads it as an ML-DSA-65 key with an issuer that is not ' +
          'itself', read ? read.issuer.replace(/\n/g, ', ') : '');
  t.check(got.rebuilt && got.reconciled === true,
          'replacing the Root makes the listener reconcile');
  const after = mlDsa(got.second);
  t.check(after && after.fingerprint256 !== before.fingerprint256 &&
          chainsTo(after.certPem, after.chainPem, got.secondRoot),
          'and the ML-DSA certificate is RE-ISSUED under the new Root with ' +
          'it, not only the RSA one — a post-quantum client is handed it by ' +
          'OpenSSL\'s choice rather than by anybody\'s');
  t.check((got.anchors || []).indexOf(got.secondRoot) >= 0,
          'and the Root is what the listener publishes as its anchor');
  log.debug("Leaving theListener().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await inProcess(t);
  } finally {
    // `npm test` runs every file in ONE process, and two later files assert
    // that only the default realm is left. A realm's removal purges its stores,
    // so nothing this file certified outlives it either.
    const realms = require('../common/realms');
    [REALM_A, REALM_B].forEach(function (id) {
      if (realms.get(id)) {
        realms.remove(id);
      }
    });
  }
  theListener(t, spawnChild());
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function () {
    process.exit(0);
  }, function (e) {
    process.stderr.write(String((e && e.stack) || e) + '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'pq_key_certification',
  describe: 'The eleven post-quantum signing keys per realm and the ML-DSA ' +
            'listener certificate are leaves of the embedded CA: every ' +
            'algorithm mapped, certified on generation in its own realm, ' +
            'cross-verified between the two independent readings, refused in ' +
            'another realm, public halves only, idempotent, superseded when ' +
            'replaced, and renewable for the composites',
  run: run
};
