'use strict';
//
// File: pqc_support.js
//
// ===========================================================================
// THE POST-QUANTUM ICON ON /admin/pki AND /admin/keys: THE CLASSIFIER AND THE
// MARK (2026-09-13).
//
// `common/pqc_support.js` decides whether a key pair uses a post-quantum
// algorithm and `admin-ui/pqc_badge.js` draws the icon that says so. What is
// held here is what a page cannot be asked:
//
//   A. EVERY ALGORITHM, IN EVERY SPELLING. The pages name keys four ways — a
//      JOSE `alg`, a key-material id, a node key type and an OID — and every
//      post-quantum algorithm this service or its vendored registry knows must
//      come out marked, with the right KIND, while every classical spelling
//      must come out unmarked. A table, because a page shows only the keys it
//      happens to hold.
//   B. A CERTIFICATE IS CLASSIFIED BY ITS KEY, NOT ITS SIGNATURE. An ML-DSA key
//      certified by an RSA CA is marked; an EC key certified by an ML-DSA CA
//      is not; an EC key whose certificate carries an alternative ML-DSA key is
//      a HYBRID and not a post-quantum key. None of the last two is a
//      certificate this service issues by itself, which is why they are built
//      here.
//   C. THE MARK, in a CHILD PROCESS because the renderer requires the console:
//      nothing for a classical key, one labelled image per kind, the hybrid
//      drawn weaker, no script, and a label escaped.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives.
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const CHILD_FLAG = 'STS_PQC_SUPPORT_CHILD';
const REALM = 'pqcbadge-a';

const log = require('bunyan').createLogger({ name: 'pqc_support',
  level: process.env.LOG_LEVEL || 'info' });

async function inProcess(t) {
  log.debug("Entering inProcess().");
  const support = require('../common/pqc_support');
  const pqJose = require('../common/pq_jose');
  const pqcX509 = require('../common/vendored/pqc_x509');
  const x509 = require('../common/vendored/x509');
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const realms = require('../common/realms');

  // -------------------------------------------------------------------------
  t.log.info('=== A. every algorithm, in every spelling ===');
  // -------------------------------------------------------------------------
  const wrong = [];
  const expect = function (name, kind) {
    log.debug("Entering expect().");
    const got = support.ofAlgorithm(name);
    const gotKind = got ? got.kind : null;
    if (gotKind !== kind) {
      wrong.push(String(name) + ' → ' + gotKind + ' (expected ' + kind + ')');
    }
    log.debug("Leaving expect().");
  };
  pqJose.PQ_ALGS.forEach(function (alg) {
    expect(alg, pqJose.COMPOSITES[alg] ? 'composite' : 'pq');
  });
  pqcX509.algIds('sig').forEach(function (id) {
    const kind = pqcX509.alg(id).family === 'Composite ML-DSA'
      ? 'composite' : 'pq';
    expect(id, kind);
    expect(id.toLowerCase(), kind);
    expect(pqcX509.alg(id).oid, kind);
  });
  pqcX509.algIds('kem').forEach(function (id) {
    expect(id, 'kem');
    expect(pqcX509.alg(id).oid, 'kem');
  });
  ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'].forEach(function (nodeType) {
    expect(nodeType, 'pq');
  });
  ['RS256', 'PS512', 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA', 'Ed25519',
   'Ed448', 'rsa-2048', 'rsa-4096', 'ec-p256', 'ec-p521', 'ed25519', 'P-256',
   'secp256k1', 'sha256-rsa', 'sha256-ecdsa', '1.2.840.113549.1.1.1',
   '1.2.840.10045.2.1', '1.3.101.112', 'rsa', '', null, undefined
  ].forEach(function (classical) {
    expect(classical, null);
  });
  t.equal(wrong.join('; '), '',
          'every post-quantum algorithm is marked with the right kind in ' +
          'every spelling — JOSE, key-material id, node key type, OID — and ' +
          'every classical spelling is not');
  const composite = support.ofAlgorithm('ML-DSA-44-Ed25519');
  t.check(composite && /ML-DSA-44/.test(composite.label) &&
          /Ed25519/.test(composite.label),
          'a composite names BOTH halves, because "post-quantum" alone would ' +
          'hide the classical half', composite && composite.label);
  t.check(/FIPS 204/.test(support.sentence(support.ofAlgorithm('ML-DSA-65')))
          && /signs nothing/.test(support.sentence(
            support.ofAlgorithm('ML-KEM-768'))),
          'the sentence names the standard, and says a KEM key signs nothing');

  // -------------------------------------------------------------------------
  t.log.info('=== B. a certificate is classified by its key ===');
  // -------------------------------------------------------------------------
  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: [REALM] });
  await pki.ensureScope(REALM);
  t.equal(support.ofCertificate(pki.serviceRoot().certificatePem), null,
          'the RSA Root CA is not marked');
  const pqAlgs = ['ML-DSA-44', 'ML-DSA-65-ES256'];
  await pki.certifyPqKeys(REALM, pqAlgs.map(function (alg) {
    return { alg: alg,
             publicJwk: pqJose.akpPublicJwk(alg, pqJose.generate(alg).pub,
                                            'badge') };
  }));
  const pure = support.ofCertificate(
    pki.certificateFor(REALM, 'jose', 'ML-DSA-44').certificatePem);
  const comp = support.ofCertificate(
    pki.certificateFor(REALM, 'jose', 'ML-DSA-65-ES256').certificatePem);
  t.check(pure && pure.kind === 'pq',
          'an ML-DSA-44 key certified by an RSA Issuing CA IS marked — the ' +
          'key decides, not the signature');
  t.check(comp && comp.kind === 'composite' && /P-256/.test(comp.label),
          'a composite certificate is marked as a composite, naming its ' +
          'classical half', comp && comp.label);

  const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ecPublic = ec.publicKey.export({ type: 'spki', format: 'pem' });
  const pqIssuer = await pqcX509.generateKeyPair('ML-DSA-44');
  const underPq = await x509.issueCertificate({
    subject: [{ name: 'CN', value: 'EC key under an ML-DSA issuer' }],
    subjectPublicKey: ecPublic,
    signatureAlg: 'ml-dsa-44',
    issuerPrivateKey: pqcX509.privatePem('ML-DSA-44', pqIssuer.priv),
    profile: 'digital-signature'
  });
  t.equal(support.ofCertificate(underPq.pem), null,
          'an EC key certified by an ML-DSA issuer is NOT marked — a ' +
          'post-quantum signature on a certificate does not make its key ' +
          'post-quantum');

  const altKey = await pqcX509.generateKeyPair('ML-DSA-65');
  const hybrid = await x509.issueCertificate({
    subject: [{ name: 'CN', value: 'hybrid' }],
    subjectPublicKey: ecPublic,
    subjectAltPublicKey: pqcX509.publicPem('ML-DSA-65', altKey.pub),
    signatureAlg: 'sha256-ecdsa',
    issuerPrivateKey: ec.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    profile: 'digital-signature'
  });
  const hybridInfo = support.ofCertificate(hybrid.pem);
  t.check(hybridInfo && hybridInfo.kind === 'hybrid' &&
          /ML-DSA-65/.test(hybridInfo.label),
          'an EC key whose certificate carries an alternative ML-DSA-65 key ' +
          'is a HYBRID — marked, and not as a post-quantum key',
          JSON.stringify(hybridInfo));
  t.equal(support.ofCertificate('-----BEGIN CERTIFICATE-----\nAAAA\n' +
                                '-----END CERTIFICATE-----'), null,
          'a certificate that will not parse is not marked');
  const precedence = support.of({ certificatePem: hybrid.pem,
                                  algorithms: ['ec-p256'] });
  t.check(precedence && precedence.kind === 'hybrid' &&
          support.of({ algorithms: ['rsa-2048', 'ml-dsa-87'] }).kind ===
            'pq' &&
          support.of({ algorithms: ['rsa-2048'] }) === null,
          'the certificate is asked first — only it can see a hybrid — and ' +
          'then each name in order');
  log.debug("Leaving inProcess().");
}

async function childBody() {
  log.debug("Entering childBody().");
  const badge = require('../admin-ui/pqc_badge');
  process.stdout.write('PQCBADGE ' + JSON.stringify({
    none: badge.badge(null),
    classical: badge.badgeFor({ algorithms: ['RS256'] }),
    pq: badge.badgeFor({ algorithms: ['ML-DSA-65'] }),
    composite: badge.badgeFor({ algorithms: ['ML-DSA-44-Ed25519'] }),
    kem: badge.badgeFor({ algorithms: ['ML-KEM-768'] }),
    hybrid: badge.badge({ kind: 'hybrid', label: 'alternative ML-DSA-65 key',
                          standard: 'X.509 (2019) clause 9.8' }),
    hostile: badge.badge({ kind: 'pq', label: '"><script>alert(1)</script>',
                           standard: '' }),
    legend: badge.legend()
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
  clean.LOG_LEVEL = 'fatal';
  clean.STS_TLS_PORT = '0';
  clean.STS_MTLS_PORT = '0';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: path.resolve(__dirname, '..'), env: clean, encoding: 'utf8',
    timeout: 120000, maxBuffer: 16 * 1024 * 1024 });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('PQCBADGE ') === 0;
  })[0];
  log.debug("Leaving spawnChild().");
  return line ? JSON.parse(line.slice('PQCBADGE '.length))
    : { error: 'the child produced no result (exit ' + result.status + '): ' +
               String(result.stderr || '').slice(-1200) };
}

function theMark(t, got) {
  log.debug("Entering theMark().");
  t.log.info('=== C. the mark ===');
  if (got.error) {
    t.bad('the renderer child did not run', got.error);
    log.debug("Leaving theMark().");
    return;
  }
  t.check(got.none === '' && got.classical === '',
          'a classical key gets nothing at all, so a row can concatenate the ' +
          'mark unconditionally');
  const one = function (html, word, sentence) {
    log.debug("Entering one().");
    log.debug("Leaving one().");
    return /role="img"/.test(html) &&
           /<svg[^>]*aria-hidden="true"/.test(html) &&
           html.indexOf('>' + word + '</span>') >= 0 &&
           new RegExp('aria-label="[^"]*' + sentence).test(html) &&
           new RegExp('title="[^"]*' + sentence).test(html);
  };
  t.check(one(got.pq, 'PQC', 'Post-quantum key pair: ML-DSA-65') &&
          one(got.composite, 'PQC+', 'Composite post-quantum key pair') &&
          one(got.kem, 'PQC KEM', 'key-establishment key') &&
          one(got.hybrid, 'PQC alt', 'Hybrid: a classical key'),
          'each of the four kinds is one labelled image — an icon, its ' +
          'word, and the sentence as both tooltip and accessible name');
  t.check(/dashed/.test(got.hybrid) && !/dashed/.test(got.pq),
          'the hybrid is drawn visibly weaker, because its key is not ' +
          'post-quantum');
  const all = [got.pq, got.composite, got.kem, got.hybrid, got.legend]
    .join('');
  t.check(!/<script/i.test(all) && !/\son[a-z]+=/i.test(all) &&
          !/<img\b/i.test(all) && !/url\(/i.test(all),
          'no script, no event handler and no image request — an inline SVG ' +
          'on pages that are script-src \'none\'');
  t.check(got.hostile.indexOf('<script>') < 0 &&
          got.hostile.indexOf('&lt;script&gt;') >= 0,
          'a label is escaped in the tooltip and the accessible name');
  t.check((got.legend.match(/class="pqc-badge /g) || []).length === 4,
          'the legend draws all four marks with the renderer itself, so it ' +
          'cannot describe a mark the rows do not use');
  log.debug("Leaving theMark().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await inProcess(t);
  } finally {
    // `realm_isolation.js` asserts only the default realm is left.
    const realms = require('../common/realms');
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
  }
  theMark(t, spawnChild());
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
  name: 'pqc_support',
  describe: 'The post-quantum icon on /admin/pki and /admin/keys: every ' +
            'algorithm in every spelling, a certificate classified by its ' +
            'key rather than its signature, the hybrid kept apart, and a ' +
            'labelled no-script mark',
  run: run
};
