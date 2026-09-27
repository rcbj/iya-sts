'use strict';
// ===========================================================================
// tests/vc_jsonld.js — THE CLOSED JSON-LD LOADER AND RDFC-1.0 (#194-#196,
// 2026-09-26).
//
// oid4vc/vc_jsonld.ts answers the RDFC cryptosuites' contexts from files it
// ships and fetches nothing. Four claims:
//
//   A. Every context file is byte for byte the document its URL served on
//      2026-09-26 — each held to the SHA-256 the module's header records —
//      and the VC 2.0 context hashes to the digests the VC Data Model's own
//      relatedResource example carries (its test suite's fixtures).
//   B. A context it does not hold is REFUSED with the URL named, never
//      fetched; a redefined protected term is refused in safe mode.
//   C. RDFC-1.0 over it reproduces the Data Integrity ECDSA specification's
//      canonical document and proof configuration for its P-256 and P-384
//      vectors (fetched into the tests image with the W3C suites,
//      tests/vc-suites/fetch-suites.sh).
//   D. A value with a base direction canonicalizes (rdfDirection
//      i18n-datatype) rather than being refused as lossy.
// ===========================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'vc_jsonld_test',
  level: process.env.LOG_LEVEL || 'info' });

const SUITES = process.env.STS_VC_SUITES_DIR || '/opt/vc-suites';
const VECTORS = path.join(SUITES, 'vc-di-ecdsa-test-suite', 'tests', 'input',
                          'vc-di-ecdsa', 'TestVectors');

// The hashes oid4vc/vc_jsonld.ts's header records.
const HASHES = {
  'credentials_examples_v2.json':
    '57393fbc69d6efb9b9b5dc9cb6b9880b0944360abfe2eaf459c9e58cf2279d7c',
  'data_integrity_v1.json':
    'b5d829bd09aa7c42abc6efa0c8ed7635313b5487f37ccfce3ecd149ca9418554',
  'data_integrity_v2.json':
    '67f21e6e33a6c14e5ccfd2fc7865f7474fb71a04af7e94136cb399dfac8ae8f4',
  'multikey_v1.json':
    'ba2c182de2d92f7e47184bcca8fcf0beaee6d3986c527bf664c195bbc7c58597',
  'did_v1.json':
    '4f3eae5568c9c5f036a082088f9e192019ee06faa78973c87ff91d5421b88dad',
  'cid_v1.json':
    'ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85',
  'security_v1.json':
    'abaf97e107d1925503c433dcaf3ffd2831697cacc1ed2a293e1bc8030d5bcb47',
  'security_v2.json':
    '611bd81151d5efe53ec9aed78f5a813e577287bc9451ee26d6879b1b8b46bc3b',
  'ed25519_2020_v1.json':
    'b9e1ab971fd8bf2c7553e0c4a9438e0b9450afde1ea1ca5b2492368b9f549588',
  'jws_2020_v1.json':
    'd648e05ddc6577827ca2bfd5e931f53e9ebc6e52a57a8da81df4ec8c46ffcd1e',
  'status_list_2021_v1.json':
    '6dd06a52bedb771e059c1083ba8ba7848dce22f6b4a8cfa0b98ba3fc188870e4',
  'citizenship_v4rc1.json':
    '5038c7383afd7ab2158f1b997913a8f60978a0abcf96e0b0d08e29f146d2db1e'
};

async function rejects(fn) {
  log.debug("Entering rejects().");
  try {
    await fn();
  } catch (e) {
    log.debug("Caught in rejects(): " + ((e && e.message) || e));
    log.debug("Leaving rejects(). It threw.");
    return String((e && e.message) || e);
  }
  log.debug("Leaving rejects(). It did not throw.");
  return '';
}

async function run(t) {
  log.debug("Entering run().");
  const jl = require('../oid4vc/vc_jsonld');

  t.log.info('=== A. the contexts are what their URLs served ===');
  const dir = path.join(__dirname, '..', 'oid4vc', 'contexts');
  const files = fs.readdirSync(dir).filter(function (f) {
    return /\.json$/.test(f);
  }).sort();
  t.check(files.join(',') === Object.keys(HASHES).sort().join(','),
          'A1. oid4vc/contexts holds exactly the files the header lists',
          files.join(', '));
  Object.keys(HASHES).forEach(function (f) {
    const sum = crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(dir, f))).digest('hex');
    t.check(sum === HASHES[f], 'A2. ' + f + ' has its recorded SHA-256', sum);
  });
  const v2 = jl.resourceBytes('https://www.w3.org/ns/credentials/v2');
  t.check(!!v2 && crypto.createHash('sha384').update(v2).digest('base64') ===
          'l/HrjlBCNWyAX91hr6LFV2Y3heB5Tcr6IeE4/Tje8YyzYBM8IhqjHWiWpr8+ZbYU',
          'A3. the VC 2.0 context is the bytes the VCDM\'s relatedResource ' +
          'digestSRI names');
  t.check(jl.knownContexts().length === 15,
          'A4. fifteen contexts are held', String(jl.knownContexts().length));

  t.log.info('=== B. nothing is fetched ===');
  const unknown = await rejects(function () {
    return jl.canonize({ '@context': ['https://www.w3.org/ns/credentials/v2',
                                      'https://example.com/contexts/v1'],
                         type: ['VerifiableCredential'] });
  });
  t.check(/https:\/\/example\.com\/contexts\/v1/.test(unknown) &&
          /fetches none/.test(unknown),
          'B1. an unknown context is refused with its URL named', unknown);
  const redefined = await rejects(function () {
    return jl.expand({ '@context': ['https://www.w3.org/ns/credentials/v2',
      { VerifiableCredential: 'https://example.org/#Bad' }],
      type: ['VerifiableCredential'] });
  });
  t.check(/protected/i.test(redefined),
          'B2. redefining a protected term is refused', redefined);

  t.log.info('=== C. the ECDSA specification\'s canonical forms ===');
  const unsigned = JSON.parse(fs.readFileSync(path.join(VECTORS,
                                                        'unsigned.json')));
  for (const curve of ['P256', 'P384']) {
    const base = path.join(VECTORS, 'ecdsa-rdfc-2019-' + curve.toLowerCase());
    const want = fs.readFileSync(path.join(base, 'canonDocECDSA' + curve +
                                           '.txt'), 'utf8');
    const got = await jl.canonize(unsigned);
    t.check(got === want, 'C1. the unsigned credential canonicalizes as ' +
            'the ' + curve + ' vector does');
    const config = JSON.parse(fs.readFileSync(path.join(base,
      'proofConfigECDSA' + curve + '.json')));
    const wantConfig = fs.readFileSync(path.join(base, 'proofCanonECDSA' +
                                                 curve + '.txt'), 'utf8');
    t.check(await jl.canonize(config) === wantConfig,
            'C2. the ' + curve + ' proof configuration canonicalizes as the ' +
            'vector does');
  }

  t.log.info('=== D. a base direction ===');
  const directed = await jl.canonize({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'], issuer: 'did:example:issuer',
    name: { '@value': 'Name', '@language': 'en', '@direction': 'ltr' },
    credentialSubject: { id: 'did:example:subject' } });
  t.check(/https:\/\/www\.w3\.org\/ns\/i18n#en_ltr/.test(directed),
          'D1. a directed value is an i18n-datatype literal, not refused');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_jsonld',
  describe: 'the closed JSON-LD loader: the vendored contexts held to their ' +
            'hashes, nothing fetched, RDFC-1.0 matching the ECDSA ' +
            'specification\'s canonical vectors',
  run: run
};
