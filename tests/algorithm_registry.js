// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: algorithm_registry.js
//
// ---------------------------------------------------------------------------
// THE ONE SIGNATURE-ALGORITHM REGISTRY (#1368, phase 1, #1374).
//
// Every table of algorithms became a view of `common/crypto_impl/
// algorithm_registry.js` and was to change no member and no order. So:
//
//   1. each view's bytes are PINNED. Each hash below was computed from the
//      table as it stood in the tree BEFORE the registry existed, so this
//      holds the views to what they replaced and not to themselves. A change
//      to one is a change to what this service signs, accepts or publishes:
//      make it on purpose, and update the pin in the same commit;
//   2. the modules' tables ARE the views: what they export equals them, and
//      the private ones are assigned from the registry in their source;
//   3. the engines' own tables agree: `pq_jose.js`, `x509.js`, `xmldsig.js`;
//   4. a row and the recorded lists cannot drift: a spelling in one is in the
//      other, so a row added to the registry alone fails here;
//   5. every setting that names an algorithm names a row;
//   6. the two orders stay two orders: preference order is not what an
//      unconfigured service does (the correction #1368's review made).
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');

const PINS = {
  joseTable: '1738c651c7a317b863a2fb3472da33e6',
  coseTable: 'd74511c3a94532e3077a963cee5feeb1',
  coseNames: '85ff1cb6ef8e0f9e30028dbf072411be',
  insecureCoseIds: '16664fafdd5eaab7c6b4ead9656ff7c0',
  coseStatus: 'e9068b40e23af5709dfc807f2f637597',
  coseMdoc: '1cbe09c75ffedeffcc47a0bc8e3bedfa',
  xmlSignatureMethods: '682b1645360a11078960c86e44f21c74',
  xmlSignaturesRefused: '1c5e033a2191d97f2fe56b562d204e29',
  xmlDigestMethods: 'accf42b61b00d4c0bac63ec97446db15',
  xmlDigestsRefused: 'f9415e7e4b824267e1a21b891e8f3d8e',
  httpSignatureAlgorithms: 'cffcb869d804ddb12b418af683cfd61b',
  cmsSignatures: '616b0a451439b34e9c8206f43b9b7c4a',
  dkimAlgorithms: '0824b7f8b92696968882d606083a5c95',
  mlDsaOids: 'b4ad87c0795b89c6e4aa167e160a7f76',
  rawFamilies: '8b386ee676352efa9c9864447424ac04',
  asymmetricJoseNames: '2ca9aff27012da1fe74756af81cc477c',
  postQuantumJoseNames: 'b88d5d40ea12feb4621587e4cc05ecdd',
  pkiSignatureAlgorithms: '54514332a08071aa3757e83e3a603029',
  pkiKeyAlgorithms: '8151f8f7dfd775d0dc9b55cfda36e3b8'
};

// The settings that name JOSE algorithms in a list of their own.
const JOSE_SETTINGS = ['keys.signingAlgorithms',
  'oauth2.accessTokenSigningAlg', 'oauth2.httpSignatureResponseAlg',
  'oauth2.signedMetadataAlgorithm', 'federation.jwtAlgorithms',
  'wstrust.jwtAlgorithm', 'oid4vci.credentialSigningAlgorithm',
  'oid4vp.x509SigningAlgorithm', 'oid4vp.requestObjectSigningAlgorithm',
  'oidfed.signingAlg', 'did.personKeyAlgorithm', 'ssf.signingAlgorithm'];

function pin(value) {
  return nodeCrypto.createHash('sha256').update(JSON.stringify(value))
    .digest('hex').slice(0, 32);
}

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function source(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

module.exports = {
  name: 'algorithm_registry',
  run: function run(t) {
    const registry = require('../common/crypto_impl/algorithm_registry');
    const stsCrypto = require('../common/crypto');
    const config = require('../common/config');
    const webauthn = require('../authn/webauthn');
    const pqJose = require('../common/pq_jose');
    const keyMaterial = require('../common/crypto_impl/key_material');
    const x509 = require('../common/crypto_impl/x509');
    const xmldsig = require('../common/crypto_impl/xmldsig');
    const pqc = require('../common/pqc_support');
    const statusCodec = require('../oid4vc/vc_status_codec');
    const signerGroups = require('../common/signer_groups');

    // 1. The bytes, against the tree before the registry.
    const views = {
      joseTable: registry.joseTable(nodeCrypto.constants),
      coseTable: registry.coseTable(),
      coseNames: registry.coseNames(),
      insecureCoseIds: registry.insecureCoseIds(),
      coseStatus: registry.coseIdsByName('cose.status'),
      coseMdoc: registry.coseIds('cose.mdoc'),
      xmlSignatureMethods: registry.xmlSignatureMethods(),
      xmlSignaturesRefused: registry.xmlSignaturesRefused(),
      xmlDigestMethods: registry.xmlDigestMethods(),
      xmlDigestsRefused: registry.xmlDigestsRefused(),
      httpSignatureAlgorithms: registry.httpSignatureAlgorithms(),
      cmsSignatures: registry.cmsSignatures(),
      dkimAlgorithms: registry.dkimAlgorithms(),
      mlDsaOids: registry.mlDsaOids(),
      rawFamilies: registry.RAW_SIGNATURE_FAMILIES,
      asymmetricJoseNames: registry.asymmetricJoseNames(),
      postQuantumJoseNames: registry.postQuantumJoseNames(),
      pkiSignatureAlgorithms: registry.pkiSignatureAlgorithms(),
      pkiKeyAlgorithms: registry.pkiKeyAlgorithms()
    };
    Object.keys(PINS).forEach(function (name) {
      t.check(pin(views[name]) === PINS[name],
        'the ' + name + ' view has the members and order it had before the ' +
        'registry', pin(views[name]));
    });

    // 2. The modules' tables are the views.
    t.check(same(stsCrypto.JWS_ALGS, views.joseTable),
      'crypto.js JWS_ALGS is the view');
    t.check(same(stsCrypto.JWS_SIGNING_ALGS, registry.joseNames()),
      'crypto.js JWS_SIGNING_ALGS is every JOSE row, in today\'s order');
    t.check(same(stsCrypto.JWS_ASYMMETRIC_ALGS, views.asymmetricJoseNames),
      'crypto.js JWS_ASYMMETRIC_ALGS is the asymmetric rows');
    t.check(same(stsCrypto.COSE_SIGNATURE_ALGS, views.coseTable),
      'crypto.js COSE_SIGNATURE_ALGS is the view');
    t.check(same(stsCrypto.DKIM_ALGORITHMS, views.dkimAlgorithms),
      'crypto.js DKIM_ALGORITHMS is the view');
    t.check(same(stsCrypto.ML_DSA_OIDS, views.mlDsaOids),
      'crypto.js ML_DSA_OIDS is the view');
    t.check(same(stsCrypto.RAW_SIGNATURE_FAMILIES, views.rawFamilies),
      'crypto.js RAW_SIGNATURE_FAMILIES is the view');
    t.check(same(stsCrypto.PKINIT_CMS_SIGNATURES, views.cmsSignatures),
      'crypto.js PKINIT_CMS_SIGNATURES is the view');
    t.check(same(webauthn.COSE_ALGS, views.coseNames),
      'webauthn.js COSE_ALGS is the view');
    t.check(same(webauthn.INSECURE_COSE_ALGS, views.insecureCoseIds),
      'webauthn.js INSECURE_COSE_ALGS is the view');
    t.check(same(statusCodec.COSE_ALGS, views.coseStatus),
      'vc_status_codec COSE_ALGS is the status consumer\'s view');
    [['common/crypto.js', 'XML_SIGNATURE_METHODS', 'xmlSignatureMethods'],
     ['common/crypto.js', 'XML_SIGNATURE_REFUSED', 'xmlSignaturesRefused'],
     ['common/crypto.js', 'XML_DIGEST_METHODS', 'xmlDigestMethods'],
     ['common/crypto.js', 'XML_DIGEST_REFUSED', 'xmlDigestsRefused'],
     ['common/crypto.js', 'HTTP_SIGNATURE_ALGORITHMS',
      'httpSignatureAlgorithms'],
     ['common/config.js', 'PKI_KEY_ALGORITHMS', 'pkiKeyAlgorithms'],
     ['common/config.js', 'PKI_SIGNATURE_ALGORITHMS',
      'pkiSignatureAlgorithms'],
     ['common/config.js', 'SET_SIGNING_ALGORITHMS', 'asymmetricJoseNames'],
     ['common/config.js', 'VC_PQ_SIGNING_ALGS', 'postQuantumJoseNames']
    ].forEach(function (row) {
      t.check(source(row[0]).indexOf('const ' + row[1] +
        ' = algorithmRegistry.' + row[2] + '(') >= 0,
      row[0] + ' assigns ' + row[1] + ' from the registry');
    });
    t.check(source('oid4vc/vc_mdoc.ts').indexOf(
      'algorithmRegistry.coseIds(\'cose.mdoc\')') >= 0,
      'vc_mdoc.ts reads its own COSE list from the registry');
    const rsaPair = signerGroups.PAIRS && signerGroups.PAIRS[0];
    if (rsaPair) {
      t.check(same(rsaPair.jwsAlgs, ['RS256', 'RS384', 'RS512', 'PS256',
        'PS384', 'PS512']), 'the RSA signer group signs the RS and PS rows',
      JSON.stringify(rsaPair.jwsAlgs));
    }

    // Each COSE consumer keeps its own set: a spec bounds it, not the surface.
    t.check(views.coseMdoc.every(function (id) {
      return registry.bySpelling('cose', id).keyKind !== 'rsa';
    }), 'mdoc takes no RSA (ISO/IEC 18013-5)');
    t.check(views.coseMdoc.length === 12 &&
      Object.keys(views.coseStatus).length === 14 &&
      Object.keys(views.coseTable).length === 20,
    'the three COSE sets stay different sizes on purpose');

    // 3. The engines' own tables.
    t.check(same(pqJose.PQ_ALGS, views.postQuantumJoseNames),
      'pq_jose.js speaks exactly the post-quantum JOSE rows');
    t.check(same(keyMaterial.keyAlgIds().slice().sort(),
      views.pkiKeyAlgorithms.slice().sort()),
    'key_material.js generates exactly the PKI key ids');
    t.check(same(Object.keys(x509.SIG_ALGS).slice().sort(),
      views.pkiSignatureAlgorithms.slice().sort()),
    'x509.js signs exactly the PKI signature ids');
    views.pkiSignatureAlgorithms.forEach(function (id) {
      const entry = x509.SIG_ALGS[id];
      if (entry && entry.oid) {
        t.check(registry.bySpelling('x509', id).oid === entry.oid,
          'the row and x509.js agree on the OID of ' + id);
      }
    });
    Object.keys(xmldsig.SIG_METHODS).forEach(function (uri) {
      const spec = xmldsig.SIG_METHODS[uri];
      if (spec.postQuantum && (spec.family === 'mldsa' ||
                               spec.family === 'slhdsa')) {
        t.check(registry.bySpelling('xml', uri) !== null,
          'xmldsig.js\'s post-quantum URI has a row', uri);
      }
    });
    registry.joseNames().concat(registry.pkiSignatureAlgorithms())
      .forEach(function (name) {
        const row = registry.bySpelling('jose', name) ||
          registry.bySpelling('x509', name);
        const kind = pqc.ofAlgorithm(name);
        t.check((kind ? kind.kind : null) === row.pqc,
          'pqc_support.ts and the row agree on what kind ' + name + ' is',
          String(kind && kind.kind) + ' / ' + String(row.pqc));
      });

    // 4. A row and the recorded lists cannot drift.
    const ids = new Set();
    registry.ROWS.forEach(function (row) {
      t.check(!ids.has(row.id), 'a row\'s id is unique', row.id);
      ids.add(row.id);
      t.check(row.pqc === null || row.pqc === 'pq' || row.pqc === 'composite',
        'a row\'s post-quantum class is a signature\'s', row.id);
      if (row.hash) {
        t.check(row.weak === (row.hash === 'sha1' || row.hash === 'ripemd160'),
          'a row is weak exactly when its hash is', row.id);
        t.check(row.sha1 === (row.hash === 'sha1'),
          'a row is sha1 exactly when its hash is', row.id);
      }
      registry.SURFACES.forEach(function (surface) {
        if (row[surface] !== null) {
          t.check(registry.bySpelling(surface, row[surface]) === row,
            'a spelling names exactly one row', surface + ' ' + row[surface]);
        }
      });
    });
    ['jose', 'cose', 'xml', 'x509', 'cms', 'di', 'tls', 'dkim']
      .forEach(function (surface) {
        const listed = registry.recorded(surface);
        registry.on(surface).forEach(function (row) {
          t.check(listed.indexOf(row[surface]) >= 0,
            'a row on ' + surface + ' is in that surface\'s recorded order',
            row.id);
        });
        listed.forEach(function (value) {
          t.check(registry.bySpelling(surface, value) !== null,
            'a recorded spelling on ' + surface + ' has a row', String(value));
        });
      });
    registry.on('httpsig').forEach(function (row) {
      t.check(row.jose !== null ||
        registry.recorded('httpsig').indexOf(row.httpsig) >= 0,
      'an HTTP signature row is a JWS name or one of section 3.3\'s', row.id);
    });

    // 5. Every setting that names an algorithm names a row.
    const setting = function (key) {
      return config.SETTINGS.filter(function (row) {
        return row.key === key;
      })[0];
    };
    JOSE_SETTINGS.forEach(function (key) {
      const row = setting(key);
      t.check(!!row, 'the setting exists', key);
      ((row && (row.enumValues || row.csvValues)) || [])
        .forEach(function (name) {
          t.check(name === 'default' ||
            registry.bySpelling('jose', name) !== null,
          key + ' names a JOSE row', name);
        });
    });
    t.check(same(setting('keys.signingAlgorithms').csvValues,
      registry.joseNames()), 'keys.signingAlgorithms offers every JOSE row');
    setting('webauthn.algorithms').csvValues.forEach(function (name) {
      t.check(registry.on('cose').some(function (row) {
        return row.id === name;
      }), 'webauthn.algorithms names a COSE row', name);
    });
    t.check(setting('webauthn.algorithms').csvValues.length ===
      registry.on('cose').length, 'webauthn.algorithms offers every COSE row');
    setting('pki.keyAlgorithm').enumValues.slice(0, 7).forEach(function (id) {
      t.check(/^(rsa|ec)-|^ed25519$/.test(id),
        'pki.keyAlgorithm starts with the classical keys', id);
    });
    String(setting('tls.signatureAlgorithms').dflt).split(':')
      .forEach(function (name) {
        t.check(registry.bySpelling('tls', name) !== null,
          'tls.signatureAlgorithms\' default names a row', name);
      });
    setting('gnap.zcapCryptosuite').enumValues.forEach(function (name) {
      t.check(registry.bySpelling('di', name) !== null,
        'gnap.zcapCryptosuite names a Data Integrity row', name);
    });

    // 6. The two orders.
    t.check(registry.on('jose')[0].id === 'ML-DSA-87',
      'preference order starts with the strongest post-quantum algorithm');
    t.check(registry.recorded('jose')[0] === 'HS256',
      'what an unconfigured service does is NOT preference order');

    // Aliases, and what are not aliases.
    t.check(registry.bySpelling('xml',
      'http://www.w3.org/2007/05/xmldsig-more#rsa-sha224').id === 'RSA-SHA224',
    'XML\'s second rsa-sha224 URI is an alias of the row');
    t.check(registry.bySpelling('cose', -8).id !== registry.bySpelling(
      'cose', -19).id, 'COSE -8 and -19 are two rows');
    t.check(registry.bySpelling('cose', -7).id !== registry.bySpelling(
      'cose', -9).id, 'COSE -7 and -9 are two rows');
    t.check(registry.bySpelling('cose', '-7').id === 'ES256',
      'a COSE identifier may be a string');
    t.check(registry.bySpelling('httpsig', 'PS512') ===
      registry.bySpelling('httpsig', 'rsa-pss-sha512'),
    'RFC 9421\'s name and the JWS name are one row');
    t.check(registry.byOid('1.2.840.113549.1.1.10').length === 3,
      'the RSASSA-PSS OID names every hash the parameters may choose');
    t.check(registry.bySpelling('jose', 'nonsense') === null &&
      registry.bySpelling('nonsense', 'RS256') === null &&
      registry.byId('nonsense') === null && registry.spelling('nonsense',
        'jose') === null, 'an unknown name is null, never a throw');

    // A leaf: `config.js` reads it, so it may read nothing of this service.
    const requires = source('common/crypto_impl/algorithm_registry.js')
      .split('\n').filter(function (line) {
        return !/^\s*\/\//.test(line) && /require\(/.test(line);
      });
    t.check(requires.length === 1 && /require\('bunyan'\)/.test(requires[0]),
      'the registry requires nothing of this service', requires.join(' | '));
    const copied = registry.coseTable();
    copied['-7'].name = 'changed';
    t.check(registry.coseTable()['-7'].name === 'ES256',
      'a view is a copy: no caller changes what another reads');
  }
};
