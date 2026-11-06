// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: signature_policy_metadata.js
//
// ---------------------------------------------------------------------------
// WHAT IS PUBLISHED IS WHAT IS CONFIGURED (#1368, phase 5).
//
// **THE PINS BELOW WERE TAKEN BEFORE PHASE 5 EXISTED**, from the documents an
// image of the tree before it answered over HTTP, so they hold the new code to
// what it replaced and not to itself. They cover every `*alg_values*` list at any
// depth and every key's shape in the JWK Set, and not whole documents, so that an
// unrelated new member does not fail here. 1.0.0 is certified: a default moving
// is a certification question, so change a pin only on purpose.
//
// IN A CHILD, for `tests/jose_kid.js`'s reason: loading the whole protocol stack
// into `run.js`'s one process changes what later files see.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');

const PINS = {
  'discovery': {
    'path': '/.well-known/openid-configuration',
    'lists': 16,
    'pin': 'b10c8804b9157b28e888c7c97be8163d'
  },
  'authorizationServer': {
    'path': '/.well-known/oauth-authorization-server',
    'lists': 12,
    'pin': 'b48c5bfdc4f95de7a137a15c3eab659d'
  },
  'credentialIssuer': {
    'path': '/.well-known/openid-credential-issuer',
    'lists': 16,
    'pin': '254bca2e4730829edb5445152b747a22'
  }
};

const JWKS_SHAPE = [
  ['RSA', '', 'sig', ''],
  ['EC', 'ES256', 'sig', 'P-256'],
  ['EC', 'ES384', 'sig', 'P-384'],
  ['EC', 'ES512', 'sig', 'P-521'],
  ['EC', 'ES256K', 'sig', 'secp256k1'],
  ['AKP', 'ML-DSA-44', 'sig', ''],
  ['AKP', 'ML-DSA-65', 'sig', ''],
  ['AKP', 'ML-DSA-87', 'sig', ''],
  ['AKP', 'SLH-DSA-SHA2-128s', 'sig', ''],
  ['AKP', 'SLH-DSA-SHAKE-128s', 'sig', ''],
  ['AKP', 'ML-DSA-44-ES256', 'sig', ''],
  ['AKP', 'ML-DSA-65-ES256', 'sig', ''],
  ['AKP', 'ML-DSA-87-ES384', 'sig', ''],
  ['AKP', 'ML-DSA-44-Ed25519', 'sig', ''],
  ['AKP', 'ML-DSA-65-Ed25519', 'sig', ''],
  ['AKP', 'ML-DSA-87-Ed448', 'sig', ''],
  ['RSA', '', 'enc', ''],
  ['EC', '', 'enc', 'P-256']
];

function childMain() {
  const ROOT_DIR = process.env.SPM_ROOT;
  const http = require('http');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const config = require(ROOT_DIR + '/common/config');
    const nodeCryptoChild = require('crypto');
    const server = http.createServer(app).listen(0, '127.0.0.1');
    await new Promise(function (resolve) {
      server.on('listening', resolve);
    });
    const port = server.address().port;
    const get = function (p) {
      return new Promise(function (resolve, reject) {
        http.get({ host: '127.0.0.1', port: port, path: p }, function (res) {
          let text = '';
          res.on('data', function (c) {
            text += c;
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, text: text,
                      cache: res.headers['cache-control'] });
          });
        }).on('error', reject);
      });
    };
    const json = async function (p) {
      return JSON.parse((await get(p)).text);
    };
    const lists = function (node, out, at) {
      if (Array.isArray(node)) {
        node.forEach(function (one, i) {
          lists(one, out, at + '/' + i);
        });
      } else if (node && typeof node === 'object') {
        Object.keys(node).sort().forEach(function (k) {
          const v = node[k];
          if (Array.isArray(v) && /alg_values/.test(k)) {
            out.push(at + '/' + k + '=' + v.join(','));
          } else if (v && typeof v === 'object') {
            lists(v, out, at + '/' + k);
          }
        });
      }
      return out;
    };
    const pins = JSON.parse(process.env.SPM_PINS);
    const shape = JSON.parse(process.env.SPM_SHAPE);

    // ---- At the defaults, what was published before this phase. -----------
    for (const name of Object.keys(pins)) {
      const found = lists(await json(pins[name].path), [], '');
      const pin = nodeCryptoChild.createHash('sha256')
        .update(found.join('\n')).digest('hex').slice(0, 32);
      note(pin === pins[name].pin && found.length === pins[name].lists,
           name + ': every algorithm list is what it was before phase 5',
           pin + ' / ' + found.length);
    }
    const shapeOf = function (doc) {
      return doc.keys.map(function (k) {
        return [k.kty, k.alg || '', k.use || '', k.crv || ''];
      });
    };
    note(JSON.stringify(shapeOf(await json('/oauth2/jwks'))) ===
         JSON.stringify(shape),
         'the JWK Set holds the keys it held before phase 5');

    // ---- SAML: the one deliberate exception. ------------------------------
    const saml = await get('/saml2/metadata');
    const signing = saml.text.match(/<alg:SigningMethod /g) || [];
    note(signing.length > 3 && /<alg:DigestMethod /.test(saml.text),
         'IdP metadata publishes algorithm support by default',
         signing.length);
    note(saml.text.indexOf('<alg:SigningMethod') >
         saml.text.indexOf('<md:Extensions>') &&
         saml.text.indexOf('<alg:SigningMethod') <
         saml.text.indexOf('</md:Extensions>'),
         'inside md:Extensions, where a consumer may ignore them');
    // The profile's section 2.4: what the entity can VERIFY, in order of
    // preference. So an accept list narrows it, and the signing list does not.
    note(/<alg:SigningMethod xmlns:alg="[^"]+" Algorithm="[^"]*ml-dsa-87"/
      .test(saml.text.slice(saml.text.indexOf('<alg:SigningMethod'))
        .split('/>')[0] + '/>'), 'in order of preference, strongest first');
    note(/<alg:SigningMethod /.test((await get('/saml11/metadata')).text),
         'SAML 1.1 metadata carries them: it is the same document');
    note(!/algsupport/.test((await get(
      '/FederationMetadata/2007-06/FederationMetadata.xml')).text),
    'the WS-Federation view does not');
    config.setOverride('saml.acceptedSignatureAlgorithms', 'RS256');
    const narrowed = (await get('/saml2/metadata')).text;
    note((narrowed.match(/<alg:SigningMethod /g) || []).length === 1 &&
         /Algorithm="[^"]*rsa-sha256"\/>/.test(narrowed),
         'an accept list is what it then publishes');
    config.clearOverride('saml.acceptedSignatureAlgorithms');
    note(!/rsa-sha1"|hmac-|md5/.test(saml.text.slice(
      saml.text.indexOf('<md:Extensions>'),
      saml.text.indexOf('</md:Extensions>'))),
    'no weak method and no HMAC is advertised');
    config.setOverride('saml2.publishAlgorithmSupport', false);
    note(!/alg:SigningMethod/.test((await get('/saml2/metadata')).text),
         'the setting turns them off');
    config.clearOverride('saml2.publishAlgorithmSupport');

    // ---- A classical list. ------------------------------------------------
    config.setOverride('keys.signingAlgorithms', 'PS256,RS256');
    let doc = await json('/.well-known/openid-configuration');
    note(JSON.stringify(doc.id_token_signing_alg_values_supported) ===
         JSON.stringify(['PS256', 'RS256']),
         'the signing list is published in the order configured',
         doc.id_token_signing_alg_values_supported);
    let keys = shapeOf(await json('/oauth2/jwks'));
    note(keys.every(function (k) {
      return k[2] === 'enc' || k[0] === 'RSA';
    }), 'the JWK Set carries the keys of that list and no others');
    config.clearOverride('keys.signingAlgorithms');

    // ---- A post-quantum-first list. ---------------------------------------
    config.setOverride('keys.signingAlgorithms', 'ML-DSA-65,RS256');
    doc = await json('/.well-known/openid-configuration');
    note(doc.id_token_signing_alg_values_supported[0] === 'ML-DSA-65',
         'a post-quantum first list is published first',
         doc.id_token_signing_alg_values_supported);
    config.clearOverride('keys.signingAlgorithms');

    // ---- keys.pqcOnly. ----------------------------------------------------
    config.setOverride('keys.pqcOnly', true);
    doc = await json('/.well-known/openid-configuration');
    const idToken = doc.id_token_signing_alg_values_supported;
    note(idToken.indexOf('RS256') >= 0,
         'RS256 stays in the ID Token list: Discovery requires it');
    note(idToken.indexOf('ES256') < 0 && idToken.indexOf('ML-DSA-65') >= 0,
         'and nothing else classical does', idToken);
    note(doc.userinfo_signing_alg_values_supported.indexOf('RS256') < 0,
         'other lists hold no classical algorithm',
         doc.userinfo_signing_alg_values_supported);
    keys = shapeOf(await json('/oauth2/jwks'));
    note(keys.some(function (k) {
      return k[0] === 'AKP';
    }) && !keys.some(function (k) {
      return k[0] === 'EC' && k[2] === 'sig';
    }), 'the JWK Set holds no classical curve key');
    note(keys.some(function (k) {
      return k[0] === 'RSA' && k[2] === 'sig';
    }), 'and keeps the RSA key RS256 ID Tokens verify with');
    config.clearOverride('keys.pqcOnly');

    // ---- An accept list, with the sign list left to what it covers. -------
    config.setOverride('keys.acceptedSigningAlgorithms', 'RS256,ES256');
    doc = await json('/.well-known/openid-configuration');
    note(JSON.stringify(doc.request_object_signing_alg_values_supported.filter(
      function (alg) {
        return alg !== 'none';
      })) === JSON.stringify(['RS256', 'ES256']),
    'what the realm accepts is published as what it accepts',
    doc.request_object_signing_alg_values_supported);
    config.clearOverride('keys.acceptedSigningAlgorithms');

    // ---- A post-quantum attester: advertised only where one is configured. 
    const keyMaterial = require(ROOT_DIR + '/common/crypto_impl/key_material');
    const x509 = require(ROOT_DIR + '/common/crypto_impl/x509');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const issuer = require(ROOT_DIR + '/oid4vc/vc_issuer');
    const attesterPair = await keyMaterial.generateKeyPair('ml-dsa-65');
    const attester = await x509.issueCertificate({
      subject: [{ name: 'CN', value: 'post-quantum attester' }],
      subjectPublicKey: attesterPair.publicPem, signatureAlg: 'ml-dsa-65',
      issuerPrivateKey: attesterPair.privatePem,
      notBefore: new Date(0).toISOString(),
      notAfter: new Date(4102444800000).toISOString()
    });
    const pqAlgs = function (meta) {
      const out = [];
      Object.keys(meta.credential_configurations_supported)
        .forEach(function (id) {
          const types = meta.credential_configurations_supported[id]
            .proof_types_supported || {};
          ((types.attestation || {}).proof_signing_alg_values_supported || [])
            .forEach(function (alg) {
              if (/^ML-DSA/.test(alg)) {
                out.push(alg);
              }
            });
        });
      return out;
    };
    note(pqAlgs(await json('/.well-known/openid-credential-issuer'))
      .length === 0,
    'no post-quantum attestation is advertised with no such attester');
    config.setOverride('oid4vci.keyAttestationTrustedCertificates',
                       attester.pem);
    note(pqAlgs(await json('/.well-known/openid-credential-issuer'))
      .indexOf('ML-DSA-65') >= 0,
    'and ML-DSA-65 is once an attester holds that key');
    const attesterRaw = require(ROOT_DIR + '/common/crypto_impl/pqc_x509')
      .decodePkcs8(new Uint8Array(Buffer.from(attesterPair.privatePem
        .replace(/-----[^-]+-----|\s/g, ''), 'base64')));
    const now = Math.floor(Date.now() / 1000);
    const token = stsCrypto.signJws({ iat: now, exp: now + 300,
      attested_keys: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }] },
    Buffer.from(attesterRaw.priv), { algorithm: 'ML-DSA-65',
      header: { typ: 'key-attestation+jwt' } });
    let attestationError = '';
    try {
      issuer.verifyKeyAttestation(token, {});
    } catch (e) {
      attestationError = e.message;
    }
    note(!/does not verify|this issuer accepts/.test(attestationError),
         'and an attestation it signed gets past the signature',
         attestationError);
    config.clearOverride('oid4vci.keyAttestationTrustedCertificates');

    // ---- The describer, and /crypto/metadata. -----------------------------
    const metadata = await json('/crypto/metadata');
    ['cose', 'dataIntegrity', 'x509', 'httpsig'].forEach(function (name) {
      note(Array.isArray(metadata.algorithms[name].accepted) &&
           metadata.algorithms[name].accepted.length > 0,
           '/crypto/metadata has a ' + name + ' section');
    });
    note(metadata.algorithms.tls.signatureAlgorithms.length > 0 &&
         metadata.algorithms.webauthn.offered.length > 0,
         'and the TLS and WebAuthn lists');
    const policy = require(ROOT_DIR + '/common/signature_policy');
    config.setOverride('cose.acceptedAlgorithms', 'ES256');
    const described = policy.describe().surfaces.cose.rows;
    note(described.filter(function (row) {
      return row.accepts;
    }).length === 1 && described.some(function (row) {
      return !row.accepts && /cose\.acceptedAlgorithms/.test(row.acceptRefusal);
    }), 'the describer says what is accepted, and why the rest is not');
    config.clearOverride('cose.acceptedAlgorithms');

    server.close();
  })().catch(function (e) {
    note(false, 'the test itself threw', e && e.stack);
  }).then(function () {
    fs.writeFileSync(process.env.SPM_OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

// The defaults, which is what the pins are of: no setting of this run's own and
// no configuration file reaches the child.
function cleanEnv() {
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  env.STS_LOG_LEVEL = 'fatal';
  return env;
}

module.exports = {
  name: 'signature_policy_metadata',
  run: function run(t) {
    const out = path.join(os.tmpdir(), 'spm-' +
      nodeCrypto.randomBytes(6).toString('hex') + '.json');
    const child = childProcess.spawnSync(process.execPath, ['-e',
      'const fs = require("fs");\n(' + childMain.toString() + ')();'],
    { env: Object.assign(cleanEnv(), {
      SPM_ROOT: ROOT, SPM_OUT: out,
      SPM_PINS: JSON.stringify(PINS), SPM_SHAPE: JSON.stringify(JWKS_SHAPE)
    }), encoding: 'utf8', timeout: 240000, maxBuffer: 1 << 28 });
    t.check(fs.existsSync(out), 'the child ran to the end',
      String(child.stderr || '').slice(-400));
    if (fs.existsSync(out)) {
      JSON.parse(fs.readFileSync(out, 'utf8')).forEach(function (one) {
        t.check(one.ok, one.what, one.detail);
      });
      fs.unlinkSync(out);
    }
  }
};
