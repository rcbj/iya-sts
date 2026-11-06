// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/certificate_pins.js — EVERY SOURCE OF A PINNED CERTIFICATE IS ON THE
// INVENTORY (#1360, Phase 6).
//
// A setting holding a certificate that the inventory does not read expires with
// nobody told. So the settings are compared with `common/config.js`: a row whose
// name says it holds trust anchors, a CA bundle or trusted certificates and
// which `certificate_pins.ts` does not list fails here. The other sources are
// driven in a child, because they reach route modules.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back: a row
// removed from SETTINGS; `fromCloudAnchors()` not de-duplicating; a thumbprint
// listed with no thumbprint; the x5c of `oauthJwks` not read.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');
const kit = require('./tools/trust_kit');

const ROOT = path.join(__dirname, '..');
// A setting of this shape names certificates; these do not hold pins.
const CERTIFICATE_SETTING = /(TrustAnchors|TrustedCertificates|Certificates|CaBundle|TrustBundle)$/;
const NOT_PINS = {
  'listener.trustIssuedClientCertificates': 'a switch, holding no certificate',
  'tls.trustIssuedClientCertificates': 'a switch, holding no certificate'
};

function childMain() {
  const root = process.argv[1];
  const pem = process.argv[2];
  const pins = require(root + '/common/certificate_pins');
  const applications = require(root + '/common/applications');
  const federation = require(root + '/federation/federation');
  const config = require(root + '/common/config');
  const der = pem.replace(/-----[^-]+-----|\s+/g, '');
  applications.list = function () {
    return [{ identifier: 'app-one', fields: {
      samlSigningCertificate: [pem], samlEncryptionCertificate: [pem],
      oauthJwks: [JSON.stringify({ keys: [{ kty: 'EC', x5c: [der, der] },
                                          { kty: 'EC' }] })],
      oauthAssertionJwks: ['not json'],
      oauthTlsClientCertificateThumbprint: ['abc'],
      gnapKey: [JSON.stringify({ proof: 'mtls', cert: der })]
    } }, { identifier: 'app-two', fields: {
      gnapKey: [JSON.stringify({ proof: 'mtls', 'cert#S256': 'def' })] } }];
  };
  federation.list = function () {
    return [{ id: 'fed-one', fedSigningCertificate: pem,
              fedJwks: JSON.stringify({ keys: [{ x5c: [der] }] }) }];
  };
  config.setOverride('oid4vp.mdocTrustAnchors', pem + '\n' + pem);
  const out = {
    settings: pins.fromSettings(), applications: pins.fromApplications(),
    federation: pins.fromFederation(), gnap: pins.fromGnapClients(),
    cloud: pins.fromCloudAnchors(),
    table: require(root + '/common/pki_cloud_anchors.json').azureRoots.length
  };
  process.stdout.write('\nRESULT' + JSON.stringify(out));
  process.exit(0);
}

async function run(t) {
  const config = fs.readFileSync(path.join(ROOT, 'common/config.js'), 'utf8');
  const source = fs.readFileSync(path.join(ROOT, 'common/certificate_pins.ts'),
                                 'utf8');
  const keys = [];
  const pattern = /\{ key: '([a-zA-Z0-9.]+)'/g;
  let one = pattern.exec(config);
  while (one) {
    keys.push(one[1]);
    one = pattern.exec(config);
  }
  const missing = keys.filter(function (key) {
    return CERTIFICATE_SETTING.test(key) && !NOT_PINS[key] &&
           source.indexOf("'" + key + "'") === -1;
  });
  t.check(keys.length > 100 && missing.length === 0,
          'every setting that names certificates is on the inventory',
          missing.join(', '));
  const leaf = await kit.mint({ cn: 'a pin' });
  const child = childProcess.spawnSync(process.execPath, ['-e',
    '(' + childMain.toString() + ')()', ROOT, leaf.pem],
    { encoding: 'utf8', timeout: 120000, maxBuffer: 1 << 26,
      env: Object.assign({}, process.env, { LOG_LEVEL: 'fatal' }) });
  const at = (child.stdout || '').lastIndexOf('\nRESULT');
  t.check(at !== -1, 'the child answered', (child.stderr || '').slice(-400));
  if (at === -1) {
    return;
  }
  const out = JSON.parse(child.stdout.slice(at + 7));
  const whereOf = function (rows) {
    return rows.map(function (row) {
      return row.where;
    });
  };
  t.equal(out.settings.length, 2,
          'a setting holding two certificates is two rows');
  t.equal(out.settings[0].purpose, 'anchor-admission',
          'and a root is judged as a root');
  const apps = out.applications;
  t.check(whereOf(apps).indexOf('app-one samlSigningCertificate') !== -1 &&
          apps.filter(function (row) {
            return row.purpose === 'encryption-recipient';
          }).length === 1,
          'an application\'s certificates are listed under their own rows',
          JSON.stringify(whereOf(apps)));
  const jwks = apps.filter(function (row) {
    return row.purpose === 'jose-signer';
  });
  t.check(jwks.length === 1 && jwks[0].chain.length === 1,
          'a JWK set lists each x5c with its chain, and a key with none or a ' +
          'value that is not JSON names nothing', JSON.stringify(jwks));
  t.check(apps.some(function (row) {
    return row.thumbprint === 'abc' && !row.pem;
  }), 'a certificate named only by its thumbprint is listed as one', '');
  t.equal(out.federation.length, 2,
          'a relationship lists its certificate and its keys');
  t.check(out.gnap.length === 2 && !!out.gnap[0].pem &&
          out.gnap[1].thumbprint === 'def',
          'a GNAP client lists its certificate, or the thumbprint it gave', '');
  const distinct = new Set(out.cloud.map(function (row) {
    return row.pem;
  }));
  t.check(out.cloud.length === distinct.size && out.cloud.length > out.table,
          'the cloud anchors are listed once per certificate',
          out.cloud.length + ' rows');
}

module.exports = {
  name: 'certificate_pins',
  describe: '#1360: every source of a pinned certificate is on the inventory',
  run: run
};
