// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_keys_certified_late_branch.js
//
// ===========================================================================
// A REALM'S KEYS MADE BEFORE ITS CERTIFICATE AUTHORITY BRANCH ARE CERTIFIED
// ONCE THE BRANCH EXISTS, AND A CREDENTIAL ASKS FOR ITS CERTIFICATE RATHER
// THAN LEAVING `x5c` OFF (2026-11-04).
//
// `sts_eudi_wallet_portal` failed in cluster mode, three runs in four: the
// eudi wallet's listing of the SD-JWT VC it had just been issued had no
// `signature`, because the wallet verifies a stored credential OFFLINE, from
// the `x5c` in its header, and the credential carried none although
// `oid4vci.credentialCertificateHeader` is `x5c`. The realm's classical keys
// had never been certified: a worker made them at 10:54:51.44 (helpers.js's
// `certifyLater()` ran, found no branch and gave up, at debug), another
// process built the branch at 10:54:53.29, and the realm watcher certifies
// only where it built the branch itself AND holds the keys. Nothing asked
// again, so `jose_certificate_header.js`'s `headerFor()` found no certificate
// and quietly answered `{}`.
//
// What is held here, in a CHILD PROCESS with the whole stack and its
// certificate authority started (so the realm watcher is subscribed, as in
// the service):
//
//   A. A realm that ARRIVES from another process (`restored`, so this
//      process's watcher builds nothing — the cluster's shape) and whose
//      keys are then made HERE: the RS256 and ES256 keys end up certified
//      under that realm's JOSE Issuing CA, and a `vci-credential` signature
//      by the ES256 key carries an `x5c` whose leaf holds that key and whose
//      issuer is the realm's JOSE Issuing CA. Without the fix nothing
//      certifies them, ever.
//   B. A realm whose ES256 certificate is NOT HERE when a credential is
//      signed (the register's slot emptied, as a process meets a key another
//      node has not yet certified or whose row has not arrived): the
//      synchronous header is empty, and `certificateHeaderForAsync()` — what
//      the OpenID4VCI credential signers call — answers with the `x5c` all
//      the same, because it reads the store and asks for the certificate.
//
// **IN A CHILD** for `tests/jose_certificate_header.js`'s reason: loading the
// whole stack into `run.js`'s one process builds a certificate authority and
// registers every route on the shared app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'realm_keys_certified_late_branch',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Shipped as source with `node -e`, so everything it needs is required inside.
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.LATE_ROOT;
  const OUT = process.env.LATE_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function sleep(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }
  function pemOf(b64) {
    return '-----BEGIN CERTIFICATE-----\n' +
           b64.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    await require(ROOT_DIR + '/common/service_state').start();
    const realms = require(ROOT_DIR + '/common/realms');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const pki = require(ROOT_DIR + '/common/pki');

    note(pki.buildsRealmBranches(),
         'the certificate authority started and builds runtime realms\' ' +
         'branches (the realm watcher is subscribed), as in the service');

    // The ES256 key of a realm's set, and its kid and SPKI.
    const es256Of = function (keys) {
      return (keys.extraKeys || []).filter(function (one) {
        return one.alg === 'ES256';
      })[0] || null;
    };
    const spkiOfJwk = function (jwk) {
      return nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' })
        .export({ type: 'spki', format: 'der' }).toString('base64');
    };
    const certified = function (realmId, slot) {
      return !!pki.certificateFor(realmId, 'jose', slot);
    };

    // ---- A. keys made before the branch, in a realm from elsewhere --------
    const A = 'latebranch-a';
    const made = realms.create({ id: A, restored: true });
    note(made && made.ok, 'A0. a realm arriving from another process is ' +
         'defined here', JSON.stringify(made && made.errors));
    note(!pki.certificateFor(A, 'jose', 'RS256') && !pki.hasChain(A),
         'A1. and this process built no branch for it — its watcher leaves ' +
         'a restored realm to the process that created it');
    const keysA = realms.run(realms.get(A), function () {
      return helpers.stsKeysFor.of(A);
    });
    const esA = es256Of(keysA);
    note(!!esA, 'A2. its key set is made here, with an ES256 key',
         esA ? esA.publicJwk.kid : '(none)');
    for (let i = 0; i < 200 &&
         !(certified(A, 'RS256') && certified(A, 'ES256:P-256')); i++) {
      await sleep(100);
    }
    note(certified(A, 'RS256') && certified(A, 'ES256:P-256'),
         'A3. its RS256 and ES256 keys are certified under its own JOSE ' +
         'Issuing CA although they were made before its branch existed',
         'RS256=' + certified(A, 'RS256') + ' ES256=' +
         certified(A, 'ES256:P-256'));
    const headerA = esA ? realms.run(realms.get(A), function () {
      return helpers.certificateHeaderFor('vci-credential', 'ES256',
                                          esA.publicJwk.kid);
    }) : {};
    const x5cA = Array.isArray(headerA.x5c) ? headerA.x5c : [];
    note(x5cA.length >= 2,
         'A4. a credential signed by that ES256 key carries x5c, the ' +
         'setting\'s default for OpenID4VCI credentials',
         JSON.stringify(Object.keys(headerA)));
    let leafHolds = false;
    let issuedByJose = false;
    try {
      const leaf = new nodeCrypto.X509Certificate(pemOf(x5cA[0]));
      leafHolds = leaf.publicKey.export({ type: 'spki', format: 'der' })
        .toString('base64') === spkiOfJwk(esA.publicJwk);
      const issuing = new nodeCrypto.X509Certificate(pemOf(x5cA[1]));
      issuedByJose = leaf.verify(issuing.publicKey) &&
                     /JOSE/.test(issuing.subject);
    } catch (e) {
      // The detail below says what was there; the reason rides on it.
      leafHolds = false;
      issuedByJose = false;
      note(false, 'A5. the x5c could be read', e.message);
    }
    note(leafHolds, 'A5. the first certificate holds the signing key ' +
         '(RFC 7515 section 4.1.6), so a wallet verifying offline finds it');
    note(issuedByJose, 'A6. and it is signed by the realm\'s JOSE Issuing ' +
         'CA, the next certificate in the chain');

    // ---- B. a certificate not here when the credential is signed ---------
    const B = 'latebranch-b';
    const madeB = realms.create({ id: B });
    note(madeB && madeB.ok, 'B0. a realm created here',
         JSON.stringify(madeB && madeB.errors));
    const keysB = realms.run(realms.get(B), function () {
      return helpers.stsKeysFor.of(B);
    });
    const esB = es256Of(keysB);
    for (let i = 0; i < 200 && !certified(B, 'ES256:P-256'); i++) {
      await sleep(100);
    }
    note(certified(B, 'ES256:P-256'),
         'B1. its ES256 key is certified (the precondition)');
    // As a process meets it when another node has not certified the key yet,
    // or its row has not arrived: the register holds nothing for the slot.
    const forgot = pki.forgetCertificate(B, 'jose', 'ES256:P-256');
    const kidB = esB ? esB.publicJwk.kid : '';
    const before = realms.run(realms.get(B), function () {
      return helpers.certificateHeaderFor('vci-credential', 'ES256', kidB);
    });
    note(forgot.ok && !before.x5c,
         'B2. with the certificate not here, the synchronous header is empty',
         JSON.stringify(before));
    const after = await realms.run(realms.get(B), function () {
      return helpers.certificateHeaderForAsync('vci-credential', 'ES256',
                                               kidB);
    });
    let holdsB = false;
    try {
      holdsB = Array.isArray(after.x5c) && new nodeCrypto.X509Certificate(
        pemOf(after.x5c[0])).publicKey.export({ type: 'spki', format: 'der' })
        .toString('base64') === spkiOfJwk(esB.publicJwk);
    } catch (e) {
      holdsB = false;
      note(false, 'B3. the x5c could be read', e.message);
    }
    note(holdsB,
         'B3. the credential signer\'s asynchronous header asks for the ' +
         'certificate and carries an x5c over the signing key all the same',
         JSON.stringify(Object.keys(after)));
    const none = await realms.run(realms.get(B), function () {
      return helpers.certificateHeaderForAsync('vci-credential', 'HS256',
                                               kidB);
    });
    note(Object.keys(none).length === 0,
         'B4. an HMAC signature still gets nothing, and waits for nothing');

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: (e && e.stack) || String(e) });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'late-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', LATE_ROOT: ROOT,
                                  LATE_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_keys_certified_late_branch',
  describe: 'a realm\'s keys made before its certificate authority branch ' +
            'are certified once it exists, and an OpenID4VCI credential ' +
            'asks for its certificate rather than leaving x5c off',
  run: run
};
