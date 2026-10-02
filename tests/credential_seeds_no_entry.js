// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/credential_seeds_no_entry.js
// ===========================================================================
// A CERTIFICATE, A WALLET PRESENTATION AND AN SVID SEED NO DIRECTORY ENTRY IN
// PRODUCT (#414, 2026-10-02).
//
// Every accepted credential reaches `stats.recordAuthentication()`, and the
// directory's observer (`ldap_server.js`'s `autoCreateUser()`) turns the name
// it carries into an entry — in development, where `ldap.autocreateUsers` is
// the demonstration's "the first person to claim a name gets it". Product
// never creates a person because a credential named one
// (`mode.autoCreates()`), and a session needs an entry to be the subject of,
// so there a credential naming somebody nobody provisioned signs nobody in.
// Nothing asserted it for the three doors whose credential names its holder
// itself (#113 item 10; `tests/stable_subject.js` B5 is development, and about
// a `urn:uuid` subject):
//
//   A. `GET /tls/sign-in`, over a real handshake, with a client certificate
//      from a CA in the client truststore that this service did not build —
//      its common name is the identity;
//   B. an OpenID4VP presentation at `/authn/wallet` of an SD-JWT VC from a
//      trusted foreign issuer (`oid4vp.trustedIssuerCertificates`) whose `sub`
//      names somebody — it verifies and signs nobody in (STS-VC-0058) in both
//      modes, and the identity it carries is recorded;
//   C. an X509-SVID minted by the realm's SPIFFE authority, presented as a
//      SPIRE Server API caller — `spiffe_auth.ts`'s `callerOf()` over a call
//      carrying the certificate, then `spiffe_grpc.ts`'s `policyRefusal()`
//      (which starts the caller's session) and `recordCaller()`, the steps
//      the Server API's wrapper takes for an authorized call.
//
// In a CHILD PROCESS with the whole stack, each door twice, with a name of
// its own each time: in DEVELOPMENT, the control — the door is reached, the
// certificate signs its holder in, and an entry appears for each name; then
// in PRODUCT, the same doors: the certificate signs nobody in (the session
// refused STS-AUTHN-0180, no entry to be the subject of), the presentation
// signs nobody in, the SVID's caller is authenticated and its session is a
// record naming no subject — and NO entry appears for any of the three, the
// directory holding exactly as many entries as before.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'credential_seeds_no_entry',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = nodeCrypto.randomBytes(4).toString('hex');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const M = JSON.parse(process.env.CS_MATERIAL);
  const https = require('https');
  const nodeCrypto = require('crypto');
  const walletKit = require(ROOT + '/tests/wallet_kit');

  // GET /tls/sign-in over a real handshake, presenting `cert` and `key`.
  function signInWith(port, cert, key) {
    return new Promise(function (resolve) {
      const req = https.request({ host: '127.0.0.1', port: port,
        path: '/tls/sign-in', method: 'GET', cert: cert, key: key,
        rejectUnauthorized: false, agent: false }, function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let body = {};
          try {
            body = JSON.parse(text);
          } catch (e) {
            body = { raw: text.slice(0, 300), parseError: e.message };
          }
          resolve({ status: res.statusCode, body: body });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, body: { error: e.message } });
      });
      req.end();
    });
  }

  walletKit.boot().then(async function (w) {
    try {
      await doors(w);
    } catch (e) {
      w.note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });

  async function doors(w) {
    const m = w.m;
    const note = w.note;
    await require(ROOT + '/common/service_state').start();
    const pki = require(ROOT + '/common/pki');
    await pki.ensureScope('');
    const tls = require(ROOT + '/tls/tls_server');
    const audit = require(ROOT + '/common/audit');
    const ca = require(ROOT + '/spiffe/spiffe_ca');
    const auth = require(ROOT + '/spiffe/spiffe_auth');
    const grpc = require(ROOT + '/spiffe/spiffe_grpc');

    // THE MAIN PORT'S POSTURE, as `tests/rfc8705_mtls.js` builds it: a
    // client certificate asked for and never required, over the client
    // truststore — which holds the foreign CA from here on.
    const serverCert = tls.serverCertificate();
    const listener = https.createServer(Object.assign({
      cert: serverCert.certPem, key: serverCert.privateKeyPem,
      ca: tls.clientTruststoreOptions().ca,
      requestCert: true, rejectUnauthorized: false
    }, tls.protocolOptions()), m.app);
    tls.trustClientCertificatesOn(listener, 'the #414 test listener');
    await new Promise(function (r) { listener.listen(0, '127.0.0.1', r); });
    const tlsPort = listener.address().port;
    const anchored = tls.addAnchors(fs.readFileSync(M.caCert, 'utf8'));
    note(anchored.added === 1, 'setup: the foreign CA is a client trust ' +
         'anchor', JSON.stringify(anchored));

    // THE FOREIGN ISSUER, trusted for presentations and exempt from the
    // status reference it does not publish — `tests/oid4vp_sign_in.js` 6h's
    // arrangement.
    const partner = m.stsCrypto.selfSignedRsaCertificate(
      { commonName: 'cs partner issuer' });
    w.inRealm(function () {
      m.config.setOverride('oid4vp.trustedIssuerCertificates',
                           partner.certPem);
      m.config.setOverride('oid4vp.statusOptionalIssuers',
        m.stsCrypto.certificateThumbprint(partner.certPem,
                                          { format: 'hex' }));
    });
    const aud = w.inRealm(function () {
      return m.config.value('oid4vp.clientId');
    });
    const partnerSigner = { privateKey:
      nodeCrypto.createPrivateKey(partner.privateKeyPem) };
    const presentAs = async function (sub) {
      const holder = w.holderKey();
      const now = Math.floor(Date.now() / 1000);
      const credential = w.jws({ alg: 'RS256', typ: 'dc+sd-jwt' },
        { iss: 'https://partner.example', vct: m.vcConfigs.VCI_VCT,
          sub: sub, cnf: { jwk: holder.jwk }, nbf: now - 5, exp: now + 600,
          _sd_alg: 'sha-256', _sd: [] }, partnerSigner) + '~';
      const who = w.browser();
      const one = await w.start(who, w.pendingSignIn());
      if (!one.requestObject) {
        return { ok: false, code: 'no request object',
                 page: one.started || {} };
      }
      const presentation = await w.present('dc+sd-jwt', credential, holder,
                                           one.requestObject.nonce, aud);
      const answered = await w.respond(one, presentation,
                                       { format: 'dc+sd-jwt' });
      const page = await w.request('GET', one.waitPath, { browser: who });
      return { ok: page.status === 303, code: page.code, page: page,
               answered: answered, session: w.sessionOf(who) };
    };

    // A SPIRE Server API caller presenting `svid`, as grpc-js hands the call
    // to `spiffe_grpc.ts`: the TLS auth context carrying the peer's leaf.
    const callWith = function (svid) {
      const leaf = new nodeCrypto.X509Certificate(svid.certificatePem);
      const peerCertificate = leaf.toLegacyObject();
      return {
        getAuthContext: function () {
          return { transportSecurityType: 'ssl',
                   sslPeerCertificate: peerCertificate };
        },
        getPeer: function () {
          return 'ipv4:127.0.0.1:41414';
        }
      };
    };
    const entryCount = function () {
      return w.inRealm(function () {
        return m.ldap.entries.size;
      });
    };
    const holds = function (name) {
      return w.inRealm(function () {
        return !!m.ldap.existingUserEntry(name) ||
               !!m.helpers.userFor(name).sub;
      });
    };
    const refusedForNoEntry = function (name) {
      return audit.list().some(function (row) {
        return row.action === 'session.refuse' && row.actor === name &&
               row.errorCode === 'STS-AUTHN-0180';
      });
    };

    for (const mode of ['development', 'product']) {
      const PRODUCT = mode === 'product';
      const label = PRODUCT ? 'PRODUCT' : 'DEVELOPMENT';
      if (PRODUCT) {
        m.config.setOverride('global.mode', 'product');
        // SOFT-FAIL, WHAT A DEPLOYMENT WHOSE PRIVATE CA PUBLISHES NO CRL
        // SETS: product's `auto` is hard-fail, which refuses this file's CA's
        // certificates for naming no distribution point before a session is
        // asked for — a refusal that would read as the one under test. A
        // revoked certificate is still refused under soft-fail.
        m.config.setOverride('pki.revocationCheck', 'soft-fail');
      }
      try {
        // --- A. the certificate ------------------------------------------
        const certName = M.names[mode];
        let before = entryCount();
        const signed = await signInWith(tlsPort,
          fs.readFileSync(M.leaf[mode], 'utf8'),
          fs.readFileSync(M.key[mode], 'utf8'));
        const session = signed.body.session || {};
        const cert = signed.body.clientCertificate || {};
        note(cert.presented === true && cert.verified === true,
             'A0. ' + label + ': the foreign certificate naming ' + certName +
             ' is presented and verifies', JSON.stringify(cert));
        if (!PRODUCT) {
          note(signed.body.signedIn === true && session.started === true &&
               holds(certName) && entryCount() > before,
               'A1. ' + label + ': GET /tls/sign-in signs its holder in, and ' +
               'an entry for ' + certName + ' is made (the control)',
               JSON.stringify({ status: signed.status, session: session }));
        } else {
          note(signed.status === 200 && signed.body.signedIn === false &&
               session.started !== true,
               'A1. ' + label + ': GET /tls/sign-in signs nobody in',
               JSON.stringify({ status: signed.status, session: session }));
          note(refusedForNoEntry(certName),
               'A2. ' + label + ': the session was refused because the ' +
               'directory holds no entry for ' + certName +
               ' (STS-AUTHN-0180)');
          note(!holds(certName) && entryCount() === before,
               'A3. ' + label + ': and no entry was made — the directory ' +
               'holds as many entries as before', entryCount() + ' / ' +
               before);
        }

        // --- B. the wallet presentation ----------------------------------
        const walletName = 'cs-wallet-' + mode.slice(0, 4) + '-' + M.stamp;
        before = entryCount();
        const presented = await presentAs(walletName);
        note(!presented.ok && presented.code === 'STS-VC-0058' &&
             !presented.session,
             'B1. ' + label + ': a trusted foreign issuer\'s presentation ' +
             'naming ' + walletName + ' verifies and signs nobody in ' +
             '(STS-VC-0058)', presented.code + ' ' +
             (presented.page.status || '') + ' ' +
             JSON.stringify(presented.answered && presented.answered.json));
        if (!PRODUCT) {
          note(holds(walletName) && entryCount() > before,
               'B2. ' + label + ': and the identity it carries is recorded, ' +
               'which makes an entry for ' + walletName + ' (the control)',
               entryCount() + ' / ' + before);
        } else {
          note(!holds(walletName) && entryCount() === before,
               'B2. ' + label + ': and no entry is made for ' + walletName +
               ' — the directory holds as many entries as before',
               entryCount() + ' / ' + before);
        }

        // --- C. the SVID -------------------------------------------------
        const svidId = 'spiffe://' + w.inRealm(function () {
          return ca.trustDomain();
        }) + '/cs-svid-' + mode.slice(0, 4) + '-' + M.stamp;
        before = entryCount();
        const svid = await w.inRealm(function () {
          return ca.mintX509Svid(svidId, { ttl: 600 });
        });
        const caller = w.inRealm(function () {
          return auth.callerOf(callWith(svid), 'server');
        });
        // `prepareCall()`'s two steps for an authorized caller: the access
        // policy's question (which starts the caller's session through
        // `sessionForCaller()`), then the recording.
        const refused = w.inRealm(function () {
          return grpc.policyRefusal(caller,
                                    'spire.api.server.entry.v1.Entry/' +
                                    'ListEntries');
        });
        w.inRealm(function () {
          auth.recordCaller(caller);
        });
        const svidSession = w.inRealm(function () {
          return m.authn.sessionsOf(svidId)[0] || null;
        });
        note(caller.authenticated === true && caller.spiffeId === svidId,
             'C1. ' + label + ': the X509-SVID for ' + svidId + ' is an ' +
             'authenticated SPIRE Server API caller',
             JSON.stringify({ id: caller.spiffeId, refusal: caller.refusal,
                              policy: refused }));
        if (!PRODUCT) {
          note(holds(svidId) && entryCount() > before,
               'C2. ' + label + ': and the caller is recorded, which makes ' +
               'an entry for ' + svidId + ' (the control)',
               entryCount() + ' / ' + before);
        } else {
          note(!holds(svidId) && entryCount() === before,
               'C2. ' + label + ': and no entry is made for ' + svidId +
               ' — the directory holds as many entries as before',
               entryCount() + ' / ' + before);
          note(!svidSession || !(svidSession.user && svidSession.user.sub),
               'C3. ' + label + ': its session is a record of the call and ' +
               'names no subject — nobody is signed in as a person',
               JSON.stringify(svidSession && svidSession.user));
        }
      } finally {
        if (PRODUCT) {
          m.config.clearOverride('pki.revocationCheck');
          m.config.clearOverride('global.mode');
        }
      }
    }
    listener.close();
  }
}

// THE CERTIFICATES NOBODY HERE ISSUED, made with OpenSSL: a CA and, signed by
// it, one client certificate per mode, each naming a person nobody created —
// `tests/rfc8705_mtls.js`'s arrangement. Made per run and removed after it.
function openssl(dir, args) {
  log.debug("Entering openssl().");
  childProcess.execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  log.debug("Leaving openssl().");
}

function makeMaterial() {
  log.debug("Entering makeMaterial().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-414-'));
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
              '-nodes'];
  openssl(dir, ['req', '-x509'].concat(ec, ['-keyout', 'ca.key', '-out',
    'ca.pem', '-days', '2', '-subj', '/CN=Issue 414 Test Foreign CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign']));
  fs.writeFileSync(path.join(dir, 'leaf.cnf'),
    'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n' +
    'extendedKeyUsage=clientAuth\n');
  const material = { dir: dir, stamp: STAMP,
                     caCert: path.join(dir, 'ca.pem'),
                     names: {}, leaf: {}, key: {} };
  ['development', 'product'].forEach(function (mode) {
    const name = 'cs-cert-' + mode.slice(0, 4) + '-' + STAMP;
    openssl(dir, ['req'].concat(ec, ['-keyout', mode + '.key', '-out',
      mode + '.csr', '-subj', '/CN=' + name]));
    openssl(dir, ['x509', '-req', '-in', mode + '.csr', '-CA', 'ca.pem',
      '-CAkey', 'ca.key', '-CAcreateserial', '-out', mode + '.pem',
      '-days', '1', '-extfile', 'leaf.cnf']);
    material.names[mode] = name;
    material.leaf[mode] = path.join(dir, mode + '.pem');
    material.key[mode] = path.join(dir, mode + '.key');
  });
  log.debug("Leaving makeMaterial().");
  return material;
}

async function run(t) {
  log.debug("Entering run().");
  let material = null;
  try {
    material = makeMaterial();
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('openssl made the foreign CA and its client certificates',
          (e && e.message) || String(e));
    log.debug("Leaving run(). No openssl.");
    return;
  }
  try {
    kit.inAChild(t, childMain, 'credential-seeds-no-entry',
                 { CS_MATERIAL: JSON.stringify(material) });
  } finally {
    fs.rmSync(material.dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'credential_seeds_no_entry',
  describe: 'a client certificate at GET /tls/sign-in, a wallet ' +
            'presentation and an X509-SVID naming nobody provisioned make ' +
            'an entry in development and none in product, where they sign ' +
            'nobody in (#414)',
  run: run
};
