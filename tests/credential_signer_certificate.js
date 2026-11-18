// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: credential_signer_certificate.js
//
// ===========================================================================
// A CREDENTIAL IS SIGNED BY A KEY OF ITS OWN, WHOSE CERTIFICATE NAMES ITS
// ISSUER (#1880), in process, against the real stack and its certificate
// authority.
//
// `common/credential_signer.js` argues the design. What is held here, each
// time reading the credential a wallet receives, and reading the certificate
// with two parsers this service does not use to write it — node's
// X509Certificate, and the `openssl` command where the image has it:
//
//   A. THE DEFAULT, UNPINNED. An SD-JWT VC's `x5c` leaf is NOT the realm's
//      general JOSE key; its subjectAltName is URIs only (no dNSName), one
//      per name the main port's certificate asserts, on the main port, with
//      the did:web of each; its extended key usage is id-kp-documentSigning
//      and nothing a TLS stack accepts; its keyUsage is digitalSignature
//      alone; OpenSSL refuses it as a TLS server certificate and accepts the
//      chain; the last `x5c` member is not self-signed and is signed by the
//      Root, which is not in `x5c`; the credential verifies with the leaf's
//      key; this service's own path check and paranoid PKI's `vc-issuer`
//      fields accept it; `/oauth2/jwks` publishes the key with that chain;
//      and the key verifies none of the realm's own tokens.
//   B. PINNED. With `global.publicBaseUrl` set, the certificate is RE-ISSUED
//      over the same key and names exactly that issuer and its did:web; the
//      `iss` is one of them; the certificate it replaced is still in the
//      register and not revoked, so a credential issued under it verifies.
//   C. A REALM's credential signer is its own, and names the realm's prefix.
//   D. EVERY KEY FAMILY: ES256, and ML-DSA-44 — a post-quantum key with a
//      certificate OVER ITSELF, never a partner's.
//   E. `keys.credentialSigner=realm-key` is 1.0.0's: the general key and its
//      certificate. A credential signed either way, and one from before the
//      address change, is accepted by this realm's Verifier.
//   F. THE LIVE CERTIFICATE IS NEVER ON ITS CA'S CRL (run #478), AND A
//      COMPROMISED KEY IS NEVER CERTIFIED AGAIN. Revoked keyCompromise — as
//      sts_pki_revocation revokes the first JOSE leaf by subject, which is
//      now this one — the key leaves /oauth2/jwks at once, the next
//      credential is signed by a NEW key under a new certificate, and a
//      credential the old key signed is refused. Revoked superseded, the
//      same key gets a new certificate and its credentials still verify.
//      Put on hold, the key is replaced as for a compromise, and a released
//      hold makes its credentials verify again (it signs nothing again).
//      After the JOSE Issuing CA is re-issued and its leaves re-certified,
//      the certificate published is still one its CA has not revoked.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({
  name: 'credential_signer_certificate',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    const note = w.note;
    const m = w.m;
    const nodeCrypto = require('crypto');
    const childProcess = require('child_process');
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const pki = require(ROOT + '/common/pki');
    const keystore = require(ROOT + '/common/keystore');
    const revocation = require(ROOT + '/common/pki_revocation');
    const trust = require(ROOT + '/common/certificate_trust');
    const DOC_SIGNING = '1.3.6.1.5.5.7.3.36';
    const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
    const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
    const REALM = 'csrealm';

    function pemOf(b64) {
      return '-----BEGIN CERTIFICATE-----\n' +
        String(b64).match(/.{1,64}/g).join('\n') +
        '\n-----END CERTIFICATE-----\n';
    }
    function headerOf(jwt) {
      return JSON.parse(Buffer.from(String(jwt).split('~')[0].split('.')[0],
                                    'base64url').toString('utf8'));
    }
    function sansOf(cert) {
      return String(cert.subjectAltName || '').split(', ')
        .filter(Boolean);
    }
    function urisOf(cert) {
      return sansOf(cert).filter(function (one) {
        return one.indexOf('URI:') === 0;
      }).map(function (one) {
        return one.slice(4);
      }).sort();
    }
    function spkiOf(keyObject) {
      return keyObject.export({ type: 'spki', format: 'der' })
        .toString('base64');
    }
    function didOf(base) {
      const rest = base.replace(/^https?:\/\//, '');
      const slash = rest.indexOf('/');
      const host = slash < 0 ? rest : rest.slice(0, slash);
      const segs = slash < 0 ? [] : rest.slice(slash + 1).split('/');
      return 'did:web:' + [host.replace(/:/g, '%3A')].concat(segs).join(':');
    }
    // The `openssl` command, where the image has it; null where it has not.
    function openssl(args, input) {
      try {
        return { ok: true, out: childProcess.execFileSync('openssl', args,
          { input: input, stdio: ['pipe', 'pipe', 'pipe'] }).toString() };
      } catch (e) {
        if (e && e.code === 'ENOENT') {
          return null;
        }
        return { ok: false, out: String((e && e.stdout) || '') +
                                 String((e && e.stderr) || '') };
      }
    }
    async function presentToBarDoor(credential, holder) {
      const begun = await w.verificationStart('by=reference&format=' +
                                              encodeURIComponent('dc+sd-jwt'));
      if (begun.status !== 302) {
        return { status: begun.status, text: JSON.stringify(begun.json) };
      }
      const url = new URL(begun.headers.location);
      const ro = w.decode((await w.request('GET',
        w.pathOf(url.searchParams.get('request_uri')))).text);
      await w.inRealm(function () {
        const tx = m.verifier.transactionFor(ro.state);
        tx.requested = [];
        m.verifier.saveTransaction(tx);
      });
      return w.request('POST', '/oid4vp/response', {
        form: { state: ro.state,
                vp_token: w.vpToken('dc+sd-jwt',
                  w.presentSdJwt(credential, holder, ro.nonce,
                                 ro.client_id)) } });
    }

    try {
      await keystore.start();
      await pki.start({ realmIds: [''],
        keySetFor: function (id) {
          return m.helpers.stsKeysFor.of(id);
        },
        keySetHeldFor: function () {
          return false;
        } });
      await pki.ensureScope('');
      w.provision();
      const rootPem = pki.serviceRoot().certificatePem;
      const rootCert = new nodeCrypto.X509Certificate(rootPem);

      // ================================================================
      // A. THE DEFAULT, UNPINNED
      // ================================================================
      const holder = w.holderKey();
      const sd = await w.issue('cs-alice', holder);
      const jwt = sd.credential ? String(sd.credential).split('~')[0] : '';
      const header = jwt ? headerOf(jwt) : {};
      const claims = jwt ? w.decode(jwt) : {};
      const x5c = header.x5c || [];
      note(!!sd.credential && x5c.length === 3,
           'A1. an SD-JWT VC is issued and its x5c is leaf, Issuing CA and ' +
           'Intermediate', (sd.error || '') + ' ' + x5c.length);
      const leafPem = x5c.length ? pemOf(x5c[0]) : '';
      const leaf = leafPem ? new nodeCrypto.X509Certificate(leafPem) : null;
      const general = new nodeCrypto.X509Certificate(
        w.inRealm(function () { return m.helpers.STS.certPem; }));
      note(leaf && spkiOf(leaf.publicKey) !== spkiOf(general.publicKey) &&
           header.kid !== w.inRealm(function () {
             return m.helpers.publishedKidFor(m.helpers.STS.kid);
           }),
           'A2. the leaf is NOT the realm\'s general JOSE key: the ' +
           'credential has a signer of its own', header.kid);
      const sans = leaf ? sansOf(leaf) : [];
      const uris = leaf ? urisOf(leaf) : [];
      const https = m.config.value('global.https') === true;
      const port = Number(m.config.value('global.port'));
      const expected = [];
      [].concat(m.config.value('tls.hostnames') || [])
        .concat(m.config.value('tls.ips') || []).forEach(function (name) {
          const base = (https ? 'https' : 'http') + '://' +
                       String(name).toLowerCase() + ':' + port;
          expected.push(base, didOf(base));
          if (port === (https ? 443 : 80)) {
            const bare = (https ? 'https' : 'http') + '://' +
                         String(name).toLowerCase();
            expected.push(bare, didOf(bare));
          }
        });
      expected.sort();
      note(sans.length > 0 && sans.every(function (one) {
        return one.indexOf('URI:') === 0;
      }) && JSON.stringify(uris) === JSON.stringify(expected),
           'A3. its subjectAltName is URIs only — no DNS name — one for ' +
           'every name tls.hostnames and tls.ips assert, on the main port, ' +
           'and the did:web of each', JSON.stringify(sans));
      note(uris.indexOf(claims.iss) < 0,
           'A4. the request reached the stack on an ephemeral port nobody ' +
           'configured, so its iss is NOT named — the credential is still ' +
           'signed (STS-PKI-0283 is logged), and a Host header never ' +
           'becomes a name the Root certifies', claims.iss);
      const ekus = leaf ? (leaf.keyUsage || []) : [];
      note(ekus.length === 1 && ekus[0] === DOC_SIGNING &&
           ekus.indexOf(SERVER_AUTH) < 0 && ekus.indexOf(CLIENT_AUTH) < 0,
           'A5. its extended key usage is id-kp-documentSigning alone ' +
           '(RFC 9336) — no serverAuth, no clientAuth', JSON.stringify(ekus));
      const last = x5c.length
        ? new nodeCrypto.X509Certificate(pemOf(x5c[x5c.length - 1])) : null;
      note(last && last.subject !== last.issuer && !last.checkIssued(last) &&
           last.verify(rootCert.publicKey) &&
           x5c.indexOf(rootCert.raw.toString('base64')) < 0,
           'A6. the last x5c member is not self-signed: it is the ' +
           'Intermediate, signed by the Root, and the Root is not in x5c ' +
           '(HAIP 1.0 section 6.1.1)', last && last.subject);
      let verified = null;
      try {
        verified = m.stsCrypto.verifyJws(jwt, leaf.publicKey,
                                         { algorithms: [header.alg] });
      } catch (e) {
        verified = { error: e.message };
      }
      note(verified && verified.iss === claims.iss,
           'A7. the credential verifies with the key IN the leaf',
           JSON.stringify(verified && (verified.error || verified.iss)));
      const text = openssl(['x509', '-noout', '-text'], leafPem);
      if (text) {
        const out = text.out;
        note(text.ok && /X509v3 Subject Alternative Name/.test(out) &&
             !/DNS:/.test(out) && /URI:/.test(out) &&
             /Document Signing|1\.3\.6\.1\.5\.5\.7\.3\.36/.test(out) &&
             !/TLS Web Server|TLS Web Client/.test(out) &&
             /X509v3 Key Usage: critical\s+Digital Signature\s*\n/.test(out),
             'A8. OpenSSL reads the same: URIs, no DNS name, Document ' +
             'Signing, and a critical keyUsage of Digital Signature alone',
             out.slice(out.indexOf('X509v3 extensions'),
                       out.indexOf('X509v3 extensions') + 900));
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs1880-'));
        fs.writeFileSync(path.join(dir, 'root.pem'), rootPem);
        fs.writeFileSync(path.join(dir, 'chain.pem'),
                         pemOf(x5c[1]) + pemOf(x5c[2]));
        fs.writeFileSync(path.join(dir, 'leaf.pem'), leafPem);
        const plain = openssl(['verify', '-CAfile',
          path.join(dir, 'root.pem'), '-untrusted',
          path.join(dir, 'chain.pem'), path.join(dir, 'leaf.pem')]);
        const asServer = openssl(['verify', '-purpose', 'sslserver',
          '-CAfile', path.join(dir, 'root.pem'), '-untrusted',
          path.join(dir, 'chain.pem'), path.join(dir, 'leaf.pem')]);
        fs.rmSync(dir, { recursive: true, force: true });
        note(plain.ok && !asServer.ok &&
             /(unsupported|unsuitable) certificate purpose/i
               .test(asServer.out),
             'A9. OpenSSL builds the chain to the Root, and refuses the leaf ' +
             'as a TLS server certificate', plain.out.trim() + ' / ' +
             asServer.out.trim().split('\n').slice(-2).join(' '));
      } else {
        note(true, 'A8-A9. (no openssl in this image: node\'s reading only)');
      }
      const ownPath = await pki.verifyLeaf('', leafPem,
                                           [pemOf(x5c[1]), pemOf(x5c[2])]);
      note(ownPath.ok, 'A10. this service\'s own path check accepts it',
           ownPath.why || '');
      const fields = await w.inRealm(function () {
        m.config.setOverride('pki.paranoid', 'on');
        const answer = trust.fields('vc-issuer', leafPem, { realmId: '' });
        m.config.clearOverride('pki.paranoid');
        return answer;
      });
      note(fields.ok,
           'A11. and paranoid PKI mode\'s vc-issuer rule accepts its fields ' +
           '(documentSigning is not refused)', fields.code + ' ' + fields.why);
      const jwks = await w.request('GET', '/oauth2/jwks');
      const published = ((jwks.json && jwks.json.keys) || [])
        .filter(function (k) {
          return k.x5c && k.x5c[0] === x5c[0];
        })[0];
      // A published JWK's x5c runs through the Root (`helpers.x5cOf()`,
      // #1064); a credential's stops below it.
      note(published && published.x5c.filter(function (one) {
        return one !== rootCert.raw.toString('base64');
      }).join(',') === x5c.join(','),
           'A12. /oauth2/jwks — which JWT VC Issuer Metadata names — ' +
           'publishes the credential key with the same chain (and the ' +
           'Root, as every published JWK does)',
           published ? published.kid : 'not published');
      const accepted = w.inRealm(function () {
        return m.helpers.allVerificationKeys().filter(function (one) {
          return one.publicJwk && /^sts-vc-/.test(one.publicJwk.kid);
        }).length;
      });
      note(accepted === 0,
           'A13. and it is not among the keys this realm verifies its own ' +
           'tokens with', accepted);
      const serialA = leaf ? leaf.serialNumber : '';
      const spkiA = leaf ? spkiOf(leaf.publicKey) : '';

      // ================================================================
      // B. PINNED: THE ADDRESS SET CHANGES, THE CERTIFICATE IS RE-ISSUED
      // ================================================================
      await w.inRealm(function () {
        m.config.setOverride('global.publicBaseUrl', w.base);
      });
      const pinned = await w.issue('cs-alice', holder);
      const pinnedJwt = pinned.credential
        ? String(pinned.credential).split('~')[0] : '';
      const pinnedHeader = pinnedJwt ? headerOf(pinnedJwt) : {};
      const pinnedLeaf = (pinnedHeader.x5c || []).length
        ? new nodeCrypto.X509Certificate(pemOf(pinnedHeader.x5c[0])) : null;
      const pinnedIss = pinnedJwt ? w.decode(pinnedJwt).iss : '';
      note(pinnedLeaf &&
           JSON.stringify(urisOf(pinnedLeaf)) ===
             JSON.stringify([w.base, didOf(w.base)].sort()) &&
           urisOf(pinnedLeaf).indexOf(pinnedIss) >= 0,
           'B1. with global.publicBaseUrl pinned, the certificate names ' +
           'exactly that issuer and its did:web, and iss is one of them',
           pinnedLeaf && JSON.stringify(urisOf(pinnedLeaf)) + ' iss=' +
           pinnedIss);
      note(pinnedLeaf && pinnedLeaf.serialNumber !== serialA &&
           spkiOf(pinnedLeaf.publicKey) === spkiA,
           'B2. it was RE-ISSUED when the address set changed — a new ' +
           'serial — over the same key', serialA + ' -> ' +
           (pinnedLeaf && pinnedLeaf.serialNumber));
      note(revocation.issuedHere('', 'jose', serialA) &&
           !revocation.isRevoked('', 'jose', serialA),
           'B3. the certificate it replaced is still in the register and ' +
           'not revoked, so a credential issued under it stays verifiable',
           serialA);
      const again = await w.issue('cs-alice', holder);
      const againHeader = again.credential ? headerOf(again.credential) : {};
      note((againHeader.x5c || [])[0] === (pinnedHeader.x5c || [])[0],
           'B4. and with nothing changed, the next credential carries the ' +
           'same certificate — it is not re-issued per credential');

      // ================================================================
      // C. A REALM
      // ================================================================
      m.realms.create({ id: REALM });
      await pki.ensureScope(REALM);
      await w.inRealm(function () {
        w.provision();
      }, m.realms.get(REALM));
      const inRealm = await w.issue('cs-alice', holder,
        { prefix: '/realm/' + REALM, realm: m.realms.get(REALM) });
      const realmHeader = inRealm.credential
        ? headerOf(inRealm.credential) : {};
      const realmLeaf = (realmHeader.x5c || []).length
        ? new nodeCrypto.X509Certificate(pemOf(realmHeader.x5c[0])) : null;
      const realmBase = w.base + '/realm/' + REALM;
      note(realmLeaf && spkiOf(realmLeaf.publicKey) !== spkiA &&
           JSON.stringify(urisOf(realmLeaf)) ===
             JSON.stringify([realmBase, didOf(realmBase)].sort()),
           'C1. a realm\'s credential signer is its own key, and its ' +
           'certificate names the realm\'s issuer, prefix and all',
           (inRealm.error || '') + ' ' +
           (realmLeaf && JSON.stringify(urisOf(realmLeaf))));

      // ================================================================
      // D. EVERY KEY FAMILY: ES256 AND ML-DSA-44
      // ================================================================
      for (const alg of ['ES256', 'ML-DSA-44']) {
        await w.inRealm(function () {
          m.config.setOverride('oid4vci.credentialSigningAlgorithm', alg);
        });
        const got = await w.issue('cs-alice', w.holderKey());
        const h = got.credential ? headerOf(got.credential) : {};
        const one = (h.x5c || []).length
          ? new nodeCrypto.X509Certificate(pemOf(h.x5c[0])) : null;
        const keys = await w.request('GET', '/oauth2/jwks');
        const jwk = ((keys.json && keys.json.keys) || []).filter(function (k) {
          return k.x5c && k.x5c[0] === (h.x5c || [])[0];
        })[0];
        let overItself = false;
        if (one && jwk && alg === 'ES256') {
          overItself = spkiOf(one.publicKey) ===
            spkiOf(nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' }));
        } else if (one && jwk) {
          const held = pki.pqJwkFromCertificate(one.toString());
          overItself = !!held && held.alg === alg &&
                       held.publicJwk.pub === jwk.pub;
        }
        note(h.alg === alg && one && overItself &&
             (one.keyUsage || []).join(',') === DOC_SIGNING &&
             urisOf(one).indexOf(w.base) >= 0 &&
             !sansOf(one).some(function (s) { return /^DNS:/.test(s); }),
             'D1[' + alg + ']. a credential signed with ' + alg + ' carries ' +
             'a certificate OVER THAT KEY (never a partner\'s), with ' +
             'documentSigning and the issuer URI, and no DNS name',
             (got.error || '') + ' alg=' + h.alg + ' x5c=' +
             (h.x5c || []).length + ' overItself=' + overItself);
      }
      await w.inRealm(function () {
        m.config.clearOverride('oid4vci.credentialSigningAlgorithm');
      });

      // ================================================================
      // E. realm-key, 1.0.0's behaviour, and the Verifier accepts both
      // ================================================================
      await w.inRealm(function () {
        m.config.setOverride('keys.credentialSigner', 'realm-key');
      });
      const oldHolder = w.holderKey();
      const old = await w.issue('cs-alice', oldHolder);
      const oldHeader = old.credential ? headerOf(old.credential) : {};
      const oldLeaf = (oldHeader.x5c || []).length
        ? new nodeCrypto.X509Certificate(pemOf(oldHeader.x5c[0])) : null;
      note(oldLeaf && spkiOf(oldLeaf.publicKey) === spkiOf(general.publicKey),
           'E1. keys.credentialSigner=realm-key signs with the realm\'s ' +
           'general JOSE key, as 1.0.0 did', oldHeader.kid);
      await w.inRealm(function () {
        m.config.clearOverride('keys.credentialSigner');
      });
      const oldAnswer = await presentToBarDoor(old.credential, oldHolder);
      const newAnswer = await presentToBarDoor(pinned.credential, holder);
      const firstAnswer = await presentToBarDoor(sd.credential, holder);
      note(oldAnswer.status === 200 && newAnswer.status === 200 &&
           firstAnswer.status === 200,
           'E2. this realm\'s Verifier accepts a credential signed by the ' +
           'general key, one by the credential signer, and one issued ' +
           'under the certificate that was replaced',
           [oldAnswer.status, newAnswer.status, firstAnswer.status].join(' ') +
           ' ' + String(oldAnswer.text || '').slice(0, 160) + ' ' +
           String(newAnswer.text || '').slice(0, 160));

      // ================================================================
      // F. THE LIVE CERTIFICATE IS NEVER ON ITS CA'S CRL
      // ================================================================
      // Every credential-signer certificate /oauth2/jwks publishes, and any
      // of them its issuing authority's register (what its CRL and OCSP
      // responder answer from) calls revoked.
      async function publishedCredentialLeaves() {
        const got = await w.request('GET', '/oauth2/jwks');
        const leaves = ((got.json && got.json.keys) || [])
          .filter(function (k) {
            return /^sts-vc-/.test(String(k.kid)) && k.x5c && k.x5c.length;
          }).map(function (k) {
            return new nodeCrypto.X509Certificate(pemOf(k.x5c[0]));
          });
        return { leaves: leaves,
                 revoked: leaves.filter(function (one) {
                   return !!revocation.isRevoked('', 'jose',
                                                 one.serialNumber);
                 }).map(function (one) {
                   return one.serialNumber;
                 }) };
      }
      const live = pki.certificateFor('', 'jose', 'vc-issuer:RSA');
      const liveKid = String(live.kid || '');
      const revokedLive = revocation.revoke('', 'jose',
        { serialHex: live.serialHex, reason: 'keyCompromise',
          subject: live.subject, note: 'credential_signer_certificate F' });
      const afterRevoke = await publishedCredentialLeaves();
      note(revokedLive.ok && afterRevoke.revoked.length === 0 &&
           !afterRevoke.leaves.some(function (one) {
             return one.serialNumber.toLowerCase().replace(/^0+/, '') ===
                    String(live.serialHex).toLowerCase().replace(/^0+/, '');
           }),
           'F1. the live credential-signing certificate revoked, as ' +
           'sts_pki_revocation does, /oauth2/jwks publishes it no more — no ' +
           'published certificate is on its CA\'s CRL',
           live.serialHex + ' revoked=' + JSON.stringify(afterRevoke.revoked));
      const reissued = await w.issue('cs-alice', holder);
      const reissuedHeader = reissued.credential
        ? headerOf(reissued.credential) : {};
      const reissuedLeaf = (reissuedHeader.x5c || []).length
        ? new nodeCrypto.X509Certificate(pemOf(reissuedHeader.x5c[0])) : null;
      note(afterRevoke.leaves.every(function (one) {
        return spkiOf(one.publicKey) !== spkiA;
      }) && !(((await w.request('GET', '/oauth2/jwks')).json || {}).keys ||
              []).some(function (k) {
        return k.kid === w.inRealm(function () {
          return m.helpers.publishedKidFor(liveKid);
        });
      }),
           'F1b. a key whose certificate was revoked keyCompromise is not ' +
           'published at all, bare or otherwise', liveKid);
      note(reissuedLeaf &&
           !revocation.isRevoked('', 'jose', reissuedLeaf.serialNumber) &&
           spkiOf(reissuedLeaf.publicKey) !== spkiA &&
           reissuedHeader.kid !== header.kid,
           'F2. and the next credential is signed by a NEW key (never the ' +
           'compromised one certified again), under a certificate not ' +
           'revoked', (reissued.error || '') + ' ' + reissuedHeader.kid +
           ' ' + (reissuedLeaf && reissuedLeaf.serialNumber));
      const oldRefused = await presentToBarDoor(pinned.credential, holder);
      const newAccepted = await presentToBarDoor(reissued.credential, holder);
      note(oldRefused.status !== 200 && newAccepted.status === 200,
           'F2b. a credential the compromised key signed is refused by ' +
           'this realm\'s Verifier; one the new key signed is accepted',
           oldRefused.status + ' ' + newAccepted.status);
      const spkiB = reissuedLeaf ? spkiOf(reissuedLeaf.publicKey) : '';
      const afterIssue = await publishedCredentialLeaves();
      note(afterIssue.leaves.length > 0 && afterIssue.revoked.length === 0,
           'F3. which /oauth2/jwks publishes again',
           afterIssue.leaves.length + ' revoked=' +
           JSON.stringify(afterIssue.revoked));

      // SUPERSEDED: the same key, a new certificate.
      const liveB = pki.certificateFor('', 'jose', 'vc-issuer:RSA~1');
      revocation.revoke('', 'jose', { serialHex: liveB && liveB.serialHex,
        reason: 'superseded', subject: liveB && liveB.subject,
        note: 'credential_signer_certificate F' });
      const afterSuperseded = await w.issue('cs-alice', holder);
      const supersededHeader = afterSuperseded.credential
        ? headerOf(afterSuperseded.credential) : {};
      const supersededLeaf = (supersededHeader.x5c || []).length
        ? new nodeCrypto.X509Certificate(pemOf(supersededHeader.x5c[0]))
        : null;
      const stillGood = await presentToBarDoor(reissued.credential, holder);
      note(liveB && supersededLeaf &&
           spkiOf(supersededLeaf.publicKey) === spkiB &&
           supersededHeader.kid === reissuedHeader.kid &&
           !revocation.isRevoked('', 'jose', supersededLeaf.serialNumber) &&
           stillGood.status === 200,
           'F3b. revoked superseded, the SAME key gets a new certificate, ' +
           'and what it signed before still verifies',
           (liveB && liveB.serialHex) + ' -> ' +
           (supersededLeaf && supersededLeaf.serialNumber) + ' ' +
           stillGood.status);

      // ON HOLD: replaced as for a compromise; released, trusted again.
      const liveC = pki.certificateFor('', 'jose', 'vc-issuer:RSA~1');
      revocation.revoke('', 'jose', { serialHex: liveC && liveC.serialHex,
        reason: 'certificateHold', subject: liveC && liveC.subject,
        note: 'credential_signer_certificate F' });
      const afterHold = await w.issue('cs-alice', holder);
      const holdHeader = afterHold.credential
        ? headerOf(afterHold.credential) : {};
      const heldRefused = await presentToBarDoor(reissued.credential, holder);
      note(holdHeader.kid && holdHeader.kid !== reissuedHeader.kid &&
           heldRefused.status !== 200,
           'F3c. put on hold, the key signs no more — a new one does — and ' +
           'what it signed is refused while the hold stands',
           holdHeader.kid + ' ' + heldRefused.status);
      const released = revocation.release('', 'jose',
                                          liveC && liveC.serialHex);
      const afterRelease = await presentToBarDoor(reissued.credential,
                                                  holder);
      const nextAfterRelease = await w.issue('cs-alice', holder);
      const releaseHeader = nextAfterRelease.credential
        ? headerOf(nextAfterRelease.credential) : {};
      note(released && released.ok !== false &&
           afterRelease.status === 200 &&
           releaseHeader.kid === holdHeader.kid,
           'F3d. the hold released, what the held key signed verifies ' +
           'again, and the newer key goes on signing',
           JSON.stringify(released && (released.errors || released.ok)) +
           ' ' + afterRelease.status + ' ' + releaseHeader.kid);

      const rebuilt = await pki.reissueUseCase('', 'jose');
      const afterRebuild = await publishedCredentialLeaves();
      const rebuiltCredential = await w.issue('cs-alice', holder);
      const rebuiltHeader = rebuiltCredential.credential
        ? headerOf(rebuiltCredential.credential) : {};
      const rebuiltLeaf = (rebuiltHeader.x5c || []).length
        ? new nodeCrypto.X509Certificate(pemOf(rebuiltHeader.x5c[0])) : null;
      note(rebuilt && rebuilt.ok !== false &&
           afterRebuild.revoked.length === 0 && rebuiltLeaf &&
           !revocation.isRevoked('', 'jose', rebuiltLeaf.serialNumber),
           'F4. after the JOSE Issuing CA is re-issued and its leaves ' +
           're-certified, neither /oauth2/jwks nor the next credential ' +
           'carries a certificate its CA has revoked',
           JSON.stringify(rebuilt && (rebuilt.errors || rebuilt.ok)) + ' ' +
           JSON.stringify(afterRebuild.revoked));
      const recertified = await pki.recertifyUseCase('', 'jose');
      const afterRecertify = await publishedCredentialLeaves();
      note(recertified && afterRecertify.revoked.length === 0,
           'F5. and the same after its leaves are re-certified in place',
           JSON.stringify(afterRecertify.revoked));

      await w.inRealm(function () {
        m.config.clearOverride('global.publicBaseUrl');
      });
    } catch (e) {
      note(false, 'the test ran to its end', e && e.stack);
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'credential-signer-certificate');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'credential signer certificate',
  describe: 'a credential is signed by a key of its own whose certificate ' +
            'names its issuer as a URI, with documentSigning and no DNS ' +
            'name, re-issued when the issuer addresses change (#1880)',
  run: run
};
