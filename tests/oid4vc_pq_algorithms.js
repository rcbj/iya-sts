// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oid4vc_pq_algorithms.js
//
// ===========================================================================
// POST-QUANTUM ALGORITHMS IN OPENID4VP AND THE JOSE CREDENTIAL FORMATS, AND
// THE WALLET COMPATIBILITY MODE (#657), in process, against the real stack.
//
// Every one of the eleven post-quantum and composite JWS algorithms
// (ML-DSA-44/65/87, SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s and the six
// composite ML-DSA ones), each through every door #657 opened:
//
//   1. oid4vp.x509SigningAlgorithm: an x509_hash Request Object signed with
//      it, by the key of the Verifier's certificate in `x5c` — checked as a
//      wallet does, against the leaf's SubjectPublicKeyInfo under the
//      vendored X.509 reading (`pqc_x509.js`), not the signer's;
//   2. oid4vp.requestObjectSigningAlgorithm: a pre-registered Request
//      Object signed with it, by the key /oauth2/jwks publishes under the
//      header's `kid`; and for one algorithm the decentralized_identifier
//      prefix (the DID document lists the key), the self-issued Verifier
//      Attestation (its `cnf` is the key) and the Entity Configuration's
//      openid_credential_verifier `jwks`; a sign-in's Digital Credentials
//      API request; and a synchronous build refused rather than unsigned;
//   3. a TRUSTED FOREIGN ISSUER whose certificate holds a key of it: a
//      dc+sd-jwt credential whose Token Status List that issuer serves,
//      signed with the same key, and a jwt_vc_json credential — both
//      accepted at the bar door; a Key Binding JWT and a VP JWT by an
//      ML-DSA-44 holder;
//   4. oid4vc.walletCompatibility: the issuer's and the Verifier's metadata
//      name none of the eleven, a credential, an x509 and a pre-registered
//      Request Object are refused (STS-VC-0152), a foreign credential, a
//      KB-JWT and a proof of possession signed with one are refused
//      (STS-VC-0153), and the classical algorithms still work.
//
// The foreign issuer's keys, credentials, status lists and holder proofs
// are made by `common/pq_jose.js` through the test's own calls — the wallet
// kit's arrangement — and the realm's signatures are checked against the
// certificate and the published JWK, never by asking the module that made
// them.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'oid4vc_pq_algorithms',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    const note = w.note;
    const m = w.m;
    try {
      await sections(w, note, m);
    } catch (e) {
      note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });

  async function sections(w, note, m) {
    const http = require('http');
    const nodeCrypto = require('crypto');
    const pki = require(ROOT + '/common/pki');
    const pqcX509 = require(ROOT + '/common/crypto_impl/pqc_x509');
    const x509 = require(ROOT + '/common/crypto_impl/x509');
    const vcDid = require(ROOT + '/oid4vc/vc_did');
    const PQ = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128s',
                'SLH-DSA-SHAKE-128s', 'ML-DSA-44-ES256', 'ML-DSA-65-ES256',
                'ML-DSA-87-ES384', 'ML-DSA-44-Ed25519', 'ML-DSA-65-Ed25519',
                'ML-DSA-87-Ed448'];
    const touched = ['oid4vp.x509SigningAlgorithm',
                     'oid4vp.requestObjectSigningAlgorithm',
                     'oid4vp.clientIdPrefix', 'oid4vp.signInClientIdPrefix',
                     'oid4vp.trustedIssuerCertificates',
                     'oid4vp.requireStatusReference',
                     'oid4vci.credentialSigningAlgorithm',
                     'oid4vc.walletCompatibility',
                     'federation.outboundAllowHttp', 'oid4vp.claims'];

    await w.inRealm(function () {
      w.provision();
      m.config.setOverride('federation.outboundAllowHttp', 'true');
      m.config.setOverride('oid4vp.claims', '');
    });

    function headerOf(jws) {
      return JSON.parse(Buffer.from(String(jws).split('.')[0], 'base64url')
        .toString('utf8'));
    }

    function pemOf(b64) {
      return '-----BEGIN CERTIFICATE-----\n' +
        String(b64).match(/.{1,64}/g).join('\n') +
        '\n-----END CERTIFICATE-----\n';
    }

    function spkiOf(certificatePem) {
      const pkijs = require('pkijs');
      const der = Buffer.from(String(certificatePem)
        .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
      const cert = pkijs.Certificate.fromBER(new Uint8Array(der));
      return new Uint8Array(cert.subjectPublicKeyInfo.toSchema()
        .toBER(false));
    }

    // A composite's JOSE signature in X.509's form: the ECDSA half is R||S
    // in JOSE and a DER Ecdsa-Sig-Value in X.509 (pq_key_certification.js).
    function x509SignatureOf(alg, signature) {
      const cfg = m.pqJose.COMPOSITES[alg];
      if (!cfg || m.pqJose.TRAD[cfg.trad].kind !== 'ec') {
        return Buffer.from(signature);
      }
      const tradLength = m.pqJose.TRAD[cfg.trad].sigLen;
      const mlPart = signature.subarray(0, signature.length - tradLength);
      const tradPart = signature.subarray(signature.length - tradLength);
      return Buffer.concat([mlPart,
                            Buffer.from(x509.ecdsaRawToDer(tradPart))]);
    }

    // A JWS checked as a WALLET checks it: its signature over the signing
    // input, against a SubjectPublicKeyInfo, under the vendored X.509
    // reading — the other implementation in this tree.
    async function pqJwsVerifies(jws, alg, spki) {
      const parts = String(jws).split('.');
      const decoded = pqcX509.decodeSpki(spki);
      if (!decoded || decoded.alg !== pki.PQ_JOSE_IN_X509[alg].id) {
        return false;
      }
      try {
        return !!(await pqcX509.verify(decoded.alg,
          x509SignatureOf(alg, Buffer.from(parts[2], 'base64url')),
          Buffer.from(parts[0] + '.' + parts[1], 'ascii'), decoded.pub));
      } catch (e) {
        return false;
      }
    }

    async function requestObjectOf(begun) {
      const url = new URL(begun.headers.location);
      return (await w.request('GET',
        w.pathOf(url.searchParams.get('request_uri')))).text;
    }

    // ==================================================================
    // 1. oid4vp.x509SigningAlgorithm, every post-quantum algorithm
    // ==================================================================
    const x509Results = [];
    for (let i = 0; i < PQ.length; i++) {
      const alg = PQ[i];
      await w.inRealm(function () {
        m.config.setOverride('oid4vp.x509SigningAlgorithm', alg);
      });
      const begun = await w.verificationStart(
        'by=reference&client_id_prefix=x509_hash');
      if (begun.status !== 302) {
        x509Results.push(alg + ': start ' + begun.status + ' ' +
                         JSON.stringify(begun.json).slice(0, 200));
        continue;
      }
      const ro = await requestObjectOf(begun);
      const header = headerOf(ro);
      const claims = w.decode(ro);
      const leafPem = pemOf((header.x5c || [])[0] || '');
      const leafDer = Buffer.from((header.x5c || [])[0] || '', 'base64');
      const hash = nodeCrypto.createHash('sha256').update(leafDer)
        .digest('base64url');
      const verifies = await pqJwsVerifies(ro, alg, spkiOf(leafPem));
      const ok = header.alg === alg && header.typ === 'oauth-authz-req+jwt' &&
        (header.x5c || []).length === 3 && verifies &&
        claims.client_id === 'x509_hash:' + hash;
      x509Results.push(alg + ': ' + (ok ? 'ok' : 'FAILED alg=' + header.alg +
        ' x5c=' + (header.x5c || []).length + ' verifies=' + verifies +
        ' client_id=' + claims.client_id));
    }
    note(x509Results.every(function (r) { return /: ok$/.test(r); }) &&
         x509Results.length === 11,
         '1a. an x509_hash Request Object signed with each of the eleven ' +
         'post-quantum algorithms verifies against the key of the ' +
         'certificate it carries in x5c, read as X.509, and its Client ' +
         'Identifier is that certificate\'s hash', x509Results.join('; '));

    const syncRefused = await w.inRealm(async function () {
      m.config.setOverride('oid4vp.x509SigningAlgorithm', 'ML-DSA-65');
      // The certificate in place first, so what is refused is the signature.
      await m.verifier.prepareSignedClientId(w.fakeReq(''), 'x509_hash');
      try {
        m.verifier.buildVpRequest(w.fakeReq(''),
          { byReference: true, clientIdPrefix: 'x509_hash' });
        return null;
      } catch (e) {
        return e;
      }
    });
    note(syncRefused && syncRefused.code === 'STS-VC-0113',
         '1b. the synchronous build refuses a post-quantum Request Object ' +
         'rather than answering an unsigned one',
         syncRefused && syncRefused.message);

    const dcSignIn = await w.inRealm(async function () {
      m.config.setOverride('oid4vp.signInClientIdPrefix', 'x509_hash');
      await m.verifier.prepareSignedClientId(w.fakeReq(''), 'x509_hash');
      return m.verifier.buildVpRequestAsync(w.fakeReq(''), {
        signIn: { authnId: 'pq-test', bindingHash: 'h', completePath: '/x',
                  ttlMs: 60000, crossDevice: false, issuerDids: [],
                  dcApiOrigin: w.origin } });
    });
    const dcRo = dcSignIn.signIn.dcApi.request;
    const dcVerifies = await pqJwsVerifies(dcRo, 'ML-DSA-65',
      spkiOf(pemOf(headerOf(dcRo).x5c[0])));
    const stored = await w.inRealm(function () {
      return m.verifier.transactionFor(dcSignIn.state);
    });
    note(headerOf(dcSignIn.requestObject).alg === 'ML-DSA-65' &&
         headerOf(dcRo).alg === 'ML-DSA-65' && dcVerifies &&
         stored && stored.requestObject === dcSignIn.requestObject &&
         stored.signIn.dcApi.request === dcRo,
         '1c. a sign-in\'s Request Object and its Digital Credentials API ' +
         'request are both signed with ML-DSA-65 under the certificate, ' +
         'and the stored transaction holds the signed ones',
         headerOf(dcRo).alg + ' ' + dcVerifies);

    // ==================================================================
    // 2. oid4vp.requestObjectSigningAlgorithm, every post-quantum one
    // ==================================================================
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.clientIdPrefix', 'pre-registered');
    });
    const published = await w.request('GET', '/oauth2/jwks');
    const jwks = (published.json && published.json.keys) || [];
    const roResults = [];
    for (let i = 0; i < PQ.length; i++) {
      const alg = PQ[i];
      await w.inRealm(function () {
        m.config.setOverride('oid4vp.requestObjectSigningAlgorithm', alg);
      });
      const begun = await w.verificationStart('by=reference');
      if (begun.status !== 302) {
        roResults.push(alg + ': start ' + begun.status + ' ' +
                       JSON.stringify(begun.json).slice(0, 200));
        continue;
      }
      const ro = await requestObjectOf(begun);
      const header = headerOf(ro);
      const jwk = jwks.filter(function (k) {
        return k.kid === header.kid && k.alg === alg;
      })[0];
      let ok = false;
      let why = '';
      if (!jwk) {
        why = 'no ' + alg + ' key in /oauth2/jwks under ' + header.kid;
      } else {
        const spkiPem = pki.pqSubjectPublicKeyPem(alg, jwk);
        const der = Buffer.from(spkiPem.replace(/-----[^-]+-----/g, '')
          .replace(/\s+/g, ''), 'base64');
        ok = header.alg === alg &&
             await pqJwsVerifies(ro, alg, new Uint8Array(der));
        why = ok ? '' : 'alg=' + header.alg + ' did not verify';
      }
      roResults.push(alg + ': ' + (ok ? 'ok' : 'FAILED ' + why));
    }
    note(roResults.every(function (r) { return /: ok$/.test(r); }) &&
         roResults.length === 11,
         '2a. a pre-registered Request Object signed with each of the ' +
         'eleven verifies against the key /oauth2/jwks publishes under its ' +
         'kid', roResults.join('; '));

    await w.inRealm(function () {
      m.config.setOverride('oid4vp.requestObjectSigningAlgorithm',
                           'ML-DSA-65');
    });
    const byDid = await w.verificationStart(
      'by=reference&client_id_prefix=decentralized_identifier');
    const didRo = byDid.status === 302 ? await requestObjectOf(byDid) : '';
    const didDoc = await w.inRealm(function () {
      return vcDid.stsDidDocument(w.fakeReq(''));
    });
    const didKid = didRo ? headerOf(didRo).kid : '';
    const method = (didDoc.verificationMethod || []).filter(function (vm) {
      return vm.id === didKid;
    })[0];
    let didVerifies = false;
    if (method && method.publicKeyJwk) {
      const spkiPem = pki.pqSubjectPublicKeyPem('ML-DSA-65',
                                                method.publicKeyJwk);
      didVerifies = await pqJwsVerifies(didRo, 'ML-DSA-65', new Uint8Array(
        Buffer.from(spkiPem.replace(/-----[^-]+-----/g, '')
          .replace(/\s+/g, ''), 'base64')));
    }
    note(!!method && didVerifies && /^did:web:/.test(didKid),
         '2b. decentralized_identifier: the Request Object names its key ' +
         'as a DID URL, the DID document lists it, and the signature ' +
         'verifies against it', didKid + ' ' + byDid.status);

    const attested = await w.verificationStart(
      'by=reference&client_id_prefix=verifier_attestation');
    const attRo = attested.status === 302 ? await requestObjectOf(attested) :
      '';
    const attestation = attRo ? w.decode(headerOf(attRo).jwt) : {};
    const cnf = attestation.cnf && attestation.cnf.jwk;
    note(headerOf(attRo).alg === 'ML-DSA-65' && cnf &&
         cnf.kty === 'AKP' && cnf.alg === 'ML-DSA-65' &&
         cnf.kid === headerOf(attRo).kid,
         '2c. verifier_attestation: the self-issued attestation\'s cnf is ' +
         'the ML-DSA-65 key the request is signed with',
         JSON.stringify(cnf || {}).slice(0, 120));

    const entity = await w.request('GET', '/.well-known/openid-federation');
    const ec = entity.text ? w.decode(entity.text) : {};
    const ecVerifier = (ec.metadata || {}).openid_credential_verifier || {};
    const ecKey = ((ecVerifier.jwks || {}).keys || [])[0] || {};
    note(ecKey.alg === 'ML-DSA-65' && ecKey.kty === 'AKP',
         '2d. openid_federation: the Entity Configuration\'s ' +
         'openid_credential_verifier jwks is the ML-DSA-65 request key',
         entity.status + ' ' + JSON.stringify(ecKey).slice(0, 120));

    const syncRo = await w.inRealm(function () {
      try {
        m.verifier.buildVpRequest(w.fakeReq(''), { byReference: true });
        return null;
      } catch (e) {
        return e;
      }
    });
    note(syncRo && syncRo.code === 'STS-VC-0155',
         '2e. and the synchronous build refuses it, STS-VC-0155',
         syncRo && syncRo.message);

    await w.inRealm(function () {
      m.config.setOverride('oid4vp.requestObjectSigningAlgorithm', 'ES256');
    });
    const classical = await w.verificationStart('by=reference');
    const classicalRo = classical.status === 302 ?
      await requestObjectOf(classical) : '';
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.requestObjectSigningAlgorithm');
    });
    const dflt = await w.verificationStart('by=reference');
    const dfltRo = dflt.status === 302 ? await requestObjectOf(dflt) : '';
    note(headerOf(classicalRo).alg === 'ES256' &&
         headerOf(dfltRo).alg === 'RS256',
         '2f. a classical algorithm is signed as before, and RS256 is the ' +
         'default', headerOf(classicalRo).alg + ' ' + headerOf(dfltRo).alg);

    // ==================================================================
    // 3. A TRUSTED FOREIGN ISSUER WITH A POST-QUANTUM KEY
    // ==================================================================
    let listKey = null;
    let listAlg = '';
    let listPath = '';
    let served = 0;
    const listServer = http.createServer(function (req, res) {
      served += 1;
      const values = [];
      values[3] = 0;
      const bytes = m.codec.packTsl(values, 2, 64);
      const now = Math.floor(Date.now() / 1000);
      const token = m.stsCrypto.signJws(m.codec.statusListJwtPayload({
        sub: listPath, iat: now, exp: now + 600, ttl: 300, bits: 2,
        bytes: bytes }), listKey, {
        algorithm: listAlg,
        header: { alg: listAlg, typ: 'statuslist+jwt' } });
      res.writeHead(200,
        { 'content-type': 'application/statuslist+jwt' }).end(token);
    });
    await new Promise(function (r) {
      listServer.listen(0, '127.0.0.1', r);
    });
    const holder = w.holderKey();
    const pqHolder = w.holderKey('ML-DSA-44');

    async function foreignIssuer(alg, i) {
      const pair = m.pqJose.generate(alg);
      const jwk = m.pqJose.akpPublicJwk(alg, pair.pub);
      const made = await w.inRealm(function () {
        return pki.certifyVerifierKey(undefined, {
          dnsName: 'pq-issuer-' + i + '.test', alg: alg,
          keyAlg: pki.PQ_JOSE_IN_X509[alg].id.toLowerCase(),
          publicKeyPem: pki.pqSubjectPublicKeyPem(alg, jwk) });
      });
      return { alg: alg, priv: pair.priv,
               certPem: made.ok ? made.certificate.certificatePem : '',
               made: made };
    }

    function sdJwt(issuer, holderJwk, uri) {
      const now = Math.floor(Date.now() / 1000);
      return m.stsCrypto.signJws({
        iss: 'https://pq-partner.example', vct: m.vcConfigs.VCI_VCT,
        sub: 'urn:uuid:pq-partner-person', cnf: { jwk: holderJwk },
        nbf: now - 5, exp: now + 600,
        status: uri ? { status_list: { idx: 3, uri: uri } } : undefined,
        _sd_alg: 'sha-256', _sd: [] }, issuer.priv,
        { algorithm: issuer.alg,
          header: { alg: issuer.alg, typ: 'dc+sd-jwt' } }) + '~';
    }

    function jwtVc(issuer, holderJwk) {
      const now = Math.floor(Date.now() / 1000);
      return m.stsCrypto.signJws({
        iss: 'https://pq-partner.example', sub: 'urn:uuid:pq-partner-person',
        nbf: now - 5, exp: now + 600, cnf: { jwk: holderJwk },
        vc: { '@context': ['https://www.w3.org/2018/credentials/v1'],
              type: m.vcConfigs.VCI_JWT_TYPES,
              credentialSubject: { id: 'urn:uuid:pq-partner-person' } } },
        issuer.priv,
        { algorithm: issuer.alg, header: { alg: issuer.alg, typ: 'JWT' } });
    }

    async function presentToBarDoor(format, presentationOf) {
      // `+` in a query is a space: dc+sd-jwt is encoded.
      const begun = await w.verificationStart('by=reference&format=' +
                                              encodeURIComponent(format));
      if (begun.status !== 302) {
        return { status: begun.status, text: JSON.stringify(begun.json) };
      }
      const ro = w.decode(await requestObjectOf(begun));
      await w.inRealm(function () {
        const tx = m.verifier.transactionFor(ro.state);
        tx.requested = [];
        m.verifier.saveTransaction(tx);
      });
      return w.request('POST', '/oid4vp/response', {
        form: { state: ro.state,
                // The bar door asks one credential query, whatever the
                // format, under the SD-JWT query's id (vc_status_list.js).
                vp_token: w.vpToken('dc+sd-jwt',
                  presentationOf(ro.nonce, ro.client_id)) } });
    }

    const issuers = [];
    for (let i = 0; i < PQ.length; i++) {
      issuers.push(await foreignIssuer(PQ[i], i));
    }
    note(issuers.every(function (one) { return !!one.certPem; }),
         '3a. a certificate over each of the eleven foreign keys',
         issuers.filter(function (one) { return !one.certPem; })
           .map(function (one) {
             return one.alg + ' ' + JSON.stringify(one.made.errors);
           }).join('; '));
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.trustedIssuerCertificates',
        issuers.map(function (one) { return one.certPem; }).join('\n'));
    });
    const sdResults = [];
    const jwtResults = [];
    for (let i = 0; i < issuers.length; i++) {
      const issuer = issuers[i];
      listKey = issuer.priv;
      listAlg = issuer.alg;
      listPath = 'http://127.0.0.1:' + listServer.address().port +
                 '/statuslist/' + i;
      const before = served;
      const sd = await presentToBarDoor('dc+sd-jwt', function (nonce, aud) {
        return w.presentSdJwt(sdJwt(issuer, holder.jwk, listPath), holder,
                              nonce, aud);
      });
      sdResults.push(issuer.alg + ': ' + sd.status +
        (served > before ? ' (list fetched)' : ' (list NOT fetched)') +
        (sd.status === 200 ? '' : ' ' + String(sd.text).slice(0, 160)));
      await w.inRealm(function () {
        m.config.setOverride('oid4vp.requireStatusReference', 'own-only');
      });
      const jv = await presentToBarDoor('jwt_vc_json', function (nonce, aud) {
        return w.presentJwtVc(jwtVc(issuer, holder.jwk), holder, nonce, aud);
      });
      await w.inRealm(function () {
        m.config.clearOverride('oid4vp.requireStatusReference');
      });
      jwtResults.push(issuer.alg + ': ' + jv.status +
        (jv.status === 200 ? '' : ' ' + String(jv.text).slice(0, 160)));
    }
    note(sdResults.every(function (r) {
      return /: 200 \(list fetched\)$/.test(r);
    }),
         '3b. a dc+sd-jwt credential from a trusted issuer with each of the ' +
         'eleven keys is accepted, its Token Status List fetched and ' +
         'verified against the same post-quantum key', sdResults.join('; '));
    note(jwtResults.every(function (r) { return /: 200$/.test(r); }),
         '3c. and a jwt_vc_json credential from each of them',
         jwtResults.join('; '));

    const kbPq = await presentToBarDoor('dc+sd-jwt', function (nonce, aud) {
      listKey = issuers[1].priv;
      listAlg = issuers[1].alg;
      return w.presentSdJwt(sdJwt(issuers[1], pqHolder.jwk, listPath),
                            pqHolder, nonce, aud);
    });
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.requireStatusReference', 'own-only');
    });
    const vpPq = await presentToBarDoor('jwt_vc_json', function (nonce, aud) {
      return w.presentJwtVc(jwtVc(issuers[1], pqHolder.jwk), pqHolder,
                            nonce, aud);
    });
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.requireStatusReference');
    });
    note(kbPq.status === 200 && vpPq.status === 200,
         '3d. an ML-DSA-44 holder\'s Key Binding JWT and VP JWT are ' +
         'accepted', kbPq.status + ' ' + vpPq.status + ' ' +
         String(kbPq.text).slice(0, 120));

    // ==================================================================
    // 4. oid4vc.walletCompatibility
    // ==================================================================
    await w.inRealm(function () {
      m.config.setOverride('oid4vc.walletCompatibility', 'true');
    });
    const issuerMeta = (await w.request('GET',
      '/.well-known/openid-credential-issuer')).json || {};
    const configs = issuerMeta.credential_configurations_supported || {};
    const pqInIssuer = [];
    Object.keys(configs).forEach(function (id) {
      const c = configs[id];
      if (c.format === 'ldp_vc') {
        return;
      }
      [].concat(c.credential_signing_alg_values_supported || [],
        ((c.proof_types_supported || {}).jwt || {})
          .proof_signing_alg_values_supported || [])
        .forEach(function (alg) {
          if (PQ.indexOf(alg) >= 0) {
            pqInIssuer.push(id + ':' + alg);
          }
        });
    });
    const vpFormats = await w.inRealm(function () {
      return m.verifier.federationVerifierMetadata(w.fakeReq(''))
        .vp_formats_supported;
    });
    const pqInVerifier = [].concat(
      vpFormats['dc+sd-jwt']['sd-jwt_alg_values'],
      vpFormats['dc+sd-jwt']['kb-jwt_alg_values'],
      vpFormats.jwt_vc_json.alg_values).filter(function (alg) {
      return PQ.indexOf(alg) >= 0;
    });
    note(!pqInIssuer.length && !pqInVerifier.length &&
         vpFormats.jwt_vc_json.alg_values.indexOf('ES256') >= 0,
         '4a. in wallet compatibility mode neither the issuer\'s nor the ' +
         'Verifier\'s metadata names a post-quantum algorithm for the JOSE ' +
         'formats, and the classical ones are still there',
         pqInIssuer.concat(pqInVerifier).join(', '));

    await w.inRealm(function () {
      m.config.setOverride('oid4vp.x509SigningAlgorithm', 'ML-DSA-65');
      m.config.setOverride('oid4vp.requestObjectSigningAlgorithm',
                           'ML-DSA-65');
    });
    const x509Off = await w.verificationStart(
      'by=reference&client_id_prefix=x509_hash');
    const roOff = await w.verificationStart('by=reference');
    note(x509Off.status === 500 && x509Off.json.code === 'STS-VC-0152' &&
         roOff.status === 500 && roOff.json.code === 'STS-VC-0152',
         '4b. an x509 and a pre-registered Request Object named for ' +
         'ML-DSA-65 are refused, STS-VC-0152, and nothing is signed in ' +
         'their place', JSON.stringify([x509Off.json, roOff.json])
           .slice(0, 300));

    // Back to classical request signers: in this mode a post-quantum one
    // refuses every start, which 4b has just shown.
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.x509SigningAlgorithm');
      m.config.clearOverride('oid4vp.requestObjectSigningAlgorithm');
    });
    const foreignOff = await presentToBarDoor('dc+sd-jwt',
      function (nonce, aud) {
        return w.presentSdJwt(sdJwt(issuers[1], holder.jwk, ''), holder,
                              nonce, aud);
      });
    note(foreignOff.status === 400 &&
         /wallet compatibility mode/.test(String(foreignOff.text)),
         '4c. a trusted foreign issuer\'s ML-DSA-65 credential is refused',
         foreignOff.status + ' ' + String(foreignOff.text).slice(0, 200));

    await w.inRealm(function () {
      m.config.setOverride('oid4vp.trustedIssuerCertificates', '');
      m.config.setOverride('oid4vp.requireStatusReference', 'own-only');
    });
    await w.inRealm(function () {
      m.config.setOverride('oid4vc.walletCompatibility', 'false');
    });
    const kbOff = await w.issue('pq-holder', pqHolder);
    await w.inRealm(function () {
      m.config.setOverride('oid4vc.walletCompatibility', 'true');
    });
    const kbRefused = kbOff.credential ? await presentToBarDoor('dc+sd-jwt',
      function (nonce, aud) {
        return w.presentSdJwt(kbOff.credential, pqHolder, nonce, aud);
      }) : { status: 0, text: kbOff.error };
    note(kbRefused.status === 400 &&
         /KB-JWT is signed with ML-DSA-44/.test(String(kbRefused.text)),
         '4d. this realm\'s own credential bound to an ML-DSA-44 key is ' +
         'refused when its KB-JWT is signed with it',
         kbRefused.status + ' ' + String(kbRefused.text).slice(0, 200));

    const proofOff = await w.issue('pq-holder', pqHolder);
    note(!proofOff.credential && proofOff.response &&
         proofOff.response.status === 400 &&
         /wallet compatibility/.test(String(proofOff.response.text)),
         '4e. an OpenID4VCI proof of possession signed with ML-DSA-44 is ' +
         'refused', proofOff.error);

    await w.inRealm(function () {
      m.config.setOverride('oid4vci.credentialSigningAlgorithm', 'ML-DSA-65');
    });
    const credOff = await w.issue('pq-holder', holder);
    note(!credOff.credential && credOff.response &&
         credOff.response.status === 400 &&
         credOff.response.json.error === 'credential_request_denied',
         '4f. a credential named for ML-DSA-65 is refused, ' +
         'credential_request_denied, STS-VC-0152', credOff.error);

    await w.inRealm(function () {
      m.config.setOverride('oid4vci.credentialSigningAlgorithm', 'ES256');
    });
    const credOk = await w.issue('pq-holder', holder);
    const okAnswer = credOk.credential ? await presentToBarDoor('dc+sd-jwt',
      function (nonce, aud) {
        return w.presentSdJwt(credOk.credential, holder, nonce, aud);
      }) : { status: 0, text: credOk.error };
    note(credOk.credential && headerOf(credOk.credential).alg === 'ES256' &&
         okAnswer.status === 200,
         '4g. and a classical credential is issued and accepted as before',
         okAnswer.status + ' ' + String(okAnswer.text).slice(0, 160));

    listServer.close();
    await w.inRealm(function () {
      touched.forEach(function (key) {
        m.config.clearOverride(key);
      });
    });
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'oid4vc-pq-algorithms');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oid4vc_pq_algorithms',
  describe: 'the eleven post-quantum JWS algorithms in OpenID4VP Request ' +
            'Objects (x509 and the other prefixes), trusted foreign ' +
            'issuers, their status lists and holder proofs, and the wallet ' +
            'compatibility mode (#657)',
  run: run
};
