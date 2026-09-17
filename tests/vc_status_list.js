'use strict';

// ===========================================================================
// tests/vc_status_list.js — THE STATUS OF EVERY CREDENTIAL THIS ISSUER MINTS
// (#38's follow-ups): Token Status List (draft-ietf-oauth-status-list-21) and
// W3C Bitstring Status List v1.0.
//
// Until this the issuer published no status at all: a credential it had taken
// back went on verifying everywhere but here. The contract, driven over HTTP:
//
//   1. the lists are served — `application/statuslist+jwt`, the same list as
//      `application/statuslist+cwt` by `Accept`, the aggregation endpoint,
//      and a `BitstringStatusListCredential` per purpose as
//      `application/vc+jwt` — with `Cache-Control: max-age=<ttl>`, and a
//      historical request answers 501;
//   2. every issued credential carries its reference, in the form its data
//      model uses;
//   3. revoking flips the bit in both lists, and suspending sets the
//      suspension bit and not the revocation one;
//   4. the Verifier refuses a credential of this realm whose status is not
//      VALID — at the bar door as well as at the sign-in;
//   5. a TRUSTED FOREIGN ISSUER'S list is fetched, verified against the
//      certificate that verified the credential, cached, and its bit
//      honoured; an unreachable list means no statement can be made, so the
//      credential is refused;
//   6. the new stores are on `/admin/caches`, and the console and the
//      management API answer the same JSON (rule 7).
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'vc_status_list',
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
    const statusAdmin = require(ROOT + '/admin-ui/vc_status_admin');
    const cachesAdmin = require(ROOT + '/admin-ui/caches_admin');
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser('st-alice', { invent: false });
    });
    const aud = await w.inRealm(function () {
      return m.config.value('oid4vp.clientId');
    });

    // ==================================================================
    // 1. THE LISTS
    // ==================================================================
    const tsl = await w.request('GET', '/oid4vci/status-lists/1');
    const tslHeader = tsl.status === 200
      ? JSON.parse(Buffer.from(tsl.text.split('.')[0], 'base64url')
        .toString('utf8')) : {};
    const tslClaims = tsl.status === 200 ? w.decode(tsl.text) : {};
    note(tsl.status === 200 &&
         /^application\/statuslist\+jwt/
           .test(String(tsl.headers['content-type'])) &&
         tslHeader.typ === 'statuslist+jwt' &&
         tslClaims.sub === w.base + '/oid4vci/status-lists/1' &&
         tslClaims.status_list && tslClaims.status_list.bits === 2 &&
         typeof tslClaims.status_list.lst === 'string' &&
         tslClaims.ttl > 0 && tslClaims.exp > tslClaims.iat,
         '1a. the Token Status List is served as a JWT with typ ' +
         'statuslist+jwt, its own URI as sub, two bits per credential, a ' +
         'ttl and an exp (section 5.1)',
         tsl.status + ' ' + JSON.stringify(tslHeader) + ' ' +
         JSON.stringify({ sub: tslClaims.sub, ttl: tslClaims.ttl,
                          exp: tslClaims.exp, iat: tslClaims.iat,
                          bits: (tslClaims.status_list || {}).bits }));
    note(String(tsl.headers['cache-control']) === 'max-age=' +
           tslClaims.ttl && tsl.headers.vary === 'Accept',
         '1b. with Cache-Control matching the ttl the token itself carries ' +
         '(section 8.2), and Vary: Accept',
         tsl.headers['cache-control']);
    const cwt = await w.request('GET', '/oid4vci/status-lists/1', {
      headers: { accept: 'application/statuslist+cwt' } });
    let cwtRead = null;
    try {
      cwtRead = m.codec.cborDecode(cwt.buffer);
    } catch (e) {
      cwtRead = null;
    }
    note(cwt.status === 200 &&
         /^application\/statuslist\+cwt/
           .test(String(cwt.headers['content-type'])) &&
         cwtRead && cwtRead.tag === 18 && Array.isArray(cwtRead.value) &&
         cwtRead.value.length === 4,
         '1c. the same list as a CWT by Accept: a tagged COSE_Sign1 of four ' +
         'elements (section 5.2), not CWT-tagged',
         cwt.status + ' ' + (cwtRead && cwtRead.tag));
    const aggregation = await w.request('GET', '/oid4vci/status-lists');
    note(aggregation.status === 200 && aggregation.json &&
         JSON.stringify(aggregation.json.status_lists) ===
           JSON.stringify([w.base + '/oid4vci/status-lists/1']),
         '1d. the aggregation endpoint lists this realm\'s one list ' +
         '(section 9.3)', aggregation.text.slice(0, 120));
    const historical = await w.request('GET',
      '/oid4vci/status-lists/1?time=1686925000');
    note(historical.status === 501 && historical.code === 'STS-VC-0077',
         '1e. a historical request is answered 501: this issuer keeps none ' +
         '(section 8.4)', historical.status + ' ' + historical.code);
    const bitstring = await w.request('GET',
      '/oid4vci/status-lists/bitstring/revocation');
    const bitstringVc = bitstring.status === 200 ? w.decode(bitstring.text)
                                                 : {};
    const subject = bitstringVc.credentialSubject || {};
    let bits = null;
    try {
      bits = m.codec.decodeEncodedList(subject.encodedList);
    } catch (e) {
      bits = null;
    }
    note(bitstring.status === 200 &&
         /^application\/vc\+jwt/
           .test(String(bitstring.headers['content-type'])) &&
         String(bitstringVc.type).indexOf('BitstringStatusListCredential') >=
           0 &&
         subject.type === 'BitstringStatusList' &&
         subject.statusPurpose === 'revocation' &&
         bits && bits.length === 131072 / 8,
         '1f. the Bitstring Status List credential is served as ' +
         'application/vc+jwt and its encodedList expands to the minimum ' +
         '131,072 entries', bitstring.status + ' ' + (bits && bits.length) +
         ' ' + JSON.stringify({ ct: bitstring.headers['content-type'],
                                type: bitstringVc.type,
                                subjectType: subject.type,
                                purpose: subject.statusPurpose }));
    const unknownPurpose = await w.request('GET',
      '/oid4vci/status-lists/bitstring/nonsense');
    note(unknownPurpose.status === 404 &&
         unknownPurpose.code === 'STS-VC-0078',
         '1g. a purpose this issuer does not publish is 404, STS-VC-0078',
         unknownPurpose.status + ' ' + unknownPurpose.code);

    // ==================================================================
    // 2. EVERY CREDENTIAL CARRIES ITS REFERENCE
    // ==================================================================
    const sdHolder = w.holderKey();
    const sd = await w.issue('st-alice', sdHolder);
    const sdClaims = sd.credential
      ? w.decode(String(sd.credential).split('~')[0]) : {};
    const sdRef = (sdClaims.status || {}).status_list || {};
    note(typeof sdRef.idx === 'number' &&
         sdRef.uri === w.base + '/oid4vci/status-lists/1',
         '2a. an SD-JWT VC carries status.status_list { idx, uri } in the ' +
         'clear (section 6.2)', JSON.stringify(sdRef));
    const jwtHolder = w.holderKey();
    const jwtVc = await w.issue('st-alice', jwtHolder,
                                { format: 'jwt_vc_json' });
    const jwtClaims = jwtVc.credential ? w.decode(jwtVc.credential) : {};
    const jwtEntries = ((jwtClaims.vc || {}).credentialStatus) || [];
    note(((jwtClaims.status || {}).status_list || {}).uri ===
           w.base + '/oid4vci/status-lists/1' &&
         jwtEntries.length === 2 &&
         jwtEntries[0].type === 'BitstringStatusListEntry' &&
         jwtEntries.map(function (e) { return e.statusPurpose; }).join(',') ===
           'revocation,suspension',
         '2b. a jwt_vc_json credential carries BOTH mechanisms: the JWT ' +
         'status claim and a BitstringStatusListEntry per purpose',
         JSON.stringify(jwtEntries.map(function (e) {
           return e.statusPurpose;
         })));
    const ldpHolder = w.holderKey();
    const ldp = await w.issue('st-alice', ldpHolder, { format: 'ldp_vc' });
    const ldpEntries = (ldp.credential || {}).credentialStatus || [];
    note(ldpEntries.length === 2 &&
         ldpEntries[0].statusListCredential ===
           w.base + '/oid4vci/status-lists/bitstring/revocation' &&
         /^\d+$/.test(String(ldpEntries[0].statusListIndex)),
         '2c. an ldp_vc credential carries the two entries, with the index ' +
         'as a decimal string as that specification requires',
         JSON.stringify(ldpEntries[0] || {}));

    // ==================================================================
    // 3. FLIPPING A BIT
    // ==================================================================
    const idx = sdRef.idx;
    const before = await w.request('GET', '/oid4vci/status-lists/1');
    const beforeValue = m.codec.unpackTslValue(
      m.codec.decompress(Buffer.from(w.decode(before.text).status_list.lst,
                                     'base64url')), 2, idx);
    const revoked = await w.inRealm(function () {
      return statusAdmin.statusAction({ idx: idx, action: 'revoke' },
                                      'the test');
    });
    const after = await w.request('GET', '/oid4vci/status-lists/1');
    const afterValue = m.codec.unpackTslValue(
      m.codec.decompress(Buffer.from(w.decode(after.text).status_list.lst,
                                     'base64url')), 2, idx);
    note(beforeValue === 0 && revoked.ok && afterValue === 1,
         '3a. revoking sets that index to INVALID (0x01) in the published ' +
         'Token Status List', beforeValue + ' -> ' + afterValue);
    const jwtIdx = Number(jwtEntries[0].statusListIndex);
    await w.inRealm(function () {
      return statusAdmin.statusAction({ idx: jwtIdx, action: 'suspend' },
                                      'the test');
    });
    const revocationList = await w.request('GET',
      '/oid4vci/status-lists/bitstring/revocation');
    const suspensionList = await w.request('GET',
      '/oid4vci/status-lists/bitstring/suspension');
    const revocationBits = m.codec.decodeEncodedList(
      w.decode(revocationList.text).credentialSubject.encodedList);
    const suspensionBits = m.codec.decodeEncodedList(
      w.decode(suspensionList.text).credentialSubject.encodedList);
    note(m.codec.bitstringValue(suspensionBits, jwtIdx) === 1 &&
         m.codec.bitstringValue(revocationBits, jwtIdx) === 0 &&
         m.codec.bitstringValue(revocationBits, idx) === 1,
         '3b. suspending sets the SUSPENSION bit and leaves revocation ' +
         'clear, and the revoked credential\'s revocation bit is set — one ' +
         'index, two lists',
         [m.codec.bitstringValue(suspensionBits, jwtIdx),
          m.codec.bitstringValue(revocationBits, jwtIdx),
          m.codec.bitstringValue(revocationBits, idx)].join(','));

    // ==================================================================
    // 4. THE VERIFIER REFUSES IT
    // ==================================================================
    const barBrowser = w.browser();
    const started = await w.request('GET', '/oid4vp/start?by=reference',
                                    { browser: barBrowser });
    const barUrl = started.headers.location
      ? new URL(started.headers.location) : null;
    const barRo = barUrl ? w.decode((await w.request('GET',
      w.pathOf(barUrl.searchParams.get('request_uri')))).text) : null;
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.claims', '');
      const tx = m.verifier.transactionFor(barRo.state);
      tx.requested = [];
      m.verifier.saveTransaction(tx);
    });
    const barAnswer = await w.request('POST', '/oid4vp/response', {
      form: { state: barRo.state,
              vp_token: w.vpToken('dc+sd-jwt',
                w.presentSdJwt(sd.credential, sdHolder, barRo.nonce,
                               barRo.client_id)) } });
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.claims');
    });
    note(barAnswer.status === 400 && barAnswer.code === 'STS-VC-0072' &&
         /Credential status/.test(barAnswer.text),
         '4a. the bar door refuses a revoked credential of this realm, ' +
         'STS-VC-0072 — the Verifier consults the status, not only the ' +
         'sign-in door', barAnswer.status + ' ' + barAnswer.code);

    // ==================================================================
    // 5. A TRUSTED FOREIGN ISSUER'S LIST
    // ==================================================================
    const partner = await w.inRealm(function () {
      return m.stsCrypto.selfSignedRsaCertificate(
        { commonName: 'status partner issuer' });
    });
    const partnerKey = nodeCrypto.createPrivateKey(partner.privateKeyPem);
    let served = 0;
    let listValue = 0;
    let listPath = '';
    const partnerServer = http.createServer(function (req, res) {
      served += 1;
      if (req.url.indexOf('/statuslist') !== 0) {
        res.writeHead(404).end();
        return;
      }
      const values = [];
      values[7] = listValue;
      const bytes = m.codec.packTsl(values, 2, 64);
      const now = Math.floor(Date.now() / 1000);
      const token = m.stsCrypto.signJws(m.codec.statusListJwtPayload({
        sub: listPath, iat: now, exp: now + 600, ttl: 300, bits: 2,
        bytes: bytes }), partnerKey, {
        algorithm: 'RS256',
        header: { alg: 'RS256', typ: 'statuslist+jwt' } });
      res.writeHead(200,
        { 'content-type': 'application/statuslist+jwt' }).end(token);
    });
    await new Promise(function (r) {
      partnerServer.listen(0, '127.0.0.1', r);
    });
    listPath = 'http://127.0.0.1:' + partnerServer.address().port +
               '/statuslist/1';
    const partnerHolder = w.holderKey();
    function partnerCredential(uri) {
      return m.stsCrypto.signJws({
        iss: 'https://partner.example', vct: m.vcConfigs.VCI_VCT,
        sub: 'urn:uuid:partner-person', cnf: { jwk: partnerHolder.jwk },
        nbf: Math.floor(Date.now() / 1000) - 5,
        exp: Math.floor(Date.now() / 1000) + 600,
        status: uri ? { status_list: { idx: 7, uri: uri } } : undefined,
        _sd_alg: 'sha-256', _sd: [] }, partnerKey,
        { algorithm: 'RS256', header: { alg: 'RS256', typ: 'dc+sd-jwt' } }) +
        '~';
    }
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.trustedIssuerCertificates',
                           partner.certPem);
      m.config.setOverride('federation.outboundAllowInsecure', 'true');
      m.config.setOverride('oid4vp.claims', '');
    });

    async function presentToBarDoor(credential) {
      const who = w.browser();
      const begun = await w.request('GET', '/oid4vp/start?by=reference',
                                    { browser: who });
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
                  w.presentSdJwt(credential, partnerHolder, ro.nonce,
                                 ro.client_id)) } });
    }

    const foreignValid = await presentToBarDoor(partnerCredential(listPath));
    const fetchedOnce = served;
    note(foreignValid.status === 200 && served === 1,
         '5a. a trusted foreign issuer\'s credential is accepted once its ' +
         'Status List Token has been fetched and verified against the ' +
         'certificate that verified the credential',
         foreignValid.status + ' ' + foreignValid.text.slice(0, 160));
    const foreignAgain = await presentToBarDoor(partnerCredential(listPath));
    note(foreignAgain.status === 200 && served === fetchedOnce,
         '5b. and the list is CACHED for its ttl: the second presentation ' +
         'fetches nothing', served);
    listValue = 1;
    await w.inRealm(function () {
      m.status.forgetFetched();
    });
    const foreignRevoked = await presentToBarDoor(partnerCredential(listPath));
    note(foreignRevoked.status === 400 &&
         foreignRevoked.code === 'STS-VC-0072' &&
         /INVALID/.test(foreignRevoked.text),
         '5c. once that issuer sets the bit, the same credential is refused, ' +
         'STS-VC-0072', foreignRevoked.status + ' ' + foreignRevoked.code);
    const gone = 'http://127.0.0.1:' + (partnerServer.address().port + 1) +
                 '/statuslist/1';
    const unreachable = await presentToBarDoor(partnerCredential(gone));
    note(unreachable.status === 400 && unreachable.code === 'STS-VC-0072' &&
         /no statement about its status/.test(unreachable.text),
         '5d. a list that cannot be fetched means no statement can be made, ' +
         'so the credential is REFUSED (section 8.3), not let through',
         unreachable.status + ' ' + unreachable.code);
    const noStatus = await presentToBarDoor(partnerCredential(''));
    note(noStatus.status === 200,
         '5e. a foreign credential that names NO status is accepted: that ' +
         'issuer publishes none, which is a different thing from one this ' +
         'realm issued and cannot find', noStatus.status);
    partnerServer.close();
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.trustedIssuerCertificates');
      m.config.clearOverride('federation.outboundAllowInsecure');
      m.config.clearOverride('oid4vp.claims');
    });

    // ==================================================================
    // 6. THE STORES ARE ON /admin/caches, AND RULE 7
    // ==================================================================
    const names = m.cacheRegistry.names();
    const wanted = ['oid4vp.sign-in-register', 'oid4vci.status-entries',
                    'oid4vp.status-lists-fetched',
                    'oid4vci.status-list-tokens', 'oid4vp.transactions'];
    note(wanted.every(function (name) {
      return names.indexOf(name) >= 0;
    }), '6a. every store this feature added describes itself to ' +
        '/admin/caches (rule 3ap)',
        JSON.stringify(wanted.filter(function (name) {
          return names.indexOf(name) < 0;
        })));
    const view = await w.inRealm(function () {
      return cachesAdmin.cachesView({});
    });
    const listed = (view.caches || []).map(function (c) {
      return c.name;
    });
    const entries = await w.inRealm(function () {
      return cachesAdmin.cachesView({ cache: 'oid4vci.status-entries' });
    });
    note(wanted.every(function (name) {
      return listed.indexOf(name) >= 0;
    }) && entries.found && entries.entries.length > 0 &&
         entries.entries.every(function (row) {
           return /^idx:\d+$/.test(row.key);
         }),
         '6b. and the page the management API answers with lists them, with ' +
         'keys and no values',
         JSON.stringify((entries.entries || [])[0] || {}));
    const statusView = await w.inRealm(function () {
      return statusAdmin.statusView(w.fakeReq(''), {}).json;
    });
    note(statusView.tokenStatusList === w.base + '/oid4vci/status-lists/1' &&
         statusView.allocated >= 3 && statusView.invalid >= 1 &&
         statusView.suspended >= 1 &&
         statusView.rows.some(function (r) {
           return r.idx === idx && r.status === 'INVALID';
         }),
         '6c. /admin/vc-status (and GET /admin-api/vc-status, the same ' +
         'function) reports the lists and every credential\'s status',
         JSON.stringify({ allocated: statusView.allocated,
                          invalid: statusView.invalid,
                          suspended: statusView.suspended }));
    const refusedAction = await w.inRealm(function () {
      return statusAdmin.statusAction({ idx: idx, action: 'reinstate' },
                                      'the test');
    });
    const badIndex = await w.inRealm(function () {
      return statusAdmin.statusAction({ idx: 'nonsense', action: 'revoke' },
                                      'the test');
    });
    note(!refusedAction.ok && !badIndex.ok &&
         m.errorCodes.codeOf(badIndex) === 'STS-VC-0082',
         '6d. INVALID is final and an index that is not one is refused, ' +
         'STS-VC-0082',
         JSON.stringify(refusedAction.errors) + ' ' +
         JSON.stringify(badIndex.errors));
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'vc-status-list');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'credential status lists',
  describe: 'the Token Status List and the two Bitstring Status Lists this ' +
            'realm publishes, the reference every credential carries, and ' +
            'the Verifier consulting both this realm\'s and a trusted ' +
            'foreign issuer\'s',
  run: run
};
