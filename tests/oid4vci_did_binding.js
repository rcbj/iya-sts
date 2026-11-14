// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/oid4vci_did_binding.js
//
// ===========================================================================
// THE OpenID4VCI KEY PROOF BY DID, AND A CREDENTIAL BOUND TO THE PERSON'S
// PROVEN DID (#693 phase 2b, rcbj 2026-10-20: "Do all that").
//
// In a child (`wallet_kit.js`), against the whole stack on a loopback port:
//   1. a `jwt` proof may name its key by `kid` — a did:jwk or did:key URL —
//      instead of `jwk` (OpenID4VCI 1.0 Appendix F.1), and a configuration
//      bound to a KEY (every one, by default) binds to the key it names,
//      exactly as before; both `jwk` and `kid` (STS-VC-0140), a kid that is
//      not a DID URL (0141), a did:web (0142), a method the document does
//      not have (0143), one not under `authentication` (0144) and a kid
//      naming another key than the signer's are refused;
//   2. a configuration named in `oid4vci.didHolderBinding` advertises
//      did:jwk and did:key, and binds to a DID the PERSON proved: dc+sd-jwt
//      `cnf.kid` with `sub` unchanged, jwt_vc_json `credentialSubject.id`,
//      `sub` and `cnf.kid`, ldp_vc `credentialSubject.id`; a batch's copies
//      all carry the one DID; a `jwk` proof (0145), an administrator's
//      unproved entry (0149), somebody else's DID (0150), a DID enrolled for
//      nobody or removed after the token was issued (0148), a token naming
//      nobody this realm verified (0146) and a disabled account (0147) are
//      refused;
//   3. a deferred issuance is asked again at collection: a DID removed
//      while it waited is refused there (0148), and one still proved is
//      issued bound to it;
//   4. a DID-bound credential signs its holder in, in every format — the
//      Verifier reads the key a `cnf.kid` and a did:key subject name.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'oid4vci_did_binding',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

  walletKit.boot().then(async function (w) {
    const note = w.note;
    try {
      await sections(w, note, w.m);
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

  function brief(r) {
    if (!r) {
      return 'none';
    }
    if (r.error) {
      return String(r.error).slice(0, 300) + ' [' +
        ((r.response && r.response.code) || '') + ']';
    }
    return 'issued';
  }

  // The code and the OAuth error a refused issuance was answered with.
  function refusal(r) {
    const resp = (r && r.response) || {};
    return { code: resp.code || '', error: (resp.json && resp.json.error) ||
             '', status: resp.status || 0 };
  }

  async function sections(w, note, m) {
    const siop = require(ROOT + '/oid4vc/siop');
    const credentials = require(ROOT + '/common/credentials');
    const stamp = String(process.pid);
    const ALICE = 'vdb-alice-' + stamp;
    const BOB = 'vdb-bob-' + stamp;
    const CAROL = 'vdb-carol-' + stamp;
    const DAVE = 'vdb-dave-' + stamp;
    const SELF = 'self (SIOPv2)';
    const SD = 'IdentityCredential';
    const JWT = 'IdentityCredentialJwtVcJson';
    const LDP = 'IdentityCredentialLdpVc';

    await w.inRealm(function () {
      w.provision();
      [ALICE, BOB, CAROL, DAVE].forEach(function (name) {
        m.ldap.createUser(name, { invent: false });
      });
    });
    const aliceSub = await w.inRealm(function () {
      return m.helpers.subjectForName(ALICE);
    });

    // Keys, and the DIDs and DID URLs of them.
    function didJwkOf(holder) {
      return m.di.didJwkOf(holder.jwk);
    }
    function didKeyOf(holder) {
      return m.di.didKeyOf(holder.jwk);
    }
    function jwkKid(holder) {
      return didJwkOf(holder) + '#0';
    }
    function keyKid(holder) {
      const did = didKeyOf(holder);
      return did + '#' + did.slice('did:key:'.length);
    }
    const aliceJwk = w.holderKey('ES256');
    const aliceKey = w.holderKey('EdDSA');
    const aliceGone = w.holderKey('ES256');
    const aliceLate = w.holderKey('ES256');
    const bobJwk = w.holderKey('ES256');
    const carolJwk = w.holderKey('ES256');
    const daveJwk = w.holderKey('ES256');
    const nobody = w.holderKey('ES256');

    // What each person has enrolled: proved with a wallet, or by value.
    const enrolled = await w.inRealm(function () {
      return [
        siop.enrol(ALICE, didJwkOf(aliceJwk), 'phone', SELF,
                   { proof: 'wallet' }),
        siop.enrol(ALICE, didKeyOf(aliceKey), 'laptop', SELF,
                   { proof: 'wallet' }),
        siop.enrol(ALICE, didJwkOf(aliceGone), 'old', SELF,
                   { proof: 'wallet' }),
        siop.enrol(ALICE, didJwkOf(aliceLate), 'deferred', SELF,
                   { proof: 'wallet' }),
        siop.enrol(BOB, didJwkOf(bobJwk), 'phone', SELF,
                   { proof: 'wallet' }),
        siop.enrol(CAROL, didJwkOf(carolJwk), 'phone', SELF,
                   { proof: 'wallet' }),
        siop.enrol(DAVE, didJwkOf(daveJwk), 'typed in', 'admin',
                   { proof: 'admin' })
      ];
    });
    note(enrolled.every(function (one) {
      return one && one.ok;
    }), 'precondition: the subjects are enrolled — proved for alice, bob ' +
        'and carol, by value for dave', JSON.stringify(enrolled));

    function decodeSdJwt(credential) {
      return w.decode(String(credential).split('~')[0]);
    }

    // ==================================================================
    // 1. THE KEY PROOF BY kid, ON CONFIGURATIONS BOUND TO A KEY
    // ==================================================================
    const before = (await w.request('GET',
      '/.well-known/openid-credential-issuer')).json || {};
    const beforeConfigs = before.credential_configurations_supported || {};
    note(JSON.stringify(beforeConfigs[SD]
           .cryptographic_binding_methods_supported) === '["jwk"]' &&
         JSON.stringify(beforeConfigs[JWT]
           .cryptographic_binding_methods_supported) === '["jwk"]' &&
         JSON.stringify(beforeConfigs[LDP]
           .cryptographic_binding_methods_supported) === '["did:jwk"]',
         '1a. by default every configuration says it binds to a key, as ' +
         'before', JSON.stringify(Object.keys(beforeConfigs).map(function (k) {
           return beforeConfigs[k].cryptographic_binding_methods_supported;
         })));

    const byJwkKid = await w.issue(ALICE, aliceJwk,
                                   { configId: SD, kid: jwkKid });
    const sdKeyBound = byJwkKid.credential
      ? decodeSdJwt(byJwkKid.credential) : {};
    note(!!byJwkKid.credential && sdKeyBound.cnf && sdKeyBound.cnf.jwk &&
         sdKeyBound.cnf.jwk.x === aliceJwk.jwk.x && !sdKeyBound.cnf.kid,
         '1b. a dc+sd-jwt proof naming a did:jwk by kid is accepted, and a ' +
         'key-bound configuration binds to the key it names (cnf.jwk)',
         brief(byJwkKid) + ' ' + JSON.stringify(sdKeyBound.cnf || {}));
    const byKeyKid = await w.issue(ALICE, aliceKey,
                                   { configId: JWT, kid: keyKid });
    const jwtKeyBound = byKeyKid.credential ? w.decode(byKeyKid.credential)
                                            : {};
    note(!!byKeyKid.credential && jwtKeyBound.cnf && jwtKeyBound.cnf.jwk &&
         jwtKeyBound.cnf.jwk.x === aliceKey.jwk.x &&
         jwtKeyBound.sub === aliceSub,
         '1c. a jwt_vc_json proof naming a did:key (Ed25519) by kid is ' +
         'accepted, bound to its key, the subject unchanged',
         brief(byKeyKid) + ' ' + JSON.stringify(jwtKeyBound.cnf || {}));
    const byJwk = await w.issue(ALICE, aliceJwk, { configId: SD });
    note(!!byJwk.credential &&
         decodeSdJwt(byJwk.credential).cnf.jwk.x === aliceJwk.jwk.x,
         '1d. a proof carrying a jwk is issued as before', brief(byJwk));

    const both = await w.issue(ALICE, aliceJwk,
                               { configId: SD, kid: jwkKid, keepJwk: true });
    note(!both.credential && refusal(both).code === 'STS-VC-0140' &&
         refusal(both).error === 'invalid_proof',
         '1e. a proof with both jwk and kid is refused, invalid_proof, ' +
         'STS-VC-0140', JSON.stringify(refusal(both)));
    const noFragment = await w.issue(ALICE, aliceJwk,
      { configId: SD, kid: function (h) { return didJwkOf(h); } });
    const notDid = await w.issue(ALICE, aliceJwk,
                                 { configId: SD, kid: 'key-1' });
    const otherMethod = await w.issue(ALICE, aliceJwk,
                                      { configId: SD,
                                        kid: 'did:example:123#key-1' });
    note([noFragment, notDid, otherMethod].every(function (r) {
      return !r.credential && refusal(r).code === 'STS-VC-0141' &&
             refusal(r).error === 'invalid_proof';
    }), '1f. a kid with no fragment, one that is not a DID, and a DID ' +
        'method other than did:jwk and did:key are refused, STS-VC-0141',
         JSON.stringify([noFragment, notDid, otherMethod].map(refusal)));
    const web = await w.issue(ALICE, aliceJwk,
                              { configId: SD,
                                kid: 'did:web:wallet.example#key-1' });
    note(!web.credential && refusal(web).code === 'STS-VC-0142' &&
         refusal(web).error === 'invalid_proof',
         '1g. a did:web kid is refused, STS-VC-0142: holder binding to a ' +
         'did:web is not built', JSON.stringify(refusal(web)));
    const noSuchMethod = await w.issue(ALICE, aliceJwk,
      { configId: SD, kid: function (h) { return didJwkOf(h) + '#1'; } });
    note(!noSuchMethod.credential &&
         refusal(noSuchMethod).code === 'STS-VC-0143',
         '1h. a did:jwk URL naming a method its document does not have ' +
         '(#1) is refused, STS-VC-0143', JSON.stringify(refusal(noSuchMethod)));
    const encOnly = await w.issue(ALICE, aliceJwk, { configId: SD,
      kid: function (h) {
        const jwk = Object.assign({}, h.jwk, { use: 'enc' });
        return 'did:jwk:' + Buffer.from(JSON.stringify(jwk), 'utf8')
          .toString('base64url') + '#0';
      } });
    note(!encOnly.credential && refusal(encOnly).code === 'STS-VC-0144' &&
         refusal(encOnly).error === 'invalid_proof',
         '1i. a did:jwk whose key says use "enc" has no authentication ' +
         'method, and is refused, STS-VC-0144', JSON.stringify(
           refusal(encOnly)));
    const wrongKey = await w.issue(ALICE, aliceJwk,
      { configId: SD, kid: function () { return jwkKid(nobody); } });
    note(!wrongKey.credential && refusal(wrongKey).code === 'STS-VC-0019' &&
         refusal(wrongKey).error === 'invalid_proof',
         '1j. a proof signed by one key whose kid names another does not ' +
         'verify, STS-VC-0019', JSON.stringify(refusal(wrongKey)));

    // ==================================================================
    // 2. A CONFIGURATION BOUND TO THE PERSON'S DID
    // ==================================================================
    const set = await w.inRealm(function () {
      return m.config.setOverride('oid4vci.didHolderBinding',
                                  [SD, JWT, LDP].join(','));
    });
    note(!set || set.ok !== false,
         'precondition: oid4vci.didHolderBinding names the three plain ' +
         'configurations', JSON.stringify(set));
    const refused = await w.inRealm(function () {
      return m.config.setOverride('oid4vci.didHolderBinding',
                                  'NoSuchConfiguration');
    });
    await w.inRealm(function () {
      return m.config.setOverride('oid4vci.didHolderBinding',
                                  [SD, JWT, LDP].join(','));
    });
    note(refused && refused.ok === false,
         '2a. a configuration this issuer does not offer is refused on Save',
         JSON.stringify(refused));
    const after = (await w.request('GET',
      '/.well-known/openid-credential-issuer')).json || {};
    const afterConfigs = after.credential_configurations_supported || {};
    note([SD, JWT, LDP].every(function (id) {
      return JSON.stringify(afterConfigs[id]
        .cryptographic_binding_methods_supported) === '["did:jwk","did:key"]' &&
        JSON.stringify(afterConfigs[id].proof_types_supported) ===
        JSON.stringify(beforeConfigs[id].proof_types_supported);
    }) && JSON.stringify(afterConfigs.IdentityCredentialDid
           .cryptographic_binding_methods_supported) === '["jwk"]',
         '2b. the metadata says did:jwk and did:key for the three, with ' +
         'their proof types unchanged, and the configuration not named ' +
         'still says jwk', JSON.stringify([SD, JWT, LDP,
           'IdentityCredentialDid'].map(function (id) {
           return afterConfigs[id].cryptographic_binding_methods_supported;
         })));

    const sd = await w.issue(ALICE, aliceJwk, { configId: SD, kid: jwkKid });
    const sdBound = sd.credential ? decodeSdJwt(sd.credential) : {};
    note(!!sd.credential && sdBound.cnf &&
         sdBound.cnf.kid === jwkKid(aliceJwk) && !sdBound.cnf.jwk &&
         sdBound.sub === aliceSub,
         '2c. dc+sd-jwt: bound to her proved did:jwk as cnf.kid, no cnf.jwk, ' +
         'and sub still the subject this realm knows her by',
         brief(sd) + ' ' + JSON.stringify({ cnf: sdBound.cnf,
                                            sub: sdBound.sub }));
    const jwtVc = await w.issue(ALICE, aliceKey,
                                { configId: JWT, kid: keyKid });
    const jwtBound = jwtVc.credential ? w.decode(jwtVc.credential) : {};
    note(!!jwtVc.credential && jwtBound.cnf &&
         jwtBound.cnf.kid === keyKid(aliceKey) && !jwtBound.cnf.jwk &&
         jwtBound.sub === didKeyOf(aliceKey) &&
         jwtBound.vc && jwtBound.vc.credentialSubject &&
         jwtBound.vc.credentialSubject.id === didKeyOf(aliceKey),
         '2d. jwt_vc_json: bound to her proved did:key — ' +
         'credentialSubject.id and sub the DID, cnf.kid the DID URL',
         brief(jwtVc) + ' ' + JSON.stringify({ cnf: jwtBound.cnf,
                                               sub: jwtBound.sub }));
    const ldpJwk = await w.issue(ALICE, aliceJwk,
                                 { configId: LDP, kid: jwkKid });
    const ldpKey = await w.issue(ALICE, aliceKey,
                                 { configId: LDP, kid: keyKid });
    note(!!ldpJwk.credential && !!ldpKey.credential &&
         ldpJwk.credential.credentialSubject.id === didJwkOf(aliceJwk) &&
         ldpKey.credential.credentialSubject.id === didKeyOf(aliceKey),
         '2e. ldp_vc: credentialSubject.id is her proved did:jwk, or her ' +
         'proved did:key', brief(ldpJwk) + ' / ' + brief(ldpKey));
    const batch = await w.issue(ALICE, aliceJwk,
      { configId: SD, kid: jwkKid, holders: [aliceJwk, aliceJwk] });
    note(!!batch.credentials && batch.credentials.length === 2 &&
         batch.credentials.every(function (c) {
           return decodeSdJwt(c).cnf.kid === jwkKid(aliceJwk);
         }),
         '2f. a batch of two proofs by her DID is two credentials, both ' +
         'bound to the one DID', brief(batch));
    const issuedDids = await w.inRealm(function () {
      return m.issued.rowsForSubject(aliceSub).map(function (row) {
        return m.issued.rowByKey(row.key);
      }).filter(Boolean).map(function (row) {
        return (row.credentials || []).map(function (c) {
          return c.holderDid || '';
        });
      });
    });
    note([].concat.apply([], issuedDids).indexOf(didKeyOf(aliceKey)) >= 0,
         '2g. the issued register keeps the DID a copy is bound to',
         JSON.stringify(issuedDids).slice(0, 300));

    const jwkProof = await w.issue(ALICE, aliceJwk, { configId: SD });
    note(!jwkProof.credential && refusal(jwkProof).code === 'STS-VC-0145' &&
         refusal(jwkProof).error === 'invalid_proof',
         '2h. a proof carrying a jwk is refused for a DID-bound ' +
         'configuration, STS-VC-0145', JSON.stringify(refusal(jwkProof)));
    const daves = await w.issue(DAVE, daveJwk, { configId: SD, kid: jwkKid });
    note(!daves.credential && refusal(daves).code === 'STS-VC-0149' &&
         refusal(daves).error === 'invalid_proof',
         '2i. a DID an administrator enrolled by value is never bound, ' +
         'STS-VC-0149', JSON.stringify(refusal(daves)));
    const bobs = await w.issue(ALICE, bobJwk, { configId: SD, kid: jwkKid });
    note(!bobs.credential && refusal(bobs).code === 'STS-VC-0150',
         '2j. somebody else\'s proved DID is refused, STS-VC-0150',
         JSON.stringify(refusal(bobs)));
    const unknown = await w.issue(ALICE, nobody, { configId: SD,
                                                   kid: jwkKid });
    note(!unknown.credential && refusal(unknown).code === 'STS-VC-0148',
         '2k. a DID enrolled for nobody is refused, STS-VC-0148',
         JSON.stringify(refusal(unknown)));

    // REMOVED BETWEEN THE OFFER AND THE REQUEST: the token first.
    const tokenBeforeRemoval = await w.accessTokenFor(ALICE,
                                                      { configId: SD });
    const removed = await w.inRealm(function () {
      return siop.remove(ALICE, didJwkOf(aliceGone), ALICE);
    });
    const afterRemoval = await w.issue(ALICE, aliceGone,
      { configId: SD, kid: jwkKid, token: tokenBeforeRemoval.token });
    note(removed && removed.ok && !afterRemoval.credential &&
         refusal(afterRemoval).code === 'STS-VC-0148',
         '2l. a DID removed after the access token was issued is refused at ' +
         'the request, STS-VC-0148', JSON.stringify(refusal(afterRemoval)));

    // A TOKEN THIS REALM DID NOT VERIFY names nobody it can vouch for.
    const forged = m.stsCrypto.signJws(
      { sub: aliceSub, scope: 'identity_credential',
        iss: 'https://elsewhere.example',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300 },
      require('crypto').generateKeyPairSync('rsa',
        { modulusLength: 2048 }).privateKey,
      { algorithm: 'RS256', header: { typ: 'at+jwt' } });
    const onForged = await w.issue(ALICE, aliceJwk,
      { configId: SD, kid: jwkKid, token: forged });
    note(!onForged.credential && refusal(onForged).code === 'STS-VC-0146' &&
         refusal(onForged).error === 'credential_request_denied',
         '2m. on an access token this realm did not verify, ' +
         'credential_request_denied, STS-VC-0146',
         JSON.stringify(refusal(onForged)));

    // A DISABLED ACCOUNT: the lock alone, so the token is still good and the
    // refusal is the account's; then the administrator's act, which ends the
    // tokens too.
    const carolToken = await w.accessTokenFor(CAROL, { configId: SD });
    await w.inRealm(function () {
      credentials.setAccountDisabled(CAROL, true, {});
    });
    const disabled = await w.issue(CAROL, carolJwk,
      { configId: SD, kid: jwkKid, token: carolToken.token });
    note(!disabled.credential && refusal(disabled).code === 'STS-VC-0147' &&
         refusal(disabled).error === 'credential_request_denied',
         '2n. a disabled account is refused, credential_request_denied, ' +
         'STS-VC-0147', JSON.stringify(refusal(disabled)));

    // ==================================================================
    // 3. DEFERRED: ASKED AGAIN AT COLLECTION
    // ==================================================================
    await w.inRealm(function () {
      m.config.setOverride('oid4vci.deferredReadyMs', 0);
    });
    async function deferred(holder) {
      const got = await w.accessTokenFor(ALICE, { configId: SD });
      await w.inRealm(function () {
        m.offers.deferredAccessTokens.add(got.token);
      });
      const first = await w.issue(ALICE, holder,
                                  { configId: SD, kid: jwkKid,
                                    token: got.token });
      const tx = first.response && first.response.json &&
                 first.response.json.transaction_id;
      return { token: got.token, first: first, tx: tx };
    }
    const waiting = await deferred(aliceLate);
    await w.inRealm(function () {
      siop.remove(ALICE, didJwkOf(aliceLate), ALICE);
    });
    const collectedGone = await w.request('POST',
      '/oid4vci/deferred_credential', {
        headers: { authorization: 'Bearer ' + waiting.token },
        json: { transaction_id: waiting.tx } });
    note(waiting.first.response && waiting.first.response.status === 202 &&
         !!waiting.tx && collectedGone.status === 400 &&
         collectedGone.code === 'STS-VC-0148' && collectedGone.json &&
         collectedGone.json.error === 'credential_request_denied',
         '3a. a deferred issuance whose DID was removed while it waited is ' +
         'refused at collection, STS-VC-0148',
         (waiting.first.response && waiting.first.response.status) + ' ' +
         collectedGone.status + ' ' + collectedGone.code);
    const waitingGood = await deferred(aliceJwk);
    const collectedGood = await w.request('POST',
      '/oid4vci/deferred_credential', {
        headers: { authorization: 'Bearer ' + waitingGood.token },
        json: { transaction_id: waitingGood.tx } });
    const deferredCredential = collectedGood.json &&
      collectedGood.json.credentials && collectedGood.json.credentials[0] &&
      collectedGood.json.credentials[0].credential;
    note(collectedGood.status === 200 && !!deferredCredential &&
         decodeSdJwt(deferredCredential).cnf.kid === jwkKid(aliceJwk),
         '3b. one whose DID is still proved is issued bound to it',
         collectedGood.status + ' ' + collectedGood.text.slice(0, 200));
    await w.inRealm(function () {
      m.config.clearOverride('oid4vci.deferredReadyMs');
    });

    // ==================================================================
    // 4. A DID-BOUND CREDENTIAL SIGNS ITS HOLDER IN
    // ==================================================================
    const aud = await w.signInAudience();
    async function attempt(format, credential, holder, opts) {
      const who = w.browser();
      const one = await w.start(who, w.pendingSignIn());
      const presentation = await w.present(format, credential, holder,
        one.requestObject.nonce, aud, opts || {});
      await w.respond(one, presentation, { format: format });
      const page = await w.collect(who, one);
      const session = w.sessionOf(who);
      if (session) {
        await w.inRealm(function () {
          m.authn.endSessionById(session.id, 'the test, tidying up');
        });
      }
      return { ok: page.status === 303, code: page.code, session: session };
    }
    const cases = [
      ['dc+sd-jwt', sd.credential, aliceJwk, null],
      ['jwt_vc_json', jwtVc.credential, aliceKey, null],
      ['ldp_vc', ldpJwk.credential, aliceJwk, null],
      ['ldp_vc', ldpKey.credential, aliceKey, {
        pick: function (line) {
          return /credentials#credentialSubject> <did:key:/.test(line) ||
                 /credentials#issuer>/.test(line) ||
                 /credentials#validFrom>/.test(line) ||
                 /credentials#validUntil>/.test(line) ||
                 /ns\/credentials\/status#/.test(line) ||
                 /BitstringStatusListEntry/.test(line);
        } }]
    ];
    for (const one of cases) {
      const label = one[0] + (one[3] ? ', did:key' : '');
      if (!one[1]) {
        note(false, '4[' + label + ']. a DID-bound credential to present',
             'none was issued');
        continue;
      }
      const signedIn = await attempt(one[0], one[1], one[2], one[3]);
      note(signedIn.ok && signedIn.session &&
           signedIn.session.user.username === ALICE,
           '4[' + label + ']. a credential bound to her DID signs her in',
           signedIn.code);
    }

    await w.inRealm(function () {
      m.config.clearOverride('oid4vci.didHolderBinding');
    });
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'oid4vci-did-binding');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oid4vci_did_binding',
  describe: 'OpenID4VCI key proofs by DID (kid), and credentials bound to ' +
            'the person\'s proven did:jwk or did:key where ' +
            'oid4vci.didHolderBinding says so (#693)',
  run: run
};
