// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: person_did.js
//
// ===========================================================================
// A did:web THIS REALM PUBLISHES FOR A PERSON (#1291). rcbj's four decisions
// on #1291 are the specification: three custody modes per realm, a random
// identifier, deactivate-and-keep-the-URL, and "treat it as a proved DID".
//
// Asserted in a CHILD PROCESS that loads the whole stack and listens on a
// loopback port (`tests/wallet_kit.js`), against the real directory, the
// real sign-in surface and the real issuer and Verifier:
//
//   1. the random id, the settings' refusals (off, product without a pinned
//      base, the cap), the document's address, type and no-store;
//   2. `wallet` custody END TO END over the sign-in surface: a session, the
//      wallet's round trip with `did_act=publish`, the DID signing its
//      person in resolved from the realm's own history (nothing fetched).
//      A key already enrolled for sign-in is not published (STS-VC-0178,
//      #775), and neither is that published key a second time;
//   3. THE TWO-PROOF CHANGE: a new key with no authorization refused at the
//      start, an "authorization" signed only by the new key refused, then
//      the authorization by the current key and the new key's proof — a
//      new version, the pin following it — and an added key. A sign-in key
//      proved as the new key is STS-VC-0178 and leaves the authorization;
//   4. versions and their resolution: `?versionId=`, `?versionTime=`, the
//      resolver's didDocumentMetadata, dereferencing a versioned DID URL;
//   5. holder binding: the metadata offers did:web only where it should,
//      `cnf.kid` names the VERSION, the Verifier resolves it with no fetch
//      and signs the holder in; an ldp_vc and a did:web while publishing is
//      off are refused;
//   6. `realm` custody: sealed key never answered, preferred and released,
//      never signs in or binds; one-act add and rotate;
//   7. `download` custody: the private key answered once, `issued` until the
//      wallet proves it, then `wallet`;
//   8. deactivation: 410 when the person removes it and when the account is
//      disabled, restored on re-enable; the administrator's act and its
//      refusals; the directory never shows the value;
//   9. every new error code, the library's write and seal failures among
//      them.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'person_did',
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

  async function sections(w, note, m) {
    const siop = require(ROOT + '/oid4vc/siop');
    const pd = require(ROOT + '/oid4vc/person_did');
    const resolver = require(ROOT + '/oid4vc/vc_did_resolver');
    const credentials = require(ROOT + '/common/credentials');
    const accountState = require(ROOT + '/common/account_state');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const portalSelfIssued = require(ROOT + '/portal/portal_self_issued');
    const audit = require(ROOT + '/common/audit');
    const stamp = String(process.pid);
    const ALICE = 'pd-alice-' + stamp;
    const BOB = 'pd-bob-' + stamp;
    const CAROL = 'pd-carol-' + stamp;
    const DAVE = 'pd-dave-' + stamp;
    const SELF = 'self (SIOPv2)';
    const SD = 'IdentityCredential';
    const JWT = 'IdentityCredentialJwtVcJson';
    const LDP = 'IdentityCredentialLdpVc';

    function set(key, value) {
      return w.inRealm(function () {
        return m.config.setOverride(key, value);
      });
    }
    function clear(key) {
      return w.inRealm(function () {
        return m.config.clearOverride(key);
      });
    }
    function thumb(holder) {
      return m.stsCrypto.jwkThumbprint({ kty: holder.jwk.kty,
        crv: holder.jwk.crv, x: holder.jwk.x, y: holder.jwk.y });
    }
    function didJwkOf(holder) {
      return m.di.didJwkOf(holder.jwk);
    }

    await w.inRealm(function () {
      w.provision();
      [ALICE, BOB, CAROL, DAVE].forEach(function (name) {
        m.ldap.createUser(name, { invent: false });
      });
    });
    set('oid4vp.signIn', true);
    set('oid4vp.signInSelfIssued', true);
    set('risk.assessSignIns', false);

    // A self-issued ID Token for `did`, signed by `holder`, naming `kid`.
    function idToken(holder, did, kid, ro) {
      const now = Math.floor(Date.now() / 1000);
      return w.jws({ alg: holder.alg, typ: 'JWT', kid: kid },
                   { iss: did, sub: did, aud: ro.client_id, nonce: ro.nonce,
                     iat: now, exp: now + 300 }, holder);
    }
    // A SIOPv2 round trip from `who`: a sign-in (no `query.enrol`) or an
    // enrolment, the wallet answering as `did` with `holder`'s key.
    async function roundTrip(who, holder, did, kid, query) {
      const enrolling = query && query.enrol === '1';
      const id = enrolling ? null : await w.pendingSignIn();
      const s = await w.start(who, id,
        { query: Object.assign({ siop: '1' }, query || {}) });
      if (!s.requestObject) {
        return { started: s.started, ok: false, code: s.started.code };
      }
      const ro = s.requestObject;
      const answered = await w.request('POST', '/oid4vp/response', {
        form: w.encryptedForm(ro, { state: ro.state,
                                    id_token: idToken(holder, did, kid,
                                                      ro) }) });
      const done = await w.collect(who, s);
      return { started: s.started, answered: answered, done: done,
               ok: done.status === 303, code: done.code,
               location: (done.headers && done.headers.location) || '' };
    }
    // A browser signed in as `name` with a did:jwk they proved.
    async function sessionFor(name) {
      const key = w.holderKey('ES256');
      await w.inRealm(function () {
        siop.enrol(name, didJwkOf(key), 'phone', SELF, { proof: 'wallet' });
      });
      const who = w.browser();
      const r = await roundTrip(who, key, didJwkOf(key), didJwkOf(key) + '#0');
      await w.refreshCsrf(who);
      return { who: who, ok: r.ok && !!w.sessionOf(who), code: r.code };
    }
    // The portal's account API operations, called as the API calls them.
    const ctx = {
      BASE: '/account-api', PORTAL: '/portal', audit: audit,
      refuse: function (res, status, code, error) {
        res.status = status;
        res.code = code;
        res.body = { ok: false, errors: [error] };
        return res;
      },
      json: function (res, status, body) {
        res.status = status;
        res.body = body;
        return res;
      },
      translatorFor: function () {
        return { text: function (key) {
          return key;
        } };
      }
    };
    const ops = portalSelfIssued.accountOperations(ctx);
    const opOf = function (method, path) {
      return ops.filter(function (op) {
        return op.method === method && op.path === path;
      })[0];
    };
    const didOp = opOf('POST', '/account-api/self-issued/dids');
    const viewOp = opOf('GET', '/account-api/self-issued');
    const removeOp = opOf('POST', '/account-api/self-issued');
    function portalAct(who, body) {
      return w.inRealm(function () {
        const res = {};
        didOp.handler(w.fakeReq(''), res, { username: who }, { body: body });
        return res;
      });
    }
    function portalView(who) {
      return w.inRealm(function () {
        const res = {};
        viewOp.handler({}, res, { username: who }, { query: {} });
        return res.body;
      });
    }
    function recordsOf(who) {
      return w.inRealm(function () {
        return (credentials.readPublishedDids(who) || []).map(function (v) {
          return JSON.parse(v);
        });
      });
    }
    function listOf(who) {
      return w.inRealm(function () {
        return pd.list(who) || [];
      });
    }
    function subjectRow(who, subject) {
      return w.inRealm(function () {
        return (siop.list(who) || []).filter(function (one) {
          return one.subject === subject;
        })[0] || null;
      });
    }
    function docPath(rid, query) {
      return '/users/' + rid + '/did.json' + (query ? '?' + query : '');
    }

    // ==================================================================
    // 1. THE SETTINGS, THE RANDOM ID AND THE ADDRESS
    // ==================================================================
    set('did.personCustody', 'realm');
    const off = portalAct(BOB, { action: 'publish' });
    note(off.status === 400 && off.code === 'STS-VC-0167',
         '1a. with did.personPublishing off (the default) nothing is ' +
         'published, STS-VC-0167', off.status + ' ' + off.code);
    set('did.personPublishing', true);
    set('global.mode', 'product');
    const unpinned = portalAct(BOB, { action: 'publish' });
    clear('global.mode');
    note(unpinned.status === 400 && unpinned.code === 'STS-VC-0168' &&
         recordsOf(BOB).length === 0,
         '1b. in product mode with no public base URL pinned, publishing ' +
         'is refused, STS-VC-0168', unpinned.status + ' ' + unpinned.code);
    const first = portalAct(BOB, { action: 'publish' });
    const second = portalAct(BOB, { action: 'publish' });
    const bobRecords = recordsOf(BOB);
    const ridA = bobRecords[0] ? bobRecords[0].rid : '';
    const ridB = bobRecords[1] ? bobRecords[1].rid : '';
    note(first.status === 200 && second.status === 200 &&
         /^[A-Za-z0-9_-]{22}$/.test(ridA) && /^[A-Za-z0-9_-]{22}$/.test(ridB) &&
         ridA !== ridB && bobRecords[0].did.indexOf(BOB) < 0 &&
         new RegExp('^did:web:127\\.0\\.0\\.1%3A' + w.port + ':users:' +
                    ridA + '$').test(bobRecords[0].did),
         '1c. each DID has its own 22-character base64url id (128 random ' +
         'bits) that says nothing of its person, under :users:',
         JSON.stringify(bobRecords.map(function (one) {
           return one.did;
         })));
    set('did.personMaxPerPerson', 2);
    const capped = portalAct(BOB, { action: 'publish' });
    note(capped.status === 400 && capped.code === 'STS-VC-0169',
         '1d. did.personMaxPerPerson caps the active DIDs, STS-VC-0169',
         capped.status + ' ' + capped.code);
    clear('did.personMaxPerPerson');
    const served = await w.request('GET', docPath(ridA));
    note(served.status === 200 &&
         /application\/did\+json/.test(served.headers['content-type']) &&
         /no-store/.test(served.headers['cache-control']) &&
         served.json && served.json.id === bobRecords[0].did &&
         served.json['@context'] === undefined &&
         served.json.verificationMethod.length === 1 &&
         served.json.authentication[0] ===
           served.json.verificationMethod[0].id,
         '1e. /users/<rid>/did.json answers application/did+json, no-store, ' +
         'the JSON representation with the key under authentication',
         served.status + ' ' + JSON.stringify(served.headers));
    const unknown = await w.request('GET',
      docPath('AAAAAAAAAAAAAAAAAAAAAA'));
    note(unknown.status === 404 && unknown.code === 'STS-VC-0161',
         '1f. an address never published answers 404, STS-VC-0161',
         unknown.status + ' ' + unknown.code);

    // ==================================================================
    // 2. `wallet` CUSTODY, END TO END OVER THE SIGN-IN SURFACE
    // ==================================================================
    set('did.personCustody', 'wallet');
    const alice = await sessionFor(ALICE);
    note(alice.ok, '2a. (a control: alice signs in with a proved did:jwk)',
         alice.code);
    const k1 = w.holderKey('ES256');
    const walletOff = await w.inRealm(function () {
      return pd.publishGenerated(ALICE, w.fakeReq(''));
    });
    note(!walletOff.ok && walletOff.code === 'STS-VC-0173',
         '2b. in wallet custody the realm generates no key, STS-VC-0173',
         JSON.stringify(walletOff));
    const viaWeb = await roundTrip(alice.who, k1, 'did:web:example.test',
      'did:web:example.test#k', { enrol: '1', did_act: 'publish' });
    note(!viaWeb.ok && listOf(ALICE).length === 0,
         '2c. a did:web cannot prove the key a new DID is published with',
         viaWeb.code);
    const enrolledKey = w.holderKey('ES256');
    await w.inRealm(function () {
      siop.enrol(ALICE, didJwkOf(enrolledKey), 'phone', SELF,
                 { proof: 'wallet' });
    });
    const ownKey = await roundTrip(alice.who, enrolledKey,
      didJwkOf(enrolledKey), didJwkOf(enrolledKey) + '#0',
      { enrol: '1', did_act: 'publish' });
    note(!ownKey.ok && ownKey.code === 'STS-VC-0178' &&
         listOf(ALICE).length === 0,
         '2cb. a key already enrolled for sign-in is not published, ' +
         'STS-VC-0178 (#775)', ownKey.code);
    const published = await roundTrip(alice.who, k1, didJwkOf(k1),
      didJwkOf(k1) + '#0', { enrol: '1', did_act: 'publish' });
    const aliceDids = listOf(ALICE);
    const A = aliceDids[0] || {};
    note(published.ok && /\/portal\/self-issued\?did=published&rid=/
           .test(published.location) &&
         aliceDids.length === 1 && A.custody === 'wallet' &&
         A.proof === 'wallet' && A.currentVersion === 1 &&
         A.versions[0].keys[0].id === thumb(k1) &&
         A.versions[0].authorizedBy[0].kind === 'wallet-proof',
         '2d. the wallet\'s round trip with did_act=publish publishes a DID ' +
         'whose version 1 names the key it proved, enrolled as a proved ' +
         '(wallet) self-issued subject', published.code + ' ' +
         published.location + ' ' + JSON.stringify(A).slice(0, 400));
    const publishedAgain = await roundTrip(alice.who, k1, didJwkOf(k1),
      didJwkOf(k1) + '#0', { enrol: '1', did_act: 'publish' });
    note(!publishedAgain.ok && publishedAgain.code === 'STS-VC-0178' &&
         listOf(ALICE).length === 1,
         '2da. that key cannot publish a second DID: the published one ' +
         'pinned it as a sign-in key, STS-VC-0178', publishedAgain.code);
    const aliceSubject = subjectRow(ALICE, A.did) || {};
    note(JSON.stringify(aliceSubject.pinnedKeys) ===
           JSON.stringify([thumb(k1)]),
         '2e. its self-issued subject pins version 1\'s key',
         JSON.stringify(aliceSubject));
    const webWho = w.browser();
    const signIn = await roundTrip(webWho, k1, A.did, A.did + '#' + thumb(k1));
    const signedAs = w.sessionOf(webWho);
    note(signIn.ok && signedAs && signedAs.user.username === ALICE,
         '2f. the published did:web signs alice in: its key resolved from ' +
         'the realm\'s own history (this service listens on http, so a ' +
         'did:web fetch would have failed)', signIn.code);
    const preferred = await w.inRealm(function () {
      return siop.setPreferred(ALICE, A.did);
    });
    note(preferred.ok && w.inRealm(function () {
      return siop.preferredSubjectOf(ALICE).subject === A.did;
    }), '2g. it can be the preferred DID, which the did claim releases',
         JSON.stringify(preferred));

    // ==================================================================
    // 3. THE TWO-PROOF CHANGE
    // ==================================================================
    const k2 = w.holderKey('ES256');
    const newOnly = await roundTrip(alice.who, k2, didJwkOf(k2),
      didJwkOf(k2) + '#0', { enrol: '1', did_act: 'key.' + A.rid });
    note(!newOnly.ok && newOnly.started.code === 'STS-VC-0171',
         '3a. a new key with no authorization is refused before the wallet ' +
         'is asked, STS-VC-0171', JSON.stringify(newOnly.started.status) +
         ' ' + newOnly.started.code);
    const byNew = await roundTrip(alice.who, k2, didJwkOf(k2),
      didJwkOf(k2) + '#0', { enrol: '1',
                             did_act: 'authorize-rotate.' + A.rid });
    note(!byNew.ok && byNew.code === 'STS-VC-0171' &&
         listOf(ALICE)[0].currentVersion === 1 && !listOf(ALICE)[0].pending,
         '3b. a change "authorized" by the new key alone — not signed as ' +
         'the DID with a key its current version names — is refused, ' +
         'STS-VC-0171', byNew.code);
    const authorized = await roundTrip(alice.who, k1, A.did,
      A.did + '#' + thumb(k1), { enrol: '1',
                                 did_act: 'authorize-rotate.' + A.rid });
    note(authorized.ok && /did=authorized/.test(authorized.location) &&
         listOf(ALICE)[0].pending &&
         listOf(ALICE)[0].pending.change === 'rotate',
         '3c. signed as the DID with version 1\'s key, the rotation is ' +
         'authorized and waits for the new key', authorized.code);
    const signInKey = w.holderKey('ES256');
    await w.inRealm(function () {
      siop.enrol(ALICE, didJwkOf(signInKey), 'laptop', SELF,
                 { proof: 'wallet' });
    });
    const asNew = await roundTrip(alice.who, signInKey,
      didJwkOf(signInKey), didJwkOf(signInKey) + '#0',
      { enrol: '1', did_act: 'key.' + A.rid });
    const stillPending = listOf(ALICE)[0] || {};
    note(!asNew.ok && asNew.code === 'STS-VC-0178' &&
         stillPending.currentVersion === 1 && stillPending.pending &&
         stillPending.pending.change === 'rotate',
         '3ca. a sign-in key proved as the new key is refused, ' +
         'STS-VC-0178, and the authorization stays', asNew.code);
    const sameKey = await roundTrip(alice.who, k1, didJwkOf(k1),
      didJwkOf(k1) + '#0', { enrol: '1', did_act: 'key.' + A.rid });
    note(!sameKey.ok && sameKey.code === 'STS-VC-0170',
         '3d. a "new" key the current version already names is refused, ' +
         'STS-VC-0170', sameKey.code);
    const rotated = await roundTrip(alice.who, k2, didJwkOf(k2),
      didJwkOf(k2) + '#0', { enrol: '1', did_act: 'key.' + A.rid });
    const afterRotate = listOf(ALICE)[0] || {};
    const v2 = afterRotate.versions ? afterRotate.versions[1] : {};
    note(rotated.ok && afterRotate.currentVersion === 2 &&
         v2.change === 'rotate-key' && v2.keys.length === 1 &&
         v2.keys[0].id === thumb(k2) &&
         v2.authorizedBy[0].kind === 'current-key-proof' &&
         v2.authorizedBy[0].keyThumbprint === thumb(k1) &&
         v2.authorizedBy[1].kind === 'new-key-proof' &&
         v2.authorizedBy[1].keyThumbprint === thumb(k2) &&
         !afterRotate.pending,
         '3e. the new key\'s proof appends version 2 naming only it, with ' +
         'BOTH proofs recorded as what authorized it',
         rotated.code + ' ' + JSON.stringify(v2));
    note(JSON.stringify((subjectRow(ALICE, A.did) || {}).pinnedKeys) ===
           JSON.stringify([thumb(k2)]) &&
         subjectRow(ALICE, A.did).preferred === true,
         '3f. the pin follows the new version, and the preferred mark stays',
         JSON.stringify(subjectRow(ALICE, A.did)));
    const oldKeyIn = await roundTrip(w.browser(), k1, A.did,
                                     A.did + '#' + thumb(k1));
    const newKeyWho = w.browser();
    const newKeyIn = await roundTrip(newKeyWho, k2, A.did,
                                     A.did + '#' + thumb(k2));
    note(!oldKeyIn.ok && newKeyIn.ok,
         '3g. the rotated-out key signs nobody in; the new one does',
         oldKeyIn.code + ' / ' + newKeyIn.code);
    const k3 = w.holderKey('EdDSA');
    await roundTrip(alice.who, k2, A.did, A.did + '#' + thumb(k2),
                    { enrol: '1', did_act: 'authorize-add.' + A.rid });
    const added = await roundTrip(alice.who, k3, didJwkOf(k3),
      didJwkOf(k3) + '#0', { enrol: '1', did_act: 'key.' + A.rid });
    const afterAdd = listOf(ALICE)[0] || {};
    note(added.ok && afterAdd.currentVersion === 3 &&
         afterAdd.versions[2].change === 'add-key' &&
         afterAdd.versions[2].keys.map(function (k) {
           return k.id;
         }).join(',') === thumb(k2) + ',' + thumb(k3),
         '3h. an added key joins the current ones in version 3',
         added.code + ' ' + JSON.stringify(afterAdd.versions[2]));

    // ==================================================================
    // 4. VERSIONS AND THEIR RESOLUTION
    // ==================================================================
    const current = await w.request('GET', docPath(A.rid));
    const atOne = await w.request('GET', docPath(A.rid, 'versionId=1'));
    const atTwo = await w.request('GET', docPath(A.rid, 'versionId=2'));
    const v2Time = encodeURIComponent(afterAdd.versions[1].created);
    const byTime = await w.request('GET',
      docPath(A.rid, 'versionTime=' + v2Time));
    const tooFar = await w.request('GET', docPath(A.rid, 'versionId=9'));
    const badTime = await w.request('GET',
      docPath(A.rid, 'versionTime=yesterday'));
    const methodIds = function (r) {
      return ((r.json && r.json.verificationMethod) || []).map(function (vm) {
        return vm.id.split('#')[1];
      }).join(',');
    };
    note(methodIds(current) === thumb(k2) + ',' + thumb(k3) &&
         methodIds(atOne) === thumb(k1) && methodIds(atTwo) === thumb(k2) &&
         methodIds(byTime).indexOf(thumb(k2)) === 0 &&
         tooFar.status === 404 && tooFar.code === 'STS-VC-0163' &&
         badTime.status === 400 && badTime.code === 'STS-VC-0163',
         '4a. the address answers the current version, ?versionId= and ' +
         '?versionTime= from the history, and refuses a version that does ' +
         'not exist or a malformed time, STS-VC-0163',
         [methodIds(current), methodIds(atOne), methodIds(atTwo),
          methodIds(byTime), tooFar.status, badTime.status].join(' | '));
    const resolvedOne = await w.inRealm(function () {
      return resolver.resolve(A.did, { versionId: '1' }, w.fakeReq(''));
    });
    const resolvedNow = await w.inRealm(function () {
      return resolver.resolve(A.did, {}, w.fakeReq(''));
    });
    const meta1 = resolvedOne.didDocumentMetadata || {};
    const metaNow = resolvedNow.didDocumentMetadata || {};
    note(resolvedOne.didDocument &&
         resolvedOne.didDocument.verificationMethod[0].id ===
           A.did + '#' + thumb(k1) &&
         meta1.versionId === '1' && meta1.nextVersionId === '2' &&
         meta1.created === afterAdd.versions[0].created &&
         metaNow.versionId === '3' && metaNow.nextVersionId === undefined &&
         metaNow.created === meta1.created && !metaNow.deactivated,
         '4b. the resolver answers from the history with ' +
         'didDocumentMetadata: created, updated, versionId, nextVersionId',
         JSON.stringify([meta1, metaNow]));
    const deref = await w.inRealm(function () {
      return resolver.dereference(A.did + '?versionId=1#' + thumb(k1),
                                  {}, w.fakeReq(''));
    });
    note(deref.contentStream &&
         JSON.parse(deref.contentStream).id === A.did + '#' + thumb(k1),
         '4c. a versioned DID URL dereferences to that version\'s method',
         JSON.stringify(deref).slice(0, 300));

    // ==================================================================
    // 5. HOLDER BINDING TO THE PUBLISHED DID
    // ==================================================================
    set('oid4vci.didHolderBinding', [SD, JWT, LDP].join(','));
    const meta = (await w.request('GET',
      '/.well-known/openid-credential-issuer')).json || {};
    const configs = meta.credential_configurations_supported || {};
    note(configs[SD].cryptographic_binding_methods_supported
           .indexOf('did:web') >= 0 &&
         configs[JWT].cryptographic_binding_methods_supported
           .indexOf('did:web') >= 0 &&
         configs[LDP].cryptographic_binding_methods_supported
           .indexOf('did:web') < 0,
         '5a. with publishing on, a DID-bound dc+sd-jwt or jwt_vc_json ' +
         'configuration offers did:web; an ldp_vc does not',
         JSON.stringify([configs[SD].cryptographic_binding_methods_supported,
           configs[LDP].cryptographic_binding_methods_supported]));
    const kidNow = A.did + '#' + thumb(k2);
    const sd = await w.issue(ALICE, k2, { configId: SD, kid: kidNow });
    const sdPayload = sd.credential
      ? w.decode(String(sd.credential).split('~')[0]) : {};
    note(!!sd.credential && sdPayload.cnf &&
         sdPayload.cnf.kid === A.did + '?versionId=3#' + thumb(k2),
         '5b. a dc+sd-jwt bound to the published DID names the VERSION in ' +
         'cnf.kid', (sd.error || '') + ' ' + JSON.stringify(sdPayload.cnf));
    const jwtVc = await w.issue(ALICE, k2, { configId: JWT, kid: kidNow });
    const jwtPayload = jwtVc.credential ? w.decode(jwtVc.credential) : {};
    note(!!jwtVc.credential && jwtPayload.sub === A.did &&
         jwtPayload.cnf.kid === A.did + '?versionId=3#' + thumb(k2),
         '5c. a jwt_vc_json\'s sub is the DID, and its cnf.kid the version',
         (jwtVc.error || '') + ' ' + JSON.stringify(jwtPayload.cnf));
    const ldp = await w.issue(ALICE, k2, { configId: LDP, kid: kidNow });
    note(!ldp.credential && ldp.response && ldp.response.code ===
           'STS-VC-0166',
         '5d. an ldp_vc is not bound to a did:web (no cnf to name the ' +
         'version), STS-VC-0166', ldp.error);
    const aud = await w.signInAudience();
    async function presentIn(format, credential, holder) {
      const who = w.browser();
      const one = await w.start(who, await w.pendingSignIn());
      const presentation = await w.present(format, credential, holder,
        one.requestObject.nonce, aud, {});
      await w.respond(one, presentation, { format: format });
      const page = await w.collect(who, one);
      const session = w.sessionOf(who);
      return { ok: page.status === 303 && !!session, code: page.code,
               who: session ? session.user.username : '' };
    }
    if (sd.credential) {
      const presented = await presentIn('dc+sd-jwt', sd.credential, k2);
      note(presented.ok && presented.who === ALICE,
           '5e. the Verifier resolves cnf.kid\'s version from the realm\'s ' +
           'own history, with no fetch, and signs alice in',
           presented.code);
    }
    // A later rotation leaves version 3 resolvable: the credential still
    // names a key the DID named then.
    if (jwtVc.credential) {
      const presentedJwt = await presentIn('jwt_vc_json', jwtVc.credential,
                                           k2);
      note(presentedJwt.ok && presentedJwt.who === ALICE,
           '5f. a jwt_vc_json bound to the DID signs alice in',
           presentedJwt.code);
    }
    set('did.personPublishing', false);
    const offBind = await w.issue(ALICE, k2, { configId: SD, kid: kidNow });
    note(!offBind.credential && offBind.response &&
         offBind.response.code === 'STS-VC-0142',
         '5g. with publishing off, a did:web kid is refused as before, ' +
         'STS-VC-0142', offBind.error);
    set('did.personPublishing', true);

    // ==================================================================
    // 6. `realm` CUSTODY
    // ==================================================================
    const B = listOf(BOB)[0] || {};
    const bobRecord = recordsOf(BOB)[0] || {};
    const sealedKey = bobRecord.privateKeys &&
      bobRecord.privateKeys[B.versions[0].keys[0].id];
    note(B.custody === 'realm' && B.proof === 'realm' && !!sealedKey &&
         JSON.stringify(B).indexOf('"d"') < 0 &&
         JSON.stringify(portalView(BOB)).indexOf(sealedKey.value) < 0,
         '6a. a realm-custody DID keeps its private key on the record and ' +
         'never in a view of it', JSON.stringify(B).slice(0, 200));
    const bobPreferred = await w.inRealm(function () {
      return siop.setPreferred(BOB, B.did);
    });
    note(bobPreferred.ok && w.inRealm(function () {
      return siop.preferredSubjectOf(BOB).subject === B.did;
    }), '6b. it can be preferred, and the did claim releases it',
         JSON.stringify(bobPreferred));
    // Its key, which only the realm holds (development keeps it as
    // written), signs nothing in and binds nothing.
    const realmJwk = JSON.parse(sealedKey.value);
    const realmHolder = { alg: realmJwk.alg,
      jwk: { kty: realmJwk.kty, crv: realmJwk.crv, x: realmJwk.x,
             y: realmJwk.y },
      privateKey: require('crypto').createPrivateKey({ key: realmJwk,
                                                       format: 'jwk' }) };
    const realmKid = B.did + '#' + B.versions[0].keys[0].id;
    const realmIn = await roundTrip(w.browser(), realmHolder, B.did,
                                    realmKid);
    note(!realmIn.ok && realmIn.code === 'STS-VC-0164',
         '6c. a realm-custody DID signs nobody in, STS-VC-0164',
         realmIn.code);
    const realmBind = await w.issue(BOB, realmHolder,
                                    { configId: SD, kid: realmKid });
    note(!realmBind.credential && realmBind.response &&
         realmBind.response.code === 'STS-VC-0165',
         '6d. nor is a credential bound to it, STS-VC-0165',
         realmBind.error);
    const realmAdd = portalAct(BOB, { action: 'add-key', rid: B.rid });
    const realmRotate = portalAct(BOB, { action: 'rotate-key', rid: B.rid });
    const B3 = listOf(BOB)[0] || {};
    note(realmAdd.status === 200 && realmRotate.status === 200 &&
         B3.currentVersion === 3 && B3.versions[1].keys.length === 2 &&
         B3.versions[2].keys.length === 1 &&
         B3.versions[2].authorizedBy[0].kind === 'person' &&
         Object.keys(recordsOf(BOB)[0].privateKeys).length === 1,
         '6e. add-key and rotate-key are one act each, authorized by the ' +
         'signed-in person; a rotated-out key is not kept',
         JSON.stringify(B3.versions.map(function (v) {
           return v.change + ':' + v.keys.length;
         })));
    const wrongDoor = await w.inRealm(function () {
      return pd.actProblem(BOB, 'authorize-add.' + B.rid);
    });
    const wrongDoor2 = portalAct(ALICE, { action: 'rotate-key',
                                          rid: A.rid });
    note(wrongDoor && wrongDoor.code === 'STS-VC-0173' &&
         wrongDoor2.status === 400 && wrongDoor2.code === 'STS-VC-0173',
         '6f. a wallet act on a realm-custody DID, and a realm act on a ' +
         'wallet one, are refused, STS-VC-0173',
         JSON.stringify(wrongDoor) + ' ' + wrongDoor2.code);

    // ==================================================================
    // 7. `download` CUSTODY
    // ==================================================================
    set('did.personCustody', 'download');
    const carol = await sessionFor(CAROL);
    const downloaded = portalAct(CAROL, { action: 'publish' });
    const fresh = downloaded.body && downloaded.body.view &&
      downloaded.body.view.fresh;
    const privateJwk = fresh ? JSON.parse(Buffer.from(fresh.file.base64,
                                                      'base64').toString())
                             : {};
    const C = listOf(CAROL)[0] || {};
    note(downloaded.status === 200 && fresh && fresh.kind === 'did-key' &&
         typeof privateJwk.d === 'string' && C.custody === 'download' &&
         C.proof === 'issued' && !recordsOf(CAROL)[0].privateKeys &&
         !portalView(CAROL).fresh,
         '7a. download custody answers the private key once, keeps only ' +
         'the public half, and the DID is `issued` until proved',
         downloaded.status + ' ' + JSON.stringify(C).slice(0, 200));
    const carolHolder = { alg: privateJwk.alg,
      jwk: { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x,
             y: privateJwk.y },
      privateKey: require('crypto').createPrivateKey({ key: privateJwk,
                                                       format: 'jwk' }) };
    const carolKid = C.did + '#' + C.versions[0].keys[0].id;
    const issuedIn = await roundTrip(w.browser(), carolHolder, C.did,
                                     carolKid);
    const issuedBind = await w.issue(CAROL, carolHolder,
                                     { configId: SD, kid: carolKid });
    const issuedChange = await w.inRealm(function () {
      return pd.actProblem(CAROL, 'authorize-add.' + C.rid);
    });
    const issuedPrefer = await w.inRealm(function () {
      return siop.setPreferred(CAROL, C.did);
    });
    note(!issuedIn.ok && issuedIn.code === 'STS-VC-0164' &&
         issuedBind.response && issuedBind.response.code === 'STS-VC-0165' &&
         issuedChange && issuedChange.code === 'STS-VC-0173' &&
         issuedPrefer.ok,
         '7b. unproved, it signs nobody in (STS-VC-0164), binds nothing ' +
         '(STS-VC-0165), takes no key change (STS-VC-0173), and may be ' +
         'preferred', [issuedIn.code, issuedBind.error,
                       JSON.stringify(issuedChange)].join(' | '));
    const proved = await roundTrip(carol.who, carolHolder, C.did, carolKid,
                                   { enrol: '1' });
    const carolSubject = subjectRow(CAROL, C.did) || {};
    const provedIn = await roundTrip(w.browser(), carolHolder, C.did,
                                     carolKid);
    note(proved.ok && carolSubject.proof === 'wallet' &&
         carolSubject.preferred === true && provedIn.ok,
         '7c. proving the downloaded key with the wallet makes it `wallet`, ' +
         'keeps the preferred mark, and it signs carol in',
         proved.code + ' ' + JSON.stringify(carolSubject).slice(0, 200));

    // ==================================================================
    // 8. DEACTIVATION, AND THE DISABLED ACCOUNT
    // ==================================================================
    await w.inRealm(function () {
      return accountState.setDisabled(ALICE, true, { by: 'pd-admin' });
    });
    const whileDisabled = await w.request('GET', docPath(A.rid));
    const resolvedDisabled = await w.inRealm(function () {
      return resolver.resolve(A.did, {}, w.fakeReq(''));
    });
    await w.inRealm(function () {
      return accountState.setDisabled(ALICE, false, { by: 'pd-admin' });
    });
    const reEnabled = await w.request('GET', docPath(A.rid));
    note(whileDisabled.status === 410 && whileDisabled.json &&
         whileDisabled.json.id === A.did &&
         whileDisabled.json.deactivated === true &&
         whileDisabled.code === 'STS-VC-0162' &&
         resolvedDisabled.didDocumentMetadata.deactivated === true &&
         resolvedDisabled.didDocument === null &&
         reEnabled.status === 200,
         '8a. while the account is disabled the address answers 410 ' +
         '{ id, deactivated: true } and the resolver says deactivated; ' +
         're-enabling restores it', whileDisabled.status + ' ' +
         reEnabled.status);
    const removed = portalAct(BOB, { action: 'deactivate', rid: B.rid });
    const goneDoc = await w.request('GET', docPath(B.rid));
    const goneVersion = await w.request('GET',
                                        docPath(B.rid, 'versionId=1'));
    note(removed.status === 200 && goneDoc.status === 410 &&
         goneVersion.status === 410 &&
         subjectRow(BOB, B.did) === null &&
         !recordsOf(BOB)[0].privateKeys &&
         w.inRealm(function () {
           return siop.preferredSubjectOf(BOB);
         }) === null,
         '8b. the person deactivates it: 410 for good, its self-issued ' +
         'subject (and the preferred mark) gone, its kept key dropped',
         removed.status + ' ' + goneDoc.status);
    const again = portalAct(BOB, { action: 'deactivate', rid: B.rid });
    note(again.status === 400 && again.code === 'STS-VC-0172',
         '8c. a deactivated DID takes no further act, STS-VC-0172',
         again.code);
    const bobOther = listOf(BOB)[1] || {};
    const viaRemove = await w.inRealm(function () {
      const res = {};
      removeOp.handler({}, res, { username: BOB },
                       { body: { action: 'remove', subject: bobOther.did } });
      return res;
    });
    note(viaRemove.status === 200 &&
         listOf(BOB)[1].state === 'deactivated',
         '8d. removing a published DID from the self-issued list ' +
         'deactivates it', viaRemove.status);
    const adminDeact = await actions.usersAction({
      action: 'deactivate-published-did', user: CAROL, did: C.did },
      { actor: 'pd-admin', via: 'api' });
    const adminAgain = await actions.usersAction({
      action: 'deactivate-published-did', user: CAROL, did: C.did },
      { actor: 'pd-admin', via: 'api' });
    const adminNone = await actions.usersAction({
      action: 'deactivate-published-did', user: CAROL },
      { actor: 'pd-admin', via: 'api' });
    const adminRows = audit.list().filter(function (row) {
      return row.action === 'admin.did.deactivated';
    });
    note(adminDeact && adminDeact.ok && adminDeact.deactivated === C.did &&
         listOf(CAROL)[0].state === 'deactivated' &&
         m.errorCodes.codeOf(adminAgain) === 'STS-VC-0172' &&
         m.errorCodes.codeOf(adminNone) === 'STS-VC-0172' &&
         adminRows.some(function (row) {
           return row.actor === 'pd-admin' && row.target === CAROL &&
                  row.outcome === 'success';
         }),
         '8e. the console\'s and /admin-api\'s act deactivates it, audited ' +
         'with the administrator as the actor; a repeat and a missing DID ' +
         'are refused, STS-VC-0172', JSON.stringify([adminDeact,
                                                     adminAgain]));
    const unknownAct = await actions.usersAction({ action: 'no-such-act',
                                                   user: CAROL },
                                                 { actor: 'pd-admin' });
    note(unknownAct && !unknownAct.ok &&
         String(unknownAct.errors[0]).indexOf('deactivate-published-did') >= 0,
         '8f. the users resource\'s unknown-action sentence names it',
         String((unknownAct && unknownAct.errors || [])[0]).slice(0, 120));
    const adminView = await w.inRealm(function () {
      return require(ROOT + '/admin-core/admin_views')
        .publishedDidsJson({ user: ALICE });
    });
    note(adminView.entryFound && adminView.dids.length === 1 &&
         adminView.dids[0].did === A.did &&
         JSON.stringify(adminView).indexOf('privateKeys') < 0,
         '8g. GET /admin-api/users/published-dids lists them, without a ' +
         'private key', JSON.stringify(adminView).slice(0, 200));
    // The directory's own view of the entry (`/admin/ldap/directory`):
    // the value is withheld, so the DID and its history are not in it.
    const dumped = await w.inRealm(function () {
      return m.ldap.ldapDirectoryView({ query: { q: BOB } });
    });
    const hidden = JSON.stringify(dumped || {});
    note(hidden.indexOf(BOB) >= 0 && hidden.indexOf(B.did) < 0 &&
         hidden.indexOf(B.rid) < 0,
         '8h. the directory\'s own view of the entry withholds the ' +
         'published DID\'s value', hidden.slice(0, 160));

    // ==================================================================
    // 9. THE LIBRARY'S OWN FAILURES
    // ==================================================================
    const PersonDid = pd.PersonDid;
    const notStored = await w.inRealm(function () {
      const lib = new PersonDid(Object.assign(PersonDid.defaultDeps(), {
        credentials: Object.assign({}, credentials, {
          readPublishedDids: credentials.readPublishedDids,
          writePublishedDids: function () {
            return false;
          } }) }));
      set('did.personCustody', 'realm');
      return lib.publishGenerated(DAVE, w.fakeReq(''));
    });
    const notSealed = await w.inRealm(function () {
      const lib = new PersonDid(Object.assign(PersonDid.defaultDeps(), {
        seal: function () {
          return null;
        } }));
      return lib.publishGenerated(DAVE, w.fakeReq(''));
    });
    note(!notStored.ok && notStored.code === 'STS-VC-0174' &&
         subjectRow(DAVE, '') === null &&
         w.inRealm(function () {
           return (siop.list(DAVE) || []).length;
         }) === 0 &&
         !notSealed.ok && notSealed.code === 'STS-VC-0175',
         '9a. a record the directory does not store leaves nothing behind ' +
         '(STS-VC-0174), and a key that cannot be sealed publishes nothing ' +
         '(STS-VC-0175)', JSON.stringify([notStored, notSealed]));
    const dave = await w.inRealm(function () {
      return pd.publishGenerated(DAVE, w.fakeReq(''));
    });
    let full = null;
    if (dave.ok) {
      full = await w.inRealm(function () {
        let last = null;
        for (let i = 1; i <= PersonDid.MAX_VERSIONS; i += 1) {
          last = pd.changeRealmKey(DAVE, dave.record.rid, 'rotate');
          if (!last.ok) {
            break;
          }
        }
        return last;
      });
    }
    note(dave.ok && full && !full.ok && full.code === 'STS-VC-0176' &&
         listOf(DAVE)[0].currentVersion === PersonDid.MAX_VERSIONS,
         '9b. a DID whose history is full takes no more changes, ' +
         'STS-VC-0176', JSON.stringify(full));
    // An administrator's REMOVAL of a published DID from the self-issued
    // list deactivates it, as the portal's does.
    const daveDid = (listOf(DAVE)[0] || {}).did;
    const adminRemove = await actions.usersAction({
      action: 'remove-self-issued-subject', user: DAVE, subject: daveDid },
      { actor: 'pd-admin', via: 'api' });
    note(adminRemove && adminRemove.ok &&
         listOf(DAVE)[0].state === 'deactivated' &&
         subjectRow(DAVE, daveDid) === null,
         '9c. an administrator removing a published DID from the ' +
         'self-issued list deactivates it', JSON.stringify(adminRemove));
    // IN A SERVICE DEPLOYED AS CELLS the id carries the minting cell's
    // twelve-character tag (`common/cell_locator.ts`), so a fetch reaching
    // another cell is relayed to the one whose index holds it. A stand-in
    // tag here: this process is single-cell, where `stamp()` adds nothing.
    const TAG = 'CeLLtAg_0-9z';
    const stamped = await w.inRealm(function () {
      const lib = new PersonDid(Object.assign(PersonDid.defaultDeps(), {
        stamp: function (value) {
          return String(value) + TAG;
        } }));
      const made = lib.publishGenerated(DAVE, w.fakeReq(''));
      const rid = made.ok ? made.record.rid : '';
      // Never the record itself: a realm-custody record carries the key.
      return { ok: !!made.ok, code: made.code || '', rid: rid,
               ridOf: made.ok ? lib.ridOf(made.record.did) : '',
               served: rid ? lib.served(rid, {}).status : 0,
               hosted: made.ok ? pd.isHosted(made.record.did) : false };
    });
    note(stamped.ok && stamped.rid.length === 34 &&
         stamped.rid.slice(-12) === TAG && stamped.ridOf === stamped.rid &&
         stamped.served === 200 && stamped.hosted,
         '9d. a cell-stamped id (22 characters and the cell\'s 12) is ' +
         'published, read back from its DID, served and hosted',
         JSON.stringify(stamped));

    // ==================================================================
    // 10. A PERSON RE-HOMED TO ANOTHER CELL (`common/cell_rehome.ts`):
    // two instances stand in for the two cells. "cella" minted the DID
    // and keeps its index row, but no longer holds the person; "cellb" is
    // their new home, with the entry (this process's directory) and an
    // index of its own. The channel is a JSON round trip into cellb's
    // operation, as `cell_channel.call()` is.
    // ==================================================================
    const moved = await w.inRealm(async function () {
      const rid = stamped.rid;
      const row = pd.lookup(rid);
      const atB = new PersonDid(Object.assign(PersonDid.defaultDeps(), {
        index: new Map(), isMulti: function () {
          return true;
        }, cellId: function () {
          return 'cellb';
        } }));
      const indexedAtB = atB.indexMovedIn(DAVE);
      let home = 'cellb';
      let channelDown = false;
      const asked = [];
      const atA = new PersonDid(Object.assign(PersonDid.defaultDeps(), {
        index: new Map([[rid, { did: row.did, sub: row.sub }]]),
        nameForSubject: function () {
          return '';
        },
        isMulti: function () {
          return true;
        },
        cellId: function () {
          return 'cella';
        },
        homeOfSubject: function (realmId, sub) {
          asked.push(sub);
          return Promise.resolve(home);
        },
        callCell: function (cellId, name, body) {
          if (channelDown) {
            return Promise.reject(new Error('the link is down'));
          }
          return Promise.resolve(JSON.parse(JSON.stringify(
            atB.opDocument(JSON.parse(JSON.stringify(body))))));
        } }));
      const here = pd.served(rid, {});
      const away = await atA.servedAnywhere(rid, {});
      const v1 = await atA.servedAnywhere(rid, { versionId: '1' });
      home = '';
      const nobody = await atA.servedAnywhere(rid, {});
      home = 'cellb';
      channelDown = true;
      const down = await atA.servedAnywhere(rid, {});
      return {
        indexedAtB: indexedAtB, foundAtB: !!atB.lookup(rid),
        syncAtA: atA.lookup(rid), awayAtA: (atA.lookup(rid, { away: true }) ||
                                             {}).away === true,
        hostedAtA: atA.isHosted(row.did), asked: asked, sub: row.sub,
        same: JSON.stringify(away.body) === JSON.stringify(here.body),
        away: away.status, v1: v1.status, nobody: [nobody.status, nobody.code],
        down: [down.status, down.code] };
    });
    note(moved.indexedAtB >= 1 && moved.foundAtB,
         '10a. the new home indexes the re-homed person\'s DIDs from the ' +
         'records their entry carried', JSON.stringify(moved));
    note(moved.syncAtA === null && moved.awayAtA && !moved.hostedAtA,
         '10b. the minting cell keeps its row but answers nothing of a ' +
         'person it no longer holds — not hosted there, and away when asked',
         JSON.stringify(moved));
    note(moved.away === 200 && moved.same && moved.v1 === 200 &&
         moved.asked[0] === moved.sub,
         '10c. a fetch reaching the minting cell asks the routing index ' +
         'for the person\'s subject and answers the document their new home ' +
         'serves, a version included', JSON.stringify(moved));
    note(moved.nobody[0] === 410 && moved.nobody[1] === 'STS-VC-0162' &&
         moved.down[0] === 503 && moved.down[1] === 'STS-VC-0177',
         '10d. a person no cell holds is gone (410, STS-VC-0162), and a new ' +
         'home that cannot be reached is 503, STS-VC-0177',
         JSON.stringify(moved));
    // The key a realm-custody record holds, opened at the sending cell and
    // sealed again at the receiving one; stand-ins for the two cells' keys.
    const carrier = new PersonDid(Object.assign(PersonDid.defaultDeps(), {
      open: function (text) {
        return text.indexOf('S:') === 0 ? text.slice(2) : null;
      },
      seal: function (text) {
        return { value: 'T:' + text, sealed: true };
      } }));
    const record = { rid: 'x', privateKeys: {
      k1: { value: 'S:secret', sealed: true },
      k2: { value: 'plain', sealed: false } } };
    const out = carrier.movingOut([JSON.stringify(record), 'not a record']);
    const sent = out ? JSON.parse(out[0]).privateKeys : {};
    const back = out ? carrier.movingIn(out) : null;
    const kept = back ? JSON.parse(back[0]).privateKeys : {};
    const unopened = carrier.movingOut([JSON.stringify({ privateKeys: {
      k: { value: 'X:other-cell', sealed: true } } })]);
    const unsealed = new PersonDid(Object.assign(PersonDid.defaultDeps(), {
      seal: function () {
        return null;
      } })).movingIn(out || []);
    note(sent.k1 && sent.k1.value === 'secret' && sent.k1.moving === true &&
         sent.k2.value === 'plain' && !sent.k2.moving &&
         out[1] === 'not a record' &&
         kept.k1.value === 'T:secret' && kept.k1.sealed === true &&
         kept.k1.moving === undefined && kept.k2.value === 'plain' &&
         unopened === null && unsealed === null,
         '10e. a realm-custody key leaves its cell opened and arrives sealed ' +
         'under the new cell\'s key; one that will not open, or cannot be ' +
         'sealed again, stops the move', JSON.stringify({ sent: !!out,
           kept: kept.k1, unopened: unopened, unsealed: unsealed }));
    ['did.personCustody', 'did.personPublishing',
     'oid4vci.didHolderBinding', 'oid4vp.signIn',
     'oid4vp.signInSelfIssued', 'risk.assessSignIns'].forEach(clear);
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'person-did',
               { STS_AUTHN_MULTIPLE_ACCOUNTS: 'false' });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'person_did',
  describe: 'a did:web this realm publishes for a person (#1291): the ' +
            'random id, the three custody modes, the two-proof key change, ' +
            'versions and their resolution, holder binding naming the ' +
            'version, deactivation and the disabled account, the ' +
            'administrator\'s act, and every refusal\'s code',
  run: run
};
