// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/access_token_status.js — A REVOCATION A RESOURCE SERVER CAN SEE
// WITHOUT INTROSPECTION (#432 phase 2, lane p2b; RFC 9767 section 6.3).
//
// `oauth-oidc/access_token_status.ts` argues the design. What is held here:
//
//   1. THE LIST: the realm's one access-token Status List Token as a JWT
//      (typ statuslist+jwt, its own URI as sub, one bit, ttl and exp, signed
//      with a key /oauth2/jwks publishes — verified HERE with node's crypto)
//      and as a CWT by Accept; Cache-Control matching the ttl; the
//      aggregation; 501 for a historical request; the authorization server
//      metadata's status_list_aggregation_endpoint;
//   2. OAUTH: an RFC 9068 access token from the token endpoint carries
//      status.status_list naming that list; its bit is 0, and 1 after
//      /oauth2/revoke;
//   3. ALLOCATION: random indexes, one per token, recorded with the jti and
//      kind; synchronous in a process with no shared claims table; a full
//      list refused STS-OAUTH-0817 and a failing claim store STS-OAUTH-0816;
//      an expired row ejected by the cache job;
//   4. GNAP: jwt-signed and jwt-encrypted (opened here with this file's RSA
//      key) both carry the claim; the bit is set by the grant engine's
//      revokeTokens(), and STAYS set when the revocation register forgets
//      the jti, because the token's own record still says revoked;
//   5. BISCUIT: a minted biscuit's revocation identifiers are on its record,
//      absent from /gnap/biscuit/revocations until it is revoked and present
//      after; the RS-facing discovery and /gnap/keys name both lists;
//   6. A RESOURCE SERVER'S STREAM: the GNAP subject scope covers a
//      gnap-token or gnap-grant session audienced to the resource server
//      that owns the stream and refuses every other, and a revocation with
//      no resource owner is emitted with the session alone.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason: it loads
// the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'access_token_status',
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
    const nodeCrypto = require('crypto');
    const ats = require(ROOT + '/oauth-oidc/access_token_status');
    const gnapTokens = require(ROOT + '/gnap/gnap_tokens');
    const gnapStore = require(ROOT + '/gnap/gnap_store');
    const gnapGrants = require(ROOT + '/gnap/gnap_grants');
    const gnapSignals = require(ROOT + '/gnap/gnap_signals');
    const PATH = '/status-lists/access-tokens';

    const jwks = (await w.request('GET', '/oauth2/jwks')).json;
    // The list's JWS, verified with node's own crypto against the published
    // key — not with anything of the service's.
    function verified(compact) {
      const parts = String(compact).split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url')
        .toString('utf8'));
      const jwk = (jwks.keys || []).filter(function (k) {
        return k.kid === header.kid;
      })[0];
      const ok = !!jwk && header.alg === 'RS256' && nodeCrypto.verify(
        'sha256', Buffer.from(parts[0] + '.' + parts[1]),
        nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' }),
        Buffer.from(parts[2], 'base64url'));
      return { ok: ok, header: header,
               claims: JSON.parse(Buffer.from(parts[1], 'base64url')
                 .toString('utf8')) };
    }
    async function bitAt(idx) {
      const r = await w.request('GET', PATH);
      const v = verified(r.text);
      if (!v.ok) {
        return -1;
      }
      const parts = m.codec.tslFromJson(v.claims.status_list);
      return m.codec.unpackTslValue(parts.bytes, parts.bits, idx);
    }

    // ==================================================================
    // 1. THE LIST
    // ==================================================================
    const r1 = await w.request('GET', PATH);
    const v1 = r1.status === 200 ? verified(r1.text) : { ok: false };
    note(r1.status === 200 && v1.ok &&
         /^application\/statuslist\+jwt/
           .test(String(r1.headers['content-type'])) &&
         v1.header.typ === 'statuslist+jwt' &&
         v1.claims.sub === w.base + PATH &&
         v1.claims.status_list.bits === 1 &&
         typeof v1.claims.status_list.lst === 'string' &&
         v1.claims.ttl === 60 && v1.claims.exp > v1.claims.iat &&
         v1.claims.status_list.aggregation_uri === w.base + '/status-lists',
         '1a. the access-token list is a statuslist+jwt signed with a key ' +
         '/oauth2/jwks publishes (verified here), its own URI as sub, one ' +
         'bit per token, ttl 60 and an exp',
         r1.status + ' ' + JSON.stringify(v1.header || {}) + ' ' +
         JSON.stringify(v1.claims && { sub: v1.claims.sub,
           ttl: v1.claims.ttl, bits: (v1.claims.status_list || {}).bits }));
    note(String(r1.headers['cache-control']) === 'max-age=60' &&
         r1.headers.vary === 'Accept',
         '1b. with Cache-Control max-age equal to its ttl, and Vary: Accept',
         r1.headers['cache-control']);
    const cwt = await w.request('GET', PATH, {
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
         cwtRead && cwtRead.tag === 18 && cwtRead.value.length === 4,
         '1c. the same list as a COSE_Sign1 when Accept asks for the CWT',
         cwt.status);
    const agg = await w.request('GET', '/status-lists');
    note(agg.status === 200 && agg.json &&
         JSON.stringify(agg.json.status_lists) ===
           JSON.stringify([w.base + PATH]),
         '1d. the aggregation names the one list', agg.text.slice(0, 200));
    const hist = await w.request('GET', PATH + '?time=1700000000');
    note(hist.status === 501 && hist.code === 'STS-OAUTH-0819',
         '1e. a historical list is 501, STS-OAUTH-0819', hist.status + ' ' +
         hist.code);
    const meta = await w.request('GET',
      '/.well-known/oauth-authorization-server');
    note(meta.json && meta.json.status_list_aggregation_endpoint ===
           w.base + '/status-lists',
         '1f. the authorization server metadata names it as ' +
         'status_list_aggregation_endpoint (section 9.1)',
         meta.json && meta.json.status_list_aggregation_endpoint);

    // ==================================================================
    // 2. OAUTH: AN RFC 9068 TOKEN CARRIES IT, AND REVOKING SETS THE BIT
    // ==================================================================
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser('ats-alice', { invent: false });
    });
    const got = await w.accessTokenFor('ats-alice');
    const claims = got.token ? w.decode(got.token) : {};
    const ref = (claims.status || {}).status_list || {};
    note(got.token && Number.isInteger(ref.idx) && ref.idx >= 0 &&
         ref.idx < ats.LIST_SIZE && ref.uri === w.base + PATH,
         '2a. an access token from the token endpoint carries ' +
         'status.status_list naming the realm\'s list (section 6.1)',
         JSON.stringify(claims.status || got.error));
    note(await bitAt(ref.idx) === 0, '2b. and its bit is VALID (0)');
    const revoked = await w.request('POST', '/oauth2/revoke', {
      form: Object.assign({ token: got.token }, w.client) });
    note(revoked.status === 200, '2c. /oauth2/revoke accepts it',
         revoked.status + ' ' + revoked.text.slice(0, 200));
    note(await bitAt(ref.idx) === 1,
         '2d. and the published bit is INVALID (1) after the revocation — ' +
         'computed from the register, never written by the revoking door');

    // ==================================================================
    // 3. ALLOCATION
    // ==================================================================
    const pair = await w.inRealm(async function () {
      const one = await ats.allocate({ jti: 'ats-a1', kind: 'oauth',
        expiresAt: Date.now() + 60000, base: w.base });
      const two = await ats.allocate({ jti: 'ats-a2', kind: 'gnap',
        expiresAt: Date.now() + 60000, base: w.base });
      const sync = ats.allocateInProcess({ jti: 'ats-a3', kind: 'oauth',
        expiresAt: Date.now() + 60000, base: w.base });
      return { one: one, two: two, sync: sync,
               rowOne: ats.statusOfJti('ats-a1'),
               rowSync: ats.statusOfJti('ats-a3') };
    });
    note(pair.one.idx !== pair.two.idx && pair.rowOne &&
         pair.rowOne.idx === pair.one.idx && pair.rowOne.status === 0,
         '3a. two tokens get two indexes, each recorded with its jti',
         JSON.stringify(pair));
    note(pair.sync && pair.rowSync && pair.rowSync.idx === pair.sync.idx,
         '3b. with no shared claims table an index is claimed synchronously',
         JSON.stringify(pair.sync));
    const Cls = ats.AccessTokenStatus;
    const fullRows = { get: function () {
      return { jti: 'x', kind: 'oauth', expiresAt: Date.now() + 60000 };
    }, set: function () {}, forEach: function () {} };
    let fullCode = '';
    await w.inRealm(async function () {
      try {
        await new Cls(Object.assign(Cls.defaultDeps(), { entries: fullRows }))
          .allocate({ jti: 'f', kind: 'oauth', expiresAt: 0, base: w.base });
      } catch (e) {
        fullCode = m.errorCodes.codeOf(e);
      }
    });
    note(fullCode === 'STS-OAUTH-0817',
         '3c. a list with no free index refuses, STS-OAUTH-0817 — it never ' +
         'shares a live index (section 13.3)', fullCode);
    let storeCode = '';
    await w.inRealm(async function () {
      try {
        await new Cls(Object.assign(Cls.defaultDeps(), {
          clusterClaims: { claim: function () {
            return Promise.resolve({ ok: false, reason: 'store',
                                     why: 'the test' });
          } } })).allocate({ jti: 'f', kind: 'oauth', expiresAt: 0,
                             base: w.base });
      } catch (e) {
        storeCode = m.errorCodes.codeOf(e);
      }
    });
    note(storeCode === 'STS-OAUTH-0816',
         '3d. a claim store that cannot be asked refuses, STS-OAUTH-0816',
         storeCode);
    m.cacheRegistry.ejectExpired(Date.now() + 120000);
    const afterEject = await w.inRealm(function () {
      return ats.statusOfJti('ats-a1');
    });
    note(afterEject === null,
         '3e. the caches.eject-expired job frees an expired token\'s index',
         JSON.stringify(afterEject));

    // ==================================================================
    // 4. GNAP: BOTH JWT FORMATS, AND THE GRANT ENGINE'S REVOCATION
    // ==================================================================
    const now = Math.floor(Date.now() / 1000);
    function model(jti) {
      return { jti: jti, iss: w.base + '/gnap', sub: null,
               aud: ['ats-rs'], instanceId: 'ats-client',
               access: ['read'], flags: ['bearer'], cnf: null, iat: now,
               nbf: now, exp: now + 600, label: null };
    }
    const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaJwk = Object.assign(rsa.publicKey.export({ format: 'jwk' }),
                                 { alg: 'RSA-OAEP-256' });
    const minted = await w.inRealm(async function () {
      const signed = await gnapTokens.mint('jwt-signed', model('ats-gs'),
                                           { base: w.base });
      const sealed = await gnapTokens.mint('jwt-encrypted', model('ats-ge'),
        { base: w.base, rs: { identity: 'ats-rs', jweKey: rsaJwk } });
      return { signed: signed, sealed: sealed };
    });
    const signedClaims = w.decode(minted.signed.value);
    const opened = m.stsCrypto.decryptJweCompact(minted.sealed.value, {
      privateKey: rsa.privateKey, allowedAlg: ['RSA-OAEP-256'],
      allowedEnc: ['A256GCM'] });
    const sealedClaims = w.decode(opened.plaintext.toString('utf8'));
    const sRef = (signedClaims.status || {}).status_list || {};
    const eRef = (sealedClaims.status || {}).status_list || {};
    note(sRef.uri === w.base + PATH && sRef.idx === minted.signed.statusIdx &&
         eRef.uri === w.base + PATH && eRef.idx === minted.sealed.statusIdx &&
         sRef.idx !== eRef.idx,
         '4a. a jwt-signed and a jwt-encrypted GNAP token (opened here with ' +
         'this file\'s key) each carry status.status_list in the SAME list ' +
         'as OAuth\'s tokens (rcbj\'s decision 4)',
         JSON.stringify({ s: signedClaims.status, e: sealedClaims.status }));
    await w.inRealm(function () {
      gnapStore.putToken(Object.assign(model('ats-gs'), {
        format: 'jwt-signed', grantId: 'ats-grant', revoked: false,
        rsIdentifiers: ['ats-rs'], statusIdx: sRef.idx }),
      minted.signed.value);
    });
    note(await bitAt(sRef.idx) === 0, '4b. the GNAP token\'s bit is VALID');
    await w.inRealm(function () {
      gnapGrants.revokeTokens({ id: 'ats-grant', tokens: ['ats-gs'] },
                              'the test');
    });
    note(await bitAt(sRef.idx) === 1,
         '4c. revoking it through the grant engine sets its bit');
    await w.inRealm(function () {
      m.stats.restore('ats-gs');
    });
    note(!m.stats.isRevoked('ats-gs') && await bitAt(sRef.idx) === 1,
         '4d. and it stays set when the revocation register no longer holds ' +
         'the jti: the token\'s own record still says revoked, as GNAP\'s ' +
         'introspection reads it');

    // ==================================================================
    // 5. BISCUIT
    // ==================================================================
    const bis = await w.inRealm(async function () {
      return gnapTokens.mint('biscuit', model('ats-bis'), { base: w.base });
    });
    note(Array.isArray(bis.revocationIds) && bis.revocationIds.length >= 1 &&
         bis.revocationIds.every(function (one) {
           return /^[0-9a-f]+$/.test(one);
         }),
         '5a. a minted biscuit gives its revocation identifiers',
         JSON.stringify(bis.revocationIds));
    await w.inRealm(function () {
      gnapStore.putToken(Object.assign(model('ats-bis'), {
        format: 'biscuit', grantId: 'ats-bgrant', revoked: false,
        rsIdentifiers: ['ats-rs'], revocationIds: bis.revocationIds }),
      bis.value);
    });
    let list = await w.request('GET', '/gnap/biscuit/revocations');
    note(list.status === 200 && list.json &&
         list.json.revocation_ids.indexOf(bis.revocationIds[0]) < 0,
         '5b. a live biscuit is not on /gnap/biscuit/revocations',
         list.text.slice(0, 200));
    await w.inRealm(function () {
      gnapGrants.revokeTokens({ id: 'ats-bgrant', tokens: ['ats-bis'] },
                              'the test');
    });
    list = await w.request('GET', '/gnap/biscuit/revocations');
    note(list.status === 200 && list.json.revocation_ids.indexOf(
      bis.revocationIds[0]) >= 0 && list.json.ttl === 60 &&
         String(list.headers['cache-control']) === 'max-age=60',
         '5c. and once revoked its authority block\'s identifier is, with a ' +
         'ttl and a matching max-age', list.text.slice(0, 300));
    const disc = await w.request('GET', '/.well-known/gnap-as-rs');
    const keys = await w.request('GET', '/gnap/keys');
    note(disc.json && disc.json.status_list_aggregation_endpoint ===
           w.base + '/status-lists' &&
         disc.json.biscuit_revocation_endpoint ===
           w.base + '/gnap/biscuit/revocations' &&
         keys.json && keys.json.biscuit.revocation_endpoint ===
           w.base + '/gnap/biscuit/revocations' &&
         keys.json.jwt.status_list_aggregation_endpoint ===
           w.base + '/status-lists',
         '5d. the RS-facing discovery and /gnap/keys name both lists',
         JSON.stringify({ d: disc.json, k: keys.json && keys.json.jwt }));

    // ==================================================================
    // 6. A RESOURCE SERVER'S STREAM
    // ==================================================================
    const scoped = await w.inRealm(function () {
      m.applications.createApplication({ identifier: 'ats-rs',
        kind: 'gnap-resource-server', protocols: ['gnap'],
        fields: { gnapResourceServerUri: 'https://rs.ats.test/api' } });
      m.applications.createApplication({ identifier: 'ats-other-rs',
        kind: 'gnap-resource-server', protocols: ['gnap'] });
      gnapStore.putToken(Object.assign(model('ats-uri'), {
        aud: ['https://rs.ats.test/api'], format: 'jwt-signed',
        grantId: 'ats-g2', revoked: false, rsIdentifiers: [] }), 'v-uri');
      gnapStore.saveGrant({ id: 'ats-g2', state: 'approved',
                            client: { identifier: 'ats-client' },
                            tokens: ['ats-uri'] }, 'the test');
      const record = { createdBy: 'ats-rs' };
      const other = { createdBy: 'ats-other-rs' };
      const session = function (id) {
        return { format: 'complex',
                 session: { format: 'opaque', id: id } };
      };
      const person = { format: 'complex',
        user: { format: 'iss_sub', iss: w.base, sub: 'urn:uuid:x' },
        session: { format: 'opaque', id: 'some-sign-on' } };
      return {
        token: gnapSignals.scope(record, session('gnap-token:ats-gs')),
        byUri: gnapSignals.scope(record, session('gnap-token:ats-uri')),
        grant: gnapSignals.scope(record, session('gnap-grant:ats-g2')),
        otherToken: gnapSignals.scope(other, session('gnap-token:ats-gs')),
        otherGrant: gnapSignals.scope(other, session('gnap-grant:ats-g2')),
        person: gnapSignals.scope(record, person),
        unknown: gnapSignals.scope(record, session('gnap-token:nope'))
      };
    });
    note(scoped.token === true && scoped.byUri === true &&
         scoped.grant === true,
         '6a. a resource server\'s stream covers session-revoked for a ' +
         'token audienced to it (by rsIdentifiers, or by its ' +
         'gnapResourceServerUri in aud) and for a grant one of whose tokens ' +
         'was', JSON.stringify(scoped));
    note(scoped.otherToken === false && scoped.otherGrant === false &&
         scoped.person === false && scoped.unknown === false,
         '6b. and refuses the same events on another resource server\'s ' +
         'stream, a person\'s sign-on session, and a token it never held',
         JSON.stringify(scoped));
    const optedOut = await w.inRealm(function () {
      m.applications.updateApplication('ats-rs',
        { attribute: 'gnapScopedSignals', mode: 'set', value: 'FALSE',
          actor: 'the test' });
      return gnapSignals.scope({ createdBy: 'ats-rs' },
        { format: 'complex', session: { format: 'opaque',
                                        id: 'gnap-token:ats-other' } });
    });
    note(optedOut === undefined,
         '6c. gnapScopedSignals FALSE on the entry removes the scope',
         String(optedOut));
    let captured = null;
    const Sig = gnapSignals.GnapSignals;
    await w.inRealm(function () {
      const spy = new Sig(Object.assign(Sig.defaultDeps(), {
        loadSsf: function () {
          return { emitProtocolEvent: function (o) {
            captured = o;
            return { sent: 1 };
          } };
        } }));
      return spy.tokenRevoked(w.fakeReq(''), { jti: 'ats-nobody' }, null);
    });
    note(captured && captured.type === 'session-revoked' &&
         captured.subject.format === 'complex' && !captured.subject.user &&
         captured.subject.session.id === 'gnap-token:ats-nobody',
         '6d. a revoked token nobody approved is still emitted, its subject ' +
         'the session alone, so a resource server hears of it',
         JSON.stringify(captured && captured.subject));
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'access-token-status');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'access-token status list',
  describe: 'the realm\'s one access-token Token Status List for OAuth RFC ' +
            '9068 and GNAP JWT tokens, the revoked biscuits\' identifiers, ' +
            'and a GNAP resource server\'s Shared Signals stream',
  run: run
};
