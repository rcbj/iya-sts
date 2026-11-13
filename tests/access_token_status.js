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
//   7. THE PACKED LIST (#885): the compressed bytes are reused until an
//      invalid bit changes or the earliest one expires. Half the ttl
//      re-signs from those bytes. A bit restored from another process is
//      published on the next list.
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
    const PACKED = 'oauth2.access-token-status-packed';
    const SIGNED = 'oauth2.access-token-status-lists';

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
    const packedBefore = m.cacheRegistry.detail(PACKED).summary;
    const coldAt = Date.now();
    const r1 = await w.request('GET', PATH);
    const coldMs = Date.now() - coldAt;
    const packedCold = m.cacheRegistry.detail(PACKED).summary;
    const hotAt = Date.now();
    const r1Again = await w.request('GET', PATH);
    const hotMs = Date.now() - hotAt;
    const packedHot = m.cacheRegistry.detail(PACKED).summary;
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
    note(packedCold.misses === packedBefore.misses + 1 &&
         packedHot.misses === packedCold.misses &&
         packedHot.hits === packedCold.hits + 1 &&
         r1Again.status === 200 && r1Again.text === r1.text,
         '1a-ii. the next fetch serves the same token without packing the ' +
         'list again (#885)',
         JSON.stringify({ coldMs: coldMs, hotMs: hotMs,
           misses: packedHot.misses, hits: packedHot.hits }));
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
    // 2^20 ran out on 8081 at about 620,000 people (#820, 2026-10-22).
    note(ats.LIST_SIZE >= 16777216,
         '2b-ii. the list holds 2^24 indexes, room for a million people ' +
         'with every leased block wasted', String(ats.LIST_SIZE));
    const revoked = await w.request('POST', '/oauth2/revoke', {
      form: Object.assign({ token: got.token }, w.client) });
    note(revoked.status === 200, '2c. /oauth2/revoke accepts it',
         revoked.status + ' ' + revoked.text.slice(0, 200));
    const packedRevokeBefore = m.cacheRegistry.detail(PACKED).summary;
    const revokedBit = await bitAt(ref.idx);
    const packedRevoked = m.cacheRegistry.detail(PACKED).summary;
    note(revokedBit === 1,
         '2d. and the published bit is INVALID (1) after the revocation — ' +
         'computed from the register, never written by the revoking door');
    note(packedRevoked.misses === packedRevokeBefore.misses + 1,
         '2e. publishing that bit rebuilds the compressed list (#885)',
         JSON.stringify({ misses: packedRevoked.misses }));
    const revokedAgain = await bitAt(ref.idx);
    const packedRevokeHit = m.cacheRegistry.detail(PACKED).summary;
    note(revokedAgain === 1 &&
         packedRevokeHit.misses === packedRevoked.misses &&
         packedRevokeHit.hits === packedRevoked.hits + 1,
         '2f. the fetch after it reuses that list and the bit stays INVALID',
         JSON.stringify({ hits: packedRevokeHit.hits }));

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
    // 3f (2026-10-21): the store declares its rows' expiry, the entry's own
    // `expiresAt`, so the expiry purge takes an entry and a restore skips
    // it; it had none, and 347,000 entries were read back at every start
    // on 8081.
    const handle = m.realms.handleFor('access_token_status.entries');
    const when = Date.now() + 60000;
    note(handle && typeof handle.expiresAt === 'function' &&
         handle.expiresAt({ jti: 'x', kind: 'oauth', expiresAt: when }) ===
           when && handle.retain === 'age',
         '3f. the entries carry their token\'s expiry, and the old rows ' +
         'without one go by age', JSON.stringify(handle && {
           retain: handle.retain,
           expiry: typeof handle.expiresAt === 'function' ?
             handle.expiresAt({ expiresAt: when }) : null }));
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

    // 3g–3j (2026-10-21, #820): indexes come from a LEASED BLOCK, one claim
    // for many tokens, never two live tokens on one index.
    const clock = { t: Date.now() };
    const blockClaims = [];
    const rows = new Map();
    const blocked = new Cls(Object.assign(Cls.defaultDeps(), {
      now: function () {
        return clock.t;
      },
      entries: { get: function (k) {
        return rows.get(k);
      }, set: function (k, v) {
        rows.set(k, v);
      }, forEach: function (fn) {
        rows.forEach(fn);
      } },
      clusterClaims: { claim: function (opts) {
        blockClaims.push(opts);
        return Promise.resolve({ ok: true, handle: 'h' + blockClaims.length });
      } } }));
    const life = function (ms) {
      return clock.t + ms;
    };
    const blockOf = function (ref) {
      return Math.floor(ref.idx / 1024);
    };
    const refs = await w.inRealm(function () {
      return Promise.all(Array.from({ length: 40 }, function (_, i) {
        return blocked.allocate({ jti: 'b-' + i, kind: 'oauth',
                                  expiresAt: life(60000), base: w.base });
      }));
    });
    note(blockClaims.length === 1 &&
         blockClaims[0].scope === 'oauth2.access-token-status-block' &&
         new Set(refs.map(function (one) {
           return one.idx;
         })).size === 40 &&
         refs.every(function (one) {
           return blockOf(one) === blockOf(refs[0]);
         }),
         '3g. forty tokens, concurrent ones among them, take ONE block ' +
         'claim and forty distinct indexes in that block',
         JSON.stringify({ blockClaims: blockClaims.length, block: blockOf(refs[0]) }));
    const base0 = blockOf(refs[0]) * 1024;
    let busy = 0;
    for (let i = 0; i < 1024; i++) {
      if (!rows.has(String(base0 + i))) {
        rows.set(String(base0 + i), { jti: 'live-' + i, kind: 'oauth',
                                       expiresAt: life(600000) });
        busy = base0 + i;
        break;
      }
    }
    const next = await w.inRealm(function () {
      return blocked.allocate({ jti: 'b-next', kind: 'oauth',
                                expiresAt: life(60000), base: w.base });
    });
    note(next.idx !== busy && blockOf(next) === blockOf(refs[0]),
         '3h. an index whose entry is still live is skipped',
         JSON.stringify({ busy: busy, got: next.idx }));
    const before = blockClaims.length;
    const longOne = await w.inRealm(function () {
      return blocked.allocate({ jti: 'b-long', kind: 'oauth',
                                expiresAt: life(400 * 24 * 3600000),
                                base: w.base });
    });
    note(blockClaims.length === before + 1 && longOne &&
         blockClaims[blockClaims.length - 1].ttlMs >= 400 * 24 * 3600000,
         '3i. a token that would outlive the lease gets a block leased for it',
         JSON.stringify({ blockClaims: blockClaims.length - before }));
    const beforeWindow = blockClaims.length;
    clock.t += 6 * 60 * 1000;
    await w.inRealm(function () {
      return blocked.allocate({ jti: 'b-later', kind: 'oauth',
                                expiresAt: life(60000), base: w.base });
    });
    note(blockClaims.length === beforeWindow + 1,
         '3j. past its use window a block is handed out from no more, and ' +
         'another is leased', JSON.stringify(blockClaims.length - beforeWindow));

    // 3k–3n (#884): a restart releases the blocks its origin still holds,
    // and a holder that has gone loses theirs. The decision is the
    // product's selectAbandoned(); this does not reimplement it.
    const clusterClaimsMod = require(ROOT + '/cluster/cluster_claims');
    const BLOCK = 'oauth2.access-token-status-block';
    const baseCtx = {
      ownOrigin: 'n:self:front', selfNode: 'node-self',
      goneNodes: ['node-old'],
      liveOrigins: ['n:self:front', 'n:live:front']
    };
    function abandoned(origin, over) {
      return clusterClaimsMod.selectAbandoned([{
        origin: origin, key: 'k', reservation: 'r', scope: BLOCK, realm: ''
      }], Object.assign({}, baseCtx, over)).length === 1;
    }
    const decisions = [
      ['n:self:front', { bareOwn: true }, true, 'own bare origin at start'],
      ['n:self:front@node-self', { bareOwn: true }, true,
       'own origin on this same node at start (a worker restart)'],
      ['n:self:front', { bareOwn: false }, false,
       'own bare origin while its origin claim is live'],
      ['n:self:front@node-self', { bareOwn: false }, false,
       'own origin on this node while the claim is live'],
      ['n:self:front@node-self',
       { bareOwn: false, liveOrigins: ['n:live:front'] }, true,
       'own origin claim has lapsed'],
      ['n:dead:0@node-self', { bareOwn: false }, true,
       'a sibling on this node whose origin claim has lapsed'],
      ['n:other:0@node-self',
       { bareOwn: false, liveOrigins: ['n:self:front', 'n:other:0'] }, false,
       'a live sibling on this node'],
      ['n:live:front@node-live', { bareOwn: false }, false, 'a live node'],
      ['n:live:front@node-old', { bareOwn: false }, true,
       'a node that has left, origin claim still live'],
      ['n:dead:front', { bareOwn: false }, true,
       'a bare stable origin with no origin claim'],
      ['n:live:front', { bareOwn: false }, false,
       'a bare stable origin that still holds its claim'],
      ['pid-abc', { bareOwn: false }, false,
       'a bare pid origin of another process'],
      ['pid-abc@node-old', { bareOwn: false }, true,
       'a pid origin on a node that has gone'],
      ['pid-abc@node-live', { bareOwn: false }, false,
       'a pid origin on a node that has not gone'],
      ['pid-abc@node-unknown', { bareOwn: false }, false,
       'an unknown node id proves nothing'],
      ['n:live:front@node-unknown', { bareOwn: false }, false,
       'an unknown node whose origin claim is live'],
      ['', { bareOwn: true }, false, 'an empty holder is not this origin'],
      ['n:self:front@node-self',
       { bareOwn: false, goneNodes: ['node-self'] }, false,
       'this node listed gone does not free a live own claim']
    ];
    const missed = decisions.filter(function (row) {
      return abandoned(row[0], row[1]) !== row[2];
    }).map(function (row) {
      return row[3];
    });
    note(missed.length === 0,
         '3k. a block lease is released when its holder has gone, and kept ' +
         'while the holder is live (#884)', missed.join('; '));

    const held = {
      '7': 'n:dead:front@node-old',
      '8': 'n:live:front@node-live'
    };
    const table = [
      { origin: held['7'], value: '7', key: 'k7', reservation: 'r7',
        scope: BLOCK, realm: '' },
      { origin: held['8'], value: '8', key: 'k8', reservation: 'r8',
        scope: BLOCK, realm: '' }
    ];
    clusterClaimsMod.selectAbandoned(table, Object.assign({}, baseCtx, {
      bareOwn: false
    })).forEach(function (row) {
      delete held[row.value];
    });
    function take(value) {
      if (held[value]) {
        return { ok: false, reason: 'used' };
      }
      held[value] = 'n:self:front@node-self';
      return { ok: true };
    }
    const tookDead = take('7');
    const tookLive = take('8');
    note(tookDead.ok === true && tookLive.ok === false,
         '3l. after the release the gone holder\'s block can be claimed, ' +
         'and the live holder\'s block still refuses',
         JSON.stringify({ dead: tookDead, live: tookLive }));

    const stamped = [];
    const stamper = new Cls(Object.assign(Cls.defaultDeps(), {
      clusterClaims: { claim: function (opts) {
        stamped.push(opts);
        return Promise.resolve({ ok: true, handle: 's' + stamped.length });
      } },
      claimOrigin: function () {
        return 'n:a:front@node-1';
      }
    }));
    await w.inRealm(function () {
      return stamper.allocate({ jti: 'stamp-1', kind: 'oauth',
                                expiresAt: Date.now() + 60000, base: w.base });
    });
    note(stamped.length === 1 && stamped[0].scope === BLOCK &&
         stamped[0].origin === 'n:a:front@node-1',
         '3m. a block claim is stamped origin@node',
         JSON.stringify(stamped[0] && stamped[0].origin));
    const unstamped = [];
    const plain = new Cls(Object.assign(Cls.defaultDeps(), {
      clusterClaims: { claim: function (opts) {
        unstamped.push(opts);
        return Promise.resolve({ ok: true, handle: 'u' });
      } },
      claimOrigin: function () {
        return '';
      }
    }));
    await w.inRealm(function () {
      return plain.allocate({ jti: 'stamp-2', kind: 'oauth',
                              expiresAt: Date.now() + 60000, base: w.base });
    });
    note(unstamped.length === 1 && !Object.prototype.hasOwnProperty.call(
      unstamped[0], 'origin'),
         '3n. with no origin and no node the claim omits origin',
         JSON.stringify(Object.keys(unstamped[0] || {})));

    let seen = null;
    const wired = new Cls(Object.assign(Cls.defaultDeps(), {
      clusterClaims: {
        claim: function () {
          return Promise.resolve({ ok: true, handle: 'w' });
        },
        releaseAbandoned: function (scope, opts) {
          seen = { scope: scope, bareOwn: !!(opts && opts.bareOwn) };
          return Promise.resolve(4);
        }
      }
    }));
    const released = await wired.reclaimAbandoned({ bareOwn: true });
    note(released === 4 && seen && seen.scope === BLOCK &&
         seen.bareOwn === true,
         '3o. a start asks the claims table to release this origin\'s ' +
         'blocks', JSON.stringify(seen));
    const none = await clusterClaimsMod.releaseAbandoned(BLOCK, {
      bareOwn: true
    });
    note(none === 0,
         '3p. with no shared claims table a restart releases nothing: the ' +
         'leases died with the process', String(none));

    ats.ensureReapJob();
    ats.ensureReapJob();
    const reap = require(ROOT + '/cluster/scheduler').job(
      'oauth2.access-token-block-reap');
    const off = reap && typeof reap.off === 'function' ? reap.off() : '';
    const ran = reap ? await reap.run() : null;
    note(!!reap && reap.kind === 'cluster' && reap.scope === 'service' &&
         /no shared claims table/.test(off) && ran && ran.released === 0,
         '3q. the reap job is registered, off without a shared claims ' +
         'table, and releases nothing there',
         JSON.stringify({ kind: reap && reap.kind, off: off, ran: ran }));

    // 3r–3t (#884): an index is not returned until its row has committed
    // under the block claim's fence, a lost fence does not return that
    // index, and a block whose rows are already in the store is skipped.
    // settlePublished stands in for the minted commit, so this does not
    // need a database.
    const durableRows = new Map();
    let durableOpened = false;
    let finishDurable;
    const durableGate = new Promise(function (resolve) {
      finishDurable = resolve;
    });
    const durable = new Cls(Object.assign(Cls.defaultDeps(), {
      entries: {
        get: function (k) {
          return durableRows.get(k);
        },
        set: function (k, v) {
          durableRows.set(k, v);
        },
        delete: function (k) {
          durableRows.delete(k);
        }
      },
      clusterClaims: { claim: function () {
        return Promise.resolve({
          ok: true, fenced: true, lockName: 'lock-held',
          handle: { key: 'kh' }
        });
      } },
      liveInBlock: function () {
        return Promise.resolve([]);
      },
      settlePublished: function () {
        durableOpened = true;
        return durableGate.then(function () {
          return { committed: true };
        });
      }
    }));
    const durablePending = w.inRealm(function () {
      return durable.allocate({
        jti: 'dur-1', kind: 'oauth', expiresAt: Date.now() + 60000,
        base: w.base
      });
    });
    for (let wait = 0; wait < 20 && !durableOpened; wait++) {
      await new Promise(function (resolve) {
        setImmediate(resolve);
      });
    }
    note(durableOpened === true && durableRows.size === 1,
         '3r. allocate holds the index until the status row has committed',
         String(durableOpened) + ' rows=' + durableRows.size);
    finishDurable();
    const durableRef = await durablePending;
    note(durableRef && durableRows.has(String(durableRef.idx)),
         '3r-ii. once the row has committed, that index is the one returned',
         JSON.stringify(durableRef && durableRef.idx));

    const lostRows = new Map();
    const lostSeen = [];
    const loser = new Cls(Object.assign(Cls.defaultDeps(), {
      entries: {
        get: function (k) {
          return lostRows.get(k);
        },
        set: function (k, v) {
          lostRows.set(k, v);
        },
        delete: function (k) {
          lostRows.delete(k);
        }
      },
      clusterClaims: { claim: function () {
        return Promise.resolve({
          ok: true, fenced: true, lockName: 'lock-lost',
          handle: { key: 'kl' }
        });
      } },
      liveInBlock: function () {
        return Promise.resolve([]);
      },
      settlePublished: function (row) {
        lostSeen.push(row.idx);
        if (lostSeen.length === 1) {
          return Promise.resolve({ lost: true });
        }
        return Promise.resolve({ committed: true });
      }
    }));
    const lostRef = await w.inRealm(function () {
      return loser.allocate({
        jti: 'lost-1', kind: 'oauth', expiresAt: Date.now() + 60000,
        base: w.base
      });
    });
    note(lostSeen.length === 2 && lostSeen[0] !== lostSeen[1] &&
         !lostRows.has(String(lostSeen[0])) &&
         lostRows.has(String(lostRef.idx)) &&
         lostRef.idx === lostSeen[1],
         '3s. a fence lost before the row commits does not return that ' +
         'index, and the next block\'s committed index is the one returned',
         JSON.stringify({ seen: lostSeen, got: lostRef && lostRef.idx }));

    let liveLeases = 0;
    let liveWrote = false;
    let liveCode = '';
    const crowded = new Cls(Object.assign(Cls.defaultDeps(), {
      entries: {
        get: function () {
          return null;
        },
        set: function () {
          liveWrote = true;
        }
      },
      clusterClaims: { claim: function () {
        liveLeases += 1;
        return Promise.resolve({
          ok: true, fenced: true, lockName: 'lock-live',
          handle: { key: 'kv' }
        });
      } },
      liveInBlock: function (realmId, block) {
        const out = [];
        for (let i = 0; i < 1024; i++) {
          out.push(block * 1024 + i);
        }
        return Promise.resolve(out);
      }
    }));
    await w.inRealm(async function () {
      try {
        await crowded.allocate({
          jti: 'live-1', kind: 'oauth', expiresAt: Date.now() + 60000,
          base: w.base
        });
      } catch (e) {
        liveCode = m.errorCodes.codeOf(e);
      }
    });
    note(liveCode === 'STS-OAUTH-0817' && liveLeases === 2 &&
         liveWrote === false,
         '3t. a block whose indexes are already in the store is skipped, ' +
         'and the list is full when every block tried is',
         JSON.stringify({ code: liveCode, leases: liveLeases,
                          wrote: liveWrote }));
    note(clusterClaimsMod.claimFenceLockName(
           'oauth2.access-token-status-block', '', 'abc', 'res') ===
         'fence:claim:oauth2.access-token-status-block::abc:res',
         '3u. a block claim\'s fence lock is named from the claim');

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

    // ==================================================================
    // 7. THE PACKED LIST (#885). A clock and a private bit store, so the
    // expiry is this test's and not a token section 2 revoked. The realm
    // id is not the default: the module cache is keyed by realm, and the
    // publications above already hold the default realm's list.
    // ==================================================================
    const T0 = Date.now();
    const clock7 = { t: T0 };
    const bits7 = new Map();
    bits7.set('0', { jti: 'ats-packed', expiresAt: T0 + 60000 });
    const isolated = new Cls(Object.assign(Cls.defaultDeps(), {
      now: function () {
        return clock7.t;
      },
      baseUrlOf: function () {
        return 'https://sts.example';
      },
      // Both members the list's URI reads: realmBaseOf() appends the
      // ambient realm's path prefix, and this stand-in's realm is the
      // default one, whose prefix is empty.
      realms: {
        currentId: function () {
          return 'ats-packed-test';
        },
        currentPrefix: function () {
          return '';
        }
      },
      entries: { onDemandLive: function () {
        return true;
      } },
      invalid: bits7
    }));
    function claimsOf(compact) {
      return JSON.parse(Buffer.from(String(compact).split('.')[1],
                                     'base64url').toString('utf8'));
    }
    function lstOf(compact) {
      return claimsOf(compact).status_list.lst;
    }
    function bitOf(compact, idx) {
      const parts = m.codec.tslFromJson(claimsOf(compact).status_list);
      return m.codec.unpackTslValue(parts.bytes, parts.bits, idx);
    }
    const packedBefore7 = m.cacheRegistry.detail(PACKED).summary;
    const signedBefore7 = m.cacheRegistry.detail(SIGNED).summary;
    const first7 = await isolated.listJwt({});
    const packedCold7 = m.cacheRegistry.detail(PACKED).summary;
    const second7 = await isolated.listJwt({});
    const packedHot7 = m.cacheRegistry.detail(PACKED).summary;
    const signedHot7 = m.cacheRegistry.detail(SIGNED).summary;
    note(packedCold7.misses === packedBefore7.misses + 1 &&
         packedHot7.misses === packedCold7.misses &&
         packedHot7.hits === packedCold7.hits + 1 &&
         first7 === second7 && bitOf(first7, 0) === 1 &&
         signedHot7.hits === signedBefore7.hits + 1,
         '7a. the first publication packs the list and the next one reuses ' +
         'the compressed bytes and the signature',
         JSON.stringify({ misses: packedHot7.misses, hits: packedHot7.hits }));
    const row7 = m.cacheRegistry.detail(PACKED).rows.filter(function (one) {
      return one.realm === 'ats-packed-test';
    })[0];
    note(!!row7 && row7.validUntil === T0 + 60000 &&
         !Object.prototype.hasOwnProperty.call(row7, 'compressed'),
         '7b. the registry row is the realm and the earliest expiry, and ' +
         'it does not carry the compressed bytes',
         JSON.stringify(row7 && { realm: row7.realm,
           validUntil: row7.validUntil }));
    clock7.t = T0 + 31000;
    const packedMidBefore = m.cacheRegistry.detail(PACKED).summary;
    const signedMidBefore = m.cacheRegistry.detail(SIGNED).summary;
    const mid7 = await isolated.listJwt({});
    const packedMid = m.cacheRegistry.detail(PACKED).summary;
    const signedMid = m.cacheRegistry.detail(SIGNED).summary;
    note(packedMid.misses === packedMidBefore.misses &&
         packedMid.hits === packedMidBefore.hits + 1 &&
         signedMid.misses === signedMidBefore.misses + 1 &&
         lstOf(mid7) === lstOf(first7) && mid7 !== first7,
         '7c. half the ttl re-signs from the cached bytes: the list is the ' +
         'same and the token is not',
         JSON.stringify({ packedHits: packedMid.hits,
           signedMisses: signedMid.misses }));
    clock7.t = T0 + 60000;
    const packedExpBefore = m.cacheRegistry.detail(PACKED).summary;
    const expired7 = await isolated.listJwt({});
    const packedExp = m.cacheRegistry.detail(PACKED).summary;
    note(packedExp.misses === packedExpBefore.misses + 1 &&
         bitOf(expired7, 0) === 0,
         '7d. at the earliest invalid bit\'s expiry the list is rebuilt and ' +
         'that index is published VALID',
         JSON.stringify({ misses: packedExp.misses }));

    // The other process's bit. On demand, so the list is the invalid store
    // and not a walk of entries. The realm is the ambient one: a restore
    // moves that realm's generation, which is the key the cache uses.
    const restoredIdx = 1234567;
    const publisher = new Cls(Object.assign(Cls.defaultDeps(), {
      baseUrlOf: function () {
        return 'https://sts.example';
      },
      entries: { onDemandLive: function () {
        return true;
      } }
    }));
    const beforeRestore = await publisher.listJwt({});
    const packedRestoreBefore = m.cacheRegistry.detail(PACKED).summary;
    m.realms.handleFor('access_token_status.invalid').restore(
      'default', String(restoredIdx),
      { jti: 'ats-restored', expiresAt: Date.now() + 3600000 });
    const afterRestore = await publisher.listJwt({});
    const packedRestore = m.cacheRegistry.detail(PACKED).summary;
    note(bitOf(beforeRestore, restoredIdx) === 0 &&
         bitOf(afterRestore, restoredIdx) === 1 &&
         packedRestore.misses === packedRestoreBefore.misses + 1 &&
         afterRestore !== beforeRestore,
         '7e. a bit restored from another process is published on the next ' +
         'list, which is packed again',
         JSON.stringify({ misses: packedRestore.misses,
           before: bitOf(beforeRestore, restoredIdx),
           after: bitOf(afterRestore, restoredIdx) }));
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
