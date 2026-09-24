'use strict';
//
// File: oidfed_extensions.js
//
// ===========================================================================
// THE THREE OPENID FEDERATION EXTENSIONS (#135, #136, #137, 2026-09-24), in
// process, on the default realm as a Trust Anchor with a realm beneath it,
// registered subordinates, and a foreign Intermediate with a leaf of its own
// reached through a stub outbound requester:
//
//   1. the page pointer: made and read back, refused for another realm,
//      another endpoint or a changed byte, and a page resumed from it;
//   2. the events of a registered subordinate (#137): a registration
//      recorded alone, one update event per part changed, suspension
//      (no statement, listed nowhere) and reinstatement, a revocation with
//      its reason and information page — and the history answered, signed,
//      after the subordinate is gone; the refusals;
//   3. a realm of this service: its creation its registration, a key
//      rotation a jwks_update, its deletion its revocation — answered under
//      the identifier it had; suspending it breaks the chain through it;
//   4. the Extended Subordinate Listing (#135): paging with an opaque
//      pointer, the claims, the audit timestamps, the filters, the refusals;
//   5. the Entity Collection (#136): in process only (the realm's own
//      realms), the filters and claims and refusals; then a CRAWL through a
//      foreign Intermediate to its leaf — every entity resolved to the realm
//      first, its ui_infos read from its resolved metadata — kept for the
//      endpoint; and the fetch budget of 0 leaving the leaf out;
//   6. the Entity Configuration publishing the three endpoints, and the
//      view carrying status, history and the crawl.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const stsCrypto = require('../common/crypto');
require('../ldap/ldap_server');
require('../oauth-oidc/oauth2');
const oidfed = require('../oidfed/oidfed');
const keys = require('../oidfed/federation_keys');
const EntityStatement = require('../oidfed/entity_statement');
const OidfedStore = require('../oidfed/oidfed_store');
const SubordinateEvents = require('../oidfed/subordinate_events');
const PagePointer = require('../oidfed/page_pointer');
const listing = require('../oidfed/extended_listing');
const collectionModule = require('../oidfed/entity_collection');

const log = require('bunyan').createLogger({ name: 'oidfed_extensions',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const REALM = 'oidfedx-' + RUN;
const GONE = 'oidfedg-' + RUN;
const TYPE = 'https://sts.test/marks/x-' + RUN;
const NOW = Math.floor(Date.now() / 1000);
const ES = EntityStatement.TYP.ENTITY_STATEMENT;

function fakeReq() {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { protocol: 'https', headers: { host: 'sts.test' }, query: {},
           get: function (name) {
             return String(name).toLowerCase() === 'host' ? 'sts.test' : '';
           } };
}

function inRealm(id, fn) {
  log.debug("Entering inRealm(). " + id);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(id), fn);
}

function keyPair() {
  log.debug("Entering keyPair().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  jwk.kid = stsCrypto.jwkThumbprint(jwk);
  log.debug("Leaving keyPair().");
  return { signer: { key: pair.privateKey, alg: 'ES256', kid: jwk.kid },
           jwks: { keys: [jwk] } };
}

function events(jwt) {
  log.debug("Entering events().");
  log.debug("Leaving events().");
  return EntityStatement.decode(jwt).claims.federation_registration_events
    .map(function (e) {
      return e.event;
    });
}

// A foreign Intermediate beneath the default realm, and a leaf beneath it,
// served by a stub of federation_http's fetchPublished(): each Entity
// Configuration at its well-known address, the Intermediate's list and its
// Subordinate Statement about the leaf.
function foreign(anchorId) {
  log.debug("Entering foreign().");
  const ids = { int: 'https://int-' + RUN + '.test',
                leaf: 'https://leaf-' + RUN + '.test' };
  const k = { int: keyPair(), leaf: keyPair() };
  const signed = function (payload, who) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return EntityStatement.sign(payload, ES, k[who].signer);
  };
  const docs = {};
  docs[ids.int + '/.well-known/openid-federation'] = signed({
    iss: ids.int, sub: ids.int, iat: NOW - 10, exp: NOW + 3600,
    jwks: k.int.jwks, authority_hints: [anchorId],
    metadata: { federation_entity: {
      federation_fetch_endpoint: ids.int + '/fetch',
      federation_list_endpoint: ids.int + '/list',
      organization_name: 'Intermediate ' + RUN } } }, 'int');
  docs[ids.leaf + '/.well-known/openid-federation'] = signed({
    iss: ids.leaf, sub: ids.leaf, iat: NOW - 10, exp: NOW + 3600,
    jwks: k.leaf.jwks, authority_hints: [ids.int],
    metadata: { openid_relying_party: {
      client_name: 'Leaf RP ' + RUN, 'client_name#de': 'Blatt ' + RUN,
      logo_uri: 'https://leaf-' + RUN + '.test/logo.png',
      redirect_uris: [ids.leaf + '/cb'],
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: k.leaf.jwks } } }, 'leaf');
  docs[ids.int + '/fetch?sub=' + encodeURIComponent(ids.leaf)] = signed({
    iss: ids.int, sub: ids.leaf, iat: NOW - 10, exp: NOW + 1800,
    jwks: k.leaf.jwks }, 'int');
  const fetched = [];
  const stub = {
    fetchPublished: function (url, options) {
      log.debug("Entering stub fetchPublished(). " + url);
      fetched.push(url);
      if (url === ids.int + '/list') {
        log.debug("Leaving stub fetchPublished(). The list.");
        return Promise.resolve({ ok: true, status: 200,
          contentType: 'application/json',
          body: Buffer.from(JSON.stringify([ids.leaf,
                                            'https://gone-' + RUN + '.test',
                                            anchorId])) });
      }
      const doc = docs[url];
      log.debug("Leaving stub fetchPublished(). " + !!doc);
      return Promise.resolve(doc
        ? { ok: true, status: 200, body: Buffer.from(doc),
            contentType: 'application/entity-statement+jwt' }
        : { ok: false, status: 404, body: Buffer.from(''), contentType: '',
            why: 'not here: ' + url + ' (' + String(options.accept) + ')' });
    }
  };
  log.debug("Leaving foreign().");
  return { ids: ids, keys: k, stub: stub, fetched: fetched };
}

async function run(t) {
  log.debug("Entering run().");
  realms.create({ id: REALM, name: 'OpenID Federation extensions test' });
  try {
    await body(t);
  } finally {
    const req = fakeReq();
    (oidfed.subordinates(req) || []).forEach(function (s) {
      if (!s.localRealm && s.entityId.indexOf(RUN) >= 0) {
        OidfedStore.remove(OidfedStore.KINDS.SUBORDINATE, s.entityId);
      }
    });
    OidfedStore.entries(OidfedStore.KINDS.EVENTS).forEach(function (e) {
      const key = String((e.data || {}).key || '');
      if (key.indexOf(RUN) >= 0) {
        OidfedStore.remove(OidfedStore.KINDS.EVENTS, key);
      }
    });
    OidfedStore.entries(OidfedStore.KINDS.SUSPENSION).forEach(function (e) {
      const key = String((e.data || {}).key || '');
      if (key.indexOf(RUN) >= 0) {
        OidfedStore.remove(OidfedStore.KINDS.SUSPENSION, key);
      }
    });
    OidfedStore.remove(OidfedStore.KINDS.COLLECTION, '');
    ['oidfed.collectionMaxFetches', 'oidfed.listPageMax',
     'oidfed.collectionCacheS'].forEach(function (k) {
      config.clearOverride(k);
    });
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  const req = fakeReq();
  const entity = oidfed.instance();
  const anchorId = oidfed.entityId(req);
  const leafId = inRealm(REALM, function () {
    return oidfed.entityId(req);
  });
  const realmId = String(realms.current().id);

  t.log.info('=== 1. the page pointer ===');
  const p = PagePointer.encode(realmId, 'extended-list', 'https://b.test');
  const flipped = p.slice(0, -1) + (p.slice(-1) === 'A' ? 'B' : 'A');
  t.check(PagePointer.decode(realmId, 'extended-list', p) ===
            'https://b.test' &&
          PagePointer.decode('other', 'extended-list', p) === null &&
          PagePointer.decode(realmId, 'collection', p) === null &&
          PagePointer.decode(realmId, 'extended-list', flipped) === null &&
          PagePointer.decode(realmId, 'extended-list', 'nonsense') === null,
          '1a. a pointer is read back where it was made, and nowhere else');
  const items = ['https://a.test', 'https://b.test', 'https://c.test'];
  const first = PagePointer.page(items, String, realmId, 'x', undefined, 2);
  const second = PagePointer.page(items, String, realmId, 'x', first.next, 2);
  t.check(first.ok && first.page.length === 2 && !!first.next &&
          second.ok && second.page.join() === 'https://c.test' &&
          !second.next,
          '1b. a page stops short with next, and the next page starts there',
          JSON.stringify({ first: first, second: second }));

  t.log.info('=== 2. a registered subordinate\'s history ===');
  const rpId = 'https://rp-' + RUN + '.test';
  const k1 = keyPair();
  const k2 = keyPair();
  const added = await oidfed.act({ action: 'add-subordinate', entityId: rpId,
    jwks: JSON.stringify(k1.jwks), entityTypes: 'openid_relying_party',
    eventDescription: 'onboarded',
    informationUri: 'https://sts.test/policy' }, { req: req });
  const changed = await oidfed.act({ action: 'add-subordinate',
    entityId: rpId, jwks: JSON.stringify(k2.jwks),
    entityTypes: 'openid_relying_party',
    metadata: JSON.stringify({ openid_relying_party: {
      client_name: 'RP ' + RUN } }) }, { req: req });
  const afterChange = SubordinateEvents.history(rpId).map(function (e) {
    return e.event;
  });
  t.check(added.ok && changed.ok &&
          JSON.stringify(afterChange) === JSON.stringify([
            'registration', 'metadata_update', 'jwks_update']),
          '2a. a registration recorded alone, then one event per part ' +
          'changed', JSON.stringify(afterChange));
  const suspended = await oidfed.act({ action: 'suspend-subordinate',
    entityId: rpId, reason: 'under review' }, { req: req });
  const twice = await oidfed.act({ action: 'suspend-subordinate',
    entityId: rpId }, { req: req });
  const noStatement = await oidfed.subordinateStatement(req, rpId);
  const listed = await oidfed.listing(req, {});
  t.check(suspended.ok && !twice.ok && twice.errors &&
          noStatement.ok === false && noStatement.code === 'STS-OIDFED-0057' &&
          noStatement.error === 'not_found' &&
          listed.list.indexOf(rpId) < 0,
          '2b. suspended: no statement (not_found), not listed, and not ' +
          'suspended twice', JSON.stringify(noStatement));
  const reinstated = await oidfed.act({ action: 'reinstate-subordinate',
    entityId: rpId }, { req: req });
  const statementAgain = await oidfed.subordinateStatement(req, rpId);
  const badUri = await oidfed.act({ action: 'remove-subordinate',
    entityId: rpId, informationUri: 'javascript:alert(1)' }, { req: req });
  t.check(reinstated.ok && statementAgain.ok && !badUri.ok,
          '2c. reinstated, its statement is issued again; an information ' +
          'URI that is not http(s) is refused');
  const removed = await oidfed.act({ action: 'remove-subordinate',
    entityId: rpId, reason: 'no longer operated',
    informationUri: 'https://sts.test/revocations/1' }, { req: req });
  const answered = await oidfed.eventsResponse(req, rpId);
  const header = answered.ok ? EntityStatement.decode(answered.jwt).header
                             : {};
  const verified = answered.ok
    ? EntityStatement.verify(answered.jwt, keys.jwks(),
                             'entity-events-statement+jwt') : { ok: false };
  const served = answered.ok
    ? EntityStatement.decode(answered.jwt).claims : {};
  const last = (served.federation_registration_events || []).slice(-1)[0];
  t.check(removed.ok && answered.ok && verified.ok &&
          header.typ === 'entity-events-statement+jwt' &&
          served.iss === anchorId && served.sub === rpId &&
          Number.isFinite(served.exp) &&
          JSON.stringify(events(answered.jwt)) === JSON.stringify([
            'registration', 'metadata_update', 'jwks_update', 'suspension',
            'reinstatement', 'revocation']) &&
          last.event_description === 'no longer operated' &&
          last.information_uri === 'https://sts.test/revocations/1' &&
          served.federation_registration_events.every(function (e) {
            return e.id === undefined && Number.isFinite(e.iat);
          }) &&
          served.federation_registration_events[0].information_uri ===
            'https://sts.test/policy',
          '2d. revoked, its whole history is still answered — signed, ' +
          'typed, the reason and page on the revocation, no internal ids',
          JSON.stringify(served));
  const stranger = await oidfed.eventsResponse(req, 'https://never.test');
  const noSub = await oidfed.eventsResponse(req, '');
  t.check(stranger.code === 'STS-OIDFED-0064' && stranger.status === 404 &&
          noSub.code === 'STS-OIDFED-0063' && noSub.status === 400,
          '2e. never a subordinate is not_found; no sub is invalid_request');

  t.log.info('=== 3. a realm of this service ===');
  const realmHistory = SubordinateEvents.history(
    SubordinateEvents.realmKey(REALM)).map(function (e) {
    return e.event;
  });
  await inRealm(REALM, function () {
    return keys.rotate({ reason: 'test' });
  });
  const afterRotate = SubordinateEvents.history(
    SubordinateEvents.realmKey(REALM)).map(function (e) {
    return e.event;
  });
  t.check(realmHistory[0] === 'registration' &&
          afterRotate.slice(-1)[0] === 'jwks_update',
          '3a. its creation is its registration, and a rotation of its own ' +
          'key a jwks_update in the default realm\'s history of it',
          JSON.stringify({ before: realmHistory, after: afterRotate }));
  const localSuspend = await oidfed.act({ action: 'suspend-subordinate',
    entityId: leafId, reason: 'test' }, { req: req });
  const broken = await oidfed.resolve(req, leafId, [], false);
  await oidfed.act({ action: 'reinstate-subordinate', entityId: leafId },
                   { req: req });
  const mended = await oidfed.resolve(req, leafId, [], false);
  t.check(localSuspend.ok && !broken.ok && mended.ok,
          '3b. a suspended realm resolves to nothing; reinstated, it does',
          JSON.stringify({ broken: broken.why }));
  realms.create({ id: GONE, name: 'OpenID Federation gone test' });
  const goneId = inRealm(GONE, function () {
    return oidfed.entityId(req);
  });
  realms.remove(GONE);
  const goneEvents = await oidfed.eventsResponse(req, goneId);
  t.check(goneEvents.ok && JSON.stringify(events(goneEvents.jwt)) ===
            JSON.stringify(['registration', 'revocation']) &&
          (await oidfed.view(req)).formerSubordinates.some(function (f) {
            return f.entityId === goneId && f.localRealm === GONE;
          }),
          '3c. a deleted realm is answered under the identifier it had: ' +
          'registered, revoked — and listed among the former subordinates',
          JSON.stringify(goneEvents.why || ''));

  t.log.info('=== 4. the Extended Subordinate Listing ===');
  const ids = ['a', 'b', 'c'].map(function (x) {
    return 'https://' + x + '-' + RUN + '.test';
  });
  for (let i = 0; i < ids.length; i++) {
    await oidfed.act({ action: 'add-subordinate', entityId: ids[i],
      jwks: JSON.stringify(keyPair().jwks),
      entityTypes: i === 0 ? 'openid_provider' : 'openid_relying_party',
      metadataPolicy: JSON.stringify({ openid_relying_party: {
        token_endpoint_auth_method: { one_of: ['private_key_jwt'] } } }) },
      { req: req });
  }
  await oidfed.act({ action: 'add-mark-type', type: TYPE, lifetimeS: 3600 },
                   { req: req });
  const marked = await oidfed.act({ action: 'issue-trust-mark', type: TYPE,
                                    sub: ids[1] }, { req: req });
  const all = [];
  let page = await listing.answer(entity, req, { limit: '2' });
  const pages = [page];
  while (page.ok) {
    page.body.immediate_subordinate_entities.forEach(function (e) {
      all.push(e.id);
    });
    if (!page.body.next) {
      break;
    }
    page = await listing.answer(entity, req, { limit: '2',
                                               from: page.body.next });
    pages.push(page);
  }
  const sorted = all.slice().sort();
  t.check(pages.every(function (one) {
    return one.ok && one.body.immediate_subordinate_entities.length <= 2;
  }) && JSON.stringify(all) === JSON.stringify(sorted) &&
          ids.every(function (id) {
            return all.indexOf(id) >= 0;
          }) && all.indexOf(leafId) >= 0 && all.indexOf(rpId) < 0 &&
          pages[0].body.immediate_subordinate_entities.every(function (e) {
            return Object.keys(e).join() === 'id';
          }),
          '4a. paged in identifier order, two at a time, each entry its id ' +
          'alone; the revoked subordinate is gone',
          JSON.stringify({ all: all, pages: pages.length }));
  const rich = await listing.answer(entity, req, { limit: '50',
    claims: 'subordinate_statement,metadata_policy,trust_marks',
    audit_timestamps: 'true' });
  const b = (rich.body ? rich.body.immediate_subordinate_entities : [])
    .filter(function (e) {
      return e.id === ids[1];
    })[0] || {};
  const bStatement = b.subordinate_statement
    ? EntityStatement.verify(b.subordinate_statement, keys.jwks(), ES)
    : { ok: false };
  t.check(rich.ok && bStatement.ok && bStatement.claims.sub === ids[1] &&
          b.metadata_policy && b.trust_marks && b.trust_marks.length === 1 &&
          b.trust_marks[0].trust_mark === marked.trustMark &&
          Number.isFinite(b.registered) && Number.isFinite(b.updated) &&
          b.updated >= b.registered,
          '4b. claims: the signed statement, its metadata_policy and the ' +
          'mark this realm issued; the audit timestamps', JSON.stringify(b));
  const byType = await listing.answer(entity, req, {
    entity_type: 'openid_provider' });
  const byMarks = await listing.answer(entity, req, {
    trust_mark_type: ['https://sts.test/none', TYPE] });
  const future = await listing.answer(entity, req, {
    updated_after: String(NOW + 86400) });
  const idsOf = function (r) {
    log.debug("Entering idsOf().");
    log.debug("Leaving idsOf().");
    return r.ok ? r.body.immediate_subordinate_entities.map(function (e) {
      return e.id;
    }) : null;
  };
  t.check(idsOf(byType).indexOf(ids[0]) >= 0 &&
          idsOf(byType).indexOf(ids[1]) < 0 &&
          JSON.stringify(idsOf(byMarks)) === JSON.stringify([ids[1]]) &&
          JSON.stringify(idsOf(future)) === '[]' &&
          (future.body.immediate_subordinate_entities || []).length === 0,
          '4c. filtered by entity type, by any of several mark types, and ' +
          'by updated_after', JSON.stringify({ t: idsOf(byType),
                                              m: idsOf(byMarks) }));
  const refusals = [
    await listing.answer(entity, req, { limit: '0' }),
    await listing.answer(entity, req, { limit: 'x' }),
    await listing.answer(entity, req, { updated_before: 'yesterday' }),
    await listing.answer(entity, req, { audit_timestamps: 'maybe' }),
    await listing.answer(entity, req, { from: flipped })];
  t.check(refusals.slice(0, 4).every(function (r) {
    return !r.ok && r.status === 400 && r.error === 'invalid_request' &&
           r.code === 'STS-OIDFED-0060';
  }) && refusals[4].status === 404 && refusals[4].error === 'page_not_found',
          '4d. a bad limit, time or boolean is invalid_request; a pointer ' +
          'not ours is page_not_found', JSON.stringify(refusals));

  t.log.info('=== 5. the Entity Collection ===');
  config.setOverride('oidfed.collectionCacheS', 0);
  const collection = collectionModule;
  const local = await collection.answer(entity, req, {});
  const leafInfo = local.ok ? local.body.entities.filter(function (e) {
    return e.entity_id === leafId;
  })[0] : null;
  t.check(local.ok && leafInfo &&
          leafInfo.entity_types.indexOf('openid_provider') >= 0 &&
          leafInfo.entity_types.indexOf('federation_entity') >= 0 &&
          local.body.entities.every(function (e) {
            return e.entity_id.indexOf('https://a-' + RUN) < 0;
          }) && Number.isFinite(local.body.last_updated),
          '5a. without a crawl: this service\'s own realms, resolved in ' +
          'process; a foreign subordinate nothing has resolved is left out',
          JSON.stringify(local.body));
  const narrow = await collection.answer(entity, req, {
    entity_type: 'openid_provider', entity_claims: ['entity_types',
                                                    'ui_infos'],
    ui_claims: 'display_name', query: REALM });
  const other = await collection.answer(entity, req, {
    trust_anchor: 'https://elsewhere.test' });
  const bogus = await collection.answer(entity, req, {
    entity_claims: 'secret' });
  const badUi = await collection.answer(entity, req, { ui_claims: 'color' });
  t.check(narrow.ok && narrow.body.entities.length >= 1 &&
          narrow.body.entities.every(function (e) {
            return !e.trust_marks && Object.keys(e.ui_infos || {})
              .every(function (type) {
                return (type === 'openid_provider' ||
                        type === 'federation_entity') &&
                  Object.keys(e.ui_infos[type]).every(function (n) {
                    return n.split('#')[0] === 'display_name';
                  });
              });
          }) &&
          other.status === 404 && other.error === 'invalid_trust_anchor' &&
          bogus.status === 400 && bogus.error === 'unsupported_claim' &&
          badUi.error === 'unsupported_claim',
          '5b. filtered and shaped as asked; another anchor and an unknown ' +
          'claim refused', JSON.stringify({ narrow: narrow.body, other: other,
                                            bogus: bogus }));

  // A CRAWL through a foreign Intermediate, over a stub requester.
  const f = foreign(anchorId);
  await oidfed.act({ action: 'add-subordinate', entityId: f.ids.int,
                     jwks: JSON.stringify(f.keys.int.jwks),
                     intermediate: true }, { req: req });
  const stubbed = new oidfed.Oidfed(Object.assign(
    oidfed.Oidfed.defaultDeps(), { fedHttp: function () {
      return f.stub;
    } }));
  const crawler = new collectionModule.EntityCollection(Object.assign(
    collectionModule.EntityCollection.defaultDeps(), { fedHttp: function () {
      return f.stub;
    } }));
  const crawled = await crawler.crawlNow(stubbed, req);
  const answer = await crawler.answer(stubbed, req, {});
  const found = function (id) {
    log.debug("Entering found().");
    log.debug("Leaving found().");
    return (answer.body ? answer.body.entities : []).filter(function (e) {
      return e.entity_id === id;
    })[0];
  };
  const leaf = found(f.ids.leaf);
  const kept = OidfedStore.get(OidfedStore.KINDS.COLLECTION, '');
  t.check(crawled.ok && answer.ok && found(f.ids.int) && leaf &&
          leaf.ui_infos.openid_relying_party.display_name ===
            'Leaf RP ' + RUN &&
          leaf.ui_infos.openid_relying_party['display_name#de'] ===
            'Blatt ' + RUN &&
          leaf.ui_infos.openid_relying_party.logo_uri ===
            'https://leaf-' + RUN + '.test/logo.png' &&
          !found('https://gone-' + RUN + '.test') && !found(anchorId) &&
          found(leafId) &&
          f.fetched.indexOf(f.ids.int + '/list') >= 0 &&
          kept && kept.data.entityId === anchorId &&
          kept.data.problems.some(function (p) {
            return p.indexOf('gone-' + RUN) >= 0;
          }),
          '5c. a crawl walks down through the foreign Intermediate to its ' +
          'leaf, whose display name comes from its client_name; an entry ' +
          'that does not resolve is left out and named; the realm itself ' +
          'is not its own member; the crawl is kept',
          JSON.stringify({ crawled: crawled, entities: (answer.body || {})
            .entities && answer.body.entities.map(function (e) {
            return e.entity_id;
          }), fetched: f.fetched }));
  const onePage = await crawler.answer(stubbed, req, { limit: '1' });
  const rest = onePage.ok ? await crawler.answer(stubbed, req,
    { limit: '1', from: onePage.body.next }) : { ok: false };
  t.check(onePage.ok && onePage.body.entities.length === 1 &&
          !!onePage.body.next && rest.ok &&
          rest.body.entities[0].entity_id > onePage.body.entities[0].entity_id,
          '5d. and pages one at a time');
  // THE KEPT CRAWL IS NEVER THE WHOLE ANSWER: a realm made after it is
  // collected at once, and a foreign subordinate suspended after it takes
  // what was reached through it out at once.
  const LATE = 'oidfedl-' + RUN;
  realms.create({ id: LATE, name: 'OpenID Federation late test' });
  const lateId = inRealm(LATE, function () {
    return oidfed.entityId(req);
  });
  const withLate = await crawler.answer(stubbed, req, {});
  await oidfed.act({ action: 'suspend-subordinate', entityId: f.ids.int },
                   { req: req });
  const withoutInt = await crawler.answer(stubbed, req, {});
  await oidfed.act({ action: 'reinstate-subordinate', entityId: f.ids.int },
                   { req: req });
  const withInt = await crawler.answer(stubbed, req, {});
  realms.remove(LATE);
  const has = function (r, id) {
    log.debug("Entering has().");
    log.debug("Leaving has().");
    return r.ok && r.body.entities.some(function (e) {
      return e.entity_id === id;
    });
  };
  t.check(has(withLate, lateId) && has(withLate, f.ids.leaf) &&
          !has(withoutInt, f.ids.int) && !has(withoutInt, f.ids.leaf) &&
          has(withoutInt, leafId) && has(withInt, f.ids.leaf),
          '5f. the kept crawl is merged with a fresh in-process collection: ' +
          'a realm made after it is there at once, and suspending the ' +
          'Intermediate takes it and its leaf out until it is reinstated');
  config.setOverride('oidfed.collectionMaxFetches', 0);
  const starved = await crawler.crawlNow(stubbed, req);
  const starvedAnswer = await crawler.answer(stubbed, req, {});
  t.check(starved.ok && starvedAnswer.body.entities.every(function (e) {
    return e.entity_id !== f.ids.leaf;
  }) && starvedAnswer.body.entities.some(function (e) {
    return e.entity_id === f.ids.int;
  }),
          '5e. with no list fetches allowed, the Intermediate is collected ' +
          'and its leaf is not');
  config.clearOverride('oidfed.collectionMaxFetches');

  t.log.info('=== 6. the Entity Configuration and the view ===');
  const ec = await oidfed.configuration(req);
  const fe = ec.claims.metadata.federation_entity;
  const view = await oidfed.view(req);
  const intView = view.subordinates.filter(function (s) {
    return s.entityId === f.ids.int;
  })[0];
  t.check(fe.federation_extended_list_endpoint ===
            anchorId + '/oidfed/extended-list' &&
          fe.federation_collection_endpoint ===
            anchorId + '/oidfed/collection' &&
          fe.federation_subordinate_events_endpoint ===
            anchorId + '/oidfed/subordinate-events' &&
          intView && intView.suspended === null &&
          intView.events[0].event === 'registration' &&
          view.collection && view.collection.crawl &&
          view.collection.crawl.forThisIdentifier === true,
          '6a. the three endpoints are published; the view carries each ' +
          'subordinate\'s status and history, and the crawl kept',
          JSON.stringify({ fe: fe, collection: view.collection }));
  log.debug("Leaving body().");
}

module.exports = {
  name: 'oidfed_extensions',
  describe: 'OpenID Federation extensions (#135, #136, #137): the Extended ' +
            'Subordinate Listing, the Entity Collection with a crawl ' +
            'through a foreign Intermediate, and each subordinate\'s ' +
            'history with suspension, in process',
  run: run
};
