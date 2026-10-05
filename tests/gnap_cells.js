// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_cells.js
//
// ---------------------------------------------------------------------------
// GNAP IN A SERVICE DEPLOYED AS CELLS (#98, `gnap/gnap_cells.ts`). The cell
// map, the inter-cell channel and the routing index are STUBBED — this
// process plays cell "a" of two, "a" and "b" — so what is held is the
// decision each door makes, not the network under it:
//
//   1. Single-cell mode stamps nothing and places nothing.
//   2. The handles a client, a resource server or a browser presents later
//      carry this cell's tag, and a handle carrying the OTHER cell's tag is
//      relayed there — with the body's bytes as they arrived, which is what
//      a GNAP proof covers.
//   3. A grant request is placed by its instance, then by a user reference
//      another cell holds, then by the person it names (their home).
//   4. A token this cell does not hold: a jwt-signed token by its `jti`, any
//      other format by asking the other cells, by digest.
//   5. A grant moves once: surrendered with its rows, forgotten, forwarded;
//      a continuation that reaches the old cell relayed on, and one that was
//      relayed there already answered 503 with STS-CELL-0160.
//   6. A browser pinned here at a handle minted elsewhere pulls the grant.
//   7. The group's error codes are registered.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const crypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'gnap_cells',
  level: process.env.LOG_LEVEL || 'info' });

// The two cells. `multi` is flipped by the tests below.
const PEER = { id: 'b', jurisdiction: 'ca', url: 'https://b.internal:9446',
               self: false };
const SELF = { id: 'a', jurisdiction: 'us', url: '', self: true };
let multi = false;

function stubCells() {
  log.debug("Entering stubCells().");
  const cells = require('../common/cells');
  cells.isMulti = function () {
    return multi;
  };
  cells.id = function () {
    return multi ? 'a' : '';
  };
  cells.peers = function () {
    return multi ? [PEER] : [];
  };
  cells.all = function () {
    return multi ? [SELF, PEER] : [SELF];
  };
  cells.get = function (id) {
    return id === 'a' ? SELF : (id === 'b' ? PEER : null);
  };
  log.debug("Leaving stubCells().");
}

// What the channel was asked to do, and what its `call()` answers.
const relays = [];
const calls = [];
let answer = function () {
  return {};
};

function stubChannel() {
  log.debug("Entering stubChannel().");
  const channel = require('../common/cell_channel');
  channel.relay = function (req, res, cellId, opts) {
    relays.push({ cell: cellId, reason: (opts || {}).reason,
                  body: (opts || {}).body });
    return Promise.resolve();
  };
  channel.call = function (cellId, name, body) {
    calls.push({ cell: cellId, name: name, body: body });
    return Promise.resolve(answer(cellId, name, body));
  };
  log.debug("Leaving stubChannel().");
}

function request(fields) {
  log.debug("Entering request().");
  const body = fields.json === undefined ? '' : JSON.stringify(fields.json);
  log.debug("Leaving request().");
  return Object.assign({
    method: 'POST', url: '/gnap', path: '/gnap', params: {}, query: {},
    headers: { 'content-type': 'application/json' },
    rawBody: Buffer.from(body, 'utf8'), body: body
  }, fields.req || {});
}

function response() {
  log.debug("Entering response().");
  const res = { statusCode: 200, headers: {}, sent: null };
  res.status = function (s) {
    res.statusCode = s;
    return res;
  };
  res.set = function (k, v) {
    res.headers[String(k).toLowerCase()] = v;
    return res;
  };
  res.type = function () {
    return res;
  };
  res.send = function (b) {
    res.sent = b;
    return res;
  };
  log.debug("Leaving response().");
  return res;
}

// A value stamped as cell "b" would stamp it.
function stampedB(value) {
  log.debug("Entering stampedB().");
  log.debug("Leaving stampedB().");
  return value + require('../common/cell_locator').tagOf('b');
}

async function run(t) {
  log.debug("Entering run().");
  stubCells();
  stubChannel();
  const keystore = require('../common/keystore');
  t.check(keystore.useEphemeralKek(crypto.randomBytes(32).toString('hex')),
          'a service key is installed (the locator tags are keyed on it)');
  const locator = require('../common/cell_locator');
  const store = require('../gnap/gnap_store');
  const gnapCells = require('../gnap/gnap_cells');
  const routing = require('../common/cell_routing');
  const errorCodes = require('../common/error_codes');
  const placement = require('../common/cell_placement');

  // 1. Single-cell mode.
  multi = false;
  t.equal(store.handle(18).length, store.mint(18).length,
          'single-cell mode stamps nothing');
  t.equal(await gnapCells.placeGrantRequest(request({ json: {
    client: stampedB('x'.repeat(24)) } }), response()), false,
          'single-cell mode places nothing');
  t.equal(relays.length + calls.length, 0, 'and asks no other cell');

  // 2. Stamped handles.
  multi = true;
  locator.reset();
  const mine = store.handle(18);
  t.equal(locator.locate(mine), 'a', 'a handle minted here carries this ' +
          'cell\'s tag');
  t.check(/^[A-Za-z0-9_-]+$/.test(mine), 'and is still base64url');
  const grant = store.newGrant({ state: store.STATE.PENDING });
  t.equal(locator.locate(grant.id), 'a', 'a grant id (the continuation ' +
          'URI) is stamped');
  const theirs = stampedB('g'.repeat(24));
  const signed = '{"access_token":{"access":["x"]}, "client":"k"}';
  const cont = request({ req: { rawBody: Buffer.from(signed),
                                body: signed } });
  t.equal(await gnapCells.placeContinuation(cont, response(), theirs), true,
          'a continuation for a grant the other cell minted is relayed');
  t.check(relays.length === 1 && relays[0].cell === 'b' &&
          String(relays[0].body) === signed,
          'to that cell, with the body\'s bytes exactly as they arrived');
  t.equal(await gnapCells.placeContinuation(request({}), response(),
                                            grant.id), false,
          'a continuation for a grant held here is served here');

  // 3. The grant request.
  relays.length = 0;
  t.equal(await gnapCells.placeGrantRequest(request({ json: {
    client: stampedB('i'.repeat(24)), access_token: { access: ['x'] } } }),
    response()), true, 'an instance identifier minted by the other cell ' +
          'is relayed there');
  t.equal(relays[0] && relays[0].reason, 'gnap:instance', 'by its tag');
  relays.length = 0;
  answer = function (cellId, name, body) {
    return name === 'gnap-locate' && body.kind === 'user-ref'
      ? { held: true } : {};
  };
  t.equal(await gnapCells.placeGrantRequest(request({ json: {
    client: { key: { proof: 'httpsig' } }, user: 'someref' } }),
    response()), true, 'a user reference held by the other cell is relayed');
  t.check(calls.some(function (c) {
    return c.name === 'gnap-locate' && c.body.value === store.digest('someref');
  }), 'the other cell is asked by the reference\'s digest, not the value');
  relays.length = 0;
  answer = function () {
    return {};
  };
  const homeOf = routing.homeOf;
  routing.homeOf = function (realm, kind, value) {
    return Promise.resolve(kind === 'uuid' &&
      value === '11111111-2222-3333-4444-555555555555' ? 'b' : '');
  };
  t.equal(await gnapCells.placeGrantRequest(request({ json: {
    client: { key: { proof: 'httpsig' } },
    user: { sub_ids: [{ format: 'iss_sub', iss: 'https://x',
      sub: 'urn:uuid:11111111-2222-3333-4444-555555555555' }] } } }),
    response()), true, 'a grant naming a person homed in the other cell is ' +
          'relayed to their home');
  t.equal(await gnapCells.placeGrantRequest(request({ json: {
    client: { key: { proof: 'httpsig' } },
    user: { sub_ids: [{ format: 'account', uri: 'acct:nobody@x' }] } } }),
    response()), false, 'a person nobody routes is served here');
  routing.homeOf = homeOf;
  t.equal(JSON.stringify(gnapCells.subjectHint({ assertions: [{
    format: 'id_token', value: 'e30.' + Buffer.from(JSON.stringify({
      preferred_username: 'alice' })).toString('base64url') + '.sig' }] })),
    JSON.stringify({ kind: 'name', value: 'alice' }),
    'an ID Token assertion is read (not verified) for its person');

  // 4. Tokens.
  relays.length = 0;
  const jws = 'e30.' + Buffer.from(JSON.stringify({
    jti: stampedB('j'.repeat(22)) })).toString('base64url') + '.sig';
  t.equal(await gnapCells.placeToken(request({}), response(), jws,
                                     'gnap:resource'), true,
          'a jwt-signed token minted by the other cell is placed by its jti');
  relays.length = 0;
  calls.length = 0;
  answer = function (cellId, name, body) {
    return name === 'gnap-locate' && body.kind === 'token'
      ? { held: true } : {};
  };
  t.equal(await gnapCells.placeToken(request({}), response(), 'opaque-mac',
                                     'gnap:resource'), true,
          'a token whose format hides its jti is found by asking');
  t.check(calls[0] && calls[0].body.value === store.digest('opaque-mac'),
          'by the digest of its value, never the value');
  answer = function () {
    return {};
  };
  relays.length = 0;
  t.equal(await gnapCells.placeToken(request({}), response(), 'unknown',
                                     'gnap:resource'), false,
          'a token no cell holds is served here, and refused here');

  // 5. A grant moves.
  const moving = store.newGrant({ state: store.STATE.PENDING,
    interaction: { approvalId: 'appr', expiresAt: 9999999999 } });
  store.putInteraction('approve:appr', moving.id);
  store.putUserCode('ABCDEFGH', moving.id);
  const handed = await gnapCells.surrender({ realm: '', key: 'approve:appr',
                                            to: 'b' });
  t.check(handed && handed.bundle && handed.bundle.grant.id === moving.id,
          'a waiting grant is surrendered with its rows');
  t.check(handed.bundle.interactions['approve:appr'] &&
          handed.bundle.userCodes.ABCDEFGH, 'its interaction handle and ' +
          'user code travel with it');
  t.equal(store.getGrant(moving.id), null, 'and it is forgotten here');
  relays.length = 0;
  t.equal(await gnapCells.placeContinuation(request({}), response(),
                                            moving.id), true,
          'a continuation for it is forwarded to where it went');
  t.equal(relays[0] && relays[0].cell, 'b', 'to that cell');
  const again = response();
  t.equal(await gnapCells.placeContinuation(request({ req: {
    stsCellRelay: { from: 'c' } } }), again, moving.id), true,
          'one relayed here already is answered, not relayed again');
  t.check(again.statusCode === 503 &&
          errorCodes.codeOf && errorCodes.codeOf(again) === 'STS-CELL-0160',
          'with 503 and STS-CELL-0160');
  const issued = store.newGrant({ state: store.STATE.PENDING,
    tokens: ['t'], interaction: { approvalId: 'appr2' } });
  store.putInteraction('approve:appr2', issued.id);
  const kept = await gnapCells.surrender({ realm: '', key: 'approve:appr2',
                                          to: 'b' });
  t.check(kept && !kept.bundle && store.getGrant(issued.id),
          'a grant that has issued tokens is not moved');

  // 6. A pinned browser pulls.
  const remote = stampedB('r'.repeat(24));
  const pulledGrant = { id: stampedB('p'.repeat(24)),
                        state: store.STATE.PENDING, tokens: [],
                        interaction: { approvalId: remote } };
  const approveKey = 'approve:' + remote;
  answer = function (cellId, name) {
    return name === 'gnap-surrender-grant'
      ? { bundle: { grant: pulledGrant, continuation: null,
                    interactions: { [approveKey]: { grantId: pulledGrant.id,
                                                    at: 1 } },
                    userCodes: {} } } : {};
  };
  t.equal(await gnapCells.placeInteraction(request({}), response(),
                                           approveKey), false,
          'a browser pinned here at a handle minted elsewhere is served here');
  t.check(store.grantByInteraction(approveKey) &&
          store.grantByInteraction(approveKey).id === pulledGrant.id,
          'after the grant is pulled from the cell that minted it');
  answer = function () {
    return {};
  };

  // 7. Codes and rows.
  ['STS-CELL-0160', 'STS-CELL-0161', 'STS-CELL-0162', 'STS-CELL-0163',
   'STS-CELL-0164', 'STS-CELL-0165'].forEach(function (code) {
    t.check(errorCodes.isKnown(code), code + ' is registered');
  });
  t.equal(placement.rowFor('/gnap/continue/x').strategy, 'handler',
          'a continuation is placed by its handler');
  t.equal(placement.rowFor('/gnap/approve/x').segment, 3,
          'an approval handle is the path\'s third segment');
  t.equal(placement.rowFor('/acme/gnap/continue/x').strategy, 'handler',
          'a named authorization server is placed as the default one is');
  multi = false;
  keystore.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'gnap_cells',
  describe: 'GNAP between cells (#98): stamped handles, grant requests ' +
            'placed by instance, reference and person, tokens found by ' +
            'jti or by asking, a waiting grant moved to the resource ' +
            'owner\'s cell, and single-cell mode unchanged',
  run: run
};
