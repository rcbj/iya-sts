// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cell_handlers_c.js
//
// ---------------------------------------------------------------------------
// WHERE A SCIM REQUEST AND A KERBEROS REQUEST ARE ANSWERED IN A SERVICE
// DEPLOYED AS CELLS (#98, group C). In process, with the cell map, the
// routing index and the inter-cell channel STUBBED by replacing their
// module functions — so what is asserted is the DECISION each handler makes,
// not a second cell answering:
//
//   1. SCIM: an id, a member and a home cell read out of what a client sends.
//   2. SCIM placement: a person by id relayed to their home; a create relayed
//      to the cell it names, and refused for a cell there is not; a Group
//      write or a BulkRequest spanning cells refused whole; a list served
//      here; and nothing asked at all in single-cell mode.
//   3. SCIM ingress: a create claims its login name first and is refused 409
//      when the name is homed elsewhere; an update may not name another cell.
//   4. MS-KKDCP: the KDC-PROXY-MESSAGE unframed, the client of an AS-REQ
//      found, and a request for a person homed elsewhere relayed rather than
//      handed to the KDC.
//
// What is NOT here, and why: the XACML PIP, the TLS sign-in and the LDAP bind
// decide inside a running service's handlers (a parsed PIP query, a verified
// TLS socket, an ldapjs connection), which a two-cell stack exercises; the
// decisions they make are the routing lookups asserted above.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const cells = require('../common/cells');
const cellRouting = require('../common/cell_routing');
const cellChannel = require('../common/cell_channel');
const scimCells = require('../scim/scim_cells');
const krb5Home = require('../kerberos/krb5_home');
const msgs = require('../kerberos/krb5_messages.js');
const asn1 = require('../kerberos/krb5_asn1.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const principals = require('../kerberos/krb5_principals.js');

const log = require('bunyan').createLogger({ name: 'cell_handlers_c',
  level: process.env.LOG_LEVEL || 'info' });

const ALICE = '0b6f0b8e-1f2a-4c3d-9e8f-000000000a11';
const BOB = '0b6f0b8e-1f2a-4c3d-9e8f-000000000b0b';
const EXT = 'urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User';

// The stubs, and what they saw. `homes` maps a login name or an entryUUID to
// the cell the routing index would answer.
const seen = { relays: [], lookups: 0, claims: [] };
const homes = {};
let multi = true;
let claimAnswer = { ok: true };
const saved = {};

function stub() {
  log.debug("Entering stub().");
  ['isMulti', 'id', 'get', 'homeFor'].forEach(function (k) {
    saved['cells.' + k] = cells[k];
  });
  saved.homeOf = cellRouting.homeOf;
  saved.claimName = cellRouting.claimName;
  saved.relay = cellChannel.relay;
  cells.isMulti = function () {
    return multi;
  };
  cells.id = function () {
    return multi ? 'usw2' : '';
  };
  cells.get = function (id) {
    return ['usw2', 'cac1'].indexOf(id) >= 0 ? { id: id } : null;
  };
  cells.homeFor = function (asked) {
    if (!multi) {
      return { cell: '' };
    }
    const named = asked || 'usw2';
    return ['usw2', 'cac1'].indexOf(named) >= 0 ? { cell: named }
      : { error: 'this service has no cell "' + named + '"' };
  };
  cellRouting.homeOf = function (realmId, kind, value) {
    seen.lookups += 1;
    return Promise.resolve(multi ? homes[String(value).toLowerCase()] || ''
                                 : '');
  };
  cellRouting.claimName = function (realmId, name, cellId) {
    seen.claims.push({ name: name, cell: cellId });
    return Promise.resolve(claimAnswer);
  };
  cellChannel.relay = function (req, res, cellId, opts) {
    seen.relays.push({ cell: cellId, reason: (opts || {}).reason,
                       body: (opts || {}).body });
    return Promise.resolve();
  };
  log.debug("Leaving stub().");
}

function unstub() {
  log.debug("Entering unstub().");
  ['isMulti', 'id', 'get', 'homeFor'].forEach(function (k) {
    cells[k] = saved['cells.' + k];
  });
  cellRouting.homeOf = saved.homeOf;
  cellRouting.claimName = saved.claimName;
  cellChannel.relay = saved.relay;
  log.debug("Leaving unstub().");
}

function reset() {
  log.debug("Entering reset().");
  seen.relays.length = 0;
  seen.claims.length = 0;
  seen.lookups = 0;
  multi = true;
  claimAnswer = { ok: true };
  log.debug("Leaving reset().");
}

// A request as `scim.ts` hands one to the placement: its body as text.
function request(method, id, body) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return { method: method, params: id ? { id: id } : {}, headers: {},
           body: body === undefined ? '' : JSON.stringify(body) };
}

function reading(t) {
  log.debug("Entering reading().");
  t.equal(JSON.stringify(scimCells.personKey('urn:uuid:' +
                                             ALICE.toUpperCase())),
          JSON.stringify({ kind: 'uuid', value: ALICE }),
          'a urn:uuid: id is keyed by its bare, lower-cased UUID');
  t.equal(JSON.stringify(scimCells.personKey('uid=bob,ou=users,dc=x')),
          JSON.stringify({ kind: 'name', value: 'bob' }),
          'a DN id is keyed by its RDN value');
  t.equal(scimCells.personKey('bulkId:q1'), null,
          'a bulkId reference names nobody to route by');
  t.equal(scimCells.memberIds({ Operations: [
    { op: 'add', path: 'members', value: [{ value: ALICE }] },
    { op: 'remove', path: 'members[value eq "' + BOB + '"]' }] }).join(','),
          ALICE + ',' + BOB, 'a PatchOp\'s added and removed members are read');
  const asked = {};
  asked[EXT] = { homeCell: ' cac1 ' };
  t.equal(scimCells.homeCellAsked(asked), 'cac1',
          'the home cell is read from the iya-sts User extension');
  log.debug("Leaving reading().");
}

async function placement(t) {
  log.debug("Entering placement().");
  homes[ALICE] = 'usw2';
  homes[BOB] = 'cac1';
  homes.bob = 'cac1';

  reset();
  let placed = await scimCells.place(request('GET', BOB), {},
    { operation: 'read', resourceType: 'User' }, 'default');
  t.check(placed.relayed && seen.relays.length === 1 &&
          seen.relays[0].cell === 'cac1',
          'a person homed in another cell is read there', seen.relays);

  reset();
  placed = await scimCells.place(request('PATCH', ALICE, {}), {},
    { operation: 'modify', resourceType: 'User' }, 'default');
  t.check(!placed.relayed && !seen.relays.length,
          'a person homed here is written here');

  reset();
  const create = { userName: 'carol' };
  create[EXT] = { homeCell: 'cac1' };
  placed = await scimCells.place(request('POST', '', create), {},
    { operation: 'create', resourceType: 'User' }, 'default');
  t.check(placed.relayed && seen.relays[0].cell === 'cac1' &&
          String(seen.relays[0].body).indexOf('carol') >= 0,
          'a create naming another cell is relayed there, body and all');
  t.check(!seen.claims.length, 'the relaying cell claims no name — the ' +
          'cell that creates does');

  reset();
  create[EXT] = { homeCell: 'nowhere' };
  placed = await scimCells.place(request('POST', '', create), {},
    { operation: 'create', resourceType: 'User' }, 'default');
  t.check(!placed.relayed && placed.refusal &&
          placed.refusal.code === 'STS-CELL-0140' &&
          placed.refusal.status === 400,
          'a create naming a cell there is not is refused, not placed');

  reset();
  placed = await scimCells.place(request('PATCH', 'g1', { Operations: [
    { op: 'add', path: 'members', value: [{ value: ALICE }, { value: BOB }] }
  ] }), {}, { operation: 'modify', resourceType: 'Group' }, 'default');
  t.check(placed.refusal && placed.refusal.code === 'STS-CELL-0143' &&
          !seen.relays.length,
          'a Group write naming members in two cells is refused whole');

  reset();
  placed = await scimCells.place(request('PATCH', 'g1', { Operations: [
    { op: 'add', path: 'members', value: [{ value: BOB }] }] }), {},
  { operation: 'modify', resourceType: 'Group' }, 'default');
  t.check(placed.relayed && seen.relays[0].cell === 'cac1',
          'a Group write naming members of one other cell is relayed there');

  reset();
  placed = await scimCells.place(request('POST', '', { Operations: [
    { method: 'PATCH', path: '/Users/' + ALICE, data: {} },
    { method: 'DELETE', path: '/Users/' + BOB }] }), {},
  { operation: 'bulk', resourceType: 'Bulk' }, 'default');
  t.check(placed.refusal && placed.refusal.code === 'STS-CELL-0144' &&
          !seen.relays.length,
          'a BulkRequest spanning cells is refused before anything runs');

  reset();
  placed = await scimCells.place(request('POST', '', { Operations: [
    { method: 'DELETE', path: '/Users/' + BOB },
    { method: 'POST', path: '/Users', bulkId: 'q1', data: create }] }), {},
  { operation: 'bulk', resourceType: 'Bulk' }, 'default');
  t.check(placed.refusal && placed.refusal.code === 'STS-CELL-0140',
          'a BulkRequest with a create naming no cell is refused whole');

  reset();
  create[EXT] = { homeCell: 'cac1' };
  placed = await scimCells.place(request('POST', '', { Operations: [
    { method: 'DELETE', path: '/Users/' + BOB },
    { method: 'POST', path: '/Users', bulkId: 'q1', data: create }] }), {},
  { operation: 'bulk', resourceType: 'Bulk' }, 'default');
  t.check(placed.relayed && seen.relays[0].cell === 'cac1',
          'a BulkRequest all of one other cell is relayed there whole');

  reset();
  placed = await scimCells.place(request('GET', ''), {},
    { operation: 'list', resourceType: 'User' }, 'default');
  t.check(!placed.relayed && !seen.lookups,
          'a list is answered by the serving cell\'s residents (D11)');

  reset();
  const relayedIn = request('GET', BOB);
  relayedIn.stsCellRelay = { from: 'cac1' };
  placed = await scimCells.place(relayedIn, {},
    { operation: 'read', resourceType: 'User' }, 'default');
  t.check(!placed.relayed && !seen.relays.length,
          'a request that arrived relayed is never relayed again');

  reset();
  multi = false;
  placed = await scimCells.place(request('GET', BOB), {},
    { operation: 'read', resourceType: 'User' }, 'default');
  t.check(!placed.relayed && !seen.lookups && !seen.relays.length,
          'single-cell mode asks nothing and relays nothing');
  log.debug("Leaving placement().");
}

async function ingress(t) {
  log.debug("Entering ingress().");
  reset();
  const here = { userName: 'dave' };
  let refused = await scimCells.ingressRefusal(here, true, 'default');
  t.check(refused === null && seen.claims.length === 1 &&
          seen.claims[0].cell === 'usw2',
          'a create homed here claims its login name here first');

  reset();
  claimAnswer = { ok: false, cell: 'cac1' };
  refused = await scimCells.ingressRefusal(here, true, 'default');
  t.check(refused && refused.code === 'STS-CELL-0142' &&
          refused.status === 409 && refused.scimType === 'uniqueness',
          'a login name homed in another cell is refused 409 uniqueness');

  reset();
  const elsewhere = { userName: 'erin' };
  elsewhere[EXT] = { homeCell: 'cac1' };
  refused = await scimCells.ingressRefusal(elsewhere, true, 'default');
  t.check(refused && refused.code === 'STS-CELL-0141' && !seen.claims.length,
          'a create whose home is another cell is not made here');

  reset();
  refused = await scimCells.ingressRefusal(elsewhere, false, 'default');
  t.check(refused && refused.code === 'STS-CELL-0145' &&
          refused.scimType === 'mutability',
          'an update may not move a person to another cell');

  reset();
  multi = false;
  refused = await scimCells.ingressRefusal(elsewhere, true, 'default');
  t.check(refused === null && !seen.claims.length,
          'single-cell mode ignores homeCell and claims nothing');
  log.debug("Leaving ingress().");
}

// A KDC-PROXY-MESSAGE around one Kerberos message, as MS-KKDCP frames it.
function proxyMessage(bytes) {
  log.debug("Entering proxyMessage().");
  const framed = Buffer.alloc(4 + bytes.length);
  framed.writeUInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(framed, 4);
  log.debug("Leaving proxyMessage().");
  return Buffer.from(asn1.encSequence([
    asn1.encContext(0, asn1.encOctetString(framed))]));
}

function asReq(realm, name) {
  log.debug("Entering asReq().");
  log.debug("Leaving asReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: name },
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ['krbtgt', realm] },
      till: new Date(Date.now() + 3600000),
      nonce: 4242,
      etypes: [kcrypto.etypeByName('aes256-cts-hmac-sha1-96').id]
    }
  });
}

async function kdcProxy(t) {
  log.debug("Entering kdcProxy().");
  const realm = principals.REALM;
  const alice = asReq(realm, ['frank']);
  const unframed = krb5Home.messageOf(proxyMessage(alice));
  t.check(!!unframed && Buffer.from(unframed).equals(Buffer.from(alice)),
          'the KDC-PROXY-MESSAGE is unframed to the message it carries');
  t.equal(krb5Home.messageOf(Buffer.from('not DER')), null,
          'a body that is not a KDC-PROXY-MESSAGE is the KDC\'s to refuse');
  const client = await krb5Home.clientOf(alice, null);
  t.check(!!client && client.name === 'frank',
          'an AS-REQ\'s client is its cname', client);
  t.equal(await krb5Home.clientOf(asReq(realm, ['frank', 'admin']), null),
          null, 'a two-component name is nobody to route by');
  t.equal(await krb5Home.clientOf(asReq('ELSEWHERE.INVALID', ['frank']),
                                  null),
          null, 'a name in a realm this KDC does not serve is left to the KDC');

  reset();
  homes.frank = 'cac1';
  const app = { post: function (path, fn) {
    app.route = fn;
  } };
  krb5Home.registerRoutes(app);
  let nexted = false;
  await new Promise(function (resolve) {
    app.route({ body: proxyMessage(alice), headers: {} }, {},
      function () {
        nexted = true;
        resolve();
      });
    setTimeout(resolve, 200);
  });
  t.check(!nexted && seen.relays.length === 1 &&
          seen.relays[0].cell === 'cac1' &&
          seen.relays[0].reason === 'kdc-proxy',
          'an AS-REQ for a person homed elsewhere is relayed, not answered');

  reset();
  homes.frank = 'usw2';
  nexted = false;
  await new Promise(function (resolve) {
    app.route({ body: proxyMessage(alice), headers: {} }, {},
      function () {
        nexted = true;
        resolve();
      });
    setTimeout(resolve, 200);
  });
  t.check(nexted && !seen.relays.length,
          'an AS-REQ for a person homed here goes on to the KDC');

  reset();
  multi = false;
  nexted = false;
  app.route({ body: proxyMessage(alice), headers: {} }, {}, function () {
    nexted = true;
  });
  t.check(nexted && !seen.lookups,
          'single-cell mode hands the request to the KDC at once');
  log.debug("Leaving kdcProxy().");
}

async function run(t) {
  log.debug("Entering run().");
  stub();
  try {
    reading(t);
    await placement(t);
    await ingress(t);
    await kdcProxy(t);
  } finally {
    unstub();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_handlers_c',
  describe: 'Where SCIM and MS-KKDCP requests are answered in a service ' +
            'deployed as cells (#98): a person\'s home, a create\'s named ' +
            'cell, writes spanning cells refused whole, lists served here, ' +
            'and a Kerberos client relayed to its home',
  run: run
};
