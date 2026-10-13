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
//   5. RAW TCP AND UDP 88 (#588): the KDC's real listeners on an ephemeral
//      port, the router `krb5_home.install()` sets, and the inter-cell
//      channel's `call()` stubbed — answered by the `kdc-message` operation's
//      own handler, in process, so the round trip through JSON is real. A
//      request whose client is homed elsewhere is relayed and its reply
//      framed for the transport; one homed here is answered locally; a
//      router that throws falls through; RFC 4120 section 7.2.1's UDP size
//      limit holds for a relayed reply; an unreachable home is
//      KDC_ERR_SVC_UNAVAILABLE; single-cell mode sets no router; and with no
//      router the sockets answer as they always did.
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
const net = require('net');
const dgram = require('dgram');

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

// One message over TCP 88's framing, and the reply unframed.
function overTcp(port, bytes) {
  log.debug("Entering overTcp().");
  log.debug("Leaving overTcp().");
  return new Promise(function (resolve, reject) {
    const socket = net.connect(port, '127.0.0.1');
    let got = Buffer.alloc(0);
    const timer = setTimeout(function () {
      socket.destroy();
      reject(new Error('no TCP reply in 5 s'));
    }, 5000);
    socket.on('error', function (e) {
      clearTimeout(timer);
      reject(e);
    });
    socket.on('data', function (chunk) {
      got = Buffer.concat([got, chunk]);
      if (got.length >= 4 && got.length >= 4 + got.readUInt32BE(0)) {
        clearTimeout(timer);
        socket.end();
        resolve({ declared: got.readUInt32BE(0),
                  message: got.subarray(4, 4 + got.readUInt32BE(0)) });
      }
    });
    const framed = Buffer.alloc(4 + bytes.length);
    framed.writeUInt32BE(bytes.length, 0);
    Buffer.from(bytes).copy(framed, 4);
    socket.write(framed);
  });
}

// One datagram to UDP 88, and the datagram that answers it.
function overUdp(port, bytes) {
  log.debug("Entering overUdp().");
  log.debug("Leaving overUdp().");
  return new Promise(function (resolve, reject) {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(function () {
      socket.close();
      reject(new Error('no UDP reply in 5 s'));
    }, 5000);
    socket.on('message', function (message) {
      clearTimeout(timer);
      socket.close();
      resolve(message);
    });
    socket.send(Buffer.from(bytes), port, '127.0.0.1');
  });
}

// The KRB-ERROR code a reply carries, or null for a reply that is not one.
function errorCodeOf(reply) {
  log.debug("Entering errorCodeOf().");
  try {
    log.debug("Leaving errorCodeOf().");
    return msgs.readKrbError(reply).errorCode;
  } catch (e) {
    log.debug("Caught in errorCodeOf(): " + ((e && e.message) || e));
    return null;
  }
}

async function rawSockets(t) {
  log.debug("Entering rawSockets().");
  const kdc = require('../kerberos/krb5_kdc.js');
  const realm = principals.REALM;
  const frank = asReq(realm, ['frank']);
  const listeners = kdc.listen(0);
  await listeners.whenReady;
  const port = listeners.port;
  // The other cell, as `cell_channel.call()` reaches it: the operation's
  // own handler, through JSON both ways, or what a test sets `homeAnswer` to.
  const calls = [];
  let homeAnswer = null;
  const savedCall = cellChannel.call;
  cellChannel.call = function (cellId, name, body) {
    calls.push({ cell: cellId, name: name, body: body });
    if (homeAnswer) {
      return homeAnswer(body);
    }
    return krb5Home.answerRelayed(JSON.parse(JSON.stringify(body)),
                                  { peer: 'usw2' })
      .then(function (answer) {
        return JSON.parse(JSON.stringify(answer));
      });
  };
  try {
    // --- No router: what the sockets did before #588. ---
    reset();
    kdc.setMessageRouter(null);
    const before = (await overTcp(port, frank)).message;
    t.check(!!msgs.identify(before) && !calls.length && !seen.lookups,
            'with no router a TCP message is answered here, nothing asked');
    const beforeUdp = await overUdp(port, frank);
    t.check(!!msgs.identify(beforeUdp) && !calls.length,
            'with no router a UDP message is answered here');

    // --- Single-cell mode sets no router. ---
    reset();
    multi = false;
    t.equal(krb5Home.install(kdc), false,
            'single-cell mode installs no message router');
    await overTcp(port, frank);
    t.check(!calls.length && !seen.lookups,
            'and port 88 asks nothing of the routing index');
    t.check(require('../common/cell_channel').opNames()
      .indexOf(krb5Home.KDC_MESSAGE_OP) >= 0,
            'the kdc-message operation is registered');

    // --- Multi-cell: the router installed. ---
    reset();
    t.equal(krb5Home.install(kdc), true,
            'a service deployed as cells installs the router');

    reset();
    homes.frank = 'cac1';
    const relayed = await overTcp(port, frank);
    t.check(calls.length === 1 && calls[0].cell === 'cac1' &&
            calls[0].name === 'kdc-message' &&
            calls[0].body.transport === 'tcp' &&
            /127\.0\.0\.1/.test(calls[0].body.address) &&
            Buffer.from(calls[0].body.message, 'base64').equals(frank),
            'a TCP AS-REQ for a person homed elsewhere is sent home whole, ' +
            'with its transport and client address', calls[0]);
    t.check(!!msgs.identify(relayed.message) &&
            relayed.declared === relayed.message.length,
            'and the home cell\'s reply is framed with its length prefix');

    reset();
    calls.length = 0;
    homes.frank = 'cac1';
    const relayedUdp = await overUdp(port, frank);
    t.check(calls.length === 1 && calls[0].body.transport === 'udp' &&
            !!msgs.identify(relayedUdp),
            'a UDP AS-REQ for a person homed elsewhere is answered at home');

    // A reply the home cell made that is too big for a datagram.
    reset();
    calls.length = 0;
    const marker = kdc.errorReply(60, { eText: 'answered by cac1' });
    const big = Buffer.concat([Buffer.from(marker), Buffer.alloc(4000)]);
    homeAnswer = function () {
      return Promise.resolve({ reply: big.toString('base64'),
                               refusal: null });
    };
    const tooBig = await overUdp(port, frank);
    t.equal(errorCodeOf(tooBig), 52,
            'a relayed reply too big for UDP is KRB_ERR_RESPONSE_TOO_BIG, ' +
            'exactly as one made here');
    const wholeOverTcp = await overTcp(port, frank);
    t.check(wholeOverTcp.message.equals(big),
            'and over TCP the same relayed reply arrives whole');
    homeAnswer = function () {
      return Promise.resolve({
        reply: Buffer.from(marker).toString('base64'), refusal: null });
    };
    const small = await overUdp(port, frank);
    t.check(msgs.readKrbError(small).eText === 'answered by cac1',
            'a relayed reply that fits is the home cell\'s, byte for byte');

    // A home cell that cannot be reached: fail-closed.
    reset();
    homeAnswer = function () {
      return Promise.reject(new Error('connect ECONNREFUSED'));
    };
    const unreachable = await overTcp(port, frank);
    t.equal(errorCodeOf(unreachable.message), 29,
            'an unreachable home cell is KDC_ERR_SVC_UNAVAILABLE, not an ' +
            'answer here');
    homeAnswer = null;

    // A realm's hard geofence: refused here, not carried.
    reset();
    calls.length = 0;
    const transfer = require('../common/cell_transfer');
    const savedServe = transfer.serveDecision;
    transfer.serveDecision = function () {
      return require('../common/error_codes').mark({ allowed: false,
        relay: false, why: 'geofenced' }, 'STS-CELL-0183');
    };
    let fenced = null;
    try {
      fenced = await overTcp(port, frank);
    } finally {
      transfer.serveDecision = savedServe;
    }
    t.check(errorCodeOf(fenced.message) === 12 && !calls.length,
            'a hard geofence refuses KDC_ERR_POLICY and relays nothing');

    // Homed here, or nobody to route by: answered where it arrived.
    reset();
    calls.length = 0;
    homes.frank = 'usw2';
    await overTcp(port, frank);
    t.check(!calls.length && seen.lookups === 1,
            'a person homed here is answered here');
    reset();
    calls.length = 0;
    await overTcp(port, asReq(realm, ['frank', 'admin']));
    await overUdp(port, Buffer.from('not Kerberos'));
    t.check(!calls.length && !seen.lookups,
            'a multi-component name and an undecodable message are the ' +
            'KDC\'s to answer here');

    // A router that throws: logged, and the message answered here.
    reset();
    calls.length = 0;
    kdc.setMessageRouter(function () {
      throw new Error('a router that fails');
    });
    const fell = await overTcp(port, frank);
    t.check(!!msgs.identify(fell.message) && !calls.length,
            'a router that throws falls through to this cell\'s KDC');
    kdc.setMessageRouter(function () {
      return Promise.resolve(null);
    });
    const declined = await overUdp(port, frank);
    t.check(!!msgs.identify(declined) && errorCodeOf(declined) !== 29,
            'a router that answers null leaves the message to this KDC');

    // The home half on its own: no message is a failed operation.
    let threw = false;
    try {
      await krb5Home.answerRelayed({}, { peer: 'cac1' });
    } catch (e) {
      log.debug("Caught in rawSockets(): " + ((e && e.message) || e));
      threw = /STS-KRB-0208/.test(String(e && e.message));
    }
    t.check(threw, 'an operation carrying no message fails, coded');
  } finally {
    kdc.setMessageRouter(null);
    cellChannel.call = savedCall;
    listeners.tcp.close();
    if (listeners.udp) {
      listeners.udp.close();
    }
  }
  log.debug("Leaving rawSockets().");
}

async function run(t) {
  log.debug("Entering run().");
  stub();
  try {
    reading(t);
    await placement(t);
    await ingress(t);
    await kdcProxy(t);
    await rawSockets(t);
  } finally {
    unstub();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_handlers_c',
  describe: 'Where SCIM, MS-KKDCP and TCP/UDP 88 requests are answered ' +
            'in a service deployed as cells (#98, #588): a person\'s home, ' +
            'a create\'s named cell, writes spanning cells refused whole, ' +
            'lists served here, and a Kerberos client relayed to its home ' +
            'over either door',
  run: run
};
