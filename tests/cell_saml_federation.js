// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_saml_federation.js
//
// ---------------------------------------------------------------------------
// SAML, WS-TRUST AND FEDERATION IN A SERVICE DEPLOYED AS CELLS (#98 D10), IN
// PROCESS, with the cell map, the key and the channel stubbed. What a running
// pair of cells would show, pinned at the function:
//
//   1. a fixed-layout handle carries its cell in its last four bytes, keeps
//      its first sixteen, and says nothing in single-cell mode;
//   2. a SAML 2.0 and a SAML 1.1 artifact minted in one cell are relayed —
//      the whole SOAP body, before anything is spent — by the other cell's
//      resolver, and one this cell minted is not;
//   3. a SAML 1.1 AssertionID and a federation flow handle are stamped and
//      still fit the patterns and the 80-byte RelayState they must;
//   4. a query's session holder is asked of the peers, and a peer that
//      cannot be reached leaves the query here;
//   5. a partner's sign-out matches the same sessions in every cell
//      (`matcherOf()`), and both inter-cell operations are registered;
//   6. `relayToCell()` relays nothing in single-cell mode, nothing already
//      relayed, and nothing to a cell the map does not have.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'cell_saml_federation',
  level: process.env.LOG_LEVEL || 'info' });

const HERE = 'cac1';
const THERE = 'usw2';
const KEY = nodeCrypto.randomBytes(32);

// Replaces properties of a module's exports, and returns the function that
// puts them back.
function stub(target, replacements) {
  log.debug("Entering stub().");
  const saved = {};
  Object.keys(replacements).forEach(function (k) {
    saved[k] = target[k];
    target[k] = replacements[k];
  });
  log.debug("Leaving stub().");
  return function restore() {
    log.debug("Entering restore().");
    Object.keys(saved).forEach(function (k) {
      target[k] = saved[k];
    });
    log.debug("Leaving restore().");
  };
}

// Two cells, this one being `id`.
function cellMap(cells, id, multi) {
  log.debug("Entering cellMap().");
  const all = [{ id: HERE, jurisdiction: 'ca', url: 'https://cac1:8446',
                 self: id === HERE },
               { id: THERE, jurisdiction: 'us', url: 'https://usw2:8446',
                 self: id === THERE }];
  log.debug("Leaving cellMap().");
  return stub(cells, {
    isMulti: function () {
      log.debug("Entering isMulti().");
      log.debug("Leaving isMulti().");
      return multi;
    },
    id: function () {
      log.debug("Entering id().");
      log.debug("Leaving id().");
      return id;
    },
    all: function () {
      log.debug("Entering all().");
      log.debug("Leaving all().");
      return multi ? all : all.filter(function (one) {
        return one.id === id;
      });
    },
    peers: function () {
      log.debug("Entering peers().");
      log.debug("Leaving peers().");
      return multi ? all.filter(function (one) {
        return one.id !== id;
      }) : [];
    },
    get: function (cellId) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return all.filter(function (one) {
        return one.id === cellId;
      })[0] || null;
    }
  });
}

// 1. The fixed-layout tag.
function handles(t, cells, cellLocator) {
  log.debug("Entering handles().");
  let restore = cellMap(cells, THERE, true);
  cellLocator.reset();
  const raw = nodeCrypto.randomBytes(20);
  const stamped = cellLocator.stampBytes(raw, 4);
  t.check(stamped.length === 20 &&
          stamped.subarray(0, 16).equals(raw.subarray(0, 16)),
          'a stamped handle keeps its length and its first sixteen bytes');
  t.check(stamped.subarray(16).equals(cellLocator.tagBytes(THERE, 4)),
          'and ends in the minting cell\'s four-byte tag');
  t.equal(cellLocator.locateBytes(stamped, 4), THERE,
          'the minting cell is read back from it');
  t.equal(cellLocator.elsewhereBytes(stamped, 4), '',
          'and it is not "elsewhere" in the cell that minted it');
  restore();
  restore = cellMap(cells, HERE, true);
  t.equal(cellLocator.elsewhereBytes(stamped, 4), THERE,
          'the other cell finds it minted elsewhere');
  restore();
  restore = cellMap(cells, HERE, false);
  t.check(cellLocator.stampBytes(raw, 4) === raw,
          'single-cell mode stamps nothing');
  t.equal(cellLocator.locateBytes(stamped, 4), '',
          'and reads nothing');
  restore();
  log.debug("Leaving handles().");
  return stamped;
}

// 2. The two resolvers relay an artifact another cell minted.
async function artifacts(t, cells, cellLocator, samlCells) {
  log.debug("Entering artifacts().");
  require('../ldap/ldap_server');
  const saml2sso = require('../saml/saml2_sso');
  const saml11sso = require('../saml/saml11_sso');
  const channel = require('../common/cell_channel');
  const kit = require('./tools/saml_signing_kit');
  const relays = [];
  const restoreChannel = stub(channel, {
    relay: function (req, res, cellId, opts) {
      log.debug("Entering relay().");
      relays.push({ cell: cellId, opts: opts || {} });
      res.status(200).send('relayed');
      log.debug("Leaving relay().");
      return Promise.resolve();
    }
  });
  let restore = cellMap(cells, THERE, true);
  cellLocator.reset();
  const handle = samlCells.stampHandle(nodeCrypto.randomBytes(20));
  restore();
  const header2 = Buffer.from([0, 4, 0, 0]);
  const source = nodeCrypto.createHash('sha1').update('idp').digest();
  const art2 = Buffer.concat([header2, source, handle]).toString('base64');
  const art11 = Buffer.concat([Buffer.from([0, 1]), source, handle])
    .toString('base64');
  restore = cellMap(cells, HERE, true);
  t.equal(samlCells.artifactCell(art2, 44), THERE,
          'a SAML 2.0 artifact minted in the other cell names it');
  t.equal(samlCells.artifactCell(art11, 42), THERE,
          'so does a SAML 1.1 artifact');
  t.equal(samlCells.artifactCell(art11, 44), '',
          'a value of the wrong length names nobody');

  const direct2 = new saml2sso.Saml2Sso(saml2sso.Saml2Sso.defaultDeps());
  const envelope2 = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/' +
    'soap/envelope/"><soap:Body><samlp:ArtifactResolve xmlns:samlp="urn:' +
    'oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:' +
    '2.0:assertion" ID="_r1" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '"><saml:Issuer>https://sp.test</saml:Issuer>' +
    '<samlp:Artifact>' + art2 + '</samlp:Artifact></samlp:ArtifactResolve>' +
    '</soap:Body></soap:Envelope>';
  const req2 = kit.fakeReq('POST', '/saml2/ars', {}, '', envelope2,
    { headers: { host: 'idp.test', 'content-type': 'text/xml' } });
  const res2 = kit.fakeRes();
  direct2['resolveArtifact'](req2, res2);
  t.check(relays.length === 1 && relays[0].cell === THERE &&
          String(relays[0].opts.body || '') === envelope2,
          'the ArtifactResolve is relayed WHOLE to the minting cell',
          JSON.stringify(relays.map(function (r) {
            return r.cell;
          })));

  const direct11 = new saml11sso.Saml11Sso(saml11sso.Saml11Sso.defaultDeps());
  const envelope11 = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org' +
    '/soap/envelope/"><soap:Body><samlp:Request xmlns:samlp="urn:oasis:' +
    'names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" ' +
    'RequestID="_q1" IssueInstant="' + new Date().toISOString() + '">' +
    '<samlp:AssertionArtifact>' + art11 + '</samlp:AssertionArtifact>' +
    '</samlp:Request></soap:Body></soap:Envelope>';
  const req11 = kit.fakeReq('POST', '/saml11/responder', {}, '', envelope11,
    { headers: { host: 'idp.test', 'content-type': 'text/xml' } });
  req11.params = {};
  direct11['respond'](req11, kit.fakeRes());
  t.check(relays.length === 2 && relays[1].cell === THERE,
          'the SAML 1.1 artifact Request is relayed to the minting cell too');

  // Relayed already: served here, never relayed again.
  const again = kit.fakeReq('POST', '/saml2/ars', {}, '', envelope2,
    { headers: { host: 'idp.test', 'content-type': 'text/xml' },
      stsCellRelay: true });
  const resAgain = kit.fakeRes();
  direct2['resolveArtifact'](again, resAgain);
  await resAgain.done;
  t.check(relays.length === 2 && /ArtifactResponse/.test(resAgain.body),
          'a request relayed once is answered where it landed');
  restore();
  restoreChannel();
  log.debug("Leaving artifacts().");
}

// 3. Stamped identifiers still fit.
function identifiers(t, cells, cellLocator) {
  log.debug("Entering identifiers().");
  const helpers = require('../common/helpers');
  const restore = cellMap(cells, THERE, true);
  cellLocator.reset();
  const id = cellLocator.stamp(helpers.genId());
  t.check(/^_[0-9a-f]{32}[A-Za-z0-9_-]{12}$/.test(id),
          'a stamped SAML 1.1 AssertionID is still an xsd:ID', id);
  const handle = 'fed-' + cellLocator.stamp(helpers.randomId(18));
  t.check(/^fed-[A-Za-z0-9_-]{1,64}$/.test(handle) && handle.length <= 80,
          'a stamped federation handle fits its pattern and a RelayState',
          handle);
  t.equal(cellLocator.locate(handle), THERE,
          'and names the cell that holds the flow');
  restore();
  log.debug("Leaving identifiers().");
}

// 4. The session holder of a query.
async function holders(t, cells, samlCells) {
  log.debug("Entering holders().");
  const channel = require('../common/cell_channel');
  let restore = cellMap(cells, HERE, true);
  let restoreChannel = stub(channel, {
    call: function (cellId, name, body) {
      log.debug("Entering call().");
      log.debug("Leaving call().");
      return Promise.resolve({ holds: cellId === THERE &&
                               name === samlCells.HOLDER_OP &&
                               body.nameId === 'nid-1' });
    }
  });
  t.equal(await samlCells.sessionHolder({}, 'saml2', 'https://sp.test',
                                        'nid-1'), THERE,
          'the peer holding the session is found');
  t.equal(await samlCells.sessionHolder({ stsCellRelay: true }, 'saml2',
                                        'https://sp.test', 'nid-1'), '',
          'a relayed query is not placed again');
  restoreChannel();
  restoreChannel = stub(channel, {
    call: function () {
      log.debug("Entering call().");
      log.debug("Leaving call().");
      return Promise.reject(new Error('unreachable'));
    }
  });
  t.equal(await samlCells.sessionHolder({}, 'saml11', 'rp', 'nid-1'), '',
          'a peer that cannot be asked leaves the query here');
  restoreChannel();
  restore();
  restore = cellMap(cells, HERE, false);
  t.equal(await samlCells.sessionHolder({}, 'saml2', 'https://sp.test',
                                        'nid-1'), '',
          'single-cell mode asks nobody');
  t.equal(samlCells.answer({ realm: '', profile: 'saml2',
                             party: 'https://sp.test',
                             nameId: 'nobody-' + Date.now() }).holds, false,
          'a cell holding no such session says so');
  restore();
  log.debug("Leaving holders().");
}

// 5. The partner sign-out's one predicate, and the operations.
function signOut(t) {
  log.debug("Entering signOut().");
  const slo = require('../federation/federation_slo');
  const matcherOf = slo.FederationSlo.matcherOf;
  const oidc = matcherOf({ protocol: 'oidc', sid: 's1', sub: '' });
  t.check(oidc({ protocol: 'oidc', sid: 's1' }) &&
          !oidc({ protocol: 'oidc', sid: 's2' }) &&
          !oidc({ protocol: 'saml2', sid: 's1' }),
          'an OpenID Connect sign-out matches its sid and nothing else');
  t.check(!matcherOf({ protocol: 'oidc' })({ protocol: 'oidc' }),
          'one naming neither sid nor sub matches nothing');
  const saml = matcherOf({ protocol: 'saml', nameId: { value: 'n1' },
                           indexes: ['i1'] });
  t.check(saml({ protocol: 'saml2', nameId: 'n1', sessionIndex: 'i1' }) &&
          !saml({ protocol: 'saml2', nameId: 'n1', sessionIndex: 'i2' }) &&
          !saml({ protocol: 'saml2', nameId: 'n2', sessionIndex: 'i1' }),
          'a SAML sign-out matches its NameID and SessionIndex');
  t.check(matcherOf({ protocol: 'saml', nameId: { value: 'n1' } })(
    { protocol: 'wsfed', nameId: 'n1', sessionIndex: 'any' }),
          'with no SessionIndex every session of the principal');
  t.check(!matcherOf({ protocol: 'kerberos' })({ protocol: 'oidc' }),
          'an unknown match matches nothing');
  require('../saml/saml_cells');
  const names = require('../common/cell_channel').opNames();
  t.check(names.indexOf('saml-session-holder') >= 0 &&
          names.indexOf('federation-partner-signout') >= 0,
          'both inter-cell operations are registered', names.join(', '));
  log.debug("Leaving signOut().");
}

// 6. The relay helper's refusals.
function relayRefusals(t, cells) {
  log.debug("Entering relayRefusals().");
  const placement = require('../common/cell_placement');
  const channel = require('../common/cell_channel');
  let relayed = 0;
  const restoreChannel = stub(channel, {
    relay: function () {
      log.debug("Entering relay().");
      relayed += 1;
      log.debug("Leaving relay().");
      return Promise.resolve();
    }
  });
  let restore = cellMap(cells, HERE, false);
  t.equal(placement.relayToCell({}, {}, THERE, 'test'), false,
          'single-cell mode relays nothing');
  restore();
  restore = cellMap(cells, HERE, true);
  t.equal(placement.relayToCell({ stsCellRelay: true }, {}, THERE, 'test'),
          false, 'a relayed request is not relayed again');
  t.equal(placement.relayToCell({}, {}, 'nowhere', 'test'), false,
          'nor to a cell the map does not have');
  t.equal(placement.relayToCell({}, {}, HERE, 'test'), false,
          'nor to this cell');
  t.equal(placement.relayToCell({ body: 'x', headers: {} }, {}, THERE,
                                'test'), true,
          'and to a peer it relays');
  t.equal(relayed, 1, 'once');
  restore();
  restoreChannel();
  log.debug("Leaving relayRefusals().");
}

async function run(t) {
  log.debug("Entering run().");
  const cells = require('../common/cells');
  const cellLocator = require('../common/cell_locator');
  const keystore = require('../common/keystore');
  const errorCodes = require('../common/error_codes');
  // THE KEY every cell holds, as a digest the locator can make: stubbed so
  // this file installs no key-encryption key another test would inherit.
  const restoreKey = stub(keystore, {
    keyedDigest: function (label, text) {
      log.debug("Entering keyedDigest().");
      log.debug("Leaving keyedDigest().");
      return nodeCrypto.createHmac('sha256', KEY)
        .update(String(label) + '\n' + String(text)).digest('base64url');
    }
  });
  try {
    handles(t, cells, cellLocator);
    const samlCells = require('../saml/saml_cells');
    await artifacts(t, cells, cellLocator, samlCells);
    identifiers(t, cells, cellLocator);
    await holders(t, cells, samlCells);
    signOut(t);
    relayRefusals(t, cells);
    ['STS-CELL-0120', 'STS-CELL-0121', 'STS-CELL-0122']
      .forEach(function (code) {
        t.check(errorCodes.isKnown(code), code + ' is registered');
      });
  } finally {
    restoreKey();
    cellLocator.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_saml_federation',
  describe: 'SAML, WS-Trust and federation across cells (#98 D10): artifact ' +
            'handles carry their cell and are resolved there, a query is ' +
            'answered where its session is held, and a partner\'s sign-out ' +
            'matches the same sessions in every cell',
  run: run
};
