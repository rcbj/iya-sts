// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_libraries.js
//
// ---------------------------------------------------------------------------
// THE CELL LIBRARIES' OWN RULES, IN PROCESS (#98). Each is built over stub
// dependencies — the cell map over a stub settings reader, the locator over
// a stub map and a stub keyed digest — so multi-cell behaviour is asserted in
// a process that is itself single-cell, without touching `process.env`:
//
//   1. the cell map: single-cell answers, the peers parsed, the startup
//      refusals, a new person's home and the realm's listed transfers;
//   2. the locator: a stamp is twelve base64url characters, locates back to
//      its cell, is not another cell's, and stamps nothing single-cell;
//   3. a projection carries no credential attribute, by name or by pattern.
//
// The channel, the placement edge and the export are exercised end to end by
// the `cells` mode's jobs (tests/vendored/, `./run-tests.sh --modes=cells`).
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const cellsModule = require('../common/cells');
const locatorModule = require('../common/cell_locator');
const sessionsModule = require('../common/cell_sessions');

const log = require('bunyan').createLogger({ name: 'cell_libraries',
  level: process.env.LOG_LEVEL || 'info' });

// A cell map over fixed settings.
function mapOver(settings) {
  log.debug("Entering mapOver().");
  const quiet = { debug: function () {}, warn: function () {} };
  log.debug("Leaving mapOver().");
  return new cellsModule.Cells({
    value: function (key) {
      return settings[key];
    },
    log: quiet
  });
}

function cellMap(t) {
  log.debug("Entering cellMap().");
  const single = mapOver({});
  t.check(!single.isMulti() && single.isHere('anything'),
          'single-cell mode: not multi, and every cell id is here');
  let threw = false;
  try {
    single.validate();
  } catch (e) {
    log.debug("Caught in cellMap(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(!threw, 'single-cell mode validates');
  const peers = JSON.stringify([
    { id: 'cellb', jurisdiction: 'ca', url: 'https://b.internal:8446' },
    { id: 'celle', jurisdiction: 'eu', url: 'https://e.internal:8446' }]);
  const a = mapOver({ 'cells.id': 'cella', 'cells.jurisdiction': 'us',
                      'cells.peers': peers,
                      'cells.permittedTransfers': ['ca>us'],
                      'cells.jurisdictions': [] });
  t.check(a.isMulti() && a.peers().length === 2 && a.all().length === 3,
          'a cell with two peers knows three cells');
  t.equal(a.jurisdictionOf('celle'), 'eu', 'a peer\'s jurisdiction is known');
  t.check(!a.isHere('cellb') && a.isHere('cella'),
          'another cell is not here; this one is');
  t.check(a.transferListed('ca', 'us') && !a.transferListed('us', 'ca'),
          'a listed transfer is directional');
  t.check(a.transferListed('eu', 'eu'), 'staying in one jurisdiction is ' +
          'always listed');
  t.check(JSON.stringify(a.homeFor('')) === JSON.stringify({ cell: 'cella' }),
          'a new person with no home named is homed here');
  t.check('error' in a.homeFor('nowhere'),
          'a home the service has no cell for is refused');
  const pinned = mapOver({ 'cells.id': 'cella', 'cells.jurisdiction': 'us',
                           'cells.peers': peers,
                           'cells.jurisdictions': ['us', 'ca'] });
  t.check('error' in pinned.homeFor('celle'),
          'a home in a jurisdiction the realm may not place people in is ' +
          'refused');
  t.check(JSON.stringify(a.describe()).indexOf('internal') < 0,
          'the description names no peer\'s address');
  const bad = mapOver({ 'cells.id': 'Cell A', 'cells.jurisdiction': '',
                        'cells.peers': '[{"id":"cella","url":"http://x"}]' });
  let refusal = '';
  try {
    bad.validate();
  } catch (e) {
    refusal = String((e && e.message) || e);
  }
  t.check(/STS-CELL-0001/.test(refusal) && /cells\.id/.test(refusal) &&
          /jurisdiction/.test(refusal) && /mutual TLS/.test(refusal),
          'inconsistent settings are refused naming each problem',
          refusal.slice(0, 160));
  log.debug("Leaving cellMap().");
}

function locator(t) {
  log.debug("Entering locator().");
  const crypto = require('crypto');
  const key = crypto.randomBytes(32);
  const digest = function (label, text) {
    return crypto.createHmac('sha256', key).update(label + ':' + text)
      .digest('base64url');
  };
  const stubMap = function (id) {
    return { isMulti: function () { return true; },
             id: function () { return id; },
             all: function () {
               return [{ id: 'cella' }, { id: 'cellb' }];
             } };
  };
  const atA = new locatorModule.CellLocator({ cells: stubMap('cella'),
                                              digest: digest });
  const atB = new locatorModule.CellLocator({ cells: stubMap('cellb'),
                                              digest: digest });
  const raw = crypto.randomBytes(24).toString('base64url');
  const stamped = atA.stamp(raw);
  t.check(stamped.length === raw.length + 12 && stamped.indexOf(raw) === 0 &&
          /^[A-Za-z0-9_-]+$/.test(stamped),
          'a stamp is twelve base64url characters appended');
  t.equal(atB.locate(stamped), 'cella', 'another cell finds the minting ' +
          'cell from the tag');
  t.equal(atB.elsewhere(stamped), 'cella', 'and knows it is elsewhere');
  t.equal(atA.elsewhere(stamped), '', 'the minting cell knows it is its own');
  t.equal(atB.locate(raw), '', 'an unstamped value locates nowhere');
  const single = new locatorModule.CellLocator({
    cells: { isMulti: function () { return false; },
             id: function () { return ''; },
             all: function () { return []; } },
    digest: digest });
  t.equal(single.stamp(raw), raw, 'single-cell mode stamps nothing');
  log.debug("Leaving locator().");
}

function projection(t) {
  log.debug("Entering projection().");
  const free = sessionsModule.credentialFree({
    uid: ['alice'], cn: ['Alice'], mail: ['alice@example.com'],
    userPassword: ['{SCRYPT}…'], stsTotpCredential: ['$aesgcm$…'],
    stsWebauthnCredential: ['…'], stsBackupCodes: ['…'],
    stsAssertionPrivateKey: ['…'], stsSomeNewSecretThing: ['…'],
    stsAppPassword: ['…'], entryUUID: ['u-1']
  });
  t.check(free.uid && free.cn && free.mail && free.entryUUID,
          'a projection keeps what a protocol reads about the person');
  const leaked = Object.keys(free).filter(function (name) {
    return /password|totp|webauthn|backup|privatekey|secret/i.test(name);
  });
  t.check(!leaked.length, 'a projection carries no credential, by name or ' +
          'by pattern', leaked.join(', ') || 'none');
  log.debug("Leaving projection().");
}

// EACH CELL'S OWN CONSOLE (#361): the one address the Cells page draws,
// recognised on a request's Host, and refused when it is not an origin.
function consoles(t) {
  log.debug("Entering consoles().");
  const peers = JSON.stringify([
    { id: 'cellb', jurisdiction: 'ca', url: 'https://b.internal:8446',
      consoleUrl: 'https://cellb.idp.example/' },
    { id: 'celle', jurisdiction: 'eu', url: 'https://e.internal:8446' }]);
  const a = mapOver({ 'cells.id': 'cella', 'cells.jurisdiction': 'us',
                      'cells.peers': peers,
                      'cells.consoleUrl': 'https://cella.idp.example' });
  const urls = a.all().map(function (c) {
    return c.id + '=' + c.consoleUrl;
  }).join(' ');
  t.check(urls === 'cella=https://cella.idp.example ' +
                   'cellb=https://cellb.idp.example celle=',
          'each cell carries its own console origin, a trailing slash off, ' +
          'and one with none configured carries none', urls);
  t.check(a.consoleOfHost('cellb.idp.example').id === 'cellb' &&
          a.consoleOfHost('CELLA.idp.example:443').id === 'cella' &&
          a.consoleOfHost('idp.example') === null &&
          a.consoleOfHost('') === null,
          'a request\'s Host is recognised as a cell\'s console only when ' +
          'it is one of the configured origins');
  t.check(mapOver({ 'cells.consoleUrl': 'https://x.example' })
            .consoleOfHost('x.example') === null,
          'single-cell mode recognises no console address');
  const described = JSON.stringify(a.describe());
  t.check(described.indexOf('cellb.idp.example') > 0 &&
          described.indexOf('internal') < 0,
          'the description carries the console origins and still no ' +
          'channel address');
  const bad = mapOver({ 'cells.id': 'cella', 'cells.jurisdiction': 'us',
                        'cells.consoleUrl': 'http://cella.idp.example/admin',
                        'cells.peers': JSON.stringify([
                          { id: 'cellb', jurisdiction: 'ca',
                            url: 'https://b.internal:8446',
                            consoleUrl: 'https://x/y' }]) });
  let refusal = '';
  try {
    bad.validate();
  } catch (e) {
    refusal = String((e && e.message) || e);
  }
  t.check(/cells\.consoleUrl "http:/.test(refusal) &&
          /cells\.peers\[0\]\.consoleUrl/.test(refusal),
          'a console address that is not an https origin is refused, this ' +
          'cell\'s and a peer\'s', refusal.slice(0, 200));
  log.debug("Leaving consoles().");
}

async function run(t) {
  log.debug("Entering run().");
  cellMap(t);
  consoles(t);
  locator(t);
  projection(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_libraries',
  describe: 'The cell libraries over stub dependencies (#98): the cell map ' +
            'and its refusals, the locator\'s tag, and a projection without ' +
            'credentials',
  run: run
};
