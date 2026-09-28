// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_placement.js
//
// ---------------------------------------------------------------------------
// WHERE EVERY ROUTE IS SERVED IN A SERVICE DEPLOYED AS CELLS (#98 D10).
//
// `common/cell_placement.ts`'s ROWS is the table, and it is only worth
// something if it is COMPLETE and TRUE:
//
//   1. every endpoint `sts_metadata.ts` describes — which the suite already
//      holds to be every route the router has — is covered by a row, so a
//      new endpoint cannot arrive without somebody deciding where it is
//      served;
//   2. every `handler` row names a file that exists and that actually asks
//      the placement (or relays through the channel) — a row that says "the
//      handler decides" over a handler that does not is the to-do that
//      documents itself as done;
//   3. the helpers the rows rest on do what they say: a named authorization
//      server is placed as the default one is, the longest prefix wins, and
//      a parsed body is re-serialised the way it arrived.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const placement = require('../common/cell_placement');

const log = require('bunyan').createLogger({ name: 'cell_placement',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The endpoint paths sts_metadata.ts describes, read from its source so this
// test does not have to load the whole service to learn them.
function describedPaths() {
  log.debug("Entering describedPaths().");
  const text = fs.readFileSync(path.join(ROOT, 'sts_metadata.ts'), 'utf8');
  const start = text.indexOf('const ENDPOINTS');
  const body = text.slice(start);
  const out = [];
  const re = /\{ path: '([^']+)'/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    out.push(m[1]);
  }
  log.debug("Leaving describedPaths(). " + out.length);
  return out;
}

function everyRouteHasARow(t) {
  log.debug("Entering everyRouteHasARow().");
  const paths = describedPaths();
  t.check(paths.length > 400, 'the endpoint list was read', paths.length +
          ' path(s)');
  const missing = paths.filter(function (p) {
    return !placement.rowFor(p.replace(/:[a-zA-Z_]+/g, 'x'));
  });
  t.check(!missing.length, 'every described endpoint is covered by a ' +
          'placement row', missing.slice(0, 20).join(', ') || 'all');
  log.debug("Leaving everyRouteHasARow().");
}

function handlerRowsAreTrue(t) {
  log.debug("Entering handlerRowsAreTrue().");
  const handlers = placement.ROWS.filter(function (row) {
    return row.strategy === 'handler';
  });
  t.check(handlers.length > 5, 'the table has handler rows', String(
    handlers.length));
  handlers.forEach(function (row) {
    const file = path.join(ROOT, row.handler || '');
    if (!row.handler || !fs.existsSync(file)) {
      t.bad('the handler row ' + row.prefix + ' names a file that exists',
            String(row.handler));
      return;
    }
    const text = fs.readFileSync(file, 'utf8');
    t.check(/cell_placement|cellPlacement|cell_channel|cellChannel/
              .test(text),
            'the handler row ' + row.prefix + ' names a module that asks ' +
            'the placement (' + row.handler + ')');
  });
  rowsHaveReasons(t);
  log.debug("Leaving handlerRowsAreTrue().");
}

// Every row says why; a row with no reason is a decision nobody can check.
function rowsHaveReasons(t) {
  log.debug("Entering rowsHaveReasons().");
  const bare = placement.ROWS.filter(function (row) {
    return !row.why || row.why.length < 10;
  });
  t.check(!bare.length, 'every placement row carries its reason',
          bare.map(function (r) { return r.prefix; }).join(', ') || 'all');
  log.debug("Leaving rowsHaveReasons().");
}

function helpers(t) {
  log.debug("Entering helpers().");
  t.equal(placement.canonicalPath('/tenant1/oauth2/token'), '/oauth2/token',
          'a named authorization server\'s token endpoint is placed as the ' +
          'default one');
  t.equal(placement.canonicalPath('/oauth2/token'), '/oauth2/token',
          'the default one is itself');
  t.equal(placement.canonicalPath('/tenant1/gnap'), '/gnap',
          'a named server\'s GNAP endpoint too');
  t.equal(placement.rowFor('/oauth2/token').strategy, 'handler',
          'the token endpoint is decided by its handler');
  t.equal(placement.rowFor('/oauth2/jwks').strategy, 'local',
          'the key set is served where it arrives');
  t.equal(placement.rowFor('/oauth2/authorize').strategy, 'artifact',
          'the authorization endpoint looks for a pushed request');
  t.equal(placement.rowFor('/scim/v2/Schemas/x').strategy, 'local',
          'the longest prefix wins over /scim');
  t.equal(placement.rowFor('/.well-known/est/simpleenroll').strategy,
          'handler', 'EST under .well-known is an enrollment, not metadata');
  const form = placement.serialisedBody({ method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: { grant_type: 'authorization_code', code: 'abc', scope: ['a', 'b'] }
  }).toString('utf8');
  t.equal(form, 'grant_type=authorization_code&code=abc&scope=a&scope=b',
          'a parsed form is re-serialised as a form');
  const json = placement.serialisedBody({ method: 'POST',
    headers: { 'content-type': 'application/json' }, body: { a: 1 }
  }).toString('utf8');
  t.equal(json, '{"a":1}', 'a parsed JSON body is re-serialised as JSON');
  const raw = placement.serialisedBody({ method: 'POST',
    headers: { 'content-type': 'text/xml' }, body: '<x/>'
  }).toString('utf8');
  t.equal(raw, '<x/>', 'a text body is sent as it came');
  t.equal(placement.serialisedBody({ method: 'POST', body: { a: 1 },
    rawBody: Buffer.from('{ "a" : 1 }') }).toString('utf8'), '{ "a" : 1 }',
          'the bytes as they arrived win over a re-serialisation');
  t.equal(placement.serialisedBody({ method: 'GET', body: {} }).length, 0,
          'a GET sends no body');
  log.debug("Leaving helpers().");
}

async function run(t) {
  log.debug("Entering run().");
  everyRouteHasARow(t);
  handlerRowsAreTrue(t);
  helpers(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_placement',
  describe: 'Where every route is served when the service is deployed as ' +
            'cells (#98 D10): every endpoint has a placement row, every ' +
            'handler row names a module that asks, and the helpers behave',
  run: run
};
