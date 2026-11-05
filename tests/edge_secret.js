// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: edge_secret.js
//
// ---------------------------------------------------------------------------
// A CDN'S EDGES ARE EVERYBODY'S (#1336, common/client_address.js): a request
// from `global.edgeProxies` must carry `global.edgeSecret`, and the header is
// gone from the request whatever the answer. In process, because the peer of a
// request arriving over HTTP is the test runner and cannot be an edge.
// ---------------------------------------------------------------------------
'use strict';

const config = require('../common/config');
const clientAddress = require('../common/client_address');

function fromPeer(peer, secret) {
  const req = { socket: { remoteAddress: peer }, headers: {}, rawHeaders: [] };
  if (secret !== undefined) {
    req.headers['x-origin-verify'] = secret;
    req.rawHeaders.push('X-Origin-Verify', secret);
  }
  req.rawHeaders.push('Accept', '*/*');
  return req;
}

function run(t) {
  const EDGE = '198.51.100.7';
  const OTHER = '203.0.113.9';
  try {
    t.ok(!clientAddress.edgeRefused(fromPeer(EDGE)),
      '1. no ranges configured: nothing is asked of anybody');

    config.setOverride('global.edgeProxies', '198.51.100.0/24, not-a-range');
    t.ok(clientAddress.edgeRefused(fromPeer(EDGE, 'anything')),
      '2. ranges with no secret refuse every edge: a half-made deployment ' +
      'fails closed');
    t.ok(clientAddress.edgeRefused(fromPeer(EDGE, '')),
      '3. an empty header never matches an empty secret');

    config.setOverride('global.edgeSecret', 's3cret');
    t.ok(!clientAddress.edgeRefused(fromPeer(EDGE, 's3cret')),
      '4. an edge with the secret passes');
    t.ok(clientAddress.edgeRefused(fromPeer(EDGE, 'wrong')),
      '5. an edge with the wrong secret is refused');
    t.ok(clientAddress.edgeRefused(fromPeer('::ffff:' + EDGE)),
      '6. an edge with no secret is refused, IPv4-mapped peer included');
    t.ok(!clientAddress.edgeRefused(fromPeer(OTHER)),
      '7. a peer outside the ranges is not claiming to be an edge');
    t.ok(clientAddress.edgeRefused(fromPeer('198.51.100.8', 'wrong')) &&
         !clientAddress.edgeRefused(fromPeer('198.51.101.8', 'wrong')),
      '8. a value that is not a range is ignored, never widened');

    [fromPeer(EDGE, 's3cret'), fromPeer(EDGE, 'wrong'),
      fromPeer(OTHER, 's3cret')].forEach(function (req, i) {
      clientAddress.edgeRefused(req);
      t.ok(req.headers['x-origin-verify'] === undefined &&
           req.rawHeaders.length === 2 && req.rawHeaders[0] === 'Accept',
        '9.' + i + ' the header is off the request, parsed and raw alike, ' +
        'whatever the answer');
    });
  } finally {
    config.clearOverride('global.edgeSecret');
    config.clearOverride('global.edgeProxies');
    clientAddress.reset();
  }
}

module.exports = {
  name: 'edge_secret',
  describe: 'A CDN edge must carry this deployment\'s secret, and the header ' +
            'never travels further',
  run: run
};
