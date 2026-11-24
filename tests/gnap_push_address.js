// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: gnap_push_address.js
//
// ===========================================================================
// GNAP'S PUSH FINISH URI UNDER THE OUTBOUND POLICY'S ADDRESS RULES (#1614,
// ASVS 5.0.0 1.3.6).
//
// The finish URI arrives on the grant request, so it is the caller's kind of
// URL, and `gnap/gnap_http.ts` now dials it the way an RFC 9101
// `request_uri` is dialled since #1609: through
// `federation/federation_http.ts`'s `outboundAllowed()`, `vetHost()` and
// `pinnedLookup()`. In process, against listeners on loopback:
//
//   A. PRODUCT: a push to a loopback address is refused STS-GNAP-0606 and
//      NOTHING reaches the listener; `addressVerdict()`, which the grant
//      request asks, refuses it the same way.
//   B. `security.outboundAllowedHosts` leaving the host out refuses it, in
//      development too.
//   C. `federation.outbound` off refuses it, and nothing is dialled.
//   D. PRODUCT, A PUBLIC-STANDING HOST: a name `vetHost()` answered with an
//      address is dialled, over https verified against the push CA, and the
//      connection goes to THAT address — the name itself resolves nowhere, so
//      a delivery proves the lookup was pinned.
//   E. DEVELOPMENT, NO LIST: loopback is still dialled, as before.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const testCa = require('./protocol/outbound_test_ca');

const log = require('bunyan').createLogger({ name: 'gnap_push_address',
  level: process.env.LOG_LEVEL || 'info' });

// A listener on loopback that records every request it is sent.
function listen(options, seen) {
  log.debug("Entering listen().");
  const server = (options ? https : http).createServer(options || {},
                                                       function (req, res) {
    req.resume();
    req.on('end', function () {
      seen.push(req.url);
      res.writeHead(204);
      res.end();
    });
  });
  log.debug("Leaving listen().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const gnapHttp = require('../gnap/gnap_http');
  const fedHttp = require('../federation/federation_http');
  const transport = gnapHttp.PUSH_TRANSPORT;

  const ca = await testCa.makeCa();
  const leaf = await testCa.listenerCertificate(ca, 'push.example');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gnap-push-address-'));
  const caFile = path.join(dir, 'ca.crt');
  fs.writeFileSync(caFile, ca.certPem);

  const seen = [];
  const plain = await listen(null, seen);
  const secure = await listen(leaf, seen);
  const plainUri = 'http://127.0.0.1:' + plain.address().port + '/push';
  const publicUri = 'https://push.example:' + secure.address().port +
                    '/push';

  const touched = ['global.mode', 'gnap.pushFinish', 'federation.outbound',
                   'security.outboundAllowedHosts', transport.allowHttpKey,
                   transport.caFileKey];
  const set = function (key, value) {
    const result = config.setOverride(key, value);
    if (!result.ok) {
      throw new Error('setting ' + key + ' was refused: ' +
                      result.errors.join(' '));
    }
  };
  const push = async function (uri) {
    const r = await gnapHttp.pushFinish(uri, { hash: 'h',
                                               interact_ref: 'r' });
    return { ok: r.ok, code: r.errorCode || '', why: r.why || '' };
  };
  const realVetHost = fedHttp.vetHost;
  try {
    set('gnap.pushFinish', true);
    set('federation.outbound', true);
    // Plain http to loopback is what product allows with the switch on
    // (RFC 9635 section 2.5.2.1), so A is about the address and not the
    // scheme.
    set(transport.allowHttpKey, true);
    set(transport.caFileKey, caFile);

    t.log.info('=== A. product: a loopback address is not dialled ===');
    set('global.mode', 'product');
    let before = seen.length;
    let r = await push(plainUri);
    t.check(!r.ok && r.code === 'STS-GNAP-0606',
            'A1. a push to 127.0.0.1 is refused STS-GNAP-0606', r.why);
    t.check(/loopback, private, link-local or reserved/.test(r.why),
            'A2. and the reason names the internal-address rule', r.why);
    t.equal(seen.length, before, 'A3. and nothing reached the listener');
    const verdict = await gnapHttp.addressVerdict(plainUri);
    t.check(!verdict.ok && verdict.errorCode === 'STS-GNAP-0606',
            'A4. addressVerdict(), which the grant request asks, refuses it',
            JSON.stringify(verdict));
    const notUrl = await gnapHttp.addressVerdict('not a url');
    t.check(notUrl.ok,
            'A5. a URI that is not a URL is left to urlVerdict()',
            JSON.stringify(notUrl));

    t.log.info('=== B. security.outboundAllowedHosts ===');
    set('global.mode', 'development');
    set('security.outboundAllowedHosts', 'elsewhere.example');
    before = seen.length;
    r = await push(plainUri);
    t.check(!r.ok && r.code === 'STS-GNAP-0606' &&
            /security\.outboundAllowedHosts/.test(r.why),
            'B1. a host the list leaves out is refused, in development too',
            r.why);
    t.equal(seen.length, before, 'B2. and nothing reached the listener');
    config.clearOverride('security.outboundAllowedHosts');

    t.log.info('=== C. federation.outbound off ===');
    set('federation.outbound', false);
    before = seen.length;
    r = await push(plainUri);
    t.check(!r.ok && r.code === 'STS-GNAP-0606' &&
            /federation\.outbound is off/.test(r.why),
            'C1. nothing is dialled with federation.outbound off', r.why);
    t.equal(seen.length, before, 'C2. and nothing reached the listener');
    set('federation.outbound', true);

    t.log.info('=== D. product: a public-standing host, pinned ===');
    set('global.mode', 'product');
    const asked = [];
    // What a public name answers to the check. push.example resolves
    // nowhere, so a delivery can only have gone to the address answered here.
    fedHttp.vetHost = async function (hostname) {
      asked.push(hostname);
      return { ok: true, address: '127.0.0.1', family: 4 };
    };
    before = seen.length;
    r = await push(publicUri);
    t.check(r.ok, 'D1. a host vetHost() allowed is dialled', r.why);
    t.equal(asked.join(','), 'push.example',
            'D2. vetHost() was asked for the URI\'s own host');
    t.equal(seen.length, before + 1,
            'D3. and the push reached the vetted address: the connection ' +
            'was pinned, since the name resolves nowhere');
    fedHttp.vetHost = realVetHost;

    t.log.info('=== E. development, no list: loopback still dialled ===');
    set('global.mode', 'development');
    before = seen.length;
    r = await push(plainUri);
    t.check(r.ok, 'E1. development dials a loopback finish URI', r.why);
    t.equal(seen.length, before + 1, 'E2. and it reached the listener');
  } finally {
    fedHttp.vetHost = realVetHost;
    touched.forEach(function (key) {
      config.clearOverride(key);
    });
    plain.close();
    secure.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'gnap_push_address',
  describe: 'GNAP\'s push finish URI under the outbound policy\'s address ' +
            'rules: refused when internal in product, outside ' +
            'security.outboundAllowedHosts or with federation.outbound ' +
            'off, and pinned when dialled (#1614)',
  run: run
};
