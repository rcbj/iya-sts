'use strict';
//
// File: oidcc_conformance_findings.js
//
// ===========================================================================
// WHAT THE OPENID FOUNDATION'S CONFORMANCE SUITE FOUND BEYOND FAPI (#187,
// 2026-09-24), held in process so a regression is caught without the suite's
// three containers. `tests/vendored/sts_oidcc_conformance.js` and its
// siblings are the plans themselves; this file is the regression check for
// each service fix they led to, and `oauth-oidc/CLAUDE.md` 3bh is the record.
//
//   1. RFC 6749 SECTION 6 IN EVERY MODE. A refresh token presented by a
//      client other than the one it was issued to, or asking for scope its
//      grant never carried, is refused with both compliance modes off — the
//      suite's oidcc-refresh-token redeemed the second client's token as the
//      first and was given tokens.
//   2. RFC 6749 SECTION 4.1.2 IN EVERY MODE. A code presented twice is
//      refused and what it bought is revoked, unless the realm opts back in
//      to the old courtesy with `oauth2.codeReplayIdempotent` — which RFC
//      9700 mode ignores.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({
  name: 'oidcc_conformance_findings',
  level: process.env.LOG_LEVEL || 'info' });

const realms = require('../common/realms');
const bcp = require('../oauth-oidc/oauth2_bcp');

// A throwaway realm left standing is a failure in a later file
// (tests/sender_constraints.js), so every one made here is removed.
const MADE = [];

function throwaway(id, overrides) {
  log.debug("Entering throwaway(). id=" + id);
  if (!realms.get(id)) {
    realms.create({ id: id, label: id });
    MADE.push(id);
  }
  Object.keys(overrides || {}).forEach(function (key) {
    realms.setOverride(id, key, String(overrides[key]));
  });
  log.debug("Leaving throwaway().");
  return realms.get(id);
}

function inRealm(id, fn) {
  log.debug("Entering inRealm().");
  const answer = realms.run(realms.get(id), fn);
  log.debug("Leaving inRealm().");
  return answer;
}

// ---------------------------------------------------------------------------
// 1. RFC 6749 SECTION 6.
// ---------------------------------------------------------------------------
function checkRefreshBinding(t) {
  log.debug("Entering checkRefreshBinding().");
  t.log.info('=== 1. a refresh token is its own client\'s, in every mode ===');
  throwaway('occf-plain', {});

  const other = inRealm('occf-plain', function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-1', client_id: 'client-two', scope: 'openid' },
      clientId: 'client-one', body: {} });
  });
  t.equal(other && other.errorCode, 'STS-OAUTH-0141',
          '1a. a refresh token issued to one client and presented by ' +
          'another is refused with RFC 9700 mode off (oidcc-refresh-token)');
  t.equal(other && other.error, 'invalid_grant', '1b. as invalid_grant');
  t.check(/RFC 6749 section 6/.test(String(other && other.description)),
          '1c. and the refusal cites RFC 6749, whose rule it is',
          other && other.description);

  const own = inRealm('occf-plain', function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-2', client_id: 'client-one', scope: 'openid' },
      clientId: 'client-one', body: {} });
  });
  t.equal(own && own.ok, true, '1d. its own client redeems it');

  const wider = inRealm('occf-plain', function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-3', client_id: 'client-one', scope: 'openid' },
      clientId: 'client-one', body: { scope: 'openid profile' } });
  });
  t.equal(wider && wider.errorCode, 'STS-OAUTH-0142',
          '1e. a refresh asking for more than its grant is refused, ' +
          'invalid_scope, in every mode');

  const narrower = inRealm('occf-plain', function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-4', client_id: 'client-one',
                scope: 'openid profile' },
      clientId: 'client-one', body: { scope: 'openid' } });
  });
  t.equal(narrower && narrower.ok, true, '1f. and a narrower one is not');

  const unnamed = inRealm('occf-plain', function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-5', client_id: 'client-one' },
      clientId: '', body: {} });
  });
  t.equal(unnamed && unnamed.ok, true,
          '1g. a refresh naming no client stays RFC 9700 mode\'s refusal ' +
          '(STS-OAUTH-0140): outside it there is nobody to compare');
  log.debug("Leaving checkRefreshBinding().");
}

// ---------------------------------------------------------------------------
// 2. RFC 6749 SECTION 4.1.2.
// ---------------------------------------------------------------------------
function checkCodeSingleUse(t) {
  log.debug("Entering checkCodeSingleUse().");
  t.log.info('=== 2. a code is single use, in every mode ===');
  throwaway('occf-code', {});
  throwaway('occf-courtesy', { 'oauth2.codeReplayIdempotent': 'true' });
  throwaway('occf-mode', { 'oauth2.codeReplayIdempotent': 'true',
                           'oauth2.rfc9700': 'true' });
  const replay = function () {
    return bcp.checkCodeReplay({ clientId: 'client-one', secondsAgo: 3,
                                 issuedJtis: ['at-jti', 'rt-jti', ''] });
  };

  const plain = inRealm('occf-code', replay);
  t.equal(plain && plain.errorCode, 'STS-OAUTH-0143',
          '2a. a code presented twice is refused with RFC 9700 mode off ' +
          '(oidcc-codereuse)');
  t.equal(plain && plain.error, 'invalid_grant', '2b. as invalid_grant');
  t.equal(JSON.stringify(plain && plain.revoke),
          JSON.stringify(['at-jti', 'rt-jti']),
          '2c. naming the tokens the first redemption bought, to revoke ' +
          '(oidcc-codereuse-30seconds)');

  t.equal(inRealm('occf-courtesy', replay).ok, true,
          '2d. oauth2.codeReplayIdempotent restores the old courtesy');
  t.equal(inRealm('occf-mode', replay).errorCode, 'STS-OAUTH-0143',
          '2e. and RFC 9700 mode ignores it');
  log.debug("Leaving checkCodeSingleUse().");
}

function removeRealms() {
  log.debug("Entering removeRealms().");
  MADE.splice(0).forEach(function (id) {
    realms.remove(id);
  });
  log.debug("Leaving removeRealms().");
}

function run(t) {
  log.debug("Entering run().");
  try {
    checkRefreshBinding(t);
    checkCodeSingleUse(t);
  } finally {
    removeRealms();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidcc_conformance_findings',
  describe: 'the service fixes the OpenID conformance suite\'s OpenID ' +
            'Connect plans led to (#187): RFC 6749 section 6 and section ' +
            '4.1.2 in every mode',
  run: run
};
