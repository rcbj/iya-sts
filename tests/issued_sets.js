'use strict';
//
// File: issued_sets.js
//
// ===========================================================================
// A ROW OF /admin/tokens IS ONE ISSUANCE, AND THE GROUPING IS A FACT THE ISSUER
// STATED RATHER THAN A GUESS THIS SERVICE MADE.
//
// OAuth 2.0 and OIDC are the only families this service speaks that hand back
// several credentials at once: redeeming an authorization code returns an
// access token, a refresh token and an ID Token in ONE reply, and
// `response_type=id_token token` returns two in one fragment. Until 2026-09-05
// that table drew three rows and left the reader to reassemble the one thing
// the protocol had handed over whole, by comparing timestamps.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Most of this feature belongs over HTTP and is not here: that the table draws
// one row per reply, that the set page opens, that `revoke-set` only DISOWNS a
// SAML assertion (`record-only`, since 2026-09-05), are all driven against the
// running service by `tests/vendored/admin_api.js` and
// `tests/vendored/sts_admin_api_operations.js`. What is here is the one claim
// that CANNOT be driven over HTTP, and it is the claim the whole design rests
// on:
//
//   **TWO REPLIES THAT AGREE ON EVERY RECORDED FIELD ARE STILL TWO REPLIES.**
//
// Two people redeeming two authorization codes at the same client in the same
// millisecond produce six token records agreeing on `sub`, `username`,
// `client_id`, `scope`, `grant` and `issuedAt` — every field a heuristic could
// read. Only the set id the ISSUER minted separates them. Producing that state
// over HTTP means winning a race against the clock on purpose, which is a test
// that passes for the wrong reason on a slow morning; here it is two calls with
// the same timestamp and one assertion.
//
// The other three are here because they are STORE contracts rather than page
// behaviour: that a family which states no set id is a set of one rather than
// being dropped, that members come back in issuance order when the millisecond
// cannot separate them, and that a set whose members disagree reports `mixed`
// rather than picking one.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: a
// developer with CONFIG_FILE exported would otherwise be asserting against
// their own appconfig rather than against the service as it ships.
delete process.env.CONFIG_FILE;

const helpers = require('../common/helpers');
const stats = require('../common/admin_stats');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'issued_sets',
  level: process.env.LOG_LEVEL || 'info' });

// One JWT through the real funnel — `signJwt()` is what records a token, so a
// test that pushed a record into the store directly would be asserting against
// a shape nothing produces. `context` is the third parameter that function
// offers, and `setId` is the member under test.
//
// `'ID'` mints an ID Token the way `oauth2.ts`'s idToken() does since #118
// (2026-09-22): no `typ` claim, and the kind stated in the context.
function mint(typ, jti, setId, extra) {
  log.debug("Entering mint().");
  const now = Math.floor(Date.now() / 1000);
  const idToken = typ === 'ID';
  const payload = Object.assign({
    typ: typ, jti: jti, sub: 'urn:sts:user:alice', username: 'alice',
    client_id: 'webapp', scope: 'openid profile',
    iat: now, nbf: now, exp: now + 900
  }, extra || {});
  if (idToken) {
    delete payload.typ;
  }
  helpers.signJwt(payload, Object.assign({ sessionId: 'sess-1',
    grant: 'authorization_code', setId: setId || '' },
    idToken ? { kind: 'id_token' } : {}));
  log.debug("Leaving mint().");
}

function setsByKey(key) {
  log.debug("Entering setsByKey().");
  log.debug("Leaving setsByKey().");
  return stats.issuedSets()
              .filter(function (set) { return set.setKey === key; })[0];
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== One reply is one row ===');

  // -----------------------------------------------------------------------
  // THE CLAIM THE WHOLE DESIGN RESTS ON. Two replies, same person, same
  // client, same scope, same grant, same instant — separated only by the id
  // the issuer stated.
  // -----------------------------------------------------------------------
  mint('Bearer', 'a-one', 'REPLY-1');
  mint('Refresh', 'r-one', 'REPLY-1');
  mint('ID', 'i-one', 'REPLY-1');
  mint('Bearer', 'a-two', 'REPLY-2');
  mint('Refresh', 'r-two', 'REPLY-2');
  mint('ID', 'i-two', 'REPLY-2');

  const first = setsByKey('set:REPLY-1');
  const second = setsByKey('set:REPLY-2');
  t.check(!!first && !!second,
          'two simultaneous replies are two sets, not one',
          'REPLY-1 ' + (first ? 'found' : 'MISSING') + ', REPLY-2 ' +
          (second ? 'found' : 'MISSING'));
  t.equal(first.size, 3,
          'and neither absorbed the other: three credentials in the first');
  t.equal(second.size, 3, 'and three in the second');
  t.check(first.members.every(function (m) { return m.setId === 'REPLY-1'; }),
          'EVERY MEMBER CARRIES THE ID ITS ISSUER STATED, which is what ' +
          'makes this separable at all — a heuristic over sub, client, ' +
          'scope, grant and issuedAt would have merged these six into one ' +
          'reply nobody received',
          first.members.map(function (m) { return m.setId; }).join(','));
  t.equal(first.members.map(function (m) { return m.username; }).join(','),
          'alice,alice,alice',
          'even though the two replies agree on the person');
  t.equal(first.members[0].client_id, second.members[0].client_id,
          'and on the client');

  // -----------------------------------------------------------------------
  // ISSUANCE ORDER, which the millisecond cannot give. All six above were
  // minted inside one, so a sort on `issuedAt` alone would leave the members
  // in whatever order the sort happened to be stable in — and the set page
  // would print the refresh token above the access token issued before it.
  // -----------------------------------------------------------------------
  t.equal(first.kinds.join('+'), 'access_token+refresh_token+id_token',
          'MEMBERS COME BACK IN ISSUANCE ORDER even though every one of them ' +
          'was minted in the same millisecond — issuedList()\'s ordinal is ' +
          'what carries it, and without it this is whatever the sort did');

  // -----------------------------------------------------------------------
  // A FAMILY THAT STATES NO SET ID IS A SET OF ONE. That is the whole of what
  // "every other protocol issues one credential per act" costs, and it must be
  // a set rather than a dropped row: the tokens page lists four families and
  // three of them will never state one.
  // -----------------------------------------------------------------------
  t.log.info('=== everything else is a set of one ===');
  const assertion = stats.recordAssertion('2.0', {
    id: '_assertion-under-test', subject: 'bob', audience: 'sp1',
    expiresAt: Date.now() + 600000 });
  const ticket = stats.recordTicket('TGT', {
    client: 'alice', realm: 'EXAMPLE.COM', service: 'krbtgt/EXAMPLE.COM',
    etype: 'aes256-cts-hmac-sha1-96', expiresAt: Date.now() + 36000000 });

  const assertionSet = setsByKey('one:' + assertion.key);
  t.check(!!assertionSet, 'a SAML assertion is a set of its own',
          'looked for one:' + assertion.key);
  t.equal(assertionSet.grouped, false, 'and says it is not a group');
  t.equal(assertionSet.size, 1, 'holding the one credential');
  t.equal(assertionSet.setId, '',
          'with NO issuance id, because nothing issued it alongside anything');
  // **REVOCABLE SINCE 2026-09-05, AND THIS ASSERTION READ `0` UNTIL THAT DAY.**
  // What changed is not that an assertion became recallable — it did not, and
  // the next assertion is what pins that down — but that this service now
  // records its own POSITION on a credential it issued. The two claims are
  // `revocable` and `revocationReach`, and keeping them in one field is what
  // made the old `0` look like a fact about SAML rather than a decision here.
  t.equal(assertionSet.revocableCount, 1,
          'an assertion CAN be revoked in this service\'s own record');
  t.equal(assertionSet.members[0].revocationReach, 'record-only',
          'AND THE REVOCATION REACHES NOBODY, which is the half that must ' +
          'never change: a relying party validates the signature and the ' +
          'Conditions and asks nobody, so a row claiming this reached a ' +
          'protocol would be this mock teaching a client something false ' +
          'about every identity provider it will ever meet');

  // The Kerberos row is the case the artifact key exists for: a ticket carries
  // no identifier anybody can quote, so without a handle of this service's own
  // there would be nothing to address the row by at all.
  const ticketSet = setsByKey('one:' + ticket.key);
  t.check(!!ticketSet,
          'A KERBEROS TICKET IS ADDRESSABLE THOUGH IT HAS NO IDENTIFIER — ' +
          'the protocol gives it none and the KDC keeps no handle on it, so ' +
          'the issued register supplies one of its own',
          'looked for one:' + ticket.key);
  t.equal(ticketSet.members[0].identifier, '',
          'and it still has no identifier to quote, which is a different ' +
          'thing from having no row handle');
  t.equal(ticketSet.members[0].revocationReach, 'record-only',
          'and its revocation reaches nobody either, for the Kerberos ' +
          'version of the same reason: the service a ticket names decrypts ' +
          'it with a key it already holds and never asks this KDC');

  // -----------------------------------------------------------------------
  // A SET WHOSE MEMBERS DISAGREE REPORTS THE DISAGREEMENT. Reporting `valid`
  // or `expired` would be the list deciding which member matters, and the
  // member that matters is the one the reader has not thought of — the
  // refresh token that outlived the access token and will mint another.
  // -----------------------------------------------------------------------
  t.log.info('=== a set is often not in one state ===');
  stats.revoke('a-one', 'issued_sets.js');
  const mixed = setsByKey('set:REPLY-1');
  t.equal(mixed.state, 'mixed',
          'one revoked member makes the SET mixed rather than revoked or ' +
          'valid');
  t.equal(mixed.states.revoked, 1, 'and the breakdown counts the revoked one');
  t.equal(mixed.states.valid, 2, 'beside the two that are still good');
  t.equal(mixed.revokedCount, 1, 'which is what decides Revoke set from ' +
                                 'Restore set');
  stats.restore('a-one');
  t.equal(setsByKey('set:REPLY-1').state, 'valid',
          'and putting it back makes the set whole again');

  // -----------------------------------------------------------------------
  // THE TWO EXPIRIES. One column cannot carry both, and the earlier one is
  // what somebody debugging a refused call has arrived to find.
  // -----------------------------------------------------------------------
  const now = Math.floor(Date.now() / 1000);
  mint('Bearer', 'a-three', 'REPLY-3', { exp: now + 900 });
  mint('Refresh', 'r-three', 'REPLY-3', { exp: now + 86400 });
  const spread = setsByKey('set:REPLY-3');
  t.check(spread.expiresAtMs < spread.lastExpiresAtMs,
          'a set that comes apart before it is finished reports BOTH ends',
          'first ' + new Date(spread.expiresAtMs).toISOString() +
          ', last ' + new Date(spread.lastExpiresAtMs).toISOString());
  t.equal(spread.expiresAtMs, spread.members[0].expiresAtMs,
          'and `expiresAtMs` is the EARLIEST — when the access token dies, ' +
          'not when the refresh token does');

  // -----------------------------------------------------------------------
  // THE LOOKUP, which is what every button and the drill-down page address a
  // set by. A key nothing holds is the ORDINARY end of a set's life — dropped
  // to the registry's cap — so it is null rather than a throw.
  // -----------------------------------------------------------------------
  t.log.info('=== addressing a set ===');
  t.equal(stats.issuedSetByKey('set:REPLY-1').size, 3,
          'a set can be fetched by its key');
  t.equal(stats.issuedSetByKey('set:NEVER-EXISTED'), null,
          'and a key nothing holds is null rather than a throw — a set old ' +
          'enough to have been forgotten to the cap is the ordinary end of ' +
          'its life, not a caller\'s mistake');
  t.equal(stats.issuedSetByKey(''), null, 'as is asking for nothing');

  // -----------------------------------------------------------------------
  // THE FLATTEN. `issuedSets()` must hold every row `issuedList()` does and no
  // others: a credential that fell out of the grouping would be one this
  // console had issued and could no longer show.
  // -----------------------------------------------------------------------
  const flat = stats.issuedList();
  const inSets = stats.issuedSets().reduce(function (n, set) {
    return n + set.members.length;
  }, 0);
  t.equal(inSets, flat.length,
          'GROUPING LOSES NOTHING: every credential in the register is in ' +
          'exactly one set');
  const keys = stats.issuedSets().map(function (set) { return set.setKey; });
  t.equal(keys.length, new Set(keys).size,
          'and no two sets share a key, which is what the buttons address');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'issued sets',
  describe: 'a row of /admin/tokens is one issuance, and the issuer said so',
  run: run
};
