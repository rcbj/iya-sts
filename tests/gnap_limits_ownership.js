// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_limits_ownership.js
//
// ===========================================================================
// WHO OWNS WHAT A RIGHT NAMES, AND WHAT A RIGHT'S LIMITS MEAN (#432 phase 5).
//
//   A. THE LIMITS VOCABULARY (`common/access_limits.ts`): each member read,
//      "lower" per member (equal, lower, raised, removed, an interval added),
//      a repeating interval's periods (fixed and calendar), millionths.
//   B. THE CATALOGUE READS IT FOR BOTH PROTOCOLS: a GNAP right (STS-GNAP-
//      0860) and an RFC 9396 detail (STS-OAUTH-0916) whose limits mean
//      nothing, the demonstration type's built-in limits schema.
//   C. OWNERSHIP FROM A REGISTERED RESOURCE SET: the person, a member of the
//      owner group, somebody else; what a DN may name.
//   D. OWNERSHIP BY A LOOKUP the resource server declares, through a stubbed
//      outbound request: an owner, a 404 (nobody), a failure (unresolved),
//      the cache, the URL the identifier is encoded into, and the template
//      grammar an administrator writes (STS-REG-0334).
//   E. THE POLICY: issue-gnap-right refusing a non-owner (0861) and an
//      unanswered lookup (0863), keeping the owner, a group member, and a
//      right nobody owns; an issue-stage refusal dropping the right.
//   F. A LATER REQUEST NEVER RAISES A LIMIT: `limitsRaised()` for a dropped,
//      a raised and a lowered one.
//   G. THE RESOURCE SERVER'S TOTALS (`gnap/gnap_spend.ts`) on the one-process
//      ledger: count and amount spent to the limit and refused after it
//      (0870), the currency (0873), the receiver (0872), the window (0871),
//      the interval resetting at its boundary, a refund, and twenty spends
//      at once against a limit of five.
//   H. THE SHARED STORE: the postgres statement is one conditional upsert
//      that writes only totals within the limits and never for an older
//      period, the refund one guarded update — read off the statement a fake
//      pool receives — and a store that cannot be asked refuses (0875).
//   I. INTROSPECTION'S grant_id is reserved: no type may declare it as a
//      claim.
//   J. RFC 9396 LIMITS ARE ENFORCEABLE TOO: `carriesLimits()`,
//      `limitsRaisedBy()`, an Allow recorded with the details as the person
//      lowered them and spent once (`consumeConsent()`); `tokenSet()` puts a
//      `grant_id` on an access token whose details carry limits — none on
//      one whose details carry none — keeps it inside the refresh token, and
//      hands the SAME one to the refreshed token; Grant Management's
//      `grant_id` is used where there is one; the consent record keeps the
//      details themselves (the screen's controls, a lowered Allow and a
//      raised one refused are `tests/vendored/sts_gnap_catalogue.js`'s
//      section 8, over HTTP).
//
// IN PROCESS, in a throwaway realm. The over-HTTP half is
// `tests/vendored/sts_gnap_limits.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const errorCodes = require('../common/error_codes');
// Arms `issuance_gate.js`'s decider, as `gnap_catalogue.js` does.
require('../xacml/xacml_role_pep');
const catalogue = require('../oauth-oidc/authorization_details');
const AccessLimits = require('../common/access_limits');
const rights = require('../gnap/gnap_rights');
const ownership = require('../gnap/gnap_ownership');
const store = require('../gnap/gnap_store');
const spendModule = require('../gnap/gnap_spend');

const log = require('bunyan').createLogger({ name: 'gnap_limits_ownership',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = require('path').join(__dirname, '..');

// A spend's answer carries BigInt millionths (`spent`), which JSON cannot.
function shown(value) {
  log.debug("Entering shown().");
  log.debug("Leaving shown().");
  return JSON.stringify(value, function (key, v) {
    return typeof v === 'bigint' ? v.toString() : v;
  });
}
const RS_URI = 'https://acct.lo.test/api';
const TEMPLATE = 'https://owners.lo.test/v1/owners/{identifier}';

// A type whose limits schema lets every vocabulary member through, so the
// vocabulary — not the schema — is what refuses.
const ACCT = {
  type: 'lo-acct', actions: ['read', 'spend'],
  limits: { type: 'object',
            properties: { amount: { type: ['string', 'number'] },
                          currency: { type: 'string' },
                          count: { type: 'integer', minimum: 0 },
                          receiver: { type: ['string', 'array'] },
                          interval: { type: 'string' },
                          window: { type: 'object' } },
            additionalProperties: false }
};

async function run(t) {
  log.debug("Entering run().");
  const id = 'lo-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    await realms.run(made.realm, function () {
      return inRealm(t);
    });
  } finally {
    config.clearOverride('global.mode');
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

async function inRealm(t) {
  log.debug("Entering inRealm().");
  vocabulary(t);
  const fx = fixtures(t);
  conformance(t);
  fromResourceSets(t, fx);
  await lookups(t, fx);
  await policy(t, fx);
  later(t);
  await totals(t);
  await sharedStore(t);
  reserved(t);
  await rar(t);
  log.debug("Leaving inRealm().");
}

// ---------------------------------------------------------------- A
function vocabulary(t) {
  log.debug("Entering vocabulary().");
  t.log.info('=== A. the limits vocabulary ===');
  const problem = AccessLimits.problem;
  t.check(problem({ amount: '100.50', currency: 'EUR', count: 3,
                    receiver: ['bob'], interval: 'R/2026-10-01T00:00:00Z/P1D',
                    window: { notBefore: '2026-10-01T00:00:00Z' } }) === '',
          'A1. every member with a meaning reads');
  [[{ amount: '1.1234567', currency: 'EUR' }, /fraction/,
    'A2. at most six fraction digits'],
   [{ amount: '-1', currency: 'EUR' }, /non-negative/, 'A3. no negative'],
   [{ amount: '5' }, /together/, 'A4. an amount needs its currency'],
   [{ currency: 'EUR' }, /together/, 'A5. and a currency an amount'],
   [{ amount: 5, currency: 'eur' }, /ISO 4217/, 'A6. a currency code'],
   [{ count: 1.5 }, /count/, 'A7. a count is an integer'],
   [{ receiver: [] }, /receiver/, 'A8. a receiver list is not empty'],
   [{ interval: 'R0/2026-10-01T00:00:00Z/P1D' }, /interval/,
    'A9. R0 repeats nothing'],
   [{ interval: 'R/2026-10-01/P1D' }, /interval/,
    'A10. the start is an RFC 3339 date-time'],
   [{ interval: 'R/2026-10-01T00:00:00Z/PT' }, /interval/,
    'A11. the duration is not empty'],
   [{ window: { notBefore: '2026-10-02T00:00:00Z',
                notAfter: '2026-10-01T00:00:00Z' } }, /window/,
    'A12. a window ends after it starts'],
   [{ window: { from: '2026-10-02T00:00:00Z' } }, /window/,
    'A13. a window has only its two ends']
  ].forEach(function (one) {
    const why = problem(one[0]);
    t.check(one[1].test(why), one[2], why);
  });
  const raised = AccessLimits.raised;
  const base = { amount: '100', currency: 'EUR', count: 10,
                 receiver: ['bob', 'carol'],
                 interval: 'R12/2026-10-01T00:00:00Z/P1D',
                 window: { notBefore: '2026-10-01T00:00:00Z',
                           notAfter: '2026-12-01T00:00:00Z' },
                 purpose: 'rent' };
  const lower = function (change) {
    log.debug("Entering lower().");
    log.debug("Leaving lower().");
    return raised(base, Object.assign({}, base, change));
  };
  t.check(lower({}) === '', 'A14. equal is not raised');
  t.check(lower({ amount: '99.99' }) === '' && lower({ count: 0 }) === '' &&
          lower({ receiver: 'bob' }) === '' &&
          lower({ interval: 'R3/2026-10-01T00:00:00Z/P1W' }) === '' &&
          lower({ window: { notBefore: '2026-10-05T00:00:00Z',
                            notAfter: '2026-11-01T00:00:00Z' } }) === '',
          'A15. a smaller amount and count, fewer receivers, a longer ' +
          'period with fewer repetitions and a narrower window are lower');
  [[{ amount: '100.000001' }, /amount/, 'A16. a larger amount'],
   [{ currency: 'USD' }, /currency/, 'A17. another currency'],
   [{ count: 11 }, /count/, 'A18. a larger count'],
   [{ receiver: ['bob', 'mallory'] }, /receiver/, 'A19. a new receiver'],
   [{ interval: 'R12/2026-10-01T00:00:00Z/PT12H' }, /shorter/,
    'A20. a shorter period resets more often: raised'],
   [{ interval: 'R/2026-10-01T00:00:00Z/P1D' }, /repeats/,
    'A21. unbounded repetitions'],
   [{ interval: 'R12/2026-10-02T00:00:00Z/P1D' }, /start/,
    'A22. a moved start'],
   [{ window: { notBefore: '2026-09-01T00:00:00Z',
                notAfter: '2026-12-01T00:00:00Z' } }, /wider/,
    'A23. an earlier notBefore'],
   [{ purpose: 'anything' }, /own member/,
    'A24. a member this service gives no meaning is not changed']
  ].forEach(function (one) {
    const why = lower(one[0]);
    t.check(one[1].test(why), one[2] + ' is refused', why);
  });
  const noCount = Object.assign({}, base);
  delete noCount.count;
  t.check(/removed/.test(raised(base, noCount)),
          'A25. a limit removed is raised (no limit is the most of all)');
  t.check(/removed/.test(raised(base, undefined)),
          'A26. all limits removed is raised');
  t.check(raised({ count: 3 }, { count: 3, amount: '5', currency: 'EUR' }) ===
          '' && /interval/.test(raised({ count: 3 },
            { count: 3, interval: 'R/2026-10-01T00:00:00Z/P1D' })),
          'A27. an amount may be added, an interval may not');
  // Periods.
  const start = Date.parse('2026-10-01T00:00:00Z') / 1000;
  let p = AccessLimits.periodAt('R/2026-10-01T00:00:00Z/P1D', start + 86400 * 3 +
                                5);
  t.check(p.index === 3 && p.start === start + 86400 * 3 &&
          p.end === start + 86400 * 4, 'A28. a fixed period', JSON.stringify(p));
  p = AccessLimits.periodAt('R/2026-01-31T00:00:00Z/P1M',
                            Date.parse('2026-03-15T00:00:00Z') / 1000);
  t.check(p.index === 1, 'A29. a calendar month (Jan 31 + 1M is in March)',
          JSON.stringify(p));
  t.check(AccessLimits.periodAt('R2/2026-10-01T00:00:00Z/P1D',
                                start + 86400 * 2 + 1).outside === 'after' &&
          AccessLimits.periodAt('R2/2026-10-01T00:00:00Z/P1D',
                                start - 1).outside === 'before',
          'A30. after the last repetition and before the start are outside');
  t.check(AccessLimits.decimal(AccessLimits.units('0.1') +
                               AccessLimits.units(0.2)) === '0.3',
          'A31. amounts add in millionths, exactly');
  log.debug("Leaving vocabulary().");
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  dir.createUser('lo-alice', { invent: false });
  dir.createUser('lo-bob', { invent: false });
  dir.createUser('lo-carol', { invent: false });
  const group = dir.createGroup('lo-owners', { members: [] });
  dir.addGroupMember('lo-owners', 'lo-bob');
  const app = function (identifier, kind, fields) {
    log.debug("Entering app().");
    log.debug("Leaving app().");
    return applications.createApplication({ identifier: identifier,
      kind: kind, protocols: ['gnap', 'oauth2'], fields: fields || {} });
  };
  const made = [
    app('lo-rs', 'gnap-resource-server',
        { gnapResourceServerUri: RS_URI, oauthClientId: 'lo-rs',
          oauthAuthorizationDetailsType: [JSON.stringify(ACCT)] }),
    app('lo-lookup-rs', 'gnap-resource-server',
        { oauthClientId: 'lo-lookup-rs',
          gnapOwnerLookupUri: TEMPLATE,
          oauthAuthorizationDetailsType: [JSON.stringify(
            { type: 'lo-mailbox', actions: ['read'] })] }),
    app('lo-client', 'gnap-client', {})
  ];
  t.check(made.every(function (one) { return one && one.ok; }) &&
          group && group.ok !== false,
          'precondition: the fixtures were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  const alice = credentials.delegationFactsFor('lo-alice') || {};
  const bob = credentials.delegationFactsFor('lo-bob') || {};
  const groupDn = ((bob.groups || []).filter(function (g) {
    return /lo-owners/i.test(g.cn || g.dn);
  })[0] || {}).dn || '';
  t.check(!!alice.dn && !!groupDn, 'precondition: the owner DNs are known',
          JSON.stringify({ alice: alice.dn, group: groupDn }));
  store.putResource('lo-set-' + process.pid, {
    canonical: 'lo-set', rsIdentity: 'lo-rs', rsIdentifier: 'lo-rs',
    access: [{ type: 'lo-acct', identifier: 'acct-alice' },
             { type: 'lo-acct', identifier: 'acct-team' },
             { type: 'lo-acct', identifier: 'acct-free' }],
    tokenFormats: null, introspectionRequired: false,
    resourceOwners: { 'acct-alice': alice.dn, 'acct-team': groupDn } });
  log.debug("Leaving fixtures().");
  return { client: applications.get('lo-client'), aliceDn: alice.dn,
           groupDn: groupDn };
}

// ---------------------------------------------------------------- B
function conformance(t) {
  log.debug("Entering conformance().");
  t.log.info('=== B. the catalogue reads the vocabulary ===');
  const tok = function (access) {
    log.debug("Entering tok().");
    log.debug("Leaving tok().");
    return [{ label: 'one', access: access }];
  };
  let r = rights.conformanceRefusal(tok([{ type: 'lo-acct',
    actions: ['spend'], limits: { amount: '10' } }]));
  t.check(r && errorCodes.codeOf(r) === 'STS-GNAP-0860' &&
          r.gnapError === 'invalid_request',
          'B1. GNAP: limits whose amount has no currency are 0860',
          JSON.stringify(r));
  t.check(rights.conformanceRefusal(tok([{ type: 'lo-acct',
    actions: ['spend'], limits: { amount: '10', currency: 'EUR',
                                  count: 2 } }])) === null,
          'B2. GNAP: readable limits conform');
  const parse = function (details) {
    log.debug("Entering parse().");
    log.debug("Leaving parse().");
    return catalogue.parse(JSON.stringify(details), { clientId: 'lo-client' });
  };
  r = parse([{ type: 'lo-acct', actions: ['spend'],
               limits: { interval: 'every day' } }]);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-OAUTH-0916',
          'B3. RFC 9396: the same limits are refused the same way ' +
          '(STS-OAUTH-0916)', r.error);
  t.check(parse([{ type: 'lo-acct', actions: ['spend'],
                   limits: { count: 1 } }]).ok,
          'B4. RFC 9396: readable limits are accepted');
  const demo = rights.entryOf({ type: rights.DEMO_TYPE });
  t.check(demo && !!demo.validateLimits &&
          rights.conformanceRefusal(tok([{ type: rights.DEMO_TYPE,
            limits: { count: 5 } }])) === null &&
          errorCodes.codeOf(rights.conformanceRefusal(tok([{
            type: rights.DEMO_TYPE, limits: { colour: 'red' } }]))) ===
            'STS-GNAP-0814',
          'B5. the demonstration type declares a limits schema of the ' +
          'vocabulary and nothing else');
  log.debug("Leaving conformance().");
}

// ---------------------------------------------------------------- C
function fromResourceSets(t, fx) {
  log.debug("Entering fromResourceSets().");
  t.log.info('=== C. ownership from a registered resource set ===');
  const facts = function (identifier, who) {
    log.debug("Entering facts().");
    log.debug("Leaving facts().");
    return ownership.facts({ type: 'lo-acct', identifier: identifier },
                           ['lo-rs'], who, {});
  };
  let f = facts('acct-alice', 'lo-alice');
  t.check(f.known && f.source === 'resource-set' && f.matches === true,
          'C1. the owner the set names is the owner', JSON.stringify(f));
  f = facts('acct-alice', 'lo-carol');
  t.check(f.known && f.matches === false, 'C2. somebody else is not',
          JSON.stringify(f));
  t.check(facts('acct-team', 'lo-bob').matches === true &&
          facts('acct-team', 'lo-carol').matches === false,
          'C3. a group owner: a member is the owner, a non-member is not');
  f = facts('acct-free', 'lo-carol');
  t.check(!f.known && f.matches === undefined && !f.unresolved,
          'C4. an identifier the set names no owner for is owned by nobody',
          JSON.stringify(f));
  f = facts('acct-alice', '');
  t.check(f.known && f.matches === undefined,
          'C5. with no approver yet, ownership is known and unmatched');
  t.check(!ownership.facts({ type: 'lo-acct', identifier: 'acct-alice' },
                           ['somebody-else'], 'lo-carol', {}).known,
          'C6. a set registered by ANOTHER resource server says nothing');
  t.check(ownership.ownerKind(fx.aliceDn) === 'person' &&
          ownership.ownerKind(fx.groupDn) === 'group' &&
          ownership.ownerKind('uid=nobody,ou=people,dc=nowhere') === '' &&
          ownership.ownerKind('not a dn') === '',
          'C7. an owner is a person or a group in this realm, and nothing ' +
          'else');
  log.debug("Leaving fromResourceSets().");
}

// ---------------------------------------------------------------- D
async function lookups(t, fx) {
  log.debug("Entering lookups().");
  t.log.info('=== D. ownership by a lookup ===');
  const calls = [];
  const answers = {
    'mb-alice': { ok: true, status: 200,
                  body: Buffer.from(JSON.stringify({ owner: fx.aliceDn })) },
    'mb-none': { ok: false, status: 404, body: Buffer.alloc(0) },
    'mb-broken': { ok: false, status: 500, body: Buffer.alloc(0) }
  };
  const Cls = ownership.GnapOwnership;
  const own = new Cls(Object.assign(Cls.defaultDeps(), {
    fetchPublished: function (url) {
      log.debug("Entering fetchPublished().");
      calls.push(url);
      const id = decodeURIComponent(url.split('/').pop());
      log.debug("Leaving fetchPublished().");
      return Promise.resolve(answers[id] ||
                             { ok: false, status: 0, why: 'unreachable' });
    }
  }));
  ownership.forget();
  const targets = function () {
    log.debug("Entering targets().");
    log.debug("Leaving targets().");
    return ['lo-lookup-rs'];
  };
  const right = function (id) {
    log.debug("Entering right().");
    log.debug("Leaving right().");
    return { type: 'lo-mailbox', identifier: id };
  };
  const fetched = await own.prefetch([{ access: [right('mb-alice'),
    right('mb-none'), right('mb-broken')] }], targets);
  t.check(calls.length === 3 &&
          calls[0] === 'https://owners.lo.test/v1/owners/mb-alice',
          'D1. one lookup per identifier, at the template\'s address',
          JSON.stringify(calls));
  let f = own.facts(right('mb-alice'), ['lo-lookup-rs'], 'lo-alice', fetched);
  t.check(f.known && f.source === 'lookup' && f.matches === true,
          'D2. the owner the lookup names', JSON.stringify(f));
  t.check(own.facts(right('mb-alice'), ['lo-lookup-rs'], 'lo-carol',
                    fetched).matches === false,
          'D3. and nobody else');
  f = own.facts(right('mb-none'), ['lo-lookup-rs'], 'lo-carol', fetched);
  t.check(!f.known && !f.unresolved,
          'D4. a 404 is an answer: nobody owns it', JSON.stringify(f));
  f = own.facts(right('mb-broken'), ['lo-lookup-rs'], 'lo-carol', fetched);
  t.check(!f.known && f.unresolved,
          'D5. a failure is UNRESOLVED, not "nobody"', JSON.stringify(f));
  t.check(own.facts(right('mb-alice'), ['lo-lookup-rs'], 'lo-alice', {})
          .unresolved === true,
          'D6. a caller that did not prefetch is told unresolved');
  await own.prefetch([{ access: [right('mb-alice'), right('mb-broken')] }],
                     targets);
  t.check(calls.length === 4 && calls[3].indexOf('mb-broken') > 0,
          'D7. an owner is held (no second fetch); a failure is asked again',
          JSON.stringify(calls));
  t.check(Cls.lookupUrl(TEMPLATE, 'a/../b c') ===
          'https://owners.lo.test/v1/owners/a%2F%2E%2E%2Fb%20c',
          'D8. the identifier is percent-encoded into its one segment, ' +
          'dots included', Cls.lookupUrl(TEMPLATE, 'a/../b c'));
  const bad = applications.ownerLookupUriProblem;
  t.check(bad(TEMPLATE) === '' &&
          !!bad('http://owners.lo.test/{identifier}') &&
          !!bad('https://{identifier}.lo.test/x') &&
          !!bad('https://owners.lo.test/x?id={identifier}') &&
          !!bad('https://owners.lo.test/x/{identifier}/{identifier}') &&
          !!bad('https://owners.lo.test/x-{identifier}') &&
          !!bad('https://u:p@owners.lo.test/{identifier}') &&
          !!bad('https://owners.lo.test/x#{identifier}'),
          'D9. the template is https, a host, no user, query or fragment, ' +
          'and {identifier} once as a whole segment');
  const refused = applications.updateApplication('lo-lookup-rs', {
    attribute: 'gnapOwnerLookupUri', mode: 'set',
    value: 'http://owners.lo.test/{identifier}' });
  t.check(refused && !refused.ok &&
          errorCodes.codeOf(refused) === 'STS-REG-0334',
          'D10. writing a bad template is refused (STS-REG-0334)',
          JSON.stringify(refused));
  log.debug("Leaving lookups().");
}

// ---------------------------------------------------------------- E
async function policy(t, fx) {
  log.debug("Entering policy().");
  t.log.info('=== E. the policy ===');
  const ctx = function (approver, owners) {
    log.debug("Entering ctx().");
    log.debug("Leaving ctx().");
    return { app: fx.client, approver: approver,
             approval: approver ? 'interaction' : 'pending',
             owners: owners || {},
             targetsOf: function (access) {
               return access[0] && access[0].type === 'lo-mailbox'
                 ? ['lo-lookup-rs'] : ['lo-rs'];
             } };
  };
  const one = function (identifier, type) {
    log.debug("Entering one().");
    log.debug("Leaving one().");
    return [{ label: 'one', access: [{ type: type || 'lo-acct',
                                       identifier: identifier,
                                       actions: ['read'] }] }];
  };
  const code = function (r) {
    log.debug("Entering code().");
    log.debug("Leaving code().");
    return r && r.ok === false ? errorCodes.codeOf(r) : 'kept';
  };
  t.check(code(rights.judge(one('acct-alice'), ctx('lo-alice'),
                            'request')) === 'kept',
          'E1. the owner may be granted it');
  let r = rights.judge(one('acct-alice'), ctx('lo-carol'), 'request');
  t.check(code(r) === 'STS-GNAP-0861' && r.status === 403,
          'E2. a non-owner is refused (0861)', code(r));
  t.check(code(rights.judge(one('acct-team'), ctx('lo-bob'), 'request')) ===
          'kept', 'E3. a member of the owner group may be granted it');
  t.check(code(rights.judge(one('acct-free'), ctx('lo-carol'), 'request')) ===
          'kept', 'E4. a right nobody owns is the page\'s ordinary business');
  t.check(code(rights.judge(one('acct-alice'), ctx(''), 'request')) ===
          'kept', 'E5. before anybody approves, nothing is refused for ' +
          'ownership');
  r = rights.judge(one('mb-broken', 'lo-mailbox'), ctx('lo-carol', {
    'lo-lookup-rs\u0000mb-broken': { failed: 'unreachable' } }), 'request');
  t.check(code(r) === 'STS-GNAP-0863',
          'E6. an owner lookup that could not be answered is refused (0863)',
          code(r));
  r = rights.judge(one('acct-alice'), ctx('lo-carol'), 'issue');
  t.check(r.ok && r.tokens[0].access.length === 0 && r.dropped.length === 1 &&
          r.dropped[0].code === 'STS-GNAP-0861',
          'E7. at the issue stage the non-owner\'s right is DROPPED, as a ' +
          'skipped interaction or a derivation would find it',
          JSON.stringify(r.dropped));
  log.debug("Leaving policy().");
}

// ---------------------------------------------------------------- F
function later(t) {
  log.debug("Entering later().");
  t.log.info('=== F. a later request never raises a limit ===');
  const granted = [{ type: 'lo-acct', identifier: 'a',
                     limits: { count: 5, amount: '50', currency: 'EUR' } }];
  t.check(/removed/.test(rights.limitsRaised(granted,
    [{ type: 'lo-acct', identifier: 'a' }])),
          'F1. a right asked for WITHOUT its limits is raised');
  t.check(/count/.test(rights.limitsRaised(granted,
    [{ type: 'lo-acct', identifier: 'a',
       limits: { count: 6, amount: '50', currency: 'EUR' } }])),
          'F2. a larger count is raised');
  t.check(rights.limitsRaised(granted, [{ type: 'lo-acct', identifier: 'a',
    limits: { count: 2, amount: '10', currency: 'EUR' } }]) === '',
          'F3. lower limits are within');
  t.check(rights.limitsRaised([{ type: 'lo-acct' }], [{ type: 'lo-acct',
    identifier: 'a' }]) === '',
          'F4. a grant with no limits limits nothing');
  log.debug("Leaving later().");
}

// ---------------------------------------------------------------- G
async function totals(t) {
  log.debug("Entering totals().");
  t.log.info('=== G. the resource server\'s totals, on one process ===');
  spendModule.forget();
  const Cls = spendModule.GnapSpend;
  let now = Date.parse('2026-10-01T10:00:00Z') / 1000;
  const counters = { sharesBudgets: function () { return false; } };
  const spender = new Cls(Object.assign(Cls.defaultDeps(), {
    nowSec: function () { return now; }, counters: counters }));
  const right = { type: 'lo-acct', identifier: 'acct-g',
                  limits: { amount: '100', currency: 'EUR', count: 3,
                            receiver: ['bob'],
                            interval: 'R/2026-10-01T00:00:00Z/P1D',
                            window: { notAfter: '2026-10-10T00:00:00Z' } } };
  const op = function (amount, extra) {
    log.debug("Entering op().");
    log.debug("Leaving op().");
    return spender.spend({ grant: 'g-1', right: right, expiresAt: now + 999,
      operation: Object.assign({ amount: amount, currency: 'EUR',
                                 receiver: 'bob' }, extra || {}) });
  };
  let r = await op('60');
  t.check(r.ok && r.totals.amount === '60' && r.remaining.amount === '40' &&
          r.remaining.count === 2, 'G1. a spend within the limits',
          shown(r));
  r = await op('50');
  t.check(!r.ok && r.code === 'STS-GNAP-0870' && r.status === 403 &&
          r.error === 'insufficient_scope',
          'G2. one past the amount is refused (0870) and counts nothing',
          shown(r));
  r = await op('40');
  t.check(r.ok && r.totals.amount === '100', 'G3. exactly to the limit');
  r = await op('0');
  t.check(r.ok && r.totals.count === 3, 'G4. the third operation');
  r = await op('0');
  t.check(!r.ok && r.code === 'STS-GNAP-0870',
          'G5. a fourth passes the count');
  t.check(errorCodes.codeOf(await op('1', { currency: 'USD' })) ===
          'STS-GNAP-0873', 'G6. another currency is 0873');
  t.check(errorCodes.codeOf(await op('1', { receiver: 'mallory' })) ===
          'STS-GNAP-0872', 'G7. another receiver is 0872');
  now += 86400;
  r = await op('100');
  t.check(r.ok && r.totals.amount === '100' && r.totals.count === 1 &&
          /2026-10-02T00:00:00/.test(r.period.start),
          'G8. the totals RESET at the interval\'s boundary',
          shown(r));
  t.check(await spender.refund(r.spent) === true &&
          (await op('100')).ok,
          'G9. a refunded spend is spent again');
  now = Date.parse('2026-10-11T00:00:00Z') / 1000;
  t.check(errorCodes.codeOf(await op('1')) === 'STS-GNAP-0871',
          'G10. past the window is 0871');
  // Twenty at once against a count of five, on the one-process ledger.
  now = Date.parse('2026-10-01T10:00:00Z') / 1000;
  const five = { type: 'lo-acct', identifier: 'acct-five',
                 limits: { count: 5 } };
  const all = await Promise.all(Array.from({ length: 20 }, function () {
    return spender.spend({ grant: 'g-2', right: five, operation: {},
                           expiresAt: now + 999 });
  }));
  t.check(all.filter(function (one) { return one.ok; }).length === 5,
          'G11. twenty spends at once against a limit of five: exactly ' +
          'five succeed');
  t.check(Cls.keyOf('g-1', right) !== Cls.keyOf('g-1', five) &&
          Cls.keyOf('g-1', right) !== Cls.keyOf('g-2', right),
          'G12. totals are kept per grant and per right');
  log.debug("Leaving totals().");
}

// ---------------------------------------------------------------- H
async function sharedStore(t) {
  log.debug("Entering sharedStore().");
  t.log.info('=== H. the shared store ===');
  const pgPath = require.resolve(ROOT + '/node_modules/pg');
  const previous = require.cache[pgPath];
  const statements = [];
  const FakeClient = function () {};
  FakeClient.prototype.query = function (sql, params) {
    statements.push({ sql: String(sql), params: params || [] });
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.connect = function () { return Promise.resolve(); };
  FakeClient.prototype.end = function () { return Promise.resolve(); };
  const FakePool = function () {};
  FakePool.prototype.on = function () {};
  FakePool.prototype.query = FakeClient.prototype.query;
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.end = function () { return Promise.resolve(); };
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: { Pool: FakePool, Client: FakeClient } };
  const driverPath = require.resolve(ROOT +
                                     '/persistence/persistence_postgres');
  const previousDriver = require.cache[driverPath];
  delete require.cache[driverPath];
  try {
    const pgDriver = require(driverPath).create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} } });
    const over = await pgDriver.spendBudget('gnap.spend', '', 'k', 3, '5000000',
                                            1, '100000000', 5, 0);
    await pgDriver.refundBudget('gnap.spend', '', 'k', 3, '5000000', 1);
    const spend = statements.filter(function (one) {
      return /INSERT INTO sts_cluster_budgets/.test(one.sql);
    })[0];
    t.check(!!spend && /SELECT \$1/.test(spend.sql) &&
            /WHERE \(\$7::bigint IS NULL OR \$5::bigint <= \$7::bigint\)/
              .test(spend.sql) &&
            /ON CONFLICT \(scope, realm, key\) DO UPDATE/.test(spend.sql) &&
            /EXCLUDED\.period >= sts_cluster_budgets\.period/.test(spend.sql) &&
            /<= \$7::bigint\) AND/.test(spend.sql) &&
            /<= \$8::bigint\)/.test(spend.sql) &&
            /CASE WHEN sts_cluster_budgets\.period = EXCLUDED\.period THEN/
              .test(spend.sql) && over === null,
            'H1. a spend is ONE upsert: proposed only when it fits alone, ' +
            'written only within the limits and never for an older period, ' +
            'reset at a new one; no row back is the refusal',
            spend ? spend.sql : 'no statement');
    const refund = statements.filter(function (one) {
      return /UPDATE sts_cluster_budgets/.test(one.sql);
    })[0];
    t.check(!!refund && /period = \$4::bigint/.test(refund.sql) &&
            /amount >= \$5::bigint AND count >= \$6::bigint/.test(refund.sql),
            'H2. a refund takes back only from its own period, never below ' +
            'zero', refund ? refund.sql : 'no statement');
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
    require.cache[driverPath] = previousDriver;
  }
  const Cls = spendModule.GnapSpend;
  const failing = new Cls(Object.assign(Cls.defaultDeps(), {
    counters: { sharesBudgets: function () { return true; },
                spendBudget: function () {
                  return Promise.resolve({ ok: false, reason: 'store',
                                           why: 'down' });
                } } }));
  const r = await failing.spend({ grant: 'g', right: { type: 'x',
    limits: { count: 1 } }, operation: {}, expiresAt: 0 });
  t.check(!r.ok && r.code === 'STS-GNAP-0875' && r.status === 503,
          'H3. a shared store that cannot be asked REFUSES (0875)',
          shown(r));
  log.debug("Leaving sharedStore().");
}

// ---------------------------------------------------------------- I
function reserved(t) {
  log.debug("Entering reserved().");
  t.log.info('=== I. grant_id is reserved ===');
  const d = applications.authorizationDetailsTypeOf(JSON.stringify({
    type: 'lo-x', introspectionClaims: ['grant_id'] }));
  t.check(/already carries/.test(d.problem),
          'I1. a type may not declare grant_id as an introspection claim',
          d.problem);
  log.debug("Leaving reserved().");
}

// ---------------------------------------------------------------- J
async function rar(t) {
  log.debug("Entering rar().");
  t.log.info('=== J. RFC 9396 limits: the grant id and lowering ===');
  const oauth2 = require('../oauth-oidc/oauth2');
  const sealed = require('../oauth-oidc/refresh_token_crypto');
  const helpers = require('../common/helpers');
  const BASE = 'https://sts.lo.test';
  const limited = [{ type: 'lo-acct', actions: ['spend'],
                     limits: { amount: '50', currency: 'EUR', count: 3 } }];
  const plain = [{ type: 'lo-acct', actions: ['read'] }];
  t.check(catalogue.carriesLimits(limited) && !catalogue.carriesLimits(plain),
          'J1. carriesLimits() tells a detail with limits from one without');
  const lowered = [{ type: 'lo-acct', actions: ['spend'],
                     limits: { amount: '20', currency: 'EUR', count: 3 } }];
  t.check(catalogue.limitsRaisedBy(limited, lowered) === '' &&
          /amount/.test(catalogue.limitsRaisedBy(limited, [{ type: 'lo-acct',
            actions: ['spend'], limits: { amount: '60', currency: 'EUR',
                                          count: 3 } }])) &&
          /changed/.test(catalogue.limitsRaisedBy(limited, [{
            type: 'lo-acct', actions: ['spend', 'read'],
            limits: lowered[0].limits }])) &&
          /not the details/.test(catalogue.limitsRaisedBy(limited, [])),
          'J2. limitsRaisedBy(): lower limits only — a raise, another ' +
          'member changed and a missing detail are named');
  const digest = catalogue.digestOf(limited);
  catalogue.noteConsented('lo-alice', 'lo-client', digest, lowered);
  const spent = catalogue.consumeConsent('lo-alice', 'lo-client', digest);
  t.check(spent && JSON.stringify(spent.lowered) === JSON.stringify(lowered) &&
          catalogue.consumeConsent('lo-alice', 'lo-client', digest) === null,
          'J3. an Allow carries the details as lowered, and is spent once',
          JSON.stringify(spent));
  const claimsOf = function (jwt) {
    log.debug("Entering claimsOf().");
    log.debug("Leaving claimsOf().");
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                            .toString('utf8'));
  };
  const issue = function (extra) {
    log.debug("Entering issue().");
    log.debug("Leaving issue().");
    return oauth2.tokenSet(BASE, Object.assign({
      client_id: 'lo-client', grant: 'authorization_code', scope: '',
      sub: 'lo-alice', username: 'lo-alice',
      user: { username: 'lo-alice', sub: 'lo-alice' } }, extra));
  };
  const first = await issue({ authorization_details: limited });
  const firstGrant = claimsOf(first.access_token).grant_id;
  t.check(typeof firstGrant === 'string' && firstGrant.length > 8 &&
          first.grant_id === undefined,
          'J4. an access token whose details carry limits has a grant_id ' +
          '(and the response no Grant Management member)',
          JSON.stringify(claimsOf(first.access_token)));
  const inner = helpers.verifyOwnJws(sealed.open(first.refresh_token));
  t.check(inner && inner.limits_grant === firstGrant,
          'J5. the refresh token keeps it, inside its JWE',
          JSON.stringify(inner && inner.limits_grant));
  const renewed = await issue({ grant: 'refresh_token',
                                authorization_details: limited,
                                limits_grant: inner.limits_grant });
  t.check(claimsOf(renewed.access_token).grant_id === firstGrant,
          'J6. the refreshed token carries the SAME grant_id: one budget');
  const other = await issue({ authorization_details: limited });
  t.check(claimsOf(other.access_token).grant_id !== firstGrant,
          'J7. another authorization is another grant');
  const none = await issue({ authorization_details: plain });
  t.check(claimsOf(none.access_token).grant_id === undefined,
          'J8. details without limits carry no grant_id');
  const managed = await issue({ authorization_details: limited,
                                grant_id: 'gm-lo-1', grant_gen: 1 });
  t.check(claimsOf(managed.access_token).grant_id === 'gm-lo-1',
          'J9. Grant Management\'s grant_id is the one used where there is one');
  // The consent screen.
  const screen = require('../oauth-oidc/consent_screen');
  const path = screen.beginConsent({
    returnTo: '/oauth2/authorize?x=1', username: 'lo-alice',
    clientId: 'lo-client', scopes: [],
    authorizationDetails: catalogue.describe(limited),
    rawAuthorizationDetails: limited, detailsDigest: digest });
  const id = decodeURIComponent(path.split('consent=')[1]);
  const record = screen.pendingFor(id);
  t.check(!!record && record.rawAuthorizationDetails.length === 1,
          'J10. the consent record keeps the details themselves');
  log.debug("Leaving rar().");
}

module.exports = {
  name: 'gnap_limits_ownership',
  describe: 'who owns what a GNAP right names, and what a right\'s limits ' +
            'mean to the approval page, the token and the resource server ' +
            '(#432 phase 5)',
  run: run
};
