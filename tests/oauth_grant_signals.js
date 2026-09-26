'use strict';
//
// File: oauth_grant_signals.js
//
// ===========================================================================
// AN OAUTH GRANT REVOKED IS CAEP's `session-revoked` ABOUT THE GRANT (#239).
//
// `oauth-oidc/oauth_grant_signals.ts` fills `common/admin_stats.js`'s
// `setRevocationObserver()` slot and turns the revocations every door already
// makes into ONE event per grant, with the door's own `initiating_entity`,
// and a replay into a risk signal as well. Three contracts are asserted
// here, each where it can be seen without a port:
//
//   A. THE DECISIONS, on the class with its deliveries captured: which
//      revocations end a grant, one event per grant however many jtis one
//      act revokes, a grant announced once, the door's entity, the replay's
//      risk-level-change before its session-revoked, CAEP's own switches.
//   B. THE SLOT, on the real `admin_stats.js`: the observer is told of a
//      jti NEWLY revoked, once, with the record the issuer stated and the
//      door's `how` — through `revoke()` and `revokeWhere()` alike — and a
//      throwing observer cannot fail a revocation.
//   C. EVERY DOOR STATES ITS ACT, a source check: each `stats.revoke()` /
//      `stats.revokeWhere()` call in the OAuth doors passes a third argument,
//      because an unstated one is reported as `system`, which is true of
//      none of them. The next door written without it fails here by name.
//
// The end-to-end half — a stream, the real doors, the SETs — is
// `tests/vendored/sts_caep_oauth_grants.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const helpers = require('../common/helpers');
const stats = require('../common/admin_stats');
const grantSignals = require('../oauth-oidc/oauth_grant_signals');

const log = require('bunyan').createLogger({ name: 'oauth_grant_signals',
  level: process.env.LOG_LEVEL || 'info' });

// The class with every delivery captured and CAEP's acts chosen.
function harness(acts) {
  log.debug("Entering harness().");
  const sent = [];
  const installed = [];
  const instance = new grantSignals.OAuthGrantSignals({
    log: log,
    errorCodes: { tag: function (code) { return code + ' '; } },
    realms: {
      currentId: function () { return 'default'; },
      get: function () { return null; },
      run: function (realm, fn) { return fn(); }
    },
    subjectForName: function (name) { return 'urn:uuid:' + name; },
    stats: { setRevocationObserver: function (fn) { installed.push(fn); } },
    loadSsf: function () {
      return { emitProtocolEvent: function (asked) {
        sent.push(asked);
        return Promise.resolve({ sent: 1 });
      } };
    },
    loadSsfHttp: function () {
      return { transmitterIssuer: function () {
        return 'https://sts.example';
      } };
    },
    loadCaep: function () {
      return { autoEmitActs: function () {
        return acts || ['revoked', 'risk'];
      } };
    }
  });
  log.debug("Leaving harness().");
  return { instance: instance, sent: sent, installed: installed };
}

function token(kind, extra) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return Object.assign({ jti: 'j-' + Math.random().toString(36).slice(2),
    kind: kind, username: 'alice', sub: 'urn:uuid:alice',
    client_id: 'webapp', grantId: 'fam-1', grantRefresh: true }, extra || {});
}

async function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('A. which revocations end a grant, and what is sent');
  let h = harness();
  const refresh = token('refresh_token');
  const access = token('access_token');
  t.equal(h.instance.observe(refresh, 'the RFC 7009 revocation endpoint',
                             { initiatingEntity: 'user' }), true,
          'a refresh token revoked ends its grant');
  t.equal(h.instance.observe(access, 'the RFC 7009 revocation endpoint',
                             { initiatingEntity: 'user' }), false,
          'an access token beside a refresh token does not end the grant');
  t.equal(h.instance.observe(token('refresh_token'), 'the same act, the ' +
          'family\'s next member', { initiatingEntity: 'user' }), true,
          'a second refresh token of the same grant is queued with it');
  await h.instance.settled();
  t.equal(h.sent.length, 1, 'ONE event for the grant, not one per token');
  const one = h.sent[0] || {};
  t.equal(one.type, 'session-revoked', 'it is session-revoked');
  t.equal(one.initiatingEntity, 'user', 'with the door\'s entity');
  t.equal(one.subject && one.subject.format, 'complex',
          'a complex subject');
  t.equal(one.subject && one.subject.session.id, 'oauth-grant:fam-1',
          'whose session is oauth-grant:<the grant>');
  t.equal(one.subject && one.subject.user.sub, 'urn:uuid:alice',
          'and whose user is the person');
  t.check(/RFC 7009/.test(one.reasonAdmin || ''),
          'reason_admin says which door');

  t.equal(h.instance.observe(token('refresh_token'), 'later', {}), true,
          'the same grant revoked again is queued');
  await h.instance.settled();
  t.equal(h.sent.length, 1, 'but a grant is announced ONCE');

  h = harness();
  const quiet = [
    [token('refresh_token', { grantId: 'r' }), { superseded: true },
     'a refresh token retired by rotation'],
    [token('id_token', { grantId: 'i' }), {}, 'an ID Token'],
    [token('gnap_access_token', { grantId: 'g' }), {},
     'a GNAP token (GNAP reports its own)'],
    [token('refresh_token', { grantId: 'c', username: '' }), {},
     'a grant with no person behind it']
  ];
  quiet.forEach(function (row) {
    t.equal(h.instance.observe(row[0], 'x', row[1]), false,
            row[2] + ' ends nothing that is reported');
  });
  t.equal(h.instance.observe(token('access_token', { grantId: 'set-9',
    grantRefresh: false }), 'the admin console',
    { initiatingEntity: 'admin' }), true,
          'an access token whose grant holds no refresh token ends it');
  t.equal(h.instance.observe(token('refresh_token', { grantId: 'set-10' }),
                             'x', { initiatingEntity: 'nonsense' }), true,
          'a door naming no CAEP entity is still reported');
  await h.instance.settled();
  t.equal(h.sent.length, 2, 'two grants, two events');
  t.equal(h.sent[0].initiatingEntity, 'admin', 'the console is admin');
  t.equal(h.sent[1].initiatingEntity, 'system',
          'and an entity CAEP does not define is reported as system');

  t.log.info('A2. a replay is a risk signal, then the revocation');
  h = harness();
  h.instance.observe(token('refresh_token', { grantId: 'rep' }),
    'RFC 9700 section 2.2.2: a replayed refresh token revoked its family',
    { initiatingEntity: 'policy', replay: 'refresh-token-replay' });
  await h.instance.settled();
  t.equal(h.sent.length, 2, 'two events');
  t.equal((h.sent[0] || {}).type, 'risk-level-change',
          'risk-level-change FIRST');
  t.equal(JSON.stringify((h.sent[0] || {}).values),
          JSON.stringify({ principal: 'SESSION', current_level: 'HIGH',
                           risk_reason: 'refresh-token-replay' }),
          'SESSION, HIGH, naming the replay');
  t.equal((h.sent[1] || {}).type, 'session-revoked',
          'then session-revoked');
  t.equal((h.sent[1] || {}).initiatingEntity, 'policy', 'both policy');
  t.equal((h.sent[0] || {}).subject.session.id,
          (h.sent[1] || {}).subject.session.id, 'about the same grant');

  t.log.info('A3. CAEP\'s own switches');
  h = harness(['revoked']);
  h.instance.observe(token('refresh_token', { grantId: 'r2' }), 'x',
                     { initiatingEntity: 'policy', replay: 'x' });
  await h.instance.settled();
  t.equal(h.sent.length, 1, 'without the risk act, only session-revoked');
  h = harness(['established', 'presented', 'risk']);
  h.instance.observe(token('refresh_token', { grantId: 'r3' }), 'x',
                     { initiatingEntity: 'user' });
  await h.instance.settled();
  t.equal(h.sent.length, 0, 'without the revoked act, nothing');
  h.instance.install();
  t.equal(h.installed.length, 1, 'install() fills the slot');
  log.debug("Leaving sectionA().");
}

function mint(typ, jti, context) {
  log.debug("Entering mint().");
  const now = Math.floor(Date.now() / 1000);
  helpers.signJwt({ typ: typ, jti: jti, sub: 'urn:uuid:bob',
    username: 'bob', client_id: 'webapp', scope: 'openid',
    iat: now, nbf: now, exp: now + 900 }, context || {});
  log.debug("Leaving mint().");
}

function sectionB(t) {
  log.debug("Entering sectionB().");
  t.log.info('B. the slot on the real admin_stats.js');
  const told = [];
  stats.setRevocationObserver(function (record, via, how) {
    told.push({ record: record, via: via, how: how });
  });
  mint('Refresh', 'ogs-r1', { grantId: 'fam-b', grantRefresh: true,
                              setId: 'set-b' });
  mint('Bearer', 'ogs-a1', { grantId: 'fam-b', grantRefresh: true,
                             setId: 'set-b' });
  t.equal(stats.revoke('ogs-r1', 'door one', { initiatingEntity: 'user' }),
          true, 'a fresh revocation');
  t.equal(told.length, 1, 'is told to the observer');
  t.equal((told[0] || {}).record.grantId, 'fam-b',
          'with the grant the issuer stated');
  t.equal((told[0] || {}).record.grantRefresh, true,
          'and whether that grant holds a refresh token');
  t.equal((told[0] || {}).record.kind, 'refresh_token', 'and its kind');
  t.equal((told[0] || {}).how.initiatingEntity, 'user',
          'and the door\'s own statement');
  stats.revoke('ogs-r1', 'door one again', { initiatingEntity: 'user' });
  t.equal(told.length, 1, 'a jti already revoked is not told twice');
  stats.revokeWhere(function (record) {
    return record.jti === 'ogs-a1';
  }, 'door two', { initiatingEntity: 'admin' });
  t.equal(told.length, 2, 'revokeWhere() tells it too');
  t.equal((told[1] || {}).how.initiatingEntity, 'admin',
          'with the statement revokeWhere() was given');
  mint('Refresh', 'ogs-r2', { grantId: 'fam-c', grantRefresh: true });
  stats.setRevocationObserver(function () {
    throw new Error('a broken observer');
  });
  t.equal(stats.revoke('ogs-r2', 'door three'), true,
          'a throwing observer cannot fail the revocation');
  t.equal(stats.isRevoked('ogs-r2'), true, 'which stands');
  // Put the module's own observer back, for whatever runs next in this
  // process.
  stats.setRevocationObserver(function (record, via, how) {
    return grantSignals.observe(record, via, how);
  });
  log.debug("Leaving sectionB().");
}

// The call's argument list, by matching its parentheses from `at` (the
// index of the opening one), with strings and comments skipped well enough
// for this tree's own source.
function argumentsAt(src, at) {
  log.debug("Entering argumentsAt().");
  let depth = 0;
  let count = 1;
  let quote = '';
  for (let i = at; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') {
        i++;
      } else if (c === quote) {
        quote = '';
      }
      continue;
    }
    if (c === '\'' || c === '"' || c === '`') {
      quote = c;
    } else if (c === '(' || c === '{' || c === '[') {
      depth++;
    } else if (c === ')' || c === '}' || c === ']') {
      depth--;
      if (depth === 0) {
        log.debug("Leaving argumentsAt().");
        return count;
      }
    } else if (c === ',' && depth === 1) {
      count++;
    }
  }
  log.debug("Leaving argumentsAt(). Unbalanced.");
  return 0;
}

function sectionC(t) {
  log.debug("Entering sectionC().");
  t.log.info('C. every OAuth door states its act');
  const doors = ['../oauth-oidc/oauth2.ts', '../oauth-oidc/grant_management.ts',
                 '../common/consent.ts', '../admin-core/admin_actions.ts',
                 '../logout/logout.ts'];
  doors.forEach(function (file) {
    const src = fs.readFileSync(path.join(__dirname, file), 'utf8')
      .replace(/\/\/[^\n]*/g, '');
    const name = path.basename(file);
    const re = /stats\.(revoke|revokeWhere)\(/g;
    let m;
    let calls = 0;
    while ((m = re.exec(src))) {
      calls++;
      const n = argumentsAt(src, m.index + m[0].length - 1);
      const line = src.slice(0, m.index).split('\n').length;
      t.check(n >= 3, name + ':' + line + ' — stats.' + m[1] + '() states ' +
              'its act (initiatingEntity, superseded or replay) as a third ' +
              'argument; without one CAEP reports the grant ended by ' +
              '"system"');
    }
    t.check(calls > 0, name + ' still revokes through the one set');
  });
  log.debug("Leaving sectionC().");
}

async function run(t) {
  log.debug("Entering run().");
  await sectionA(t);
  sectionB(t);
  sectionC(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oauth_grant_signals',
  describe: 'an OAuth grant revoked is one CAEP session-revoked about the ' +
            'grant, with the door\'s initiating_entity, and a replay a risk ' +
            'signal too (#239)',
  run: run
};
