// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_person_grants.js
//
// ---------------------------------------------------------------------------
// #432 PHASE 7 IN PROCESS: WHAT A PERSON SEES OF THEIR GNAP GRANTS, WHAT A
// CLIENT IS TOLD ABOUT THEM, AND HOW A GRANT ENDS.
//
//   A. Per-client opaque subject identifiers (`pairwise_subjects.ts`'s
//      gnapOpaqueFor()): different for two clients, stable for one, shared by
//      two clients of one registered sector — and a user reference resolves
//      only for the client (or sector) it was issued to (STS-GNAP-0070).
//   B. Subject information is released only on an authorization —
//      interaction or delegation — and the authorization is SPENT: a second
//      release of the same grant (a continuation, a modification) sends
//      none, and a decision without one sends none (STS-GNAP-0793).
//   C. The grant lifetime: a continuation past it is refused
//      (STS-GNAP-0790) and the grant finalized as expired; a rotation past it
//      is refused (STS-GNAP-0791); a token never outlives its grant; the
//      expiry job records an untouched grant's end.
//   D. Finalization reasons — issued, revoked, rejected, expired — recorded
//      on the grant and audited, and an `issued` grant's tokens still live
//      at the resource server while a `revoked` one's are not.
//   E. `too_fast`: a continuation inside the wait is refused with a
//      continuation to use later (RFC 9635 section 5).
//   F. `class_id` and `display` are self-declared and marked so; the
//      registered values win.
//   G. One person's grants, the view three doors draw: only their own, the
//      portal's revoke refusing another person's grant, the console's
//      per-person revoke refusing a mismatch (STS-GNAP-0792).
//
// Why in process (tests/CLAUDE.md's first question): B, C and E move the
// clock and drive the engine's own steps directly. The HTTP half is
// `tests/vendored/sts_gnap_core.js`: section 7 (a user reference refused from
// another client; the subject not released again on continuation,
// modification or rotation) and section 15 (`/portal/gnap` listing and
// revoking, `/admin-api` listing and revoking per person, the audit actor).
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const crypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'gnap_person_grants',
  level: process.env.LOG_LEVEL || 'info' });

const SUFFIX = crypto.randomBytes(3).toString('hex');

// A grant record as the engine makes one, with the fields a test names.
function grantOf(store, fields) {
  log.debug("Entering grantOf().");
  const grant = store.newGrant(Object.assign({
    as: 'default', grantEndpoint: 'https://as.example/gnap',
    client: { identifier: 'gpg-client-' + SUFFIX, key: null, proof: 'httpsig',
              display: { name: 'gpg', declared: [] } },
    request: { tokens: [], multiple: false, subject: null, interact: null },
    ro: null, decision: null, delivered: false, polls: 0,
    grantExpiresAt: Math.floor(Date.now() / 1000) + 3600,
    subjectAuthorizedBy: null, finalization: null
  }, fields || {}));
  log.debug("Leaving grantOf().");
  return grant;
}

// An engine over the real modules with the named dependencies replaced.
function engine(overrides) {
  log.debug("Entering engine().");
  const { GnapGrants } = require('../gnap/gnap_grants');
  log.debug("Leaving engine().");
  return new GnapGrants(Object.assign(GnapGrants.defaultDeps(),
                                      overrides || {}));
}

function request() {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return { method: 'POST', headers: { host: 'as.example' }, query: {},
           protocol: 'https', get: function () {
             return 'as.example';
           } };
}

function checkPairwise(t) {
  log.debug("Entering checkPairwise().");
  t.log.info('A. per-client opaque subject identifiers');
  const ldap = require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const subject = require('../gnap/gnap_subject');
  const alice = 'gpg-alice-' + SUFFIX;
  ldap.createUser(alice, { invent: false });
  const A = 'gpg-a-' + SUFFIX;
  const B = 'gpg-b-' + SUFFIX;
  const C = 'gpg-c-' + SUFFIX;
  const D = 'gpg-d-' + SUFFIX;
  [A, B].forEach(function (id) {
    applications.createApplication({ identifier: id, kind: 'gnap-client',
                                     fields: {} });
  });
  [C, D].forEach(function (id) {
    const made = applications.createApplication({
      identifier: id, kind: 'gnap-client',
      fields: { oauthSectorIdentifierUri:
                  'https://sector-' + SUFFIX + '.example/uris.json' } });
    t.check(made && made.ok !== false, 'fixture: ' + id + ' registered with ' +
            'a sector', made);
  });
  const forA = subject.opaqueIdFor(alice, A);
  const forB = subject.opaqueIdFor(alice, B);
  t.check(forA && forB && forA !== forB,
          'two clients are told two different opaque identifiers for one ' +
          'person', forA + ' / ' + forB);
  t.equal(subject.opaqueIdFor(alice, A), forA,
          'and one client is told the same one every time');
  t.equal(subject.opaqueIdFor(alice, C), subject.opaqueIdFor(alice, D),
          'two clients of one REGISTERED sector are told the same one (OIDC ' +
          'Core section 8.1)');
  const ids = subject.subIdsFor(alice, ['opaque'], { issuer: 'https://x',
                                                     client: A });
  t.equal(ids.length === 1 && ids[0].id, forA,
          'the sub_ids a grant releases carry the client\'s own identifier');
  const own = subject.resolveUser({ reference: forA }, { client: A });
  t.check(own.ok && own.username === alice,
          'the client that was given a reference resolves it (2.4.1)', own);
  const other = subject.resolveUser({ reference: forA }, { client: B });
  t.check(!other.ok && other.errorCode === 'STS-GNAP-0070' &&
          other.gnapError === 'unknown_user',
          'another client presenting it is told unknown_user, as for a ' +
          'value never issued', other);
  const bySector = subject.resolveUser(
      { reference: subject.opaqueIdFor(alice, C) }, { client: D });
  t.check(bySector.ok && bySector.username === alice,
          'a client of the same sector may present its sector\'s reference',
          bySector);
  const bySubId = subject.resolveUser(
      { sub_ids: [{ format: 'opaque', id: forA }] }, { client: B });
  t.check(bySubId.ok && !bySubId.username,
          'an opaque sub_id from another client is a hint that names nobody',
          bySubId);
  log.debug("Leaving checkPairwise().");
  return alice;
}

async function checkSubjectRelease(t, alice) {
  log.debug("Entering checkSubjectRelease().");
  t.log.info('B. subject information on an authorization, released once');
  const store = require('../gnap/gnap_store');
  const released = [];
  const g = engine({
    baseUrlOf: function () {
      return 'https://as.example';
    },
    loadOauth2: function () {
      return { issuerOf: function () {
        return 'https://as.example';
      } };
    },
    subject: Object.assign({}, require('../gnap/gnap_subject'), {
      subIdsFor: function (who, formats, ctx) {
        released.push({ who: who, client: ctx.client });
        return [{ format: 'opaque', id: 'id-for-' + ctx.client }];
      }
    })
  });
  const asked = { subIdFormats: ['opaque'], assertionFormats: [] };
  const grant = grantOf(store, {
    request: { tokens: [], multiple: false, subject: asked, interact: null },
    ro: { username: alice, sessionId: null, authTime: 1, amr: ['pwd'] },
    decision: { approved: true, tokens: [], subject: true },
    subjectAuthorizedBy: 'interaction'
  });
  const first = await g.release(request(), grant);
  t.check(first.subject && first.subject.sub_ids &&
          first.subject.sub_ids[0].id === 'id-for-' + grant.client.identifier,
          'an approval with the subject box ticked releases it, for that ' +
          'client', first.subject);
  t.check(grant.subjectAuthorizedBy === null &&
          grant.subjectReleasedBy === 'interaction' &&
          grant.subjectReleasedAt > 0,
          'and the authorization is SPENT, the release recorded',
          JSON.stringify({ by: grant.subjectAuthorizedBy,
                           releasedBy: grant.subjectReleasedBy }));
  // What a continuation after approval or a modification within it would
  // do if it ever reached release() with the same decision.
  const again = await g.release(request(), grant);
  t.check(!again.subject && released.length === 1,
          'a second release of the same grant sends no subject information',
          again);
  const unauthorized = grantOf(store, {
    request: { tokens: [], multiple: false, subject: asked, interact: null },
    ro: { username: alice, sessionId: null, authTime: 1, amr: ['pwd'] },
    decision: { approved: true, tokens: [], subject: true }
  });
  const none = await g.release(request(), unauthorized);
  t.check(!none.subject,
          'a decision with neither an interaction nor a delegation behind it ' +
          'releases nothing (STS-GNAP-0793)', none);
  const delegated = grantOf(store, {
    request: { tokens: [], multiple: false, subject: asked, interact: null },
    ro: { username: alice, sessionId: null, authTime: 1, amr: ['assertion'] },
    decision: { approved: true, tokens: [], subject: true },
    subjectAuthorizedBy: 'delegation'
  });
  const byDelegation = await g.release(request(), delegated);
  t.check(byDelegation.subject && delegated.subjectReleasedBy === 'delegation',
          'a delegation decision authorizes one release', byDelegation);
  log.debug("Leaving checkSubjectRelease().");
}

async function checkLifetime(t, alice) {
  log.debug("Entering checkLifetime().");
  t.log.info('C. the grant lifetime');
  const config = require('../common/config');
  const store = require('../gnap/gnap_store');
  const grants = require('../gnap/gnap_grants');
  const lifetime = Number(config.value('gnap.grantLifetimeS'));
  t.equal(lifetime, 86400, 'gnap.grantLifetimeS defaults to a day');
  const now = Math.floor(Date.now() / 1000);
  t.equal(grants.grantExpiryFrom(now), now + lifetime,
          'a grant made now expires that long after');
  let clock = now;
  const g = engine({
    nowSec: function () {
      return clock;
    },
    baseUrlOf: function () {
      return 'https://as.example';
    }
  });
  const approved = grantOf(store, {
    state: store.STATE.APPROVED, delivered: true,
    ro: { username: alice }, grantExpiresAt: now + 100
  });
  t.equal(g.cappedLifetime(approved, now, 3600), 100,
          'a token issued under it is cut short at the grant\'s expiry');
  t.equal(g.cappedLifetime(approved, now, 50), 50,
          'and a shorter one is left as it is');
  clock = now + 101;
  const refused = await g.continueAccepted(request(),
      { grant: approved, body: { json: null, hadContent: false } });
  t.check(!refused.ok && refused.errorCode === 'STS-GNAP-0790' &&
          refused.gnapError === 'invalid_continuation',
          'a continuation past the grant lifetime is refused', refused);
  t.check(approved.state === store.STATE.FINALIZED &&
          approved.finalization.reason === 'expired',
          'and the grant is finalized as expired', approved.finalization);

  // A rotation past it: the engine's management door, its proof stubbed.
  const record = { jti: 'gpg-jti-' + SUFFIX, grantId: 'gpg-gone-' + SUFFIX,
                   format: 'jwt-signed', key: { proof: 'httpsig' },
                   access: ['x'], iat: now, exp: now + 50,
                   grantExpiresAt: now + 100, revoked: false };
  const fakeStore = Object.assign({}, store, {
    STATE: store.STATE,
    tokenByManagement: function () {
      return record;
    },
    getGrant: function () {
      return null;
    },
    spend: async function () {
      return { ok: true, handle: 'h' };
    },
    unspend: async function () {
      return null;
    }
  });
  const rotating = engine({
    nowSec: function () {
      return clock;
    },
    store: fakeStore,
    keys: Object.assign({}, require('../gnap/gnap_keys'), {
      describe: function () {
        return { ok: true, proof: { method: 'httpsig' } };
      }
    }),
    proof: Object.assign({}, require('../gnap/gnap_proof'), {
      presentedToken: function () {
        return 'management-token';
      },
      readBody: function () {
        return { ok: true, json: null, hadContent: false };
      },
      verifyRequestOnce: async function () {
        return { ok: true };
      }
    }),
    request: Object.assign({}, require('../gnap/gnap_request'), {
      parseRotation: function () {
        return { ok: true, key: null };
      }
    })
  });
  const rotation = await rotating.manageVerified(request(), 'handle',
                                                 { handle: null });
  t.check(!rotation.ok && rotation.errorCode === 'STS-GNAP-0791' &&
          rotation.gnapError === 'invalid_rotation',
          'a rotation past the grant lifetime is refused, even with the ' +
          'grant itself already gone', rotation);

  // The expiry job.
  const untouched = grantOf(store, { state: store.STATE.APPROVED,
                                     delivered: true, ro: { username: alice },
                                     grantExpiresAt: now + 10 });
  const denied = grantOf(store, { state: store.STATE.PENDING,
                                  expiresAt: now + 5,
                                  lastDenial: 'user_denied' });
  const job = g.expireGrants();
  t.check(untouched.state === store.STATE.FINALIZED &&
          untouched.finalization.reason === 'expired',
          'the expiry job finalizes an untouched grant past its lifetime as ' +
          'expired', untouched.finalization);
  t.check(denied.state === store.STATE.FINALIZED &&
          denied.finalization.reason === 'rejected',
          'and one whose interaction ran out after a no as rejected',
          denied.finalization);
  t.check(/finalized/.test(job.summary), 'the job reports what it did',
          job.summary);
  log.debug("Leaving checkLifetime().");
}

function checkFinalization(t, alice) {
  log.debug("Entering checkFinalization().");
  t.log.info('D. finalization reasons, and which tokens they end');
  const store = require('../gnap/gnap_store');
  const grants = require('../gnap/gnap_grants');
  const rs = require('../gnap/gnap_rs');
  const audit = require('../common/audit');
  const now = Math.floor(Date.now() / 1000);
  const issued = grantOf(store, { state: store.STATE.APPROVED,
                                  delivered: true, ro: { username: alice } });
  const token = store.putToken({ jti: store.handle(16), grantId: issued.id,
                                 format: 'macaroon', iat: now, exp: now + 600,
                                 access: ['x'], revoked: false,
                                 instanceId: issued.client.identifier },
                               'value-' + SUFFIX);
  issued.tokens = [token.jti];
  store.saveGrant(issued, 'fixture');
  grants.finalize(issued, 'released with no continuation offered', 'issued');
  t.equal(issued.finalization && issued.finalization.reason, 'issued',
          'a grant finalized after its release records issued');
  t.equal(rs.liveProblem(store.tokenByJti(token.jti)), '',
          'and its token is still live at the resource server');
  t.check(grants.revocable(issued),
          'an issued grant can still be revoked');
  const rows = audit.list().filter(function (row) {
    return row.action === 'gnap.grant.finalize' &&
           row.detail && row.detail.grant === issued.id;
  });
  t.check(rows.length === 1 && rows[0].detail.reason === 'issued',
          'the finalization is audited with its reason', rows.length);
  t.check(grants.revokeGrantBy(issued, { by: 'person', actor: alice,
                                         via: 'portal' }),
          'revoking it changes something');
  t.equal(issued.finalization.reason, 'revoked',
          'and it is then finalized as revoked');
  t.equal(rs.liveProblem(store.tokenByJti(token.jti)), 'revoked',
          'its token is refused at the resource server');
  t.check(!grants.revocable(issued) &&
          !grants.revokeGrantBy(issued, { by: 'administrator' }),
          'and a second revocation changes nothing');
  const rejected = grantOf(store, {});
  grants.finalize(rejected, 'refused: no interaction', 'rejected');
  t.equal(rejected.finalization.reason, 'rejected',
          'a refused request records rejected');
  t.check(grants.FINALIZATION_REASONS.join() ===
            'issued,revoked,rejected,expired',
          'the four reasons are the ones the console and portal draw');
  log.debug("Leaving checkFinalization().");
}

async function checkTooFast(t) {
  log.debug("Entering checkTooFast().");
  t.log.info('E. too_fast inside the continuation wait');
  const store = require('../gnap/gnap_store');
  const now = Math.floor(Date.now() / 1000);
  const g = engine({ baseUrlOf: function () {
    return 'https://as.example';
  } });
  const pending = grantOf(store, { state: store.STATE.PENDING,
                                   expiresAt: now + 600,
                                   continueNotBefore: now + 30 });
  const early = await g.continueAccepted(request(),
      { grant: pending, body: { json: null, hadContent: false } });
  t.check(!early.ok && early.gnapError === 'too_fast' &&
          early.errorCode === 'STS-GNAP-0133' &&
          early.extra && early.extra.continue &&
          early.extra.continue.access_token,
          'a continuation before the wait ends is too_fast, with a ' +
          'continuation to use later (RFC 9635 section 5)', early);
  log.debug("Leaving checkTooFast().");
}

function checkDisplay(t) {
  log.debug("Entering checkDisplay().");
  t.log.info('F. class_id and display are self-declared');
  const g = engine({});
  const bare = { identifier: 'gpg-bare', name: 'gpg-bare', fields: {} };
  const claimed = g.displayOf(bare, { display: {
    name: 'Your Bank', uri: 'https://bank.example',
    logoUri: 'data:image/png;base64,AAAA' } });
  t.check(claimed.name === 'Your Bank' &&
          claimed.declared.join() === 'name,uri,logoUri',
          'every display member taken from the request is marked declared',
          claimed);
  const registered = { identifier: 'gpg-reg', name: 'Registered Name',
                       fields: { gnapDisplayUri: 'https://reg.example' } };
  const kept = g.displayOf(registered, { display: {
    name: 'Something Else', uri: 'https://other.example' } });
  t.check(kept.name === 'Registered Name' &&
          kept.uri === 'https://reg.example' && kept.declared.length === 0,
          'the registered values win and nothing is marked declared',
          kept);
  log.debug("Leaving checkDisplay().");
}

function checkPersonView(t, alice) {
  log.debug("Entering checkPersonView().");
  t.log.info('G. one person\'s grants, and who may revoke them');
  const store = require('../gnap/gnap_store');
  const view = require('../gnap/gnap_console');
  const errorCodes = require('../common/error_codes');
  const bob = 'gpg-bob-' + SUFFIX;
  const mine = grantOf(store, { state: store.STATE.APPROVED, delivered: true,
                                ro: { username: alice },
                                approvedAccess: [{ type: 'photos',
                                                   actions: ['read'] }] });
  const theirs = grantOf(store, { state: store.STATE.APPROVED,
                                  delivered: true, ro: { username: bob } });
  const listed = view.personGrantsView(alice, {});
  const ids = listed.rows.map(function (row) {
    return row.id;
  });
  t.check(ids.indexOf(mine.id) >= 0 && ids.indexOf(theirs.id) < 0,
          'a person\'s view lists their grants and nobody else\'s', ids);
  const row = listed.rows.filter(function (one) {
    return one.id === mine.id;
  })[0];
  t.check(row && row.revocable && row.rightsAre === 'approved' &&
          row.rights[0].type === 'photos' && listed.cells.complete,
          'each row carries its rights, whether it can be revoked, and ' +
          'what a single-cell list covers', row);
  const stolen = view.revokeOwnGrant(alice, theirs.id, {});
  t.check(!stolen.ok && stolen.why === 'not-theirs' &&
          theirs.state === store.STATE.APPROVED,
          'the portal\'s revoke refuses another person\'s grant and leaves ' +
          'it alone', stolen);
  const ownRevoke = view.revokeOwnGrant(alice, mine.id, {});
  t.check(ownRevoke.ok && mine.finalization.reason === 'revoked',
          'and revokes the person\'s own', mine.finalization);
  const mismatch = view.gnapAction({ action: 'revoke-grant',
                                     grant: theirs.id, user: alice },
                                   { via: 'api' });
  t.check(!mismatch.ok && errorCodes.codeOf(mismatch) === 'STS-GNAP-0792' &&
          theirs.state === store.STATE.APPROVED,
          'the console\'s per-person revoke refuses a grant of somebody ' +
          'else\'s', mismatch);
  const matched = view.gnapAction({ action: 'revoke-grant',
                                    grant: theirs.id, user: bob },
                                  { via: 'api', actor: 'gpg-admin' });
  t.check(matched.ok && theirs.finalization.reason === 'revoked',
          'and revokes the named person\'s', matched);
  log.debug("Leaving checkPersonView().");
}

module.exports = {
  name: 'gnap_person_grants',
  describe: '#432 phase 7: per-client GNAP opaque identifiers and user ' +
            'references, subject information released once on an ' +
            'authorization, the grant lifetime, finalization reasons, ' +
            'too_fast, self-declared display, and one person\'s grants',
  run: async function (t) {
    log.debug("Entering run().");
    const alice = checkPairwise(t);
    await checkSubjectRelease(t, alice);
    await checkLifetime(t, alice);
    checkFinalization(t, alice);
    await checkTooFast(t);
    checkDisplay(t);
    checkPersonView(t, alice);
    log.debug("Leaving run().");
  }
};
