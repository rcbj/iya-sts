// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_interaction.js
//
// ===========================================================================
// #432 PHASE 6 IN PROCESS: WHO MUST BE ASKED FOR A GNAP GRANT, HOW STRONGLY
// THEY MUST HAVE SIGNED IN, AND APPROVAL BY AN ABSENT RESOURCE OWNER.
//
//   A. THE POLICY'S VERDICTS: each catalogue `interaction` value, a consent
//      action (named, and implied by naming no actions), a type's `acr`,
//      aggregated into the grant's requirement, per right.
//   B. THE SKIP: a trusted client skips a `default` type and not an
//      `always` one (STS-GNAP-0892 with no interaction offered); any client
//      gets a `never` type as itself, and not when it names a person; an
//      acr makes a skip impossible (STS-GNAP-0893) — through createGrant().
//   C. A REMEMBERED APPROVAL never stands in for an `always` type, and
//      neither does gnap.consentRequired off.
//   D. THE ISSUE STAGE drops an `always` right approved by skipping or
//      remembering (STS-GNAP-0890) and a right whose acr the session does
//      not meet (STS-GNAP-0891).
//   E. STEP-UP: what a session falls short of and what the screen must
//      demand; per ticked right; ro.acr recorded on approval; an unmet
//      step-up denied request_denied, the client told STS-GNAP-0899.
//   F. APPROVAL BY AN ABSENT OWNER: queued from createGrant() with no
//      interaction, listed only for the owner, approved on a subset,
//      denied, stepped up, capped (STS-GNAP-0897), timed out and finalized
//      rejected (STS-GNAP-0894), and forwarded from the page when another
//      person signs in; the poll wait stretched; a name nobody holds is
//      unknown_user (STS-GNAP-0901).
//   G. gnap.allowCrossUser IS GONE: no setting, and a different person's
//      approval is unknown_user.
//
// Why in process (tests/CLAUDE.md's first question): B and F drive the
// engine with a stubbed caller and move the clock, and D asks the issue
// stage directly. The HTTP half is `tests/vendored/sts_gnap_interaction.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const errorCodes = require('../common/error_codes');
const consent = require('../common/consent');
const rights = require('../gnap/gnap_rights');
const approval = require('../gnap/gnap_approval');
const store = require('../gnap/gnap_store');

const log = require('bunyan').createLogger({ name: 'gnap_interaction',
  level: process.env.LOG_LEVEL || 'info' });

const SUFFIX = crypto.randomBytes(3).toString('hex');
const T = {
  never: 'p6-never-' + SUFFIX,
  always: 'p6-always-' + SUFFIX,
  dflt: 'p6-default-' + SUFFIX,
  mfa: 'p6-mfa-' + SUFFIX
};

function request() {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return { method: 'POST', headers: { host: 'as.example' }, query: {},
           protocol: 'https', get: function () {
             return 'as.example';
           } };
}

// An engine over the real modules with the named dependencies replaced.
function engine(overrides) {
  log.debug("Entering engine().");
  const { GnapGrants } = require('../gnap/gnap_grants');
  log.debug("Leaving engine().");
  return new GnapGrants(Object.assign(GnapGrants.defaultDeps(),
                                      overrides || {}));
}

// A grant record as the engine makes one.
function grantOf(fields) {
  log.debug("Entering grantOf().");
  const grant = store.newGrant(Object.assign({
    as: 'default', grantEndpoint: 'https://as.example/gnap',
    client: { identifier: 'p6-plain-' + SUFFIX, key: null, proof: 'httpsig',
              display: { name: 'p6', declared: [] } },
    request: { tokens: [], multiple: false, subject: null, interact: null },
    ro: null, decision: null, delivered: false, polls: 0, approval: 'pending',
    grantExpiresAt: Math.floor(Date.now() / 1000) + 3600,
    subjectAuthorizedBy: null, finalization: null, requirement: null,
    ownerApproval: null
  }, fields || {}));
  store.saveGrant(grant, 'made by the test');
  log.debug("Leaving grantOf().");
  return grant;
}

function sessionOf(username, acr) {
  log.debug("Entering sessionOf().");
  log.debug("Leaving sessionOf().");
  return { id: 'sess-' + username + '-' + acr, user: { username: username },
           authTime: Math.floor(Date.now() / 1000), acr: acr,
           amr: acr === 'mfa' ? ['pwd', 'otp'] : ['pwd'] };
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  ['p6-alice', 'p6-bob', 'p6-carol'].forEach(function (name) {
    dir.createUser(name, { invent: false });
  });
  const made = [
    applications.createApplication({ identifier: 'p6-rs-' + SUFFIX,
      kind: 'gnap-resource-server', protocols: ['gnap', 'oauth2'],
      fields: { gnapResourceServerUri: 'https://p6.test/api',
                oauthClientId: 'p6-rs-' + SUFFIX,
                oauthAuthorizationDetailsType: [
                  JSON.stringify({ type: T.never, interaction: 'never' }),
                  JSON.stringify({ type: T.always, interaction: 'always' }),
                  JSON.stringify({ type: T.dflt, actions: ['read', 'delete'],
                                   consentActions: ['delete'] }),
                  JSON.stringify({ type: T.mfa, acr: 'mfa' })] } }),
    applications.createApplication({ identifier: 'p6-trusted-' + SUFFIX,
      kind: 'gnap-client', protocols: ['gnap'],
      fields: { gnapSkipInteraction: 'TRUE' } }),
    applications.createApplication({ identifier: 'p6-plain-' + SUFFIX,
      kind: 'gnap-client', protocols: ['gnap'], fields: {} })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the fixtures were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  log.debug("Leaving fixtures().");
}

function ctxFor(identifier, approvalKind, session) {
  log.debug("Entering ctxFor().");
  log.debug("Leaving ctxFor().");
  return { app: applications.get(identifier), approver: 'p6-alice',
           approval: approvalKind, session: session || null,
           targetsOf: function () { return []; },
           formatOf: function () { return 'jwt-signed'; } };
}

// ---------------------------------------------------------------- A
function verdicts(t) {
  log.debug("Entering verdicts().");
  t.log.info('=== A. the policy\'s verdicts ===');
  const req = function (right) {
    log.debug("Entering req().");
    const judged = rights.judge([{ label: '', access: [right] }],
                                ctxFor('p6-plain-' + SUFFIX, 'pending'),
                                rights.STAGES.REQUEST);
    log.debug("Leaving req().");
    return judged.requirement || {};
  };
  t.check(req({ type: T.never }).interaction === 'none',
          'A1. interaction: never is issued with nobody asked (none)');
  t.check(req({ type: T.dflt, actions: ['read'] }).interaction ===
          'skippable', 'A2. interaction: default is skippable');
  const always = req({ type: T.always });
  t.check(always.interaction === 'always' &&
          always.always.indexOf(T.always) >= 0,
          'A3. interaction: always is always', JSON.stringify(always));
  t.check(req({ type: T.dflt, actions: ['read', 'delete'] }).interaction ===
          'always', 'A4. a consent action forces interaction');
  t.check(req({ type: T.dflt }).interaction === 'always',
          'A5. naming no actions is every action, a consent one included');
  t.check(req('p6-unregistered-ref').interaction === 'skippable',
          'A6. a reference string keeps the rule before #432');
  const both = rights.judge([{ label: '', access: [{ type: T.never },
                                                   { type: T.mfa }] }],
                            ctxFor('p6-plain-' + SUFFIX, 'pending'),
                            rights.STAGES.REQUEST).requirement;
  t.check(both.interaction === 'skippable' && both.acr.join() === 'mfa' &&
          both.byRight.t0r1 && both.byRight.t0r1[0] === 'mfa' &&
          !both.byRight.t0r0,
          'A7. the most demanding interaction, and the acr per right',
          JSON.stringify(both));
  log.debug("Leaving verdicts().");
}

// ---------------------------------------------------------------- B
async function create(identifier, body, resolved) {
  log.debug("Entering create().");
  const realProof = require('../gnap/gnap_proof');
  const realSubject = require('../gnap/gnap_subject');
  const g = engine({
    proof: Object.assign({}, realProof, {
      readBody: function () {
        return { ok: true, json: body, hadContent: true };
      } }),
    subject: Object.assign({}, realSubject, {
      resolveUser: function () {
        return Object.assign({ ok: true, username: null, verified: false },
                             resolved || {});
      } })
  });
  g.identifyCaller = async function () {
    return { ok: true, app: applications.get(identifier), created: false,
             instanceId: 'p6-instance', classId: null,
             display: { name: identifier, declared: [] },
             descriptor: { proof: { method: 'httpsig' }, value: null,
                           identity: 'p6-key', format: 'reference' } };
  };
  const out = await g.createGrant(request(), null);
  log.debug("Leaving create().");
  return out;
}

async function skips(t) {
  log.debug("Entering skips().");
  t.log.info('=== B. who may skip ===');
  const ask = function (type, extra) {
    return Object.assign({ client: 'p6-instance',
                           access_token: { access: [type] } }, extra || {});
  };
  const interact = { interact: { start: ['redirect'] } };
  let r = await create('p6-trusted-' + SUFFIX,
                       ask({ type: T.dflt, actions: ['read'] }));
  t.check(r.ok && r.grant && r.grant.approval === 'skipped',
          'B1. a trusted client skips a default type', JSON.stringify(
            r.grant ? r.grant.approval : r.why));
  r = await create('p6-trusted-' + SUFFIX, ask({ type: T.always }));
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-GNAP-0892' &&
          r.gnapError === 'invalid_interaction',
          'B2. not an always type: STS-GNAP-0892 with no interaction',
          r.why);
  r = await create('p6-trusted-' + SUFFIX, ask({ type: T.always }, interact));
  t.check(r.ok && r.body && r.body.interact && r.grant.approval === 'pending',
          'B3. with interaction offered it goes to the page', JSON.stringify(
            r.body));
  r = await create('p6-plain-' + SUFFIX, ask({ type: T.never }));
  t.check(r.ok && r.grant.approval === 'skipped' && !r.grant.ro,
          'B4. any client is issued a never type as itself, nobody asked',
          r.why || '');
  r = await create('p6-plain-' + SUFFIX,
                   ask({ type: T.never }, { user: { sub_ids: [] } }),
                   { username: 'p6-bob' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-GNAP-0113',
          'B5. but not when it names a person (and owner approval is off)',
          r.why);
  r = await create('p6-plain-' + SUFFIX,
                   ask({ type: T.dflt, actions: ['read'] }));
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-GNAP-0113',
          'B6. a client not trusted never skips a default type', r.why);
  r = await create('p6-trusted-' + SUFFIX, ask({ type: T.mfa }));
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-GNAP-0893',
          'B7. a right needing an acr is never issued with no session ' +
          '(STS-GNAP-0893)', r.why);
  log.debug("Leaving skips().");
}

// ---------------------------------------------------------------- C
function remembered(t) {
  log.debug("Entering remembered().");
  t.log.info('=== C. remembered approvals ===');
  const g = engine();
  const right = { type: T.always };
  const grant = grantOf({ request: { tokens: [{ label: '', access: [right] }],
                                     multiple: false, subject: null,
                                     interact: null },
                          requirement: { interaction: 'always', acr: [],
                                         always: [T.always], byRight: {} } });
  consent.record('p6-alice', grant.client.identifier,
                 [g.digestTokenOf(right)], 'p6-alice');
  t.check(g.rememberedFor(grant, 'p6-alice') === false,
          'C1. a remembered approval does not stand in for an always type');
  config.setOverride('gnap.consentRequired', false);
  try {
    t.check(g.rememberedFor(grant, 'p6-alice') === false,
            'C2. nor does gnap.consentRequired off');
  } finally {
    config.clearOverride('gnap.consentRequired');
  }
  grant.requirement.interaction = 'skippable';
  t.check(g.rememberedFor(grant, 'p6-alice') === true,
          'C3. control: the same remembered approval stands for a ' +
          'skippable one');
  log.debug("Leaving remembered().");
}

// ---------------------------------------------------------------- D
function issueStage(t) {
  log.debug("Entering issueStage().");
  t.log.info('=== D. the issue stage ===');
  const issue = function (right, approvalKind, session) {
    return rights.judge([{ label: '', access: [right] }],
                        ctxFor('p6-plain-' + SUFFIX, approvalKind, session),
                        rights.STAGES.ISSUE);
  };
  let r = issue({ type: T.always }, 'remembered', { acr: '1', amr: [] });
  t.check(r.tokens[0].access.length === 0 && r.dropped.length === 1 &&
          r.dropped[0].code === 'STS-GNAP-0890',
          'D1. an always right approved by a remembered approval is ' +
          'dropped (STS-GNAP-0890)', JSON.stringify(r.dropped));
  r = issue({ type: T.always }, 'skipped', null);
  t.check(r.dropped.length === 1 && r.dropped[0].code === 'STS-GNAP-0890',
          'D2. and one approved by skipping');
  r = issue({ type: T.always }, 'interaction', { acr: '1', amr: [] });
  t.check(r.dropped.length === 0 && r.tokens[0].access.length === 1,
          'D3. control: on the page it stands');
  r = issue({ type: T.mfa }, 'interaction', { acr: '1', amr: ['pwd'] });
  t.check(r.dropped.length === 1 && r.dropped[0].code === 'STS-GNAP-0891',
          'D4. an acr the approving session does not meet drops the right ' +
          '(STS-GNAP-0891)');
  r = issue({ type: T.mfa }, 'owner', { acr: 'mfa', amr: ['pwd', 'otp'] });
  t.check(r.dropped.length === 0, 'D5. one it meets stands');
  log.debug("Leaving issueStage().");
}

// ---------------------------------------------------------------- E
async function stepUp(t) {
  log.debug("Entering stepUp().");
  t.log.info('=== E. step-up ===');
  const short = approval.assess(['mfa'], { acr: '1', amr: ['pwd'] });
  t.check(!short.met && short.missing.join() === 'mfa' && short.forceMfa,
          'E1. a one-factor session falls short of mfa, and the screen ' +
          'must demand a second factor', JSON.stringify(short));
  t.check(approval.assess(['1', 'mfa'], { acr: 'mfa' }).met,
          'E2. an mfa session meets 1 and mfa together');
  t.check(approval.assess(['1', 'mfa'], { acr: '0' }).ask[0] === 'mfa',
          'E3. the sign-in is asked for the strongest first');
  const grant = grantOf({ requirement: { interaction: 'skippable',
    acr: ['mfa'], always: [], byRight: { t0r1: ['mfa'] } } });
  t.check(approval.requiredAcr(grant).join() === 'mfa' &&
          approval.requiredAcr(grant, ['t0r0']).length === 0 &&
          approval.requiredAcr(grant, ['t0r0', 't0r1']).join() === 'mfa',
          'E4. the step-up is held to the rights left ticked');
  const g = engine();
  const interactive = grantOf({
    request: { tokens: [{ label: '', access: [{ type: T.mfa }] }],
               multiple: false, subject: null, interact: null },
    interaction: { finish: null, decided: false, approvalId: 'p6a' } });
  await g.decide(request(), interactive, sessionOf('p6-alice', 'mfa'),
                 { approve: true, tokens: interactive.request.tokens,
                   subject: false });
  t.check(interactive.ro && interactive.ro.acr === 'mfa',
          'E5. the grant records the acr the approval achieved');
  const unmet = grantOf({
    request: { tokens: [{ label: '', access: [{ type: T.mfa }] }],
               multiple: false, subject: null, interact: null },
    interaction: { finish: null, decided: false, approvalId: 'p6b' } });
  await g.refuseUnmetStepUp(request(), unmet, sessionOf('p6-alice', '1'),
                            ['mfa']);
  const told = await g.settle(request(), unmet);
  t.check(!told.ok && told.gnapError === 'request_denied' &&
          errorCodes.codeOf(told) === 'STS-GNAP-0899',
          'E6. an unmet step-up is denied request_denied, STS-GNAP-0899',
          JSON.stringify({ e: told.gnapError, c: errorCodes.codeOf(told) }));
  log.debug("Leaving stepUp().");
}

// ---------------------------------------------------------------- F
async function owner(t) {
  log.debug("Entering owner().");
  t.log.info('=== F. approval by an absent resource owner ===');
  config.setOverride('gnap.ownerApproval', true);
  try {
    const tokens = [{ label: '', access: [{ type: T.dflt,
                                            actions: ['read'] },
                                          { type: T.mfa }] }];
    const r = await create('p6-plain-' + SUFFIX,
      { client: 'p6-instance', access_token: { access: tokens[0].access },
        user: { sub_ids: [] } }, { username: 'p6-bob' });
    t.check(r.ok && r.body.continue && !r.body.interact &&
            r.grant.ownerApproval &&
            r.grant.ownerApproval.username === 'p6-bob',
            'F1. no interaction and a named person: the grant waits for ' +
            'them', r.why || '');
    const grant = store.getGrant(r.grant.id);
    t.check(r.body.continue.wait >= Math.ceil(600 / 59),
            'F2. the client\'s wait is stretched so its polls cover the ' +
            'owner\'s time', String(r.body.continue.wait));
    const listed = approval.pendingFor('p6-bob');
    t.check(listed.length === 1 && listed[0].client ===
            'p6-plain-' + SUFFIX && listed[0].acr.join() === 'mfa',
            'F3. listed for the owner, with the level it needs');
    t.check(approval.pendingFor('p6-alice').length === 0 &&
            !approval.find('p6-alice', listed[0].id),
            'F4. and for nobody else');
    let a = await approval.answer('p6-bob', sessionOf('p6-bob', '1'),
                                  listed[0].id, { approve: true,
                                                  ticked: ['t0r0', 't0r1'] });
    t.check(!a.ok && a.stepUp && a.code === 'STS-PORTAL-0244',
            'F5. a session short of a ticked right\'s acr is stepped up');
    a = await approval.answer('p6-bob', sessionOf('p6-bob', '1'),
                              listed[0].id, { approve: true,
                                              ticked: ['t0r0'] });
    t.check(a.ok && a.approved && grant.decision.approved &&
            grant.approval === 'owner' &&
            grant.decision.tokens[0].access.length === 1 &&
            grant.ro.username === 'p6-bob',
            'F6. approving a subset records the owner\'s decision',
            JSON.stringify(a));
    a = await approval.answer('p6-bob', sessionOf('p6-bob', '1'),
                              listed[0].id, { approve: true,
                                              ticked: ['t0r0'] });
    t.check(!a.ok && a.code === 'STS-PORTAL-0243',
            'F7. it is answered once');
    // A denial.
    const second = await create('p6-plain-' + SUFFIX,
      { client: 'p6-instance', access_token: { access: [{ type: T.never }] },
        user: { sub_ids: [] } }, { username: 'p6-carol' });
    const row = approval.pendingFor('p6-carol')[0];
    a = await approval.answer('p6-carol', sessionOf('p6-carol', '1'),
                              row.id, { approve: false });
    t.check(a.ok && !a.approved && second.grant &&
            store.getGrant(second.grant.id).decision.error === 'user_denied',
            'F8. a denial is user_denied');
    // The cap.
    config.setOverride('gnap.ownerApprovalMaxPending', 1);
    try {
      await create('p6-plain-' + SUFFIX,
        { client: 'p6-instance', access_token: { access: [{ type: T.never }] },
          user: { sub_ids: [] } }, { username: 'p6-alice' });
      const capped = await create('p6-plain-' + SUFFIX,
        { client: 'p6-instance', access_token: { access: [{ type: T.never }] },
          user: { sub_ids: [] } }, { username: 'p6-alice' });
      t.check(!capped.ok && errorCodes.codeOf(capped) === 'STS-GNAP-0897',
              'F9. a person\'s pending requests are capped (STS-GNAP-0897)',
              capped.why);
    } finally {
      config.clearOverride('gnap.ownerApprovalMaxPending');
    }
    // A timeout.
    const late = store.getGrant(approval.pendingFor('p6-alice')[0] &&
      store.listGrants().filter(function (one) {
        return one.ownerApproval && one.ownerApproval.username ===
          'p6-alice' && !one.finalization;
      })[0].id);
    late.ownerApproval.expiresAt = 1;
    late.expiresAt = 1;
    store.saveGrant(late, 'the test ran the clock out');
    const g = engine();
    const timedOut = await g.continueAccepted(
      Object.assign(request(), { method: 'POST' }),
      { grant: late, body: { json: {}, hadContent: false } });
    t.check(!timedOut.ok && errorCodes.codeOf(timedOut) === 'STS-GNAP-0894' &&
            late.finalization && late.finalization.reason === 'rejected',
            'F10. an owner who never answered: rejected, STS-GNAP-0894',
            JSON.stringify(late.finalization));
    // Forwarded from the page when somebody else signs in.
    const fwd = grantOf({ userHint: 'p6-bob',
      request: { tokens: [{ label: '', access: [{ type: T.never }] }],
                 multiple: false, subject: null, interact: null },
      interaction: { finish: null, decided: false, approvalId: 'p6c' } });
    const sent = await g.forwardToOwner(request(), fwd,
                                        sessionOf('p6-alice', '1'));
    t.check(sent && sent.queued && fwd.interaction.decided &&
            fwd.ownerApproval.username === 'p6-bob' &&
            fwd.ownerApproval.requestedBy === 'p6-alice' && !fwd.decision,
            'F11. another person at the page sends the grant to its owner');
    const same = await g.forwardToOwner(request(),
      grantOf({ userHint: 'p6-alice',
                interaction: { finish: null, decided: false,
                               approvalId: 'p6d' } }),
      sessionOf('p6-alice', '1'));
    t.check(same === null, 'F12. control: the owner themselves is not');
    const nobody = await create('p6-plain-' + SUFFIX,
      { client: 'p6-instance', access_token: { access: [{ type: T.never }] },
        user: { sub_ids: [] } }, { username: 'p6-nobody-' + SUFFIX });
    t.check(!nobody.ok && errorCodes.codeOf(nobody) === 'STS-GNAP-0901' &&
            nobody.gnapError === 'unknown_user',
            'F13. a name the directory does not hold is unknown_user ' +
            '(STS-GNAP-0901)', nobody.why);
  } finally {
    config.clearOverride('gnap.ownerApproval');
  }
  log.debug("Leaving owner().");
}

// ---------------------------------------------------------------- G
async function crossUserGone(t) {
  log.debug("Entering crossUserGone().");
  t.log.info('=== G. gnap.allowCrossUser is gone ===');
  t.check(!config.SETTINGS.some(function (row) {
    return row.key === 'gnap.allowCrossUser';
  }), 'G1. no such setting');
  const g = engine();
  const grant = grantOf({ userHint: 'p6-bob',
    request: { tokens: [{ label: '', access: [{ type: T.never }] }],
               multiple: false, subject: null, interact: null },
    interaction: { finish: null, decided: false, approvalId: 'p6e' } });
  t.check(await g.forwardToOwner(request(), grant,
                                 sessionOf('p6-alice', '1')) === null,
          'G2. with owner approval off nothing is forwarded');
  await g.decide(request(), grant, sessionOf('p6-alice', '1'),
                 { approve: true, tokens: grant.request.tokens,
                   subject: false });
  t.check(grant.decision && grant.decision.error === 'unknown_user',
          'G3. and a different person\'s approval is unknown_user');
  log.debug("Leaving crossUserGone().");
}

async function run(t) {
  log.debug("Entering run().");
  const id = 'p6-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    await realms.run(made.realm, async function () {
      fixtures(t);
      verdicts(t);
      await skips(t);
      remembered(t);
      issueStage(t);
      await stepUp(t);
      await owner(t);
      await crossUserGone(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'gnap_interaction',
  describe: '#432 phase 6: per-type interaction and consent actions as ' +
            'policy, remembered approvals never standing in for always, ' +
            'step-up to the catalogue\'s acr, and approval by an absent ' +
            'resource owner on the portal',
  run: run
};
