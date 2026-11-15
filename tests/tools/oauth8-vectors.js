// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/oauth8-vectors.js
//
// ---------------------------------------------------------------------------
// THE `oauth8` SLICE'S VECTORS (#444, phase 5): what
// `rust/crates/sts-oauth/tests/oauth8_vectors.rs` reads, run by
// `crypto-vectors.js` (`oauth8-node.json`) in a child of its own.
//
//   types      oauth2.exchangeTypeProblem(body): RFC 8693 section 2.1's
//              token types, with the list of types Node takes (Rust takes
//              fewer: the assertion, Kerberos and device-secret types are
//              not ported);
//   kinds      ownTokenKind(token, claims) and kindProblem(declared, kind);
//   actors     actorTokenProblem(claims, client, base) (#550);
//   chains     clientActorSubject(), actChainEntry(), priorActChain(),
//              originalClientAct() (#443, #471);
//   mayActs    DelegationPolicy.mayActNames(mayAct, actor) (RFC 8693
//              section 4.4);
//   verdicts   xacml_exchange_verdicts.decide() over the BUILT-IN issuance
//              policy: the two exchange questions, over fact sets;
//   decisions  DelegationPolicy.decide() over a directory described here,
//              the facts, the verdict and the sentences;
//   claims     DelegationPolicy.mayActClaimFor(name) over that directory;
//   userCodes  device_authorization.normalize(typed) (RFC 8628 section 6.1);
//   boundKeys  boundKeyProofRefusal(scope, code, proof) (OpenID Connect Key
//              Binding section 2).
//
// And `checkRust()`: the verdicts and decisions Rust computed over the
// same inputs (`oauth8-rust.json`), computed again by Node. A builder is a
// tool, not service code, and logs nothing.
// ---------------------------------------------------------------------------

const path = require('path');

const AT = 'urn:ietf:params:oauth:token-type:access_token';
const RT = 'urn:ietf:params:oauth:token-type:refresh_token';
const IT = 'urn:ietf:params:oauth:token-type:id_token';
const JT = 'urn:ietf:params:oauth:token-type:jwt';
const DS = 'urn:openid:params:token-type:device-secret';
const S2 = 'urn:ietf:params:oauth:token-type:saml2';

const TYPES = [
  {},
  { subject_token_type: AT },
  { subject_token_type: ' ' + AT + ' ', actor_token: 'x' },
  { subject_token_type: AT, actor_token_type: AT },
  { subject_token_type: AT, actor_token: 'x', actor_token_type: DS },
  { subject_token_type: IT, actor_token: 'x', actor_token_type: DS },
  { subject_token_type: DS },
  { subject_token_type: 'urn:nobody' },
  { subject_token_type: S2 },
  { subject_token_type: JT, actor_token: 'a', actor_token_type: 'urn:no' },
  { subject_token_type: RT, actor_token: 'a', actor_token_type: IT },
  { subject_token_type: AT, requested_token_type: AT }
];

function b64u(o) {
  return Buffer.from(JSON.stringify(o)).toString('base64url');
}

function jws(header, claims) {
  return b64u(header) + '.' + b64u(claims) + '.c2ln';
}

const KINDS = [
  [jws({ alg: 'ES256', typ: 'at+jwt' }, { sub: 'a', aud: 'b' }), AT],
  [jws({ alg: 'ES256', typ: 'JWT' }, { typ: 'Bearer', sub: 'a' }), IT],
  [jws({ alg: 'ES256' }, { sub: 'a', aud: 'b' }), IT],
  [jws({ alg: 'ES256' }, { sub: 'a', aud: 'b' }), AT],
  [jws({ alg: 'ES256', typ: 'logout+jwt' }, { sub: 'a', aud: 'b' }), IT],
  [jws({ alg: 'ES256' }, { sub: 'a', aud: 'b', events: {} }), JT],
  [jws({ alg: 'ES256' }, { typ: 'Refresh', sub: 'a' }), JT],
  [jws({ alg: 'ES256' }, { typ: 'Refresh', sub: 'a' }), RT],
  ['aaa.bbb.ccc.ddd.eee', RT],
  ['aaa.bbb.ccc.ddd.eee', AT],
  [jws({ alg: 'ES256' }, { iss: 'x' }), JT]
];

const BASE = 'https://sts.example/realm/r1';
const ACTORS = [
  [{ client_id: 'apigw', aud: BASE }, 'apigw', ['apigw']],
  [{ client_id: 'other', aud: BASE }, 'apigw', ['apigw']],
  [{ azp: 'apigw', aud: 'https://elsewhere' }, 'apigw', ['apigw']],
  [{ aud: ['apigw', 'x'] }, 'apigw', ['apigw', 'https://api.example']],
  [{ aud: 'https://nobody' }, 'apigw', ['apigw']],
  [{}, 'apigw', ['apigw']],
  [{ client_id: 'apigw', sub: 'urn:sts:client:web', aud: BASE }, 'apigw',
   ['apigw']],
  [{ client_id: 'apigw', sub: 'urn:sts:client:apigw',
     aud: BASE + '/oauth2/token' }, 'apigw', ['apigw']],
  [{ client_id: 'apigw', aud: ['https://a', 'https://b'] }, 'apigw',
   ['apigw']]
];

const CHAINS = [
  [null, 'https://iss'],
  [{ sub: 'a' }, ''],
  [{ sub: 'a' }, 'https://iss'],
  [{ sub: 'a', iss: 'https://other', act: { sub: 'b', act: { sub: 'c',
     iss: '' } } }, 'https://iss'],
  [[1, 2], 'https://iss']
];

const ORIGINALS = [
  [{ client_id: 'web' }, true, 'apigw', false],
  [{ client_id: 'web' }, true, 'apigw', true],
  [{ azp: 'web' }, true, 'web', true],
  [{ client_id: 'web', act: { sub: 'x' } }, true, 'apigw', false],
  [{ client_id: 'web' }, false, 'apigw', false],
  [{}, true, 'apigw', false]
];

const MAY_ACTS = [
  [{ sub: 'apigw' }, { sub: 'apigw', iss: '', aliases: [] }],
  [{ sub: 'apigw', iss: 'https://iss' }, { sub: 'apigw', iss: 'https://iss',
                                           aliases: [] }],
  [{ sub: 'apigw', iss: 'https://iss' }, { sub: 'apigw', iss: 'x',
                                           aliases: [] }],
  [{ sub: 'apigw' }, { sub: 'urn:sts:client:apigw', iss: '',
                       aliases: ['apigw'] }],
  [{ sub: 'bob' }, { sub: 'alice', iss: '', aliases: [] }],
  ['nope', { sub: 'alice', iss: '', aliases: [] }],
  [{ sub: '' }, { sub: '', iss: '', aliases: [] }]
];

// One party, as `partyFacts()` returns it.
function party(over) {
  return Object.assign({ id: '', kind: 'application', registered: true,
                         roles: [], notDelegated: false, groups: [],
                         semantics: [], defaultSemantics: '',
                         delegatesTo: [], subjectGroups: [], accepts: [],
                         mayAct: '' }, over || {});
}

// Fact sets for the built-in policy: a base delegation from S=web to
// R=api, and one change to it each.
function verdictFacts() {
  const base = function () {
    return {
      subject: party({ id: 'alice', kind: 'user', roles: ['EVERYBODY'] }),
      actor: party({ id: 'web', delegatesTo: ['api'] }),
      source: { id: 'web', requiredRoles: [], delegatesTo: ['api'] },
      target: { id: 'api', count: 1, registered: true, requiredRoles: [],
                accepts: [] },
      requestedSemantics: '', mayActPresent: false, mayActNamesActor: false,
      protectedGroups: ['admins']
    };
  };
  const changes = [
    function () {},
    function (f) { f.mayActPresent = true; },
    function (f) { f.mayActPresent = true; f.mayActNamesActor = true; },
    function (f) { f.target.count = 2; },
    function (f) { f.target.registered = false; },
    function (f) { f.target = { id: '', count: 0, registered: false,
                                requiredRoles: [], accepts: [] }; },
    function (f) { f.target = { id: '', count: 0, registered: false,
                                requiredRoles: [], accepts: [] };
                   f.actor.id = 'other'; },
    function (f) { f.subject.notDelegated = true; },
    function (f) { f.subject.groups = ['admins']; },
    function (f) { f.actor.registered = false; f.actor.id = 'ghost'; },
    function (f) { f.actor.kind = 'user'; f.actor.id = 'bob'; },
    function (f) { f.actor.kind = 'user'; f.actor.id = 'bob';
                   f.actor.roles = ['DELEGATION_ACTOR'];
                   f.target.accepts = ['bob']; },
    function (f) { f.requestedSemantics = 'impersonation'; },
    function (f) { f.requestedSemantics = 'impersonation';
                   f.actor.semantics = ['impersonation']; },
    function (f) { f.requestedSemantics = 'impersonation';
                   f.actor.semantics = ['impersonation'];
                   f.subject.semantics = ['delegation']; },
    function (f) { f.actor.defaultSemantics = 'impersonation'; },
    function (f) { f.subject.defaultSemantics = 'bogus'; },
    function (f) { f.actor.subjectGroups = ['cn=staff,ou=groups']; },
    function (f) { f.actor.subjectGroups = ['cn=staff,ou=groups'];
                   f.subject.groups = ['cn=staff,ou=groups']; },
    function (f) { f.source.requiredRoles = ['FINANCE']; },
    function (f) { f.source.requiredRoles = ['FINANCE'];
                   f.subject.roles = ['FINANCE']; },
    function (f) { f.source.delegatesTo = []; },
    function (f) { f.source.delegatesTo = []; f.target.accepts = ['web']; },
    function (f) { f.actor.id = 'third'; },
    function (f) { f.actor.id = 'third'; f.target.accepts = ['third']; },
    function (f) { f.actor.id = 'alice'; },
    function (f) { f.target.id = 'web'; },
    function (f) { f.target.id = 'web'; f.target.requiredRoles = ['X']; },
    function (f) { f.target = { id: '', count: 0, registered: false,
                                requiredRoles: [], accepts: [] };
                   f.source.id = 'web'; },
    function (f) { f.requestedSemantics = 'impersonation';
                   f.actor.semantics = ['impersonation'];
                   f.actor.delegatesTo = []; },
    function (f) { f.requestedSemantics = 'impersonation';
                   f.actor.semantics = ['impersonation'];
                   f.target.requiredRoles = ['Y']; },
    function (f) { f.actor.semantics = ['impersonation']; }
  ];
  const out = [];
  changes.forEach(function (change) {
    ['product', 'development'].forEach(function (mode) {
      const facts = base();
      change(facts);
      out.push({ facts: facts, mode: mode,
                 settings: { defaultSemantics: 'delegation',
                             actorRole: 'DELEGATION_ACTOR' } });
    });
  });
  out.push({ facts: base(), mode: 'product',
             settings: { defaultSemantics: '', actorRole: '' } });
  return out;
}

// A DIRECTORY for `decide()`: four applications and three people.
const DIRECTORY = {
  apps: [
    { identifier: 'web', dn: 'cn=web,ou=applications,dc=example',
      registeredBy: 'console', kinds: ['oauth2-client'],
      fields: { oauthClientId: ['web'], oauthAudience: ['https://web'],
                appAllowedToDelegateTo: ['https://api'] } },
    { identifier: 'api', dn: 'cn=api,ou=applications,dc=example',
      registeredBy: 'console', kinds: ['oauth2-client'],
      fields: { oauthClientId: ['api-client'],
                oauthAudience: ['https://api'],
                appAllowedToActOnBehalfOf: ['gateway'],
                appMayAct: ['uid=bob,ou=users,dc=example'] } },
    { identifier: 'gateway', dn: 'cn=gateway,ou=applications,dc=example',
      registeredBy: 'console', kinds: ['oauth2-client'],
      fields: { oauthClientId: ['gateway'],
                appDelegationSemantics: ['delegation', 'Impersonation'],
                appAllowedToDelegateTo: ['api'],
                appDefaultDelegationSemantics: ['impersonation'],
                appMayAct: ['cn=web,ou=applications,dc=example'] } },
    { identifier: 'sighted', dn: 'cn=sighted,ou=applications,dc=example',
      registeredBy: '', kinds: ['oauth2-client'],
      fields: { oauthClientId: ['sighted'],
                oauthAudience: ['https://sighted'] } },
    { identifier: 'res', dn: 'cn=res,ou=applications,dc=example',
      registeredBy: 'console', kinds: ['oauth2-resource-server'],
      fields: { oauthAudience: ['https://res'] } }
  ],
  people: {
    alice: { found: true, person: true, dn: 'uid=alice,ou=users,dc=example',
             username: 'alice', sub: 'urn:uuid:aaaa', notDelegated: false,
             mayAct: 'uid=bob,ou=users,dc=example',
             delegate: { kind: 'person', dn: 'uid=bob,ou=users,dc=example',
                         name: 'bob', sub: 'urn:uuid:bbbb' },
             groups: [{ dn: 'cn=Staff,ou=groups,dc=example', cn: 'Staff' }],
             semantics: [], defaultSemantics: '' },
    bob: { found: true, person: true, dn: 'uid=bob,ou=users,dc=example',
           username: 'bob', sub: 'urn:uuid:bbbb', notDelegated: true,
           mayAct: '', delegate: null, groups: [], semantics: ['DELEGATION'],
           defaultSemantics: 'Delegation' },
    carol: { found: true, person: true, dn: 'uid=carol,ou=users,dc=example',
             username: 'carol', sub: 'urn:uuid:cccc', notDelegated: false,
             mayAct: 'cn=gateway,ou=applications,dc=example',
             delegate: { kind: 'application',
                         dn: 'cn=gateway,ou=applications,dc=example',
                         name: '', sub: '' },
             groups: [{ dn: 'cn=admins,ou=groups,dc=example', cn: 'admins' }],
             semantics: [], defaultSemantics: '' }
  },
  roles: { 'user:alice': ['EVERYBODY'], 'user:bob': ['DELEGATION_ACTOR'],
           'application:web': ['EVERYBODY'] },
  required: { api: [], gateway: ['FINANCE'] }
};

const QUESTIONS = [
  { actor: 'web', subject: 'alice', source: ['https://web'],
    targets: ['https://api'] },
  { actor: 'gateway', subject: 'alice', source: ['https://web'],
    targets: ['https://api'] },
  { actor: 'gateway', subject: 'alice', source: ['web'],
    targets: ['https://api'], requested: 'delegation' },
  { actor: 'urn:sts:client:web', subject: 'alice', source: ['web'],
    targets: ['https://api'] },
  { actor: 'web', subject: 'bob', source: ['web'], targets: ['https://api'] },
  { actor: 'web', subject: 'carol', source: ['web'],
    targets: ['https://api'] },
  { actor: 'web', subject: 'alice', source: ['web'],
    targets: ['https://sighted'] },
  { actor: 'web', subject: 'alice', source: ['web'],
    targets: ['https://nobody'] },
  { actor: 'web', subject: 'alice', source: ['web'],
    targets: ['https://api', 'https://web'] },
  { actor: 'web', subject: 'alice', source: ['web'], targets: [] },
  { actor: 'web', subject: 'alice', source: ['https://res', 'web'],
    targets: [] },
  { actor: 'api-client', subject: 'alice', source: ['web'], targets: [] },
  { actor: 'bob', subject: 'alice', source: ['web'],
    targets: ['https://api'] },
  { actor: 'ghost', subject: 'alice', source: ['web'],
    targets: ['https://api'] },
  { actor: 'web', subject: 'alice', source: ['web'],
    targets: ['https://api'], mayActPresent: true },
  { actor: 'web', subject: 'alice', source: ['web'],
    targets: ['https://api'], mayActPresent: true, mayActNamesActor: true },
  { actor: 'web', subject: 'alice', source: ['web'],
    targets: ['https://api'], requested: 'impersonation' },
  { actor: 'web', subject: 'urn:uuid:nobody', source: [], targets: [] }
];

const USER_CODES = ['BCDF-GHJK', 'bcdf ghjk', 'b-c-d-f-1-2', '', 'ÄBC'];

const BOUND_KEYS = [
  [true, 'openid', 'code1', null],
  [true, 'openid bound_key', 'code1', null],
  [true, 'openid bound_key', 'code1',
   { claims: { c_s256: 'nope' } }],
  [true, 'openid bound_key', 'code1',
   { claims: { c_s256: require('crypto').createHash('sha256')
     .update('code1').digest('base64url') } }],
  [false, 'openid bound_key', 'code1', null]
];

const CLAIM_NAMES = ['alice', 'bob', 'carol', 'api', 'gateway', 'web',
                     'urn:sts:client:gateway', 'nobody', ''];

// The directory as `DelegationPolicy`'s dependencies read it.
function fakeDeps(ROOT, settings, modeName) {
  const helpers = require(path.join(ROOT, 'common', 'helpers'));
  const verdicts = require(path.join(ROOT, 'xacml',
                                     'xacml_exchange_verdicts'));
  const apps = DIRECTORY.apps;
  const by = function (attribute, value) {
    return apps.filter(function (a) {
      return [].concat(a.fields[attribute] || []).indexOf(value) >= 0;
    })[0] || null;
  };
  return {
    log: helpers.log,
    config: { value: function (key) {
      return settings[key] === undefined ? '' : settings[key];
    } },
    mode: { authorizesDelegation: function () { return true; },
            current: function () { return modeName; },
            issuesToUnregisteredApplications: function () {
              return modeName !== 'product';
            } },
    applications: {
      get: function (id) {
        return apps.filter(function (a) {
          return a.identifier === id;
        })[0] || null;
      },
      forClientId: function (v) { return by('oauthClientId', v); },
      forAudience: function (v) { return by('oauthAudience', v); },
      forAppliesTo: function (v) { return by('wstrustAppliesTo', v); },
      isResourceServer: function (id) {
        const a = apps.filter(function (x) {
          return x.identifier === id;
        })[0];
        return !!a && a.kinds.indexOf('oauth2-resource-server') >= 0 &&
          a.kinds.indexOf('oauth2-client') < 0;
      },
      requiredRolesOf: function (id) {
        return DIRECTORY.required[id] || [];
      },
      list: function () { return apps; }
    },
    credentials: { delegationFactsFor: function (key) {
      const k = String(key || '');
      const named = Object.keys(DIRECTORY.people).filter(function (n) {
        const p = DIRECTORY.people[n];
        return n === k || p.dn.toLowerCase() === k.toLowerCase() ||
          p.sub === k;
      })[0];
      return named ? DIRECTORY.people[named]
        : { found: false, person: false, dn: '', username: '', sub: '',
            notDelegated: false, mayAct: '', delegate: null, groups: [],
            semantics: [], defaultSemantics: '' };
    } },
    gate: { checkExchange: function (q) {
      return verdicts.decide(q, null, {});
    } },
    roles: { rolesOf: function (who) {
      return DIRECTORY.roles[who.kind + ':' + who.name] || [];
    } }
  };
}

const SETTINGS = { 'delegation.defaultSemantics': 'delegation',
                   'delegation.actorRole': 'DELEGATION_ACTOR',
                   'delegation.protectedGroups': 'Admins,cn=Ops,ou=groups',
                   'admin.readGroup': 'sts-readers', 'admin.writeGroup': '' };

function decisionOf(d) {
  return { allowed: d.allowed, enforced: d.enforced, refusal: d.refusal,
           why: d.why, authorizedBy: d.authorizedBy, attribute: d.attribute,
           semantics: d.semantics, audience: d.audience,
           intermediary: d.intermediary };
}

function questionOf(q) {
  return Object.assign({ protocol: 'OAuth 2.0', requested: '',
                         targetKind: 'audience', mayActPresent: false,
                         mayActNamesActor: false }, q);
}

async function build(ROOT) {
  const out = { problems: [], directory: DIRECTORY, settings: SETTINGS };
  try {
    require(path.join(ROOT, 'common', 'protocol_stack'));
    const oauth2 = require(path.join(ROOT, 'oauth-oidc', 'oauth2'));
    const Server = oauth2.OAuth2Server;
    const helpers = require(path.join(ROOT, 'common', 'helpers'));
    const fake = { deps: { log: helpers.log } };
    out.types = TYPES.map(function (body) {
      const p = oauth2.exchangeTypeProblem(body);
      return { body: body, code: p ? p.code : '',
               description: p ? p.description : '' };
    });
    out.kinds = KINDS.map(function (pair) {
      const token = pair[0];
      let claims = {};
      try {
        claims = token.split('.').length === 3
          ? JSON.parse(Buffer.from(token.split('.')[1], 'base64url')) : {};
      } catch (e) {
        claims = {};
      }
      const kind = oauth2.ownTokenKind(token, claims);
      return { token: token, claims: claims, declared: pair[1], kind: kind,
               problem: Server.prototype.kindProblem.call(fake, pair[1],
                                                          kind,
                                                          'subject_token') };
    });
    out.actors = ACTORS.map(function (row) {
      const self = { deps: { log: helpers.log },
                     clientAudienceNames: function () {
                       return { all: row[2] };
                     },
                     issuerOf: function () { return BASE; } };
      const p = Server.prototype.actorTokenProblem.call(self, row[0],
        { client_id: row[1] }, BASE);
      return { claims: row[0], client: row[1], names: row[2], base: BASE,
               issuer: BASE, code: p ? p.code : '',
               description: p ? p.description : '' };
    });
    out.chains = CHAINS.map(function (row) {
      return { chain: row[0], issuer: row[1],
               out: Server.priorActChain(row[0], row[1]) };
    });
    out.originals = ORIGINALS.map(function (row) {
      return { subject: row[0], verified: row[1], actor: row[2],
               namespaced: row[3],
               out: Server.originalClientAct(row[0], row[1], row[2], row[3],
                                             'https://iss') };
    });
    const policyModule = require(path.join(ROOT, 'common',
                                           'delegation_policy'));
    out.mayActs = MAY_ACTS.map(function (row) {
      return { mayAct: row[0], actor: row[1],
               names: policyModule.mayActNames(row[0], row[1]) };
    });
    const verdicts = require(path.join(ROOT, 'xacml',
                                       'xacml_exchange_verdicts'));
    out.verdicts = verdictFacts().map(function (q) {
      const answer = verdicts.decide({ facts: q.facts, mode: q.mode,
                                       protocol: 'OAuth 2.0',
                                       settings: q.settings }, null, {});
      return Object.assign({}, q, { answer: answer });
    });
    out.decisions = [];
    ['product', 'development'].forEach(function (modeName) {
      const policy = new policyModule.DelegationPolicy(
        fakeDeps(ROOT, SETTINGS, modeName));
      QUESTIONS.forEach(function (q) {
        const question = questionOf(q);
        out.decisions.push({ mode: modeName, question: question,
                             decision: decisionOf(policy.decide(question)) });
      });
    });
    const device = require(path.join(ROOT, 'oauth-oidc',
                                     'device_authorization'));
    out.userCodes = USER_CODES.map(function (one) {
      return { typed: one, normalized: device.normalize(one) };
    });
    out.boundKeys = BOUND_KEYS.map(function (row) {
      const p = Server.prototype.boundKeyProofRefusal.call(
        { deps: { log: helpers.log },
          keyBindingOn: function () { return row[0]; } },
        row[1], row[2], row[3]);
      return { on: row[0], scope: row[1], code: row[2],
               claims: row[3] ? row[3].claims : null,
               refusal: p ? p.code : '', description: p ? p.description : '' };
    });
    const claimsPolicy = new policyModule.DelegationPolicy(
      fakeDeps(ROOT, SETTINGS, 'product'));
    out.claims = CLAIM_NAMES.map(function (name) {
      return { name: name, claim: claimsPolicy.mayActClaimFor(name) };
    });
  } catch (e) {
    out.problems.push(String((e && e.stack) || e));
  }
  return out;
}

// THE OTHER DIRECTION: what Rust computed, computed again here.
function checkRust(ROOT, rows, check) {
  const same = function (a, b) {
    return JSON.stringify(a) === JSON.stringify(b);
  };
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const verdicts = require(path.join(ROOT, 'xacml', 'xacml_exchange_verdicts'));
  (rows.verdicts || []).forEach(function (row, i) {
    const a = verdicts.decide({ facts: row.facts, mode: row.mode,
                                protocol: 'OAuth 2.0',
                                settings: row.settings }, null, {});
    const mine = { verdict: a.verdict, refusal: a.refusal,
                   enforced: a.enforced, semantics: a.semantics,
                   audience: a.audience, chosen: a.chosen };
    check(same(mine, row.answer),
          'oauth8: Node decides the exchange as Rust did (' + i + ')',
          JSON.stringify(mine) + ' vs ' + JSON.stringify(row.answer));
  });
  const policyModule = require(path.join(ROOT, 'common', 'delegation_policy'));
  (rows.decisions || []).forEach(function (row, i) {
    const policy = new policyModule.DelegationPolicy(
      fakeDeps(ROOT, SETTINGS, row.mode));
    const mine = decisionOf(policy.decide(row.question));
    check(same(mine, row.decision),
          'oauth8: Node decides the delegation as Rust did (' + i + ')',
          JSON.stringify(mine) + ' vs ' + JSON.stringify(row.decision));
  });
  const claimsPolicy = new policyModule.DelegationPolicy(
    fakeDeps(ROOT, SETTINGS, 'product'));
  (rows.claims || []).forEach(function (row) {
    const mine = claimsPolicy.mayActClaimFor(row.name);
    check(same(mine, row.claim),
          'oauth8: Node names the may_act Rust named (' + row.name + ')',
          JSON.stringify(mine) + ' vs ' + JSON.stringify(row.claim));
  });
}

module.exports = { build: build, checkRust: checkRust };
